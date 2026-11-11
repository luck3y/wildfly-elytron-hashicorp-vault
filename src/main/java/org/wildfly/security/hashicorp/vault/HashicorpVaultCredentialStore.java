/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.credential.store._private.ElytronMessages.log;
import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLContext;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreExtension;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.interfaces.ClearPassword;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

/**
 * Credential store backed by HashiCorp Vault.
 *
 * <p>This credential store integrates with HashiCorp Vault to securely retrieve credentials.
 * It supports the new structured alias format with nested JSON path traversal, as well as
 * optional backward compatibility with the legacy format.
 *
 * <h2>Alias Format</h2>
 * <p>The new alias format is:
 * <pre>{@code [engine=TYPE][@mount-path][#]secret-path?key-path}</pre>
 *
 * <p>Examples:
 * <ul>
 *   <li>{@code myapp/database?password} - Simple key</li>
 *   <li>{@code myapp/config?database/host} - Nested JSON path</li>
 *   <li>{@code engine=KVv1#old-app/config?api_key} - Explicit engine type</li>
 *   <li>{@code @prod/secrets#myapp/db?password} - Custom mount path</li>
 * </ul>
 *
 * <h2>Configuration Parameters</h2>
 * <ul>
 *   <li>{@code host-address} (required) - Vault server URL</li>
 *   <li>{@code namespace} (optional) - Vault namespace (Enterprise)</li>
 *   <li>{@code trust-store-path} (optional) - Path to trust store for TLS</li>
 *   <li>{@code key-store-path} (optional) - Path to key store for mutual TLS</li>
 *   <li>{@code key-store-pass} (optional) - Key store password</li>
 *   <li>{@code trust-store-pass} (optional) - Trust store password</li>
 *   <li>{@code support-legacy-alias-format} (optional) - Enable legacy format support (default: false)</li>
 *   <li>{@code default-engine-type} (optional) - Default engine type (default: KVv2)</li>
 *   <li>{@code default-mount-path} (optional) - Default mount path (default: secret)</li>
 * </ul>
 *
 * <p>For complete documentation, see the project documentation in the {@code docs/} directory.
 *
 * @see VaultAlias
 * @see VaultKeyPathOperations
 */
public class HashicorpVaultCredentialStore extends CredentialStoreSpi {

    private static final int DEFAULT_MAX_ALIASES = 10_000;
    private static final int DEFAULT_MAX_DEPTH = 100;
    /** Default maximum number of credentials to keep in the in-memory cache. */
    private static final int DEFAULT_CREDENTIAL_CACHE_MAX_SIZE = 500;
    private static List<Class<? extends CredentialStoreExtension>> SUPPORTED_EXTENSION_TYPES =
            List.of(HashicorpVaultCredentialStoreExtension.class);
    String hostAddress;
    String namespace;
    CredentialStore.ProtectionParameter protectionParameter;
    Provider[] providers;
    VaultConnector vaultConnector;
    private String trustStorePath;
    private String keyStorePath;
    private String keyStorePass;
    private String trustStorePass;
    private SSLContext sslContext;

    /** In-memory LRU cache of retrieved credentials, keyed by parsed VaultAlias. */
    private Map<VaultAlias, Credential> credentialCache;

    /** Whether to support legacy alias format (secret-path.key). Defaults to false. */
    private boolean supportLegacyAliasFormat = false;

    /** Default engine type to use when not specified in alias. */
    private String defaultEngineType = VaultConstants.ENGINE_TYPE_KV_V2;

    /** Default mount path to use when not specified in alias. */
    private String defaultMountPath = VaultConstants.DEFAULT_MOUNT_PATH;


    @Override
    public void initialize(Map<String, String> attributes, CredentialStore.ProtectionParameter protectionParameter, Provider[] providers) throws CredentialStoreException {
        checkNotNullParam("attributes", attributes);

        // Check required attributes
        this.hostAddress = attributes.get("host-address");
        if (this.hostAddress == null || this.hostAddress.trim().isEmpty()) {
            throw ROOT_LOGGER.hostAddressRequired();
        }

        if (attributes.get("trust-store-path") != null) {
            this.trustStorePath = attributes.get("trust-store-path");
        }

        if (attributes.get("key-store-path") != null) {
            this.keyStorePath = attributes.get("key-store-path");
        }

        if (attributes.get("key-store-pass") != null) {
            this.keyStorePass = attributes.get("key-store-pass");
        }

        if (attributes.get("trust-store-pass") != null) {
            this.trustStorePass = attributes.get("trust-store-pass");
        }

        this.namespace = attributes.get("namespace");
        this.protectionParameter = protectionParameter;
        this.providers = providers;

        // Parse new configuration parameters
        if (attributes.get("support-legacy-alias-format") != null) {
            this.supportLegacyAliasFormat = Boolean.parseBoolean(attributes.get("support-legacy-alias-format"));
        }

        if (attributes.get("default-engine-type") != null) {
            this.defaultEngineType = attributes.get("default-engine-type");
            // Validate engine type
            if (!this.defaultEngineType.equals(VaultConstants.ENGINE_TYPE_KV_V1) && !this.defaultEngineType.equals(VaultConstants.ENGINE_TYPE_KV_V2)) {
                throw ROOT_LOGGER.invalidDefaultEngineType(this.defaultEngineType);
            }
        }

        if (attributes.get("default-mount-path") != null) {
            this.defaultMountPath = attributes.get("default-mount-path");
        }

        ROOT_LOGGER.tracef("Credential store initializing: host=%s, namespace=%s, defaultEngineType=%s, defaultMountPath=%s, supportLegacyAliasFormat=%b",
                this.hostAddress, this.namespace, this.defaultEngineType, this.defaultMountPath, this.supportLegacyAliasFormat);

        this.credentialCache = Collections.synchronizedMap(new LinkedHashMap<VaultAlias, Credential>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<VaultAlias, Credential> eldest) {
                return size() > DEFAULT_CREDENTIAL_CACHE_MAX_SIZE;
            }
        });

        try {
            char[] password = getStorePassword(protectionParameter);
            String token = password != null ? String.valueOf(password) : null;
            boolean hasToken = token != null && !token.trim().isEmpty();
            boolean hasClientCertConfig = this.sslContext != null
                    || (this.keyStorePath != null && !this.keyStorePath.trim().isEmpty());
            SensitiveValueHasher.traceLog("Authentication method determined: token=%s, hasToken=%b, hasClientCertConfig=%b",
                    token, hasToken, hasClientCertConfig);

            if (!hasToken && !hasClientCertConfig) {
                throw ROOT_LOGGER.noAuthenticationMethodConfigured();
            }

            SslConfig sslConfig = new SslConfig().verify(true);

            if (this.keyStorePath != null && !this.keyStorePath.trim().isEmpty()) {
                SensitiveValueHasher.traceLog("Loading KeyStore: password=%s, path=%s",
                        this.keyStorePass, this.keyStorePath);
                try {
                    KeyStore keyStore = KeyStore.getInstance("JKS");
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(this.keyStorePath)) {
                        keyStore.load(fis, this.keyStorePass != null ? this.keyStorePass.toCharArray() : null);
                    }

                    if (this.keyStorePass != null) {
                        sslConfig.keyStore(keyStore, this.keyStorePass);
                    } else {
                        sslConfig.keyStore(keyStore, "");
                    }
                } catch (Exception e) {
                    throw ROOT_LOGGER.failedToLoadKeyStore(e.getMessage(), e);
                }
            }

            if (this.trustStorePath != null && !this.trustStorePath.trim().isEmpty()) {
                SensitiveValueHasher.traceLog("Loading TrustStore: password=%s, path=%s",
                        this.trustStorePass, this.trustStorePath);
                try {
                    KeyStore trustStore = KeyStore.getInstance("JKS");
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(this.trustStorePath)) {
                        trustStore.load(fis, this.trustStorePass != null ? this.trustStorePass.toCharArray() : null);
                    }
                    if (this.trustStorePass != null) {
                        sslConfig.trustStore(trustStore);
                    } else {
                        sslConfig.trustStore(trustStore);
                    }
                } catch (Exception e) {
                    throw ROOT_LOGGER.failedToLoadTrustStore(e.getMessage(), e);
                }
            }

            try {
                sslConfig.build();
            } catch (VaultException e) {
                throw ROOT_LOGGER.failedToBuildVaultTlsConfiguration(e);
            }
            vaultConnector = new VaultConnector(this.hostAddress, token, this.namespace, sslConfig, true, sslContext);
            vaultConnector.configure();

            initialized = true;
            ROOT_LOGGER.tracef("Credential store initialized successfully for host: %s", this.hostAddress);
        } catch (IOException e) {
            throw ROOT_LOGGER.failedToInitializeVaultCredentialStore(e);
        }
    }

    public void setSslContext(SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    @Override
    public boolean isModifiable() {
        return true;
    }

    @Override
    public void store(String credentialAlias, Credential credential, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException, UnsupportedCredentialTypeException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (credentialAlias == null || credentialAlias.trim().isEmpty()) {
            throw ROOT_LOGGER.credentialAliasRequired();
        }
        if (credential == null) {
            throw ROOT_LOGGER.credentialCannotBeNull();
        }

        VaultAlias alias = parseAlias(credentialAlias);
        ROOT_LOGGER.tracef("Storing credential: alias=%s (mount=%s, path=%s, key=%s)",
                credentialAlias, alias.getMountPath(), alias.getSecretPath(), alias.getKeyPath());

        try {
            final char[] chars = credential.castAndApply(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
            if (chars == null) {
                throw ROOT_LOGGER.failedToExtractPasswordFromCredential();
            }
            vaultConnector.putSecretData(alias, new String(chars));
            putInCredentialCache(alias, credential);
            ROOT_LOGGER.tracef("Credential stored successfully: alias=%s", credentialAlias);
        } catch (ClassCastException e) {
            throw ROOT_LOGGER.onlyPasswordCredentialWithClearPasswordSupported(e);
        }
    }

    @Override
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (credentialAlias == null || credentialAlias.trim().isEmpty()) {
            throw ROOT_LOGGER.credentialAliasRequired();
        }

        VaultAlias alias = parseAlias(credentialAlias);
        ROOT_LOGGER.tracef("Retrieving credential: alias=%s, requestedType=%s", credentialAlias, credentialType.getSimpleName());

        // Check cache first using the parsed VaultAlias as key
        Credential cached;
        synchronized (credentialCache) {
            cached = credentialCache.get(alias);
        }
        if (credentialType.isInstance(cached)) {
            ROOT_LOGGER.tracef("Credential cache hit: alias=%s", credentialAlias);
            return credentialType.cast(cached);
        }

        ROOT_LOGGER.tracef("Credential cache miss: alias=%s, fetching from vault", credentialAlias);
        try {
            // Retrieve full secret data from Vault
            Map<String, Object> secretData = vaultConnector.getSecretData(alias);
            if (secretData == null) {
                ROOT_LOGGER.tracef("Credential not found: alias=%s, reason=%s", credentialAlias, "secret not found at path");
                return null;
            }

            // Resolve the specific value using key path
            String value = VaultKeyPathOperations.resolveKeyPathSegments(secretData, alias.getKeyPathSegments());
            if (value == null) {
                ROOT_LOGGER.tracef("Credential not found: alias=%s, reason=%s", credentialAlias, "key not found in secret");
                return null;
            }

            // Create credential from the value
            PasswordCredential credential = new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, value.toCharArray()));
            putInCredentialCache(alias, credential);
            ROOT_LOGGER.tracef("Credential retrieved successfully: alias=%s", credentialAlias);
            return credentialType.cast(credential);
        } catch (ClassCastException e) {
            throw ROOT_LOGGER.unsupportedCredentialType(credentialType.getSimpleName(), e);
        }
    }

    @Override
    public void remove(String credentialAlias, Class<? extends Credential> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (credentialAlias == null || credentialAlias.trim().isEmpty()) {
            throw ROOT_LOGGER.credentialAliasRequired();
        }

        VaultAlias alias = parseAlias(credentialAlias);
        ROOT_LOGGER.tracef("Removing credential: alias=%s (mount=%s, path=%s, key=%s)",
                credentialAlias, alias.getMountPath(), alias.getSecretPath(), alias.getKeyPath());

        vaultConnector.removeSecretData(alias);
        synchronized (credentialCache) {
            // Remove from cache using parsed VaultAlias as key
            // Note: If the removal empties the secret, other keys at same path are also removed from Vault
            credentialCache.remove(alias);
        }
        ROOT_LOGGER.tracef("Credential removed successfully: alias=%s", credentialAlias);
    }

    /**
     * Parse a credential alias string into a VaultAlias object.
     * Supports both new alias format and legacy format (if enabled).
     *
     * @param credentialAlias the alias string to parse
     * @return parsed VaultAlias object
     * @throws CredentialStoreException if parsing fails
     */
    private VaultAlias parseAlias(String credentialAlias) throws CredentialStoreException {
        return VaultAlias.parse(
            credentialAlias,
            this.defaultEngineType,
            this.defaultMountPath,
            this.supportLegacyAliasFormat
        );
    }

    private void putInCredentialCache(VaultAlias alias, Credential credential) {
        synchronized (credentialCache) {
            credentialCache.put(alias, credential);
        }
    }

    private static char[] getStorePassword(final CredentialStore.ProtectionParameter protectionParameter) throws IOException, CredentialStoreException {
        final char[] password;
        if (protectionParameter instanceof CredentialStore.CredentialSourceProtectionParameter) {
            password = ((CredentialStore.CredentialSourceProtectionParameter) protectionParameter).
                    getCredentialSource()
                    .applyToCredential(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        } else if (protectionParameter != null) {
            throw log.invalidProtectionParameter(protectionParameter);
        } else {
            password = null;
        }
        return password;
    }

    @Override
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        // "#" designates the root of the configured default mount.
        // Secrets reside under the mount root rather than at the root itself, so recursive listing
        // with DEFAULT_MAX_DEPTH is required to enumerate all aliases across descendant paths.
        return getAliases("#", true, DEFAULT_MAX_DEPTH);
    }

    /**
     * Get aliases from a specific path in Vault.
     *
     * @param path the Vault path to start listing from (e.g., "secret"). If null or empty, throw exception
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    public Set<String> getAliases(String path) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (path == null || path.trim().isEmpty()) {
            throw ROOT_LOGGER.emptyPathForGetAliases();
        }
        return collectAliases(normalizePath(path), false, 0);
    }

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal.
     * <p>
     * Path format depends on the {@code supportLegacyAliasFormat} configuration:
     * <ul>
     *   <li><b>New format</b> (always supported):
     *     <ul>
     *       <li>{@code @mount#secretpath} - explicit mount and secret path</li>
     *       <li>{@code #secretpath} - default mount with secret path</li>
     *       <li>{@code secretpath} - default mount with secret path (# is optional)</li>
     *       <li>{@code /} or {@code ""} - root of default mount</li>
     *       <li>{@code @mount#} or {@code @mount#/} - root of explicit mount</li>
     *     </ul>
     *   </li>
     *   <li><b>Legacy format</b> (only when {@code supportLegacyAliasFormat=true}):
     *     <ul>
     *       <li>{@code mount/secretpath} - mount point and secret path separated by first /</li>
     *       <li>{@code mount/} - root of mount point</li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param path the Vault path to start listing from. If null or empty, throw exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails or if legacy format is used when not supported
     */
    public Set<String> getAliases(String path, boolean recursive) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (path == null || path.trim().isEmpty()) {
            throw ROOT_LOGGER.emptyPathForGetAliases();
        }
        return collectAliases(normalizePath(path), recursive, DEFAULT_MAX_DEPTH);
    }

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal.
     * <p>
     * Path format depends on the {@code supportLegacyAliasFormat} configuration:
     * <ul>
     *   <li><b>New format</b> (always supported):
     *     <ul>
     *       <li>{@code @mount#secretpath} - explicit mount and secret path</li>
     *       <li>{@code #secretpath} - default mount with secret path</li>
     *       <li>{@code secretpath} - default mount with secret path (# is optional)</li>
     *       <li>{@code /} or {@code ""} - root of default mount</li>
     *       <li>{@code @mount#} or {@code @mount#/} - root of explicit mount</li>
     *     </ul>
     *   </li>
     *   <li><b>Legacy format</b> (only when {@code supportLegacyAliasFormat=true}):
     *     <ul>
     *       <li>{@code mount/secretpath} - mount point and secret path separated by first /</li>
     *       <li>{@code mount/} - root of mount point</li>
     *     </ul>
     *   </li>
     * </ul>
     *
     * @param path the Vault path to start listing from. If null or empty, throw exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @param recursiveDepth the maximum depth to traverse if recursive is true. 0 means only the specified path,
     *                       1 means one level deep, etc. Ignored if recursive is false.
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails or if legacy format is used when not supported
     */
    public Set<String> getAliases(String path, boolean recursive, int recursiveDepth) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (path == null || path.trim().isEmpty()) {
            throw ROOT_LOGGER.emptyPathForGetAliases();
        }
        if (recursiveDepth < 0) {
            throw ROOT_LOGGER.recursiveDepthMustBeNonNegative(recursiveDepth);
        }
        return collectAliases(path, recursive, recursiveDepth);
    }

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal and maximum alias limit.
     *
     * @param path the Vault path to start listing from (e.g., "secret"). If null or empty, throw exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @param recursiveDepth the maximum depth to traverse if recursive is true. 0 means only the specified path,
     *                       1 means one level deep, etc. Ignored if recursive is false.
     * @param maxNumberOfAliases the maximum number of aliases to return. Must be positive. Collection stops when this limit is reached.
     * @return set of aliases in format "path.key", containing at most maxNumberOfAliases aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    public Set<String> getAliases(String path, boolean recursive, int recursiveDepth, int maxNumberOfAliases) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (path == null || path.trim().isEmpty()) {
            throw ROOT_LOGGER.emptyPathForGetAliases();
        }
        if (recursiveDepth < 0) {
            throw ROOT_LOGGER.recursiveDepthMustBeNonNegative(recursiveDepth);
        }
        if (maxNumberOfAliases <= 0) {
            throw ROOT_LOGGER.maxNumberOfAliasesMustBePositive(maxNumberOfAliases);
        }
        return collectAliases(path, recursive, recursiveDepth, maxNumberOfAliases);
    }

    private final HashicorpVaultCredentialStoreExtension credentialStoreExtension = new HashicorpVaultCredentialStoreExtension() {
        @Override
        public void setSslContext(SSLContext sslContext) {
            HashicorpVaultCredentialStore.this.setSslContext(sslContext);
        }

        @Override
        public Set<String> getAliases(String path) throws CredentialStoreException {
            return HashicorpVaultCredentialStore.this.getAliases(path);
        }

        @Override
        public Set<String> getAliases(String path, boolean recursive) throws CredentialStoreException {
            return HashicorpVaultCredentialStore.this.getAliases(path, recursive);
        }

        @Override
        public Set<String> getAliases(String path, boolean recursive, int recursiveDepth) throws CredentialStoreException {
            return HashicorpVaultCredentialStore.this.getAliases(path, recursive, recursiveDepth);
        }

        @Override
        public Set<String> getAliases(String path, boolean recursive, int recursiveDepth, int maxNumberOfAliases) throws CredentialStoreException {
            return HashicorpVaultCredentialStore.this.getAliases(path, recursive, recursiveDepth, maxNumberOfAliases);
        }
    };

    @Override
    public <C extends CredentialStoreExtension> C getExtensionInstance(final Class<C> extensionType) {
        if (extensionType != null && extensionType.isInstance(credentialStoreExtension)) {
            return extensionType.cast(credentialStoreExtension);
        }
        return null;
    }

    @Override
    public List<Class<? extends CredentialStoreExtension>> getSupportedExtensionTypes() {
        return SUPPORTED_EXTENSION_TYPES;
    }


    private Set<String> collectAliases(String path, boolean recursive, int maxDepth) throws CredentialStoreException {
        return collectAliases(path, recursive, maxDepth, DEFAULT_MAX_ALIASES);
    }

    private Set<String> collectAliases(String path, boolean recursive, int maxDepth, int maxNumberOfAliases) throws CredentialStoreException {
        ROOT_LOGGER.tracef("Listing aliases: path=%s, recursive=%b, maxDepth=%d, maxAliases=%d",
                path, recursive, maxDepth, maxNumberOfAliases);
        Set<String> aliases = new HashSet<>();
        collectAliasesRecursive(path, aliases, recursive, maxDepth, 0, maxNumberOfAliases);
        ROOT_LOGGER.tracef("Alias listing completed: %d aliases found", aliases.size());
        return aliases;
    }

    /**
     * Recursively collect aliases from Vault using the new alias format.
     *
     * <p>This implementation:
     * <ul>
     *   <li>Parses the input path to extract engine type, mount path, and secret path</li>
     *   <li>Lists secrets at the current path</li>
     *   <li>For each secret, gets all keys and creates aliases in new format</li>
     *   <li>Recursively traverses subdirectories if enabled</li>
     * </ul>
     *
     * <p>Supported path formats:
     * <ul>
     *   <li>{@code engine=TYPE@mount#secretpath} - Full specification with engine type</li>
     *   <li>{@code @mount#secretpath} - Explicit mount with default engine type</li>
     *   <li>{@code #secretpath} - Default mount and engine type</li>
     *   <li>{@code secretpath} - Minimal format (# is optional)</li>
     *   <li>{@code mount/secretpath} - Legacy format (only when {@code supportLegacyAliasFormat=true})</li>
     * </ul>
     *
     * @param path the path to list in any supported format
     * @param aliases the set to collect aliases into
     * @param recursive whether to recurse into subdirectories
     * @param maxDepth maximum recursion depth
     * @param currentDepth current recursion depth
     * @param maxNumberOfAliases maximum number of aliases to collect
     * @throws CredentialStoreException if listing fails or path format is invalid
     */
    private void collectAliasesRecursive(String path, Set<String> aliases, boolean recursive, int maxDepth, int currentDepth, int maxNumberOfAliases) throws CredentialStoreException {
        ROOT_LOGGER.tracef("Collecting aliases: path=%s, currentDepth=%d/%d, collected=%d/%d",
                path, currentDepth, maxDepth, aliases.size(), maxNumberOfAliases);
        if (aliases.size() >= maxNumberOfAliases) {
            return;
        }

        // Parse the path using VaultPath to extract mount and secret path
        // This handles all formats: engine=TYPE@mount#secretpath, @mount#secretpath,
        // #secretpath, secretpath, and legacy mount/secretpath (when enabled)
        VaultPath vaultPath;
        try {
            vaultPath = VaultPath.parse(path != null ? path : "", defaultEngineType, defaultMountPath, supportLegacyAliasFormat);
        } catch (CredentialStoreException e) {
            // Invalid path format, cannot proceed
            ROOT_LOGGER.tracef(e, "Failed to parse path '%s'", path);
            return;
        }

        String mountPath = vaultPath.getMountPath();
        String secretPath = vaultPath.getSecretPath();
        String engineType = vaultPath.getEngineType();

        // First, try to get keys for the secret at this exact path
        // This handles the case where the path itself is a secret (e.g., "app1")
        try {
            VaultPath secretVaultPath = VaultPath.create(engineType, mountPath, secretPath);
            List<List<String>> keys = vaultConnector.getKeysForSecret(secretVaultPath);
            if (keys != null && !keys.isEmpty()) {
                for (List<String> key : keys) {
                    if (aliases.size() >= maxNumberOfAliases) return;
                    aliases.add(VaultPath.toAlias(secretPath, key));
                }
            }
        } catch (CredentialStoreException e) {
            // No secret at this path, continue
            ROOT_LOGGER.tracef(e, "No secret found at path '%s', continuing to check subdirectories", secretPath);
        }

        // If recursive and we haven't exceeded depth, list subdirectories
        if (recursive && currentDepth < maxDepth) {
            try {
                // List items under this path
                List<String> items = vaultConnector.listSecretsAtPath(mountPath, secretPath, defaultEngineType);

                if (items != null && !items.isEmpty()) {
                    // Process items from LIST
                    for (String item : items) {
                        if (aliases.size() >= maxNumberOfAliases) return;

                        if (item.endsWith("/")) {
                            // Subdirectory - recurse into it
                            String subdirName = item.substring(0, item.length() - 1);
                            String fullPath = secretPath.isEmpty() ? subdirName : secretPath + "/" + subdirName;
                            collectAliasesRecursive("@" + VaultPath.encodePath(mountPath) + "#" + VaultPath.encodePath(fullPath), aliases, recursive, maxDepth, currentDepth + 1, maxNumberOfAliases);
                        } else {
                            // Secret - get its keys
                            String fullPath = secretPath.isEmpty() ? item : secretPath + "/" + item;
                            try {
                                VaultPath childVaultPath = VaultPath.create(engineType, mountPath, fullPath);
                                List<List<String>> keys = vaultConnector.getKeysForSecret(childVaultPath);
                                if (keys != null) {
                                    for (List<String> key : keys) {
                                        if (aliases.size() >= maxNumberOfAliases) return;
                                        aliases.add(VaultPath.toAlias(fullPath, key));
                                    }
                                }
                            } catch (CredentialStoreException e) {
                                // Could not get keys for this secret, continue
                                ROOT_LOGGER.tracef(e, "Could not read secret at path '%s', skipping", fullPath);
                            }
                        }
                    }
                }
            } catch (CredentialStoreException e) {
                // Re-throw the exception - if recursive listing fails (e.g., due to permissions),
                // the caller should be notified
                throw e;
            }
        }
    }

    private String normalizePath(String path) {
        return path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }
}
