/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


import javax.net.ssl.SSLContext;

import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.hashicorp.vault.loginstrategy.ClientCertificateLoginStrategy;
import org.wildfly.security.hashicorp.vault.loginstrategy.JwtLoginStrategy;
import org.wildfly.security.hashicorp.vault.loginstrategy.LoginContext;
import org.wildfly.security.hashicorp.vault.loginstrategy.TokenLoginStrategy;
import org.wildfly.security.hashicorp.vault.loginstrategy.VaultLoginStrategy;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.json.Json;
import io.github.jopenlibs.vault.json.JsonObject;
import io.github.jopenlibs.vault.json.JsonValue;
import io.github.jopenlibs.vault.response.LogicalResponse;

/**
 * Vault Connector
 */
public class VaultConnector {

    private final String vaultUrl;
    private final String token;
    private final String namespace;
    private final SslConfig sslConfig;

    /**
     * Cached HttpClient instance (created once during initialization).
     * Reused across all Vault instances for efficient connection pooling.
     * HttpClient in Java 11+ uses connection pooling by default, so a single
     * instance can efficiently handle multiple concurrent requests to the same destination.
     */
    private final HttpClient httpClient;

    private JwtConfig jwtConfig;

    /**
     * Cache of Vault instances keyed by engine type and mount path segment count.
     * Key format: "KVv1" or "KVv2-{segmentCount}"
     * For KV v1, segment count doesn't matter (no /data/ insertion)
     * For KV v2, we need different instances for different segment counts
     */
    private final Map<String, Vault> vaultInstanceCache = new HashMap<>();

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify) {
        this(vaultUrl, token, namespace, sslConfig, sslVerify, null);
    }

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify, SSLContext sslContext) {
        this.vaultUrl = vaultUrl;
        this.token = token;
        this.namespace = namespace;
        this.sslConfig = sslConfig;

        if (sslContext != null) {
            this.httpClient = HttpClient.newBuilder().sslContext(sslContext).build();
        } else {
            this.httpClient = null;
        }
    }

    public VaultConnector(String vaultUrl, JwtConfig jwtConfig, String namespace, SslConfig sslConfig) {
        this(vaultUrl, jwtConfig, namespace, sslConfig, null);
    }

    public VaultConnector(String vaultUrl, JwtConfig jwtConfig, String namespace, SslConfig sslConfig, SSLContext sslContext) {
        this.vaultUrl = vaultUrl;
        this.token = null;
        this.namespace = namespace;
        this.sslConfig = sslConfig;
        this.jwtConfig = jwtConfig;

        if (sslContext != null) {
            this.httpClient = HttpClient.newBuilder().sslContext(sslContext).build();
        } else {
            this.httpClient = null;
        }
    }

    public void configure() {
        // Vault instances will be created lazily on first use and cached
        ROOT_LOGGER.vaultConfigurationSuccessful(this.vaultUrl);
    }

    /**
     * Login with subsequently with each possible method and stop when login was successful. Resulting Vault will carry
     * VaultConfig with token which obtained from the final login attempt.
     * Note that only methods which prerequisites are satisfied will be tried.
     * @param loginContext current login context
     * @param config initial VaultConfig
     * @return Vault with token configured
     * @throws CredentialStoreException thrown when all login strategies fail
     */
    private Vault tryLoginWithFallback(LoginContext loginContext, VaultConfig config) throws CredentialStoreException {
        List<VaultLoginStrategy> strategies = composePossibleLoginStrategiesPrioritized(loginContext);
        if (ROOT_LOGGER.isTraceEnabled()) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < strategies.size(); i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append(strategies.get(i).getClass().getSimpleName());
            }
            ROOT_LOGGER.tracef("Starting login with fallback: %d strategies to try: [%s]", strategies.size(), sb.toString());
        }

        for (VaultLoginStrategy strategy : strategies) {
            try {
                ROOT_LOGGER.tracef("Trying login strategy: %s", strategy.getClass().getSimpleName());
                String response = strategy.tryLogin(loginContext);

                if (response != null) {
                    config.token(response);
                    Vault vault = Vault.create(config.build());
                    vault.auth().lookupSelf();
                    ROOT_LOGGER.tracef("Login succeeded with strategy: %s", strategy.getClass().getSimpleName());
                    return vault;
                }
            } catch (VaultException e) {
                ROOT_LOGGER.vaultLoginAttemptFailed(strategy.getClass().getSimpleName(), e);
            }
        }

        throw ROOT_LOGGER.vaultAllLoginStrategiesFailed();
    }

    private List<VaultLoginStrategy> composePossibleLoginStrategiesPrioritized(final LoginContext loginContext) {
        final List<VaultLoginStrategy> loginStrategies = new ArrayList<>();
        if (!hasNonEmptyToken(loginContext)) {
            loginStrategies.add(new ClientCertificateLoginStrategy());
        }
        if (loginContext.getJwtConfig() != null) {
            loginStrategies.add(new JwtLoginStrategy());
        }
        if (loginContext.getToken() != null) {
            loginStrategies.add(new TokenLoginStrategy());
        }
        return loginStrategies;
    }

    private static boolean hasNonEmptyToken(final LoginContext loginContext) {
        final String t = loginContext.getToken();
        return t != null && !t.trim().isEmpty();
    }

    /**
     * Count the number of path segments in a mount path.
     * For example: "secret" = 1, "team/backend" = 2, "org/team/backend" = 3
     *
     * @param mountPath the mount path
     * @return the number of segments
     */
    private int countMountPathSegments(String mountPath) {
        if (mountPath == null || mountPath.isEmpty()) {
            return 0;
        }
        // Count slashes and add 1
        int count = 1;
        for (int i = 0; i < mountPath.length(); i++) {
            if (mountPath.charAt(i) == '/') {
                count++;
            }
        }
        return count;
    }

    /**
     * Get the appropriate Vault instance based on the path's engine type and mount path.
     * Creates Vault instances lazily on first use and caches them.
     *
     * For KV v2, different mount path segment counts require different Vault instances
     * because the driver needs to know where to insert the /data/ segment.
     *
     * @param path the vault path containing engine type and mount path information
     * @return the appropriate Vault instance for the specified engine type and mount path
     */
    private Vault getVaultForPath(VaultPath path) throws CredentialStoreException {
        String engineType = path.getEngineType();
        String mountPath = path.getMountPath();

        // Determine KV version and segment count
        final int kvVersion;
        final int segmentCount;

        if (VaultConstants.ENGINE_TYPE_KV_V1.equals(engineType)) {
            // KV v1 doesn't use /data/ insertion, so segment count doesn't matter
            kvVersion = 1;
            segmentCount = 0; // irrelevant for v1
        } else {
            // KV v2 - need to account for mount path segment count
            kvVersion = 2;
            segmentCount = countMountPathSegments(mountPath);
        }

        return getOrCreateVaultInstance(kvVersion, segmentCount);
    }

    /**
     * Get or create a cached Vault instance for the specified KV version and segment count.
     * This method ensures that Vault instances are reused efficiently across operations.
     *
     * @param kvVersion the KV engine version (1 or 2)
     * @param segmentCount the number of path segments in the mount path
     * @return the cached or newly created Vault instance
     * @throws CredentialStoreException if Vault instance creation fails
     */
    private synchronized Vault getOrCreateVaultInstance(int kvVersion, int segmentCount) throws CredentialStoreException {
        final String cacheKey;
        if (kvVersion == 1) {
            cacheKey = VaultConstants.ENGINE_TYPE_KV_V1;
        } else {
            cacheKey = VaultConstants.ENGINE_TYPE_KV_V2 + "-" + segmentCount;
        }

        Vault cached = vaultInstanceCache.get(cacheKey);
        if (cached != null) {
            ROOT_LOGGER.tracef("Vault instance cache hit: cacheKey=%s", cacheKey);
            return cached;
        }

        SensitiveValueHasher.traceLog("Creating new Vault instance: token=%s, kvVersion=%d, prefixPathDepth=%d, url=%s, namespace=%s",
                this.token, kvVersion, segmentCount, this.vaultUrl, this.namespace);
        try {
            Vault instance = createVaultInstance(kvVersion, segmentCount);
            vaultInstanceCache.put(cacheKey, instance);
            return instance;
        } catch (VaultException e) {
            throw ROOT_LOGGER.failedToCreateVaultInstance(e);
        }
    }


    /**
     * Create a Vault instance configured for the specified KV engine version and mount path depth.
     *
     * @param kvVersion the KV engine version (1 or 2)
     * @param prefixPathDepth the number of path segments in the mount path (e.g., "secret" = 1, "team/backend" = 2)
     * @return configured Vault instance
     * @throws VaultException if Vault library operations fail
     * @throws CredentialStoreException if login fails
     */
    private Vault createVaultInstance(int kvVersion, int prefixPathDepth) throws VaultException, CredentialStoreException {
        VaultConfig config = new VaultConfig()
                .sslConfig(this.sslConfig)
                .address(this.vaultUrl)
                .engineVersion(kvVersion);

        // Only set prefixPathDepth if > 1 (library default is 1 for single-segment paths)
        if (prefixPathDepth > 1) {
            config.prefixPathDepth(prefixPathDepth);
        }

        // Use the shared HttpClient only when it has been configured with a custom SSLContext.
        // Otherwise, let the Vault library create its own client from the SslConfig
        // (which may include PEM trust certificates that the default HttpClient doesn't know about).
        if (httpClient != null) {
            config.httpClient(httpClient);
        }

        if (this.namespace != null && !this.namespace.isEmpty()) {
            config.nameSpace(this.namespace);
        }

        final LoginContext loginContext = new LoginContext(token, jwtConfig,
                Vault.create(config.build()));
        return tryLoginWithFallback(loginContext, config);
    }

    /**
     * Construct the full Vault path from alias components.
     * Combines mount path and secret path with proper formatting.
     *
     * @param path the vault path
     * @return the full path for Vault API calls
     */
    String constructVaultPath(VaultPath path) {
        String mountPath = path.getMountPath();
        String secretPath = path.getSecretPath();

        // Ensure mount path doesn't end with /
        if (mountPath.endsWith("/")) {
            mountPath = mountPath.substring(0, mountPath.length() - 1);
        }

        // Ensure secret path doesn't start with /
        if (secretPath.startsWith("/")) {
            secretPath = secretPath.substring(1);
        }

        // URL-encode path segments to handle special characters (spaces, etc.)
        // The Vault library doesn't properly encode path components
        mountPath = urlEncodePath(mountPath);
        secretPath = urlEncodePath(secretPath);

        return mountPath + "/" + secretPath;
    }

    /**
     * URL-encode a path while preserving path separators (/).
     * Encodes each segment separately to avoid encoding the slashes.
     */
    private String urlEncodePath(String path) {
        if (path == null || path.isEmpty()) {
            return path;
        }

        String[] segments = path.split("/", -1);
        StringBuilder encoded = new StringBuilder();

        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                encoded.append("/");
            }
            try {
                // Encode each segment, preserving structure
                encoded.append(java.net.URLEncoder.encode(segments[i], "UTF-8")
                    .replace("+", "%20")); // Use %20 for spaces instead of +
            } catch (java.io.UnsupportedEncodingException e) {
                // UTF-8 is always supported
                throw new RuntimeException(e);
            }
        }

        return encoded.toString();
    }

    /**
     * Retrieve full secret data from Vault using the new alias format.
     * Returns the complete data map for the secret, which can then be
     * processed using VaultKeyPathOperations to extract specific values.
     *
     * @param alias the parsed vault alias containing mount path, secret path, and engine type
     * @return map of all key-value pairs in the secret, or null if secret not found
     * @throws CredentialStoreException if retrieval fails
     */
    /**
     * List all secret paths at the given mount and path.
     *
     * @param mountPath the mount path (e.g., "secret")
     * @param secretPath the secret path to list (e.g., "myapp" or "myapp/db")
     * @param engineType the engine type ("KVv1" or "KVv2")
     * @return set of subpath names (directories end with "/", secrets don't)
     * @throws CredentialStoreException if listing fails
     */
    public List<String> listSecretsAtPath(String mountPath, String secretPath, String engineType) throws CredentialStoreException {
        ROOT_LOGGER.tracef("Listing secrets at path: mountPath=%s, secretPath=%s, engineType=%s", mountPath, secretPath, engineType);
        try {
            // For KV v2, the Vault library automatically adds /metadata/ when listing
            // So we just pass mount + secret path, and it constructs the full path
            // The Vault library does not encode path components, so encode each segment here, as
            // constructVaultPath does for reads and writes. Otherwise a name such as "100%dir" or "a b"
            // produces a malformed request URL.
            String listPath;
            if (secretPath == null || secretPath.isEmpty()) {
                listPath = urlEncodePath(mountPath);
            } else {
                listPath = urlEncodePath(mountPath) + "/" + urlEncodePath(secretPath);
            }

            // Get or create a cached Vault instance for listing
            // Use the mount path segment count for proper /metadata/ insertion
            int kvVersion = VaultAlias.engineTypeToVersion(engineType);
            int segmentCount = countMountPathSegments(mountPath);
            Vault vault = getOrCreateVaultInstance(kvVersion, segmentCount);
            LogicalResponse response = vault.logical().list(listPath);
            int status = response.getRestResponse().getStatus();

            if (status == 200) {
                List<String> keys = response.getListData();
                int count = keys != null ? keys.size() : 0;
                ROOT_LOGGER.tracef("Listed %d secrets at path: mountPath=%s, secretPath=%s", count, mountPath, secretPath);
                return keys != null ? keys : new ArrayList<>();
            } else if (status == 404) {
                // Path doesn't exist or is empty
                return new ArrayList<>();
            } else if (status == 403) {
                throw ROOT_LOGGER.forbiddenToListSubpathsAtCredentialStorePath(listPath,
                    new VaultException("HTTP 403 Forbidden"));
            } else {
                throw ROOT_LOGGER.couldNotListSecretsAtPath(listPath, status);
            }
        } catch (VaultException e) {
            throw ROOT_LOGGER.couldNotListSecretsAtPath(mountPath + "/" + secretPath, e);
        }
    }

    /**
     * Get the key path of every credential value in a secret at the given path. Each key path is the list of
     * decoded segments that leads to a value, so a top-level field is a single segment and a field inside a nested
     * JSON object has one segment per level. Objects themselves are not credentials and are not returned, only
     * the values inside them, and an object with no values contributes nothing.
     *
     * @param path the vault path specifying the secret location
     * @return the key path segments of every value in the secret
     * @throws CredentialStoreException if reading fails
     */
    public List<List<String>> getKeysForSecret(VaultPath path) throws CredentialStoreException {
        List<List<String>> keyPaths = new ArrayList<>();
        collectKeyPaths(getSecretData(path), new ArrayList<>(), keyPaths);
        return keyPaths;
    }

    @SuppressWarnings("unchecked")
    private static void collectKeyPaths(Map<String, Object> data, List<String> prefix, List<List<String>> keyPaths) {
        if (data == null) {
            return;
        }
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            List<String> keyPath = new ArrayList<>(prefix);
            keyPath.add(entry.getKey());
            if (entry.getValue() instanceof Map) {
                collectKeyPaths((Map<String, Object>) entry.getValue(), keyPath, keyPaths);
            } else {
                keyPaths.add(keyPath);
            }
        }
    }

    /**
     * Convert the JSON data of a secret into maps that {@link VaultKeyPathOperations} can traverse.
     * A nested JSON object becomes a nested {@code Map}. Every other value is kept as text, as the
     * Vault client does: strings unquoted, numbers, booleans and arrays as their JSON text. JSON nulls
     * are left out, as the Vault client does.
     */
    static Map<String, Object> toDataMap(JsonObject json) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (JsonObject.Member member : json) {
            JsonValue value = member.getValue();
            if (value == null || value.isNull()) {
                continue;
            }
            if (value.isObject()) {
                result.put(member.getName(), toDataMap(value.asObject()));
            } else if (value.isString()) {
                result.put(member.getName(), value.asString());
            } else {
                result.put(member.getName(), value.toString());
            }
        }
        return result;
    }

    public Map<String, Object> getSecretData(VaultPath vaultPath) throws CredentialStoreException {
        if (vaultPath == null) {
            throw ROOT_LOGGER.vaultAliasCannotBeNull();
        }

        String path = constructVaultPath(vaultPath);

        try {
            Vault vault = getVaultForPath(vaultPath);
            LogicalResponse response = vault.logical().read(path);
            int responseStatus = response.getRestResponse().getStatus();
            if (responseStatus == 200) {
                Map<String, String> data = response.getData();
                if (data != null) {
                    ROOT_LOGGER.vaultRetrievedSecret(path, this.vaultUrl);
                    // response.getData() flattens nested JSON objects into JSON text, which key paths such as
                    // "database/credentials/password" cannot traverse. Build real nested maps from the JSON instead.
                    JsonObject dataObject = response.getDataObject();
                    if (dataObject != null) {
                        return toDataMap(dataObject);
                    }
                    return new HashMap<>(data);
                }
                return null;
            }
            if (responseStatus == 403) {
                ROOT_LOGGER.vaultForbiddenToRetrieveSecret(path);
                throw ROOT_LOGGER.vaultForbiddenToRetrieveSecretAtPath(path);
            }
            if (responseStatus == 404) {
                ROOT_LOGGER.vaultSecretNotFoundAtPath(path);
                return null;
            }

            throw ROOT_LOGGER.vaultFailedToRetrieveSecretHttp(path, vaultPath.getSecretPath(), responseStatus);
        } catch (VaultException e) {
            throw new CredentialStoreException("Failed to retrieve secret from Vault: " + e.getMessage(), e);
        }
    }

    /**
     * Read the secret at the path as a mutable map to be changed and written back. Nested JSON objects
     * become nested maps that {@link VaultKeyPathOperations} can modify. Every other value stays the
     * {@link JsonValue} Vault returned, so numbers, booleans, arrays and nulls are written back
     * unchanged. {@code response.getData()} cannot be used here: it turns nested objects into text,
     * which would then be written back as a string and destroy the structure.
     */
    private static Map<String, Object> readSecretDataForUpdate(Vault vault, String path) throws VaultException {
        Map<String, Object> secretData = new HashMap<>();
        LogicalResponse readResponse = vault.logical().read(path);
        if (readResponse.getRestResponse().getStatus() == 200) {
            JsonObject existing = readResponse.getDataObject();
            if (existing != null) {
                secretData.putAll(toMutableMap(existing));
            }
        }
        return secretData;
    }

    private static Map<String, Object> toMutableMap(JsonObject json) {
        Map<String, Object> result = new HashMap<>();
        for (JsonObject.Member member : json) {
            JsonValue value = member.getValue();
            result.put(member.getName(), value.isObject() ? toMutableMap(value.asObject()) : value);
        }
        return result;
    }

    /** Top-level values for the Vault client, with nested maps turned back into JSON objects. */
    private static Map<String, Object> toWritableData(Map<String, Object> data) {
        Map<String, Object> result = new HashMap<>();
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            result.put(entry.getKey(), toJsonValue(entry.getValue()));
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private static JsonValue toJsonValue(Object value) {
        if (value instanceof JsonValue) {
            return (JsonValue) value;
        }
        if (value instanceof Map) {
            JsonObject object = Json.object();
            for (Map.Entry<String, Object> entry : ((Map<String, Object>) value).entrySet()) {
                object.add(entry.getKey(), toJsonValue(entry.getValue()));
            }
            return object;
        }
        return Json.value(String.valueOf(value));
    }

    /**
     * Store a secret value in Vault using the new alias format.
     * This method reads the existing secret data, updates the specified key path,
     * and writes the entire secret back to Vault.
     *
     * @param alias the parsed vault alias specifying location and key path
     * @param value the value to store
     * @throws CredentialStoreException if the operation fails
     */
    Map<String, Object> putSecretData(VaultAlias alias, String value) throws CredentialStoreException {
        if (alias == null) {
            throw ROOT_LOGGER.vaultAliasCannotBeNull();
        }
        if (value == null) {
            throw ROOT_LOGGER.vaultValueCannotBeNull();
        }

        String path = constructVaultPath(alias);

        try {
            Vault vault = getVaultForPath(alias);

            // Read existing secret data to preserve other keys
            Map<String, Object> secretData = readSecretDataForUpdate(vault, path);

            // Update the value at the specified key path
            String keyPath = alias.getKeyPath();
            VaultKeyPathOperations.setNestedValueSegments(secretData, alias.getKeyPathSegments(), value);

            // Write back to Vault
            LogicalResponse response = vault.logical().write(path, toWritableData(secretData));
            int responseStatus = response.getRestResponse().getStatus();
            if (responseStatus == 200 || responseStatus == 204) {
                ROOT_LOGGER.vaultStoredSecret(path, this.vaultUrl);
                return secretData;
            }
            if (responseStatus == 403) {
                throw ROOT_LOGGER.vaultForbiddenToStoreSecretAtPath(path);
            }

            throw ROOT_LOGGER.vaultFailedToStoreSecretHttp(path, keyPath, responseStatus);
        } catch (VaultException e) {
            throw new CredentialStoreException("Failed to store secret in Vault: " + e.getMessage(), e);
        }
    }

    /**
     * Remove a secret value from Vault using the new alias format.
     * This method reads the existing secret data, removes the specified key path,
     * and either writes the remaining data back or deletes the entire secret if empty.
     *
     * @param alias the parsed vault alias specifying location and key path
     * @throws CredentialStoreException if the operation fails
     */
    void removeSecretData(VaultAlias alias) throws CredentialStoreException {
        if (alias == null) {
            throw ROOT_LOGGER.vaultAliasCannotBeNull();
        }

        String path = constructVaultPath(alias);

        try {
            Vault vault = getVaultForPath(alias);

            // Read existing secret data
            Map<String, Object> secretData = readSecretDataForUpdate(vault, path);

            // Remove the value at the specified key path
            String keyPath = alias.getKeyPath();
            boolean removed = VaultKeyPathOperations.removeNestedValueSegments(secretData, alias.getKeyPathSegments());

            if (!removed) {
                ROOT_LOGGER.vaultKeyDoesNotExistAtPath(keyPath, path);
                return;
            }

            // If secret data is now empty, delete the entire secret
            if (secretData.isEmpty()) {
                LogicalResponse deleteResponse = vault.logical().delete(path);
                int deleteStatus = deleteResponse.getRestResponse().getStatus();
                if (deleteStatus == 200 || deleteStatus == 204) {
                    ROOT_LOGGER.vaultDeletedSecretPath(path);
                    return;
                }
                if (deleteStatus == 403) {
                    throw ROOT_LOGGER.vaultForbiddenToDeleteSecretAtPath(path);
                }
                throw ROOT_LOGGER.vaultFailedToDeleteSecretHttp(path, deleteStatus);
            } else {
                // Write back the remaining keys
                LogicalResponse writeResponse = vault.logical().write(path, toWritableData(secretData));
                int writeStatus = writeResponse.getRestResponse().getStatus();
                if (writeStatus == 200 || writeStatus == 204) {
                    ROOT_LOGGER.vaultRemovedKeyFromPath(keyPath, path);
                    return;
                }
                if (writeStatus == 403) {
                    throw ROOT_LOGGER.vaultForbiddenToUpdateSecretAtPath(path);
                }
                throw ROOT_LOGGER.vaultFailedToUpdateSecretAfterRemoveKey(path, keyPath, writeStatus);
            }
        } catch (VaultException e) {
            throw new CredentialStoreException("Failed to remove secret from Vault: " + e.getMessage(), e);
        }
    }

}
