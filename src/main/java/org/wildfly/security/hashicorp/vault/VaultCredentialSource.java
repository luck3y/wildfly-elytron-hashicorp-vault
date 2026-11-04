/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.io.IOException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;
import java.util.function.Supplier;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * A credential source which is backed by a HashiCorp Vault.
 * <p>
 * This class has been updated to use the new alias format internally while maintaining
 * backwards compatibility with the legacy path/key constructor.
 */
public class VaultCredentialSource implements CredentialSource {

    private final VaultConnector vaultConnector;
    private final VaultAlias alias;

    public static Supplier<Provider[]> ELYTRON_PASSWORD_PROVIDERS = () -> new Provider[]{
            WildFlyElytronPasswordProvider.getInstance()
    };

    /**
     * Construct a new instance using an alias string.
     * <p>
     * The alias string should be in the new format:
     * {@code [engine=TYPE][@mount-path]#secret-path?key-path}
     * <p>
     * Examples:
     * <ul>
     *   <li>{@code #myapp/database?password} - Simple key with defaults</li>
     *   <li>{@code engine=KVv1@secret-v1#myapp?password} - Explicit engine and mount</li>
     *   <li>{@code @custom-mount#myapp/config?db.host} - Custom mount with nested key</li>
     * </ul>
     *
     * @param vaultConnector the service connecting to vault instance (must not be {@code null})
     * @param alias the vault alias string specifying the secret location and key (must not be {@code null})
     * @throws IllegalArgumentException if the alias format is invalid
     */
    public VaultCredentialSource(VaultConnector vaultConnector, String alias) {
        if (vaultConnector == null) {
            throw ROOT_LOGGER.vaultConnectorCannotBeNull();
        }
        if (alias == null || alias.trim().isEmpty()) {
            throw new IllegalArgumentException("Alias cannot be null or empty");
        }

        this.vaultConnector = vaultConnector;
        try {
            this.alias = VaultAlias.parse(alias, VaultConstants.ENGINE_TYPE_KV_V2, VaultConstants.DEFAULT_MOUNT_PATH);
        } catch (CredentialStoreException e) {
            throw new IllegalArgumentException("Failed to parse alias: " + e.getMessage(), e);
        }
    }

    /**
     * Construct a new instance using explicit component parameters.
     * <p>
     * This constructor allows you to specify all components of the vault secret location explicitly:
     * <ul>
     *   <li>engineType - The KV engine type (KVv1 or KVv2)</li>
     *   <li>mountPath - The mount path where the KV engine is mounted (e.g., "secret", "team/backend")</li>
     *   <li>secretPath - The path to the secret within the mount (e.g., "myapp/database")</li>
     *   <li>keyPath - The key within the secret to retrieve (e.g., "password", "database/credentials/password")</li>
     * </ul>
     *
     * @param vaultConnector the service connecting to vault instance (must not be {@code null})
     * @param engineType the engine type (KVv1 or KVv2, must not be {@code null})
     * @param mountPath the mount path (must not be {@code null})
     * @param secretPath the secret path (must not be {@code null})
     * @param keyPath the key path (must not be {@code null})
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public VaultCredentialSource(VaultConnector vaultConnector, String engineType, String mountPath,
                                  String secretPath, String keyPath) {
        if (vaultConnector == null) {
            throw ROOT_LOGGER.vaultConnectorCannotBeNull();
        }

        this.vaultConnector = vaultConnector;
        try {
            this.alias = VaultAlias.create(engineType, mountPath, secretPath, keyPath);
        } catch (CredentialStoreException e) {
            throw new IllegalArgumentException("Failed to create alias from components: " + e.getMessage(), e);
        }
    }

    /**
     * Construct a new instance using legacy path/key format.
     * <p>
     * <b>Deprecated:</b> This constructor is deprecated because the {@code secretPath} parameter
     * is ambiguous - it's unclear whether it includes the mount path or not. Use one of the
     * following constructors instead:
     * <ul>
     *   <li>{@link #VaultCredentialSource(VaultConnector, String)} - with a full alias string</li>
     *   <li>{@link #VaultCredentialSource(VaultConnector, String, String, String, String)} - with explicit components</li>
     * </ul>
     * <p>
     * This constructor maintains backwards compatibility by converting the legacy path/key
     * format to the new alias format internally. The conversion assumes:
     * <ul>
     *   <li>Default engine type: KVv2</li>
     *   <li>Default mount path: secret</li>
     *   <li>Alias format: {@code secretPath?secretKey}</li>
     * </ul>
     *
     * @param vaultConnector the service connecting to vault instance (must not be {@code null})
     * @param secretPath the path to the secret to retrieve from (must not be {@code null})
     * @param secretKey the key of the secret (must not be {@code null})
     * @deprecated Use {@link #VaultCredentialSource(VaultConnector, String)} or
     *             {@link #VaultCredentialSource(VaultConnector, String, String, String, String)} instead
     */
    @Deprecated
    public VaultCredentialSource(VaultConnector vaultConnector, String secretPath, String secretKey) {
        if (vaultConnector == null) {
            throw ROOT_LOGGER.vaultConnectorCannotBeNull();
        }
        if (secretPath == null || secretPath.trim().isEmpty()) {
            throw ROOT_LOGGER.vaultSecretPathInvalid();
        }
        if (secretKey == null || secretKey.trim().isEmpty()) {
            throw ROOT_LOGGER.vaultSecretKeyInvalid();
        }

        this.vaultConnector = vaultConnector;

        // Convert legacy path/key to new alias format
        // The secretPath in legacy format includes the mount path (e.g., "secret/testing1")
        try {
            // Extract mount path and secret path from legacy format
            String mountPath = VaultConstants.DEFAULT_MOUNT_PATH; // default
            String actualSecretPath = secretPath;

            if (secretPath.contains("/")) {
                int firstSlash = secretPath.indexOf('/');
                mountPath = secretPath.substring(0, firstSlash);
                actualSecretPath = secretPath.substring(firstSlash + 1);
            }

            this.alias = VaultAlias.create(VaultConstants.ENGINE_TYPE_KV_V2, mountPath, actualSecretPath, secretKey);
        } catch (CredentialStoreException e) {
            throw new IllegalArgumentException("Failed to convert legacy path/key to alias format: " + e.getMessage(), e);
        }
    }

    //TODO support more credential types
    public boolean isCredentialSupported(Class<? extends Credential> credentialType, String algorithm,
                                         AlgorithmParameterSpec parameterSpec) throws IOException {
        return credentialType == PasswordCredential.class &&
                (algorithm == null || ClearPassword.ALGORITHM_CLEAR.equals(algorithm));
    }

    @Override
    public <C extends Credential> C getCredential(Class<C> credentialType, String algorithm,
                                                  AlgorithmParameterSpec parameterSpec) throws IOException {
        ROOT_LOGGER.tracef("VaultCredentialSource retrieving credential: type=%s, alias=%s", credentialType.getSimpleName(), alias.toString());
        //TODO support more credential types
        if (credentialType == PasswordCredential.class) {
            try {
                vaultConnector.configure();

                // Use new alias-based methods
                Map<String, Object> secretData = vaultConnector.getSecretData(alias);
                if (secretData == null) {
                    ROOT_LOGGER.tracef("VaultCredentialSource credential not found: alias=%s, reason=%s", alias.toString(), "secret data not found");
                    return null;
                }

                String password = VaultKeyPathOperations.resolveKeyPathSegments(secretData, alias.getKeyPathSegments());
                if (password == null) {
                    ROOT_LOGGER.tracef("VaultCredentialSource credential not found: alias=%s, reason=%s", alias.toString(), "key not found in secret data");
                    return null;
                }
                PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, ELYTRON_PASSWORD_PROVIDERS);
                ClearPassword clearPassword = (ClearPassword) factory.generatePassword(
                        new ClearPasswordSpec(password.toCharArray()));
                ROOT_LOGGER.tracef("VaultCredentialSource credential retrieved successfully: alias=%s", alias.toString());
                return credentialType.cast(new PasswordCredential(clearPassword));
            } catch (Exception e) {
                throw ROOT_LOGGER.failedToRetrieveCredentialFromVaultIo(e.getMessage(), e);
            }
        }

        ROOT_LOGGER.tracef("VaultCredentialSource unsupported credential type requested: %s", credentialType.getSimpleName());
        return null;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
                                                    AlgorithmParameterSpec parameterSpec) throws IOException {
        if (isCredentialSupported(credentialType, algorithmName, parameterSpec)) {
            return SupportLevel.SUPPORTED;
        }
        return SupportLevel.UNSUPPORTED;
    }
}