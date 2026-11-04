/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Represents a parsed Vault alias in the new format.
 *
 * <p>Extends {@link VaultPath} to add key path support for complete alias specification.
 *
 * <p>Format: {@code [engine=TYPE][@mount-path]#secret-path?key-path}
 *
 * <p>Components:
 * <ul>
 *   <li>{@code engine=TYPE} - Optional engine type specification (e.g., {@code engine=KVv1}, {@code engine=KVv2})</li>
 *   <li>{@code @mount-path} - Optional mount path (e.g., {@code @secret}, {@code @team/backend})</li>
 *   <li>{@code #secret-path} - Required secret path (e.g., {@code #myapp/database})</li>
 *   <li>{@code ?key-path} - Required key path (e.g., {@code ?password}, {@code ?database/credentials/password})</li>
 * </ul>
 *
 * <p>Examples:
 * <ul>
 *   <li>{@code #myapp/database?password} - Simple key with defaults</li>
 *   <li>{@code engine=KVv1@secret-v1#myapp?password} - Explicit engine and mount</li>
 *   <li>{@code #my.app.config?db.host} - Dots in secret path and key name</li>
 *   <li>{@code #myapp/database?database/credentials/password} - Nested JSON path</li>
 * </ul>
 */
class VaultAlias extends VaultPath {

    private final String keyPath;
    private final List<String> keyPathSegments;

    /**
     * Use factory methods or VaultPath.parse() to create instances.
     * Every {@code /} in the key path is treated as a nesting separator.
     *
     * @param engineType the engine type (KVv1 or KVv2)
     * @param mountPath the mount path
     * @param secretPath the secret path
     * @param keyPath the key path
     */
    VaultAlias(String engineType, String mountPath, String secretPath, String keyPath) {
        this(engineType, mountPath, secretPath, Arrays.asList(keyPath.split("/")));
    }

    /**
     * Package-private constructor taking already-decoded key path segments. A segment may
     * itself contain a literal {@code /} (from a percent-encoded {@code %2F} in the alias).
     *
     * @param engineType the engine type (KVv1 or KVv2)
     * @param mountPath the mount path
     * @param secretPath the secret path
     * @param keyPathSegments the decoded key path segments
     */
    VaultAlias(String engineType, String mountPath, String secretPath, List<String> keyPathSegments) {
        super(engineType, mountPath, secretPath);
        this.keyPathSegments = Collections.unmodifiableList(keyPathSegments);
        this.keyPath = String.join("/", keyPathSegments);
    }

    /**
     * Create a VaultAlias directly from components without parsing.
     * This method validates the engine type but does not perform URL encoding -
     * components should already be in their decoded form.
     *
     * @param engineType the engine type (KVv1 or KVv2)
     * @param mountPath the mount path
     * @param secretPath the secret path
     * @param keyPath the key path
     * @return a new VaultAlias instance
     * @throws CredentialStoreException if the engine type is invalid or any required component is null/empty
     */
    static VaultAlias create(String engineType, String mountPath, String secretPath, String keyPath) throws CredentialStoreException {
        // Validate required parameters - null checks
        checkNotNullParam("engineType", engineType);
        checkNotNullParam("mountPath", mountPath);
        checkNotNullParam("secretPath", secretPath);
        checkNotNullParam("keyPath", keyPath);

        // Business validation - empty checks
        if (engineType.isEmpty()) {
            throw ROOT_LOGGER.engineTypeCannotBeEmpty("direct creation");
        }
        if (mountPath.isEmpty()) {
            throw ROOT_LOGGER.mountPathCannotBeEmpty("direct creation");
        }
        if (secretPath.isEmpty()) {
            throw ROOT_LOGGER.secretPathCannotBeEmpty("direct creation");
        }
        if (keyPath.isEmpty()) {
            throw ROOT_LOGGER.keyPathCannotBeEmpty("direct creation");
        }

        // Validate engine type
        if (!engineType.equals(VaultConstants.ENGINE_TYPE_KV_V1) && !engineType.equals(VaultConstants.ENGINE_TYPE_KV_V2)) {
            throw ROOT_LOGGER.invalidEngineType(engineType);
        }

        // Validate key path doesn't contain empty segments (if using nested path syntax)
        if (keyPath.contains("/")) {
            if (keyPath.startsWith("/") || keyPath.endsWith("/") || keyPath.contains("//")) {
                throw ROOT_LOGGER.keyPathContainsEmptySegment(keyPath);
            }
        }

        return new VaultAlias(engineType, mountPath, secretPath, keyPath);
    }

    /**
     * Parse a vault alias string using default engine type and mount path.
     *
     * @param alias the alias string to parse
     * @return the parsed VaultAlias
     * @throws CredentialStoreException if the alias format is invalid
     */
    public static VaultAlias parse(String alias) throws CredentialStoreException {
        return parse(alias, VaultConstants.ENGINE_TYPE_KV_V2, VaultConstants.DEFAULT_MOUNT_PATH, false);
    }

    /**
     * Parse a vault alias string with specified defaults for engine type and mount path.
     *
     * @param alias the alias string to parse
     * @param defaultEngineType the default engine type to use if not specified in alias
     * @param defaultMountPath the default mount path to use if not specified in alias
     * @return the parsed VaultAlias
     * @throws CredentialStoreException if the alias format is invalid
     */
    public static VaultAlias parse(String alias, String defaultEngineType, String defaultMountPath) throws CredentialStoreException {
        return parse(alias, defaultEngineType, defaultMountPath, false);
    }

    /**
     * Parse a vault alias string with specified defaults and optional legacy format support.
     *
     * <p>Format: {@code [engine=TYPE][@mount-path]#secret-path?key-path}
     *
     * <p>When {@code supportLegacyFormat} is true, also accepts legacy format: {@code secret-path.key}
     * where the last dot separates secret path from key. Legacy format triggers a deprecation warning.
     *
     * @param alias the alias string to parse
     * @param defaultEngineType the default engine type to use if not specified in alias
     * @param defaultMountPath the default mount path to use if not specified in alias
     * @param supportLegacyFormat whether to support legacy {@code secret.key} format
     * @return the parsed VaultAlias
     * @throws CredentialStoreException if the alias format is invalid or legacy format is not supported
     */
    public static VaultAlias parse(String alias, String defaultEngineType, String defaultMountPath,
                                   boolean supportLegacyFormat) throws CredentialStoreException {
        return VaultPath.parse(alias, defaultEngineType, defaultMountPath, supportLegacyFormat, true, VaultAlias.class);
    }

    /**
     * Get the decoded key path segments joined with {@code /} (e.g., "password",
     * "database/credentials/password"). This form is for display and logging only: a segment
     * that contained an encoded slash ({@code %2F}) is indistinguishable from a nesting
     * separator here. Use {@link #getKeyPathSegments()} to look up values.
     *
     * @return the key path
     */
    public String getKeyPath() {
        return keyPath;
    }

    /**
     * Get the decoded key path segments. Each segment is a single map key; a segment
     * may contain a literal {@code /} when the alias used {@code %2F}.
     *
     * @return an unmodifiable list of key path segments
     */
    public List<String> getKeyPathSegments() {
        return keyPathSegments;
    }

    /**
     * Convert the engine type string to a KV version number.
     *
     * @return 1 for KVv1, 2 for KVv2
     * @throws CredentialStoreException if the engine type is not a valid KV version
     */
    public int getKvVersion() throws CredentialStoreException {
        return engineTypeToVersion(getEngineType());
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        VaultAlias that = (VaultAlias) o;
        return Objects.equals(keyPathSegments, that.keyPathSegments);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), keyPathSegments);
    }

    /**
     * Convert an engine type string to a KV version number.
     * This is a utility method that can be used without creating a VaultAlias instance.
     *
     * @param engineType the engine type string (e.g., "KVv1", "KVv2")
     * @return 1 for KVv1, 2 for KVv2
     * @throws CredentialStoreException if the engine type is not a valid KV version
     */
    static int engineTypeToVersion(String engineType) throws CredentialStoreException {
        if (engineType == null) {
            throw ROOT_LOGGER.invalidEngineType("null");
        }
        switch (engineType) {
            case VaultConstants.ENGINE_TYPE_KV_V1:
                return 1;
            case VaultConstants.ENGINE_TYPE_KV_V2:
                return 2;
            default:
                throw ROOT_LOGGER.invalidEngineType(engineType);
        }
    }



    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("VaultAlias{");
        sb.append("engineType='").append(getEngineType()).append('\'');
        sb.append(", mountPath='").append(getMountPath()).append('\'');
        sb.append(", secretPath='").append(getSecretPath()).append('\'');
        sb.append(", keyPath='").append(keyPath).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
