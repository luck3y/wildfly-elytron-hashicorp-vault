/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.hashicorp.vault.KvVersionTestHelper.KvVersion;
import org.wildfly.security.password.interfaces.ClearPassword;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

/**
 * Parameterized test suite for {@link VaultConnector} covering both KV v1 and KV v2 engines.
 *
 * <p>This test class uses JUnit 5's {@code @ParameterizedTest} to run the same test logic
 * against different Vault configurations:
 * <ul>
 *   <li>KV v1 only</li>
 *   <li>KV v2 only (default)</li>
 *   <li>Mixed environment (both v1 and v2 at different mounts)</li>
 * </ul>
 *
 * <p><strong>Test Coverage:</strong>
 * <ul>
 *   <li>Basic CRUD operations (Create, Read, Update, Delete)</li>
 *   <li>Path format validation</li>
 *   <li>Error handling (404, 403)</li>
 *   <li>Multi-key secret operations</li>
 *   <li>List operations</li>
 * </ul>
 *
 * <p><strong>Key Differences Tested:</strong>
 * <ul>
 *   <li><strong>KV v1:</strong> Direct paths, no versioning, full overwrite on update</li>
 *   <li><strong>KV v2:</strong> /data/ paths, versioning, creates new version on update</li>
 * </ul>
 */
public class VaultConnectorKvVersionTestCase {

    private VaultContainer<?> vaultContainer;

    @AfterEach
    public void cleanup() {
        if (vaultContainer != null) {
            vaultContainer.stop();
        }
    }

    /**
     * Provides test configurations for parameterized tests.
     * Each configuration includes a Vault container with a specific KV version setup.
     */
    static Stream<Arguments> kvVersionConfigurations() {
        return Stream.of(
            // KV v1 only
            Arguments.of(new VaultContainerKvV1<>(VaultContainerVersion.IMAGE), "secret", KvVersion.V1),

            // KV v2 only (using standard VaultContainer which defaults to v2)
            Arguments.of(new VaultContainer<>(VaultContainerVersion.IMAGE)
                .withVaultToken("myroot")
                .withInitCommand(
                    "secrets enable transit",
                    "write -f transit/keys/my-key",
                    "kv put secret/testing1 top_secret=password123",
                    "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass",
                    "kv put secret/my-secret my-value=s3cr3t"
                ), "secret", KvVersion.V2),

            // Mixed: KV v1 at secret-v1/
            Arguments.of(new VaultContainerKvMixed<>(VaultContainerVersion.IMAGE), "secret-v1", KvVersion.V1),

            // Mixed: KV v2 at secret/
            Arguments.of(new VaultContainerKvMixed<>(VaultContainerVersion.IMAGE), "secret", KvVersion.V2)
        );
    }

    private VaultConnector createConnector(VaultContainer<?> container, String token, KvVersion version, String mountPath) throws VaultException {
        VaultConnector connector = new VaultConnector(
            container.getHttpHostAddress(),
            token,
            "admin",
            new SslConfig().verify(true).build(),
            true
        );
        connector.configure();
        return connector;
    }

    // =====================================================================
    // Helper Methods for API Migration
    // =====================================================================

    /**
     * Helper method to get a secret value using the new alias-based API.
     * Converts old-style path/key calls to new VaultAlias format.
     */
    private String getSecret(VaultConnector connector, String path, String key, String mountPath, KvVersion version) throws CredentialStoreException {
        // Extract secret path from full path (remove mount prefix)
        String secretPath = path.substring(mountPath.length());
        if (secretPath.startsWith("/")) {
            secretPath = secretPath.substring(1);
        }

        // Build alias string: #secret-path?key
        String aliasString = "#" + secretPath + "?" + key;

        // Determine engine type from KV version
        String engineType = version == KvVersion.V1 ? "KVv1" : "KVv2";

        // Parse alias
        VaultAlias alias = VaultAlias.parse(aliasString, engineType, mountPath);

        // Get secret data
        Map<String, Object> data = connector.getSecretData(alias);
        if (data == null) {
            return null;
        }

        // Resolve key path
        return VaultKeyPathOperations.resolveKeyPath(data, key);
    }

    /**
     * Helper method to put a secret value using the new alias-based API.
     */
    private void putSecret(VaultConnector connector, String path, String key, String value, String mountPath, KvVersion version) throws CredentialStoreException {
        // Extract secret path from full path
        String secretPath = path.substring(mountPath.length());
        if (secretPath.startsWith("/")) {
            secretPath = secretPath.substring(1);
        }

        // Build alias string
        String aliasString = "#" + secretPath + "?" + key;
        String engineType = version == KvVersion.V1 ? "KVv1" : "KVv2";

        // Parse alias and put secret
        VaultAlias alias = VaultAlias.parse(aliasString, engineType, mountPath);
        connector.putSecretData(alias, value);
    }

    /**
     * Helper method to remove a secret key using the new alias-based API.
     */
    private void removeSecret(VaultConnector connector, String path, String key, String mountPath, KvVersion version) throws CredentialStoreException {
        // Extract secret path from full path
        String secretPath = path.substring(mountPath.length());
        if (secretPath.startsWith("/")) {
            secretPath = secretPath.substring(1);
        }

        // Build alias string
        String aliasString = "#" + secretPath + "?" + key;
        String engineType = version == KvVersion.V1 ? "KVv1" : "KVv2";

        // Parse alias and remove secret
        VaultAlias alias = VaultAlias.parse(aliasString, engineType, mountPath);
        connector.removeSecretData(alias);
    }

    // =====================================================================
    // Basic CRUD Operations
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Get secret from {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetSecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot", version, mountPath);
        String secret = getSecret(connector, mountPath + "/testing1", "top_secret", mountPath, version);

        assertEquals("password123", secret,
            String.format("Should retrieve secret from %s mount", version));
    }

    @ParameterizedTest(name = "[{2}] Put secret to {1}")
    @MethodSource("kvVersionConfigurations")
    public void testPutSecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot", version, mountPath);

        // Put a new secret
        putSecret(connector, mountPath + "/testing1", "new_secret", "newvalue123", mountPath, version);

        // Verify it was stored
        String retrieved = getSecret(connector, mountPath + "/testing1", "new_secret", mountPath, version);
        assertEquals("newvalue123", retrieved,
            String.format("Should store and retrieve new secret in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Update existing secret in {1}")
    @MethodSource("kvVersionConfigurations")
    public void testUpdateSecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot", version, mountPath);

        // Verify original value
        String original = getSecret(connector, mountPath + "/testing1", "top_secret", mountPath, version);
        assertEquals("password123", original);

        // Update the secret
        putSecret(connector, mountPath + "/testing1", "top_secret", "updated_password", mountPath, version);

        // Verify updated value
        String updated = getSecret(connector, mountPath + "/testing1", "top_secret", mountPath, version);
        assertEquals("updated_password", updated,
            String.format("Should update existing secret in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Remove secret from {1}")
    @MethodSource("kvVersionConfigurations")
    public void testRemoveSecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot", version, mountPath);

        // Verify secret exists
        String original = getSecret(connector, mountPath + "/testing1", "top_secret", mountPath, version);
        assertNotNull(original);

        // Remove the secret
        removeSecret(connector, mountPath + "/testing1", "top_secret", mountPath, version);

        // Verify it's gone
        String removed = getSecret(connector, mountPath + "/testing1", "top_secret", mountPath, version);
        assertNull(removed,
            String.format("Should remove secret from %s", version));
    }

    // =====================================================================
    // Multi-Key Secret Operations
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Modify single key in multi-key secret at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testModifySingleKeyInMultiKeySecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot", version, mountPath);

        // Verify both keys exist initially
        assertEquals("secretpass", getSecret(connector, mountPath + "/testing2", "dbuser", mountPath, version));
        assertEquals("jmspass", getSecret(connector, mountPath + "/testing2", "jmsuser", mountPath, version));

        // Modify only dbuser
        putSecret(connector, mountPath + "/testing2", "dbuser", "new_dbpass", mountPath, version);

        // Verify dbuser changed but jmsuser remained
        assertEquals("new_dbpass", getSecret(connector, mountPath + "/testing2", "dbuser", mountPath, version),
            String.format("Should update modified key in %s", version));
        assertEquals("jmspass", getSecret(connector, mountPath + "/testing2", "jmsuser", mountPath, version),
            String.format("Should preserve unmodified key in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Remove single key from multi-key secret at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testRemoveSingleKeyFromMultiKeySecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot", version, mountPath);

        // Verify both keys exist
        assertNotNull(getSecret(connector, mountPath + "/testing2", "dbuser", mountPath, version));
        assertNotNull(getSecret(connector, mountPath + "/testing2", "jmsuser", mountPath, version));

        // Remove only dbuser
        removeSecret(connector, mountPath + "/testing2", "dbuser", mountPath, version);

        // Verify dbuser is gone but jmsuser remains
        assertNull(getSecret(connector, mountPath + "/testing2", "dbuser", mountPath, version),
            String.format("Should remove specified key in %s", version));
        assertNotNull(getSecret(connector, mountPath + "/testing2", "jmsuser", mountPath, version),
            String.format("Should preserve other keys in %s", version));
    }

    // =====================================================================
    // Error Handling
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Get non-existent secret returns null at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetNonExistentSecretReturnsNull(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot", version, mountPath);

        String result = getSecret(connector, mountPath + "/nonexistent", "somekey", mountPath, version);
        assertNull(result,
            String.format("Should return null for non-existent path in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Get non-existent key returns null at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetNonExistentKeyReturnsNull(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot", version, mountPath);

        String result = getSecret(connector, mountPath + "/testing1", "nonexistent_key", mountPath, version);
        assertNull(result,
            String.format("Should return null for non-existent key in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Invalid token throws exception at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testInvalidTokenThrowsException(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = new VaultConnector(
            vaultContainer.getHttpHostAddress(),
            "invalid-token",
            "admin",
            new SslConfig().verify(true).build(),
            true
        );

        // Configure succeeds with lazy initialization, but actual operation should fail
        connector.configure();

        // Try to use the connector - this should trigger lazy initialization and fail
        assertThrows(Exception.class, () -> getSecret(connector, mountPath + "/test", "key", mountPath, version),
            String.format("Should throw VaultException for invalid token in %s", version));
    }

    // =====================================================================
    // Path Format Validation
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Nested path operations at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testNestedPathOperations(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot", version, mountPath);

        // Create secret at nested path
        String nestedPath = mountPath + "/app/database/credentials";
        putSecret(connector, nestedPath, "username", "dbuser", mountPath, version);
        putSecret(connector, nestedPath, "password", "dbpass", mountPath, version);

        // Retrieve from nested path
        assertEquals("dbuser", getSecret(connector, nestedPath, "username", mountPath, version),
            String.format("Should handle nested paths in %s", version));
        assertEquals("dbpass", getSecret(connector, nestedPath, "password", mountPath, version),
            String.format("Should handle nested paths in %s", version));
    }
}
