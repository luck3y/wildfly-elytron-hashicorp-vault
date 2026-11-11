/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.credential.store.CredentialStoreException;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

public class VaultConnectorTestCase {

    VaultContainer<?> vaultTestContainer;

    /**
     * Helper method to get a secret value using the new alias-based API.
     * Converts old-style path+key calls to new VaultAlias format.
     *
     * @param connector the VaultConnector instance
     * @param path the full path (e.g., "secret/testing1")
     * @param key the key name
     * @return the secret value, or null if not found
     */
    private String getSecret(VaultConnector connector, String path, String key) throws CredentialStoreException {
        // Extract mount path and secret path from full path
        // Assuming default mount "secret" for these tests
        String secretPath = path.substring(path.indexOf('/') + 1);
        String aliasString = "#" + secretPath + "?" + key;

        VaultAlias alias = VaultAlias.parse(aliasString, "KVv2", "secret");
        Map<String, Object> data = connector.getSecretData(alias);
        if (data == null) {
            return null;
        }
        return VaultKeyPathOperations.resolveKeyPath(data, key);
    }

    /**
     * Helper method to put a secret value using the new alias-based API.
     */
    private void putSecret(VaultConnector connector, String path, String key, String value) throws CredentialStoreException {
        String secretPath = path.substring(path.indexOf('/') + 1);
        String aliasString = "#" + secretPath + "?" + key;

        VaultAlias alias = VaultAlias.parse(aliasString, "KVv2", "secret");
        connector.putSecretData(alias, value);
    }

    /**
     * Helper method to remove a secret value using the new alias-based API.
     */
    private void removeSecret(VaultConnector connector, String path, String key) throws CredentialStoreException {
        String secretPath = path.substring(path.indexOf('/') + 1);
        String aliasString = "#" + secretPath + "?" + key;

        VaultAlias alias = VaultAlias.parse(aliasString, "KVv2", "secret");
        connector.removeSecretData(alias);
    }

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    private void startVaultTestContainer() {
        vaultTestContainer = new VaultContainer<>(VaultContainerVersion.IMAGE)
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 ttl=30m top_secret=password123",
                        "kv put secret/testing2 ttl=30m dbuser=secretpass jmsuser=jmspass",
                        "kv put secret/my-secret ttl=30m my-value=s3cr3t"
                );
        vaultTestContainer.start();
    }

    @Test
    public void testGetSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "secret/testing1", new SslConfig().verify(true).build(), true);
        vaultService.configure();
        assertEquals("password123", getSecret(vaultService, "secret/testing1", "top_secret"));
    }

    @Test
    public void testPutSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "secret/testing1", new SslConfig().verify(true).build(), true);
        vaultService.configure();
        putSecret(vaultService, "secret/testing1", "top_secret2", "password2");

        assertEquals("password2", getSecret(vaultService, "secret/testing1", "top_secret2"));
    }

    @Test
    public void testRemoveSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "secret/testing1", new SslConfig().verify(true).build(), true);
        vaultService.configure();

        // First verify the secret exists
        String originalSecret = getSecret(vaultService, "secret/testing1", "top_secret");
        assertEquals("password123", originalSecret);

        // Remove the secret
        removeSecret(vaultService, "secret/testing1", "top_secret");

        assertNull(getSecret(vaultService, "secret/testing1", "top_secret"));
        // If we get here, the test should fail because exception was expected

    }

    @Test
    public void testIncorrectVaultToken() throws Exception {
        // setup test container with vault
        vaultTestContainer = new VaultContainer<>(VaultContainerVersion.IMAGE)
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vaultTestContainer.start();

        // Test vault service with incorrect token - this should throw VaultException when attempting to use it
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "incorrect-token", "admin", new SslConfig().verify(true).build(), true);
        vaultService.configure();
        assertThrows(CredentialStoreException.class, () -> getSecret(vaultService, "secret/testing1", "top_secret"),
                "CredentialStoreException should be thrown due to authentication failure");
    }

    @Test
    public void testRemove() throws Exception {
        // setup and start test container with vault
        startVaultTestContainer();

        // Test vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "admin", new SslConfig().verify(true).build(), true);
        vaultService.configure();
        removeSecret(vaultService, "secret/testing1", "top_secret");
    }

    // =====================================================================
    // Error response handling — 403 Forbidden and 404 Not Found paths
    // =====================================================================

    /**
     * Starts a Vault container and creates a restrictive ACL policy with a limited token.
     * The policy allows read-only access to {@code secret/data/testing1} and {@code secret/data/testing2}.
     * No write, delete, or list capabilities are granted.
     */
    private void startVaultWithRestrictedPolicy() throws Exception {
        vaultTestContainer = new VaultContainer<>(VaultContainerVersion.IMAGE)
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass",
                        "kv put secret/my-secret my-value=s3cr3t"
                );
        vaultTestContainer.start();

        vaultTestContainer.execInContainer("sh", "-c",
                "echo 'path \"secret/data/testing1\" { capabilities = [\"read\"] }\n"
                        + "path \"secret/data/testing2\" { capabilities = [\"read\"] }' "
                        + "| vault policy write restricted -");
        vaultTestContainer.execInContainer("vault", "token", "create",
                "-policy=restricted", "-id=restricted-token", "-ttl=1h");
    }

    private VaultConnector createRestrictedConnector() throws VaultException {
        VaultConnector connector = new VaultConnector(
                vaultTestContainer.getHttpHostAddress(), "restricted-token",
                "admin", new SslConfig().verify(true).build(), true);
        connector.configure();
        return connector;
    }

    /**
     * Read a non-existent path from Vault.
     * Test passes when {@code getSecret} returns {@code null} (HTTP 404 handling).
     */
    @Test
    public void testGetSecretReturnsNullForNonExistentPath() throws Exception {
        startVaultTestContainer();
        VaultConnector connector = new VaultConnector(
                vaultTestContainer.getHttpHostAddress(), "myroot", "admin",
                new SslConfig().verify(true).build(), true);
        connector.configure();
        assertNull(getSecret(connector, "secret/nonexistent", "somekey"));
    }

    /**
     * Read a secret from a path the restricted token does not have access to.
     * Test passes when {@link VaultException} is thrown indicating forbidden access.
     */
    @Test
    public void testGetSecretForbiddenWithRestrictedToken() throws Exception {
        startVaultWithRestrictedPolicy();
        VaultConnector connector = createRestrictedConnector();
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
                () -> getSecret(connector, "secret/my-secret", "my-value"));
        assertTrue(ex.getMessage().contains("Forbidden") || ex.getMessage().contains("403"),
                "Expected 'Forbidden' or '403' in message, got: " + ex.getMessage());
    }

    /**
     * Write a secret using a token that only has read access.
     * Test passes when {@link VaultException} is thrown indicating forbidden access.
     */
    @Test
    public void testPutSecretForbiddenWithRestrictedToken() throws Exception {
        startVaultWithRestrictedPolicy();
        VaultConnector connector = createRestrictedConnector();
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
                () -> putSecret(connector, "secret/testing1", "newkey", "newvalue"));
        assertTrue(ex.getMessage().contains("Forbidden") || ex.getMessage().contains("403"),
                "Expected 'Forbidden' or '403' in message, got: " + ex.getMessage());
    }

    /**
     * Remove the only key at a path using a read-only token; the delete operation is forbidden.
     * Test passes when {@link VaultException} is thrown indicating forbidden access.
     */
    @Test
    public void testRemoveSecretForbiddenOnDeleteWithRestrictedToken() throws Exception {
        startVaultWithRestrictedPolicy();
        VaultConnector connector = createRestrictedConnector();
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
                () -> removeSecret(connector, "secret/testing1", "top_secret"));
        assertTrue(ex.getMessage().contains("Forbidden") || ex.getMessage().contains("403"),
                "Expected 'Forbidden' or '403' in message, got: " + ex.getMessage());
    }

    /**
     * Remove one key from a multi-key path using a read-only token; the write-back is forbidden.
     * Test passes when {@link VaultException} is thrown indicating forbidden access.
     */
    @Test
    public void testRemoveSecretForbiddenOnWriteBackWithRestrictedToken() throws Exception {
        startVaultWithRestrictedPolicy();
        VaultConnector connector = createRestrictedConnector();
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
                () -> removeSecret(connector, "secret/testing2", "dbuser"));
        assertTrue(ex.getMessage().contains("Forbidden") || ex.getMessage().contains("403"),
                "Expected 'Forbidden' or '403' in message, got: " + ex.getMessage());
    }

    // NOTE: Tests for getKeysForPath() and listAllItemsAtPath() have been removed
    // as these methods are no longer part of the VaultConnector API.
    // The new alias-based API focuses on individual secret operations rather than
    // path-level listing operations.
}
