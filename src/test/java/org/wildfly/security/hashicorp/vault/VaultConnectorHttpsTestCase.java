/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.wildfly.security.credential.store.CredentialStoreException;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

/**
 * Dedicated tests for Vault listening on HTTPS interface
 */
public class VaultConnectorHttpsTestCase {

    private VaultContainerHttps<?> vaultTestContainer;

    private SslConfig httpsSslConfig;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    private void startVaultTestContainer() throws IOException, VaultException {
        vaultTestContainer = new VaultContainerHttps<>(VaultContainerVersion.IMAGE)
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 ttl=30m top_secret=password123",
                        "kv put secret/testing2 ttl=30m dbuser=secretpass jmsuser=jmspass",
                        "kv put secret/my-secret ttl=30m my-value=s3cr3t"
                );
        vaultTestContainer.start();

        httpsSslConfig = new SslConfig()
                //to enable HTTPS
                .pemFile(vaultTestContainer.getHttpsTrustFile().toFile())
                .verify(true)
                .build();
    }

    /**
     * Helper method to get a secret value using the new alias-based API.
     */
    private String getSecret(VaultConnector connector, String path, String key) throws CredentialStoreException {
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

    @Test
    public void testGetSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service - namespace is null for default namespace
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "myroot", null, httpsSslConfig, true);
        vaultService.configure();
        assertEquals("password123", getSecret(vaultService, "secret/testing1", "top_secret"));
    }

    @Test
    public void testPutSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service - namespace is null for default namespace
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "myroot", null, httpsSslConfig, true);
        vaultService.configure();
        putSecret(vaultService, "secret/testing1", "top_secret2", "password2");

        assertEquals("password2", getSecret(vaultService, "secret/testing1", "top_secret2"));
    }

    @Test
    public void testRemoveSecretFromVaultService() throws Exception {
        // setup test container with vault
        startVaultTestContainer();

        // Test vault service - namespace is null for default namespace
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "myroot", null, httpsSslConfig, true);
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
        vaultTestContainer = new VaultContainerHttps<>(VaultContainerVersion.IMAGE)
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vaultTestContainer.start();

        // Test vault service with incorrect token - this should throw CredentialStoreException when attempting to use it
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "incorrect-token", "admin", httpsSslConfig, true);
        vaultService.configure();
        assertThrows(CredentialStoreException.class, () -> getSecret(vaultService, "secret/testing1", "top_secret"),
                "CredentialStoreException should be thrown due to authentication failure");
    }

    @Test
    public void testRemove() throws Exception {
        // setup and start test container with vault
        startVaultTestContainer();

        // Test vault service - namespace is null for default namespace
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "myroot", null, httpsSslConfig, true);
        vaultService.configure();
        removeSecret(vaultService, "secret/testing1", "top_secret");
    }

    /**
     * Verify that connection fails when the client trusts a different CA than the one that issued
     * the Vault server certificate. The SSL handshake should be rejected.
     */
    @Test
    public void testConnectionFailsWithUntrustedServerCert() throws Exception {
        startVaultTestContainer();

        Path wrongCertDir = TlsTestMaterial.temporaryDirectory("wrong_certs");
        try {
            TlsTestMaterial wrongPem = TlsTestMaterial.generate(wrongCertDir, "localhost", true);

            SslConfig wrongTrustConfig = new SslConfig()
                    .pemFile(wrongPem.trustFile().toFile())
                    .verify(true)
                    .build();

            VaultConnector vaultService = new VaultConnector(
                    vaultTestContainer.composeHttpsHostAddress(), "myroot", "secret/testing1", wrongTrustConfig, true);
            vaultService.configure();
            assertThrows(CredentialStoreException.class, () -> getSecret(vaultService, "secret/testing1", "top_secret"));
        } finally {
            VaultTestUtils.cleanupDir(wrongCertDir);
        }
    }

    /**
     * Verify that connection fails when SSL verification is enabled but no trust PEM is configured.
     * The self-signed Vault certificate is not trusted by the JVM default trust store.
     */
    @Test
    public void testConnectionFailsWithNoTrustConfigured() throws Exception {
        startVaultTestContainer();

        SslConfig noTrustConfig = new SslConfig().verify(true).build();
        VaultConnector vaultService = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(), "myroot", "secret/testing1", noTrustConfig, true);
        vaultService.configure();
        assertThrows(CredentialStoreException.class, () -> getSecret(vaultService, "secret/testing1", "top_secret"));
    }
}
