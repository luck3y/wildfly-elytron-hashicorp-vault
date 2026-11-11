/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.hashicorp.vault.auth.TlsCertAuthConfig;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

/**
 * Set of tests verifying functionality of VaultConnector when using TLS certificate authentication method
 */
public class VaultConnectorTlsAuthTestCase {

    private VaultContainerHttps<?> vaultTestContainer;

    private static SslConfig permissibleSslAuthConfig;

    @BeforeEach
    public void beforeEach() throws Exception {
        vaultTestContainer = new VaultContainerHttps<>(VaultContainerVersion.IMAGE)
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 ttl=30m top_secret=password123",
                        "kv put secret/testing2 ttl=30m dbuser=secretpass jmsuser=jmspass",
                        "kv put secret/my-secret ttl=30m my-value=s3cr3t"
                );

        new TlsCertAuthConfig.Builder(vaultTestContainer.getClientCertificateFiles())
                //this is a custom policy created in VaultContainerHttps since we cannot use root policy
                .policies("admin")
                .build()
                .configure(this.vaultTestContainer);

        permissibleSslAuthConfig = new SslConfig()
                //to enable HTTPS
                .pemFile(vaultTestContainer.getHttpsTrustFile().toFile())
                //for TLS certificate auth method
                .clientPemFile(vaultTestContainer.getClientCertificateFiles().certFile().toFile())
                .clientKeyPemFile(vaultTestContainer.getClientCertificateFiles().keyFile().toFile())
                .verify(true)
                .build();

        vaultTestContainer.start();
    }

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
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
     * Helper method to remove a secret value using the new alias-based API.
     */
    private void removeSecret(VaultConnector connector, String path, String key) throws CredentialStoreException {
        String secretPath = path.substring(path.indexOf('/') + 1);
        String aliasString = "#" + secretPath + "?" + key;
        VaultAlias alias = VaultAlias.parse(aliasString, "KVv2", "secret");
        connector.removeSecretData(alias);
    }

    /**
     * Configure vault connector with proper SSL config and no token and obtain a secret from the vault.
     * Test will succeed when connector properly uses login by crt auth method and reuses obtained token.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n"})
    public void testGetSecretFromVaultService(final String token) throws Exception {
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), token, null, permissibleSslAuthConfig, true);
        vaultService.configure();
        assertEquals("password123", getSecret(vaultService, "secret/testing1", "top_secret"));
    }

    /**
     * Configure vault connector with proper SSL config and an invalid token and try to obtain a secret from the vault.
     * Test will fail since the connector will try to use the token to authenticate.
     */
    @Test
    public void testGetSecretFromVaultServiceInvalidToken() throws Exception {
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "invalidToken", null, new SslConfig().verify(true), true);
        vaultService.configure();
        assertThrows(CredentialStoreException.class, () -> getSecret(vaultService, "secret/testing1", "top_secret"),
                "Correct SSL auth config was provided but token was non-empty and invalid. This should fail.");
    }

    /**
     * Configure vault connector with proper SSL config and no token. Try to obtain a secret from the vault and then
     * remove it. Validate the new value of obtained secret is null.
     * Test will succeed when the secret is obtained removed and obtained again.
     */
    @Test
    public void testRemoveSecretFromVaultService() throws Exception {
        final VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), "", null, permissibleSslAuthConfig, true);
        vaultService.configure();

        final String originalSecret = getSecret(vaultService, "secret/testing1", "top_secret");
        assertEquals("password123", originalSecret);

        removeSecret(vaultService, "secret/testing1", "top_secret");

        assertNull(getSecret(vaultService, "secret/testing1", "top_secret"));
    }

    /**
     * Verify that cert auth login fails when a client certificate signed by a different CA is presented.
     * The TLS handshake succeeds (tls_require_and_verify_client_cert is false) but loginByCert() fails
     * because the certificate is not registered in Vault's cert auth backend.
     */
    @Test
    public void testCertAuthFailsWithUntrustedClientCert() throws Exception {
        Path wrongCertDir = TlsTestMaterial.temporaryDirectory("wrong_client_certs");
        try {
            TlsTestMaterial wrongPem = TlsTestMaterial.generate(wrongCertDir, "localhost", true);

            SslConfig wrongClientConfig = new SslConfig()
                    .pemFile(vaultTestContainer.getHttpsTrustFile().toFile())
                    .clientPemFile(wrongPem.certFile().toFile())
                    .clientKeyPemFile(wrongPem.keyFile().toFile())
                    .verify(true)
                    .build();

            VaultConnector vaultService = new VaultConnector(
                    vaultTestContainer.composeHttpsHostAddress(), "", "secret/testing1", wrongClientConfig, true);
            vaultService.configure();
            assertThrows(CredentialStoreException.class, () -> getSecret(vaultService, "secret/testing1", "top_secret"));
        } finally {
            VaultTestUtils.cleanupDir(wrongCertDir);
        }
    }

    /**
     * Verify that cert auth login fails when no client certificate is presented.
     * The TLS handshake succeeds (tls_require_and_verify_client_cert is false) but
     * ClientCertificateLoginStrategy fails because there is no certificate to authenticate with.
     */
    @Test
    public void testCertAuthFailsWithNoClientCert() throws Exception {
        SslConfig trustOnlyConfig = new SslConfig()
                .pemFile(vaultTestContainer.getHttpsTrustFile().toFile())
                .verify(true)
                .build();

        VaultConnector vaultService = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(), "", "secret/testing1", trustOnlyConfig, true);
        vaultService.configure();
        assertThrows(CredentialStoreException.class, () -> getSecret(vaultService, "secret/testing1", "top_secret"));
    }
}
