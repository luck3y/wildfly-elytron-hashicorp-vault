/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;

import javax.net.ssl.SSLContext;

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
 * Tests that {@link VaultConnector} works with TLS certificate authentication when a custom
 * {@link java.net.http.HttpClient} is configured because of the passed {@link SSLContext}.
 */
public class VaultConnectorWithHttpClientTestCase {

    private VaultContainerHttps<?> vaultTestContainer;
    private SSLContext sslContext;

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
                .policies("admin")
                .build()
                .configure(vaultTestContainer);

        vaultTestContainer.start();

        sslContext = SslContextTestHelper.createWithClientAuth(
                vaultTestContainer.getHttpsTrustFile(),
                vaultTestContainer.getClientCertificateFiles().certFile(),
                vaultTestContainer.getClientCertificateFiles().keyFile());
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
     * VaultConnector#getSecret test with SSLContext and TLS client auth, without token
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n"})
    public void testGetSecretWithHttpClientTlsAuth(final String token) throws Exception {
        SslConfig sslConfig = new SslConfig().verify(true).build();
        VaultConnector connector = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(),
                token,
                null,
                sslConfig,
                true,
                sslContext);
        connector.configure();
        assertEquals("password123", getSecret(connector, "secret/testing1", "top_secret"));
    }

    /**
     * VaultConnector with SSLContext and TLS client auth, remove secret test
     */
    @Test
    public void testRemoveSecretWithHttpClientTlsAuth() throws Exception {
        SslConfig sslConfig = new SslConfig().verify(true).build();
        VaultConnector connector = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(),
                "",
                null,
                sslConfig,
                true,
                sslContext);
        connector.configure();
        assertEquals("password123", getSecret(connector, "secret/testing1", "top_secret"));
        removeSecret(connector, "secret/testing1", "top_secret");
        assertNull(getSecret(connector, "secret/testing1", "top_secret"));
    }

}
