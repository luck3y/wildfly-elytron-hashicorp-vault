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
import org.wildfly.security.credential.store.CredentialStoreException;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

/**
 * Tests that {@link VaultConnector} works over HTTPS when an SSLContext is passed.
 * This verifies the code path in {@link VaultConnector#configure()}
 * that builds an HttpClient with the provided SSLContext and passes it to VaultConfig.
 */
public class ClientTLSAuthenticationWithHttpClientTestCase {

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
        vaultTestContainer.start();

        sslContext = SslContextTestHelper.createTrustOnly(vaultTestContainer.getHttpsTrustFile());
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

    /**
     * VaultConnector with SSLContext, test get secret over HTTPS
     */
    @Test
    public void testGetSecretWithHttpClientSslContext() throws Exception {
        SslConfig sslConfig = new SslConfig().verify(true).build();
        VaultConnector connector = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(),
                "myroot",
                null,
                sslConfig,
                true,
                sslContext);
        connector.configure();
        assertEquals("password123", getSecret(connector, "secret/testing1", "top_secret"));
    }

    /**
     * VaultConnector with SSLContext, test put secret over HTTPS
     */
    @Test
    public void testPutSecretWithHttpClientSslContext() throws Exception {
        SslConfig sslConfig = new SslConfig().verify(true).build();
        VaultConnector connector = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(),
                "myroot",
                null,
                sslConfig,
                true,
                sslContext);
        connector.configure();
        putSecret(connector, "secret/testing1", "top_secret2", "password2");
        assertEquals("password2", getSecret(connector, "secret/testing1", "top_secret2"));
    }

    /**
     * VaultConnector with SSLContext, test remove secret over HTTPS
     */
    @Test
    public void testRemoveSecretWithHttpClientSslContext() throws Exception {
        SslConfig sslConfig = new SslConfig().verify(true).build();
        VaultConnector connector = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(),
                "myroot",
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
