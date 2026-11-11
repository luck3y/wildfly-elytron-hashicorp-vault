/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.hashicorp.vault.auth.TlsCertAuthConfig;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Tests that {@link HashicorpVaultCredentialStore} works with TLS certificate authentication,
 * allowing initialization without a Vault token when a client certificate is configured.
 */
public class HashicorpVaultCredentialStoreTlsAuthTestCase {

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
                        "kv put secret/testing2 ttl=30m dbuser=secretpass jmsuser=jmspass"
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
     * Initialize credential store with {@code null} protection parameter (no token).
     * Cert auth via the SSLContext should succeed and allow secret retrieval.
     */
    @Test
    public void testCertAuthWithNullProtectionParameter() throws Exception {
        HashicorpVaultCredentialStore store = createStoreWithCertAuth(null);
        PasswordCredential credential = store.retrieve("#testing1?top_secret",
                PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, null);
        assertNotNull(credential);
        assertEquals("password123", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }

    /**
     * Initialize credential store with a whitespace token. The connector skips token auth
     * and falls back to cert auth.
     */
    @ParameterizedTest
    @ValueSource(strings = {"  ", "\t", "\n"})
    public void testCertAuthWithWhitespaceToken(String token) throws Exception {
        HashicorpVaultCredentialStore store = createStoreWithCertAuth(
                createProtectionParameter(token));
        PasswordCredential credential = store.retrieve("#testing1?top_secret",
                PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, null);
        assertNotNull(credential);
        assertEquals("password123", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }

    /**
     * Full CRUD cycle using cert auth with no token: store a secret, retrieve it,
     * remove it, and verify it is gone.
     */
    @Test
    public void testCertAuthCrudOperations() throws Exception {
        HashicorpVaultCredentialStore store = createStoreWithCertAuth(null);

        PasswordCredential credential = createCredentialFromPassword("mySecretValue");
        store.store("#certtest?password", credential, null);

        PasswordCredential retrieved = store.retrieve("#certtest?password",
                PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, null);
        assertNotNull(retrieved);
        assertEquals("mySecretValue", String.valueOf(retrieved.getPassword(ClearPassword.class).getPassword()));

        store.remove("#certtest?password", PasswordCredential.class,
                ClearPassword.ALGORITHM_CLEAR, null);

        PasswordCredential afterRemove = store.retrieve("#certtest?password",
                PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, null);
        assertNull(afterRemove);
    }

    /**
     * Cert auth fails when a client certificate signed by a different CA is presented.
     * TLS handshake succeeds but Vault's cert auth rejects the unregistered certificate.
     */
    @Test
    public void testCertAuthFailsWithUntrustedClientCert() throws Exception {
        Path wrongCertDir = TlsTestMaterial.temporaryDirectory("wrong_client_certs");
        try {
            TlsTestMaterial wrongPem = TlsTestMaterial.generate(wrongCertDir, "localhost", true);

            SSLContext wrongSslContext = SslContextTestHelper.createWithClientAuth(
                    vaultTestContainer.getHttpsTrustFile(),
                    wrongPem.certFile(),
                    wrongPem.keyFile());

            HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
            store.setSslContext(wrongSslContext);
            Map<String, String> attributes = new HashMap<>();
            attributes.put("host-address", vaultTestContainer.composeHttpsHostAddress());
            store.initialize(attributes, null, new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
            // Exception should be thrown when attempting to use the store
            assertThrows(CredentialStoreException.class,
                    () -> store.retrieve("#testing1?top_secret", PasswordCredential.class,
                            ClearPassword.ALGORITHM_CLEAR, null, null));
        } finally {
            VaultTestUtils.cleanupDir(wrongCertDir);
        }
    }

    /**
     * Cert auth fails when no client certificate is presented.
     * The SSLContext has trust only (no client key/cert), so ClientCertificateLoginStrategy fails.
     */
    @Test
    public void testCertAuthFailsWithNoClientCert() throws Exception {
        SSLContext trustOnlyContext = SslContextTestHelper.createTrustOnly(
                vaultTestContainer.getHttpsTrustFile());

        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        store.setSslContext(trustOnlyContext);
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.composeHttpsHostAddress());
        store.initialize(attributes, null, new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        // Exception should be thrown when attempting to use the store
        assertThrows(CredentialStoreException.class,
                () -> store.retrieve("#testing1?top_secret", PasswordCredential.class,
                        ClearPassword.ALGORITHM_CLEAR, null, null));
    }

    private HashicorpVaultCredentialStore createStoreWithCertAuth(
            CredentialStore.ProtectionParameter protectionParameter) throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        store.setSslContext(sslContext);
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.composeHttpsHostAddress());
        store.initialize(attributes, protectionParameter,
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        return store;
    }

    private static CredentialStore.CredentialSourceProtectionParameter createProtectionParameter(
            String password) throws Exception {
        return new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword(password)));
    }

    private static PasswordCredential createCredentialFromPassword(String password) throws Exception {
        PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR,
                WildFlyElytronPasswordProvider.getInstance());
        return new PasswordCredential(factory.generatePassword(
                new ClearPasswordSpec(password.toCharArray())));
    }
}
