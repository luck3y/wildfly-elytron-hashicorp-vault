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

import java.io.IOException;
import java.nio.file.Path;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * Tests the public JKS initialization properties without an overriding SSLContext.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class HashicorpVaultCredentialStoreTlsPropertiesTestCase {

    private static final String VAULT_IMAGE = VaultContainerVersion.IMAGE;
    private static final String TOKEN = "myroot";
    private static final String SEEDED_ALIAS = "#tls-properties?password";
    private static final String CRUD_ALIAS = "#tls-created?password";

    @Test
    public void testHttpsCrudWithTrustStoreProperties() throws Exception {
        try (VaultContainerHttps<?> vault = container(false)) {
            vault.start();
            Path directory = TlsTestMaterial.temporaryDirectory("untrusted-server-");
            try {
                TlsTestMaterial untrusted = TlsTestMaterial.generate(directory, "localhost", false);
                HashicorpVaultCredentialStore wrongTrust = store(trustAttributes(
                        vault.composeHttpsHostAddress(), untrusted.trustStoreFile()));
                assertThrows(CredentialStoreException.class, () -> retrieve(wrongTrust, SEEDED_ALIAS));
            } finally {
                VaultTestUtils.cleanupDir(directory);
            }
            verifyCrud(attributes(vault, false));
        }
    }

    @Test
    public void testMutualTlsCrudWithKeyAndTrustStoreProperties() throws Exception {
        try (VaultContainerHttps<?> vault = container(true)) {
            vault.start();
            // A real read with the same server trust and token must fail without a client key.
            HashicorpVaultCredentialStore noClientKey = store(attributes(vault, false));
            assertThrows(CredentialStoreException.class, () -> retrieve(noClientKey, SEEDED_ALIAS));
            verifyCrud(attributes(vault, true));
        }
    }

    @Test
    public void testIncorrectTrustStorePasswordFailsInitialization() throws Exception {
        Path directory = TlsTestMaterial.temporaryDirectory("wrong-trust-password-");
        try {
            TlsTestMaterial material = TlsTestMaterial.generate(directory, "localhost", false);
            Map<String, String> attributes = trustAttributes("https://localhost:1", material.trustStoreFile());
            attributes.put("trust-store-pass", "incorrect");
            assertLoadFailure(attributes, "Failed to load TrustStore");
        } finally {
            VaultTestUtils.cleanupDir(directory);
        }
    }

    @Test
    public void testIncorrectKeyStorePasswordFailsInitialization() throws Exception {
        Path directory = TlsTestMaterial.temporaryDirectory("wrong-key-password-");
        try {
            TlsTestMaterial material = TlsTestMaterial.generate(directory, "localhost", true);
            Map<String, String> attributes = trustAttributes("https://localhost:1", material.trustStoreFile());
            attributes.put("key-store-path", material.keyStoreFile().toString());
            attributes.put("key-store-pass", "incorrect");
            assertLoadFailure(attributes, "Failed to load KeyStore");
        } finally {
            VaultTestUtils.cleanupDir(directory);
        }
    }

    private static VaultContainerHttps<?> container(boolean mutualTls) throws IOException {
        return new VaultContainerHttps<>(VAULT_IMAGE, mutualTls)
                .withVaultToken(TOKEN)
                .withInitCommand("kv put secret/tls-properties password=seeded");
    }

    private static Map<String, String> attributes(VaultContainerHttps<?> vault, boolean clientKey) {
        Map<String, String> attributes = trustAttributes(vault.composeHttpsHostAddress(), vault.getHttpsTrustStoreFile());
        if (clientKey) {
            attributes.put("key-store-path", vault.getClientCertificateFiles().keyStoreFile().toString());
            attributes.put("key-store-pass", TlsTestMaterial.STORE_PASSWORD);
        }
        return attributes;
    }

    private static Map<String, String> trustAttributes(String address, Path trustStore) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", address);
        attributes.put("trust-store-path", trustStore.toString());
        attributes.put("trust-store-pass", TlsTestMaterial.STORE_PASSWORD);
        return attributes;
    }

    private static HashicorpVaultCredentialStore store(Map<String, String> attributes) throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        CredentialStore.ProtectionParameter token = new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(credential(TOKEN)));
        store.initialize(attributes, token, new Provider[] { WildFlyElytronPasswordProvider.getInstance() });
        return store;
    }

    private static void verifyCrud(Map<String, String> attributes) throws Exception {
        assertRemoteValue(attributes, SEEDED_ALIAS, "seeded");
        HashicorpVaultCredentialStore writer = store(attributes);
        writer.store(CRUD_ALIAS, credential("created"), null);
        assertRemoteValue(attributes, CRUD_ALIAS, "created");
        writer.store(CRUD_ALIAS, credential("updated"), null);
        assertRemoteValue(attributes, CRUD_ALIAS, "updated");
        writer.remove(CRUD_ALIAS, PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
        assertNull(retrieve(store(attributes), CRUD_ALIAS), "A fresh store must observe remote deletion");
    }

    private static void assertRemoteValue(Map<String, String> attributes, String alias, String expected) throws Exception {
        // Every verifier has an empty credential cache and must read from Vault.
        PasswordCredential value = retrieve(store(attributes), alias);
        assertNotNull(value);
        assertEquals(expected, new String(value.getPassword(ClearPassword.class).getPassword()));
    }

    private static PasswordCredential retrieve(HashicorpVaultCredentialStore store, String alias) throws Exception {
        return store.retrieve(alias, PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, null);
    }

    private static PasswordCredential credential(String value) {
        return new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, value.toCharArray()));
    }

    private static void assertLoadFailure(Map<String, String> attributes, String message) {
        CredentialStoreException failure = assertThrows(CredentialStoreException.class, () -> store(attributes));
        assertTrue(failure.getMessage().contains(message), failure::getMessage);
        assertNotNull(failure.getCause(), "The store-loading cause must be preserved");
        assertTrue(failure.getCause() instanceof IOException, "Expected a JKS file-loading failure");
    }
}
