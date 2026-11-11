/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wildfly.security.hashicorp.vault.VaultTestUtils.startVaultTestContainer;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.json.Json;
import io.github.jopenlibs.vault.json.JsonObject;

/**
 * Storing or removing a credential through {@link HashicorpVaultCredentialStore} in a secret that already holds
 * nested JSON data must leave the rest of that secret as it was: nested objects stay objects, sibling fields
 * survive, and numbers, booleans and arrays keep their JSON type.
 * <p>
 * Credentials are read back through a second store instance, because the first one caches what it stores.
 */
public class HashicorpVaultCredentialStoreNestedDataTestCase {

    private VaultContainer<?> vaultTestContainer;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    @Test
    public void testStoreIntoNestedObjectKeepsSiblings() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        writeRaw("secret/app", seedData());
        HashicorpVaultCredentialStore store = createStore(false);

        store.store("#app?db/creds/password", password("changed"), null);

        JsonObject stored = readRaw("secret/app");
        JsonObject creds = stored.get("db").asObject().get("creds").asObject();
        assertEquals("changed", creds.getString("password", null));
        assertEquals("alice", creds.getString("user", null), "sibling field in the same object must survive");
        assertEquals("pg.example.com", stored.get("db").asObject().getString("host", null),
                "sibling field one level up must survive");
        assertEquals("topsecret", stored.getString("apikey", null), "top-level field must survive");
        assertTypesKept(stored);

        HashicorpVaultCredentialStore reader = createStore(false);
        assertEquals("changed", read(reader, "#app?db/creds/password"));
        assertEquals("alice", read(reader, "#app?db/creds/user"));
        assertEquals("pg.example.com", read(reader, "#app?db/host"));
        assertEquals("topsecret", read(reader, "#app?apikey"));
    }

    @Test
    public void testStoreNewKeyIntoSecretWithNestedDataKeepsNestedObjects() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        writeRaw("secret/app", seedData());
        HashicorpVaultCredentialStore store = createStore(false);

        store.store("#app?added", password("new"), null);
        store.store("#app?db/creds/token", password("t0k3n"), null);

        JsonObject stored = readRaw("secret/app");
        assertTrue(stored.get("db").isObject(), "db must still be a JSON object, was: " + stored.get("db"));
        assertEquals("new", stored.getString("added", null));
        assertEquals("t0k3n", stored.get("db").asObject().get("creds").asObject().getString("token", null));
        assertEquals("alice", stored.get("db").asObject().get("creds").asObject().getString("user", null));
        assertTypesKept(stored);

        HashicorpVaultCredentialStore reader = createStore(false);
        assertEquals("new", read(reader, "#app?added"));
        assertEquals("t0k3n", read(reader, "#app?db/creds/token"));
        assertEquals("alice", read(reader, "#app?db/creds/user"));
    }

    @Test
    public void testRemoveNestedKeyKeepsItsSiblings() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        writeRaw("secret/app", seedData());
        HashicorpVaultCredentialStore store = createStore(false);

        store.remove("#app?db/creds/user", PasswordCredential.class, null, null);

        JsonObject stored = readRaw("secret/app");
        JsonObject creds = stored.get("db").asObject().get("creds").asObject();
        assertNull(creds.get("user"), "removed field must be gone");
        assertEquals("s3cret", creds.getString("password", null), "sibling field must survive");
        assertEquals("pg.example.com", stored.get("db").asObject().getString("host", null));
        assertEquals("topsecret", stored.getString("apikey", null));
        assertTypesKept(stored);

        HashicorpVaultCredentialStore reader = createStore(false);
        assertNull(reader.retrieve("#app?db/creds/user", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, protection()));
        assertEquals("s3cret", read(reader, "#app?db/creds/password"));
    }

    @Test
    public void testRemoveTopLevelKeyKeepsNestedObjects() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        writeRaw("secret/app", seedData());
        HashicorpVaultCredentialStore store = createStore(false);

        store.remove("#app?apikey", PasswordCredential.class, null, null);

        JsonObject stored = readRaw("secret/app");
        assertNull(stored.get("apikey"));
        assertTrue(stored.get("db").isObject(), "db must still be a JSON object, was: " + stored.get("db"));
        assertEquals("alice", stored.get("db").asObject().get("creds").asObject().getString("user", null));
        assertTypesKept(stored);

        HashicorpVaultCredentialStore reader = createStore(false);
        assertEquals("alice", read(reader, "#app?db/creds/user"));
    }

    /** The legacy {@code secret-path.key} alias must keep working on a secret that also holds nested data. */
    @Test
    public void testLegacyAliasStoreAndRemoveKeepNestedData() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        writeRaw("secret/legacyapp/config", seedData());
        HashicorpVaultCredentialStore store = createStore(true);

        store.store("legacyapp/config.apikey", password("rotated"), null);

        JsonObject stored = readRaw("secret/legacyapp/config");
        assertEquals("rotated", stored.getString("apikey", null));
        assertTrue(stored.get("db").isObject(), "db must still be a JSON object, was: " + stored.get("db"));
        assertEquals("alice", stored.get("db").asObject().get("creds").asObject().getString("user", null));
        assertTypesKept(stored);
        assertEquals("rotated", read(createStore(true), "legacyapp/config.apikey"));

        store.remove("legacyapp/config.apikey", PasswordCredential.class, null, null);

        stored = readRaw("secret/legacyapp/config");
        assertNull(stored.get("apikey"));
        assertTrue(stored.get("db").isObject(), "db must still be a JSON object, was: " + stored.get("db"));
        assertEquals("s3cret", stored.get("db").asObject().get("creds").asObject().getString("password", null));
        assertTypesKept(stored);
    }

    /** Nested secret holding string leaves plus values of every other JSON type. */
    private static Map<String, Object> seedData() {
        Map<String, Object> data = new HashMap<>();
        data.put("apikey", "topsecret");
        data.put("port", 5432);
        data.put("enabled", true);
        data.put("hosts", Json.array("h1", "h2"));
        data.put("db", Json.object()
                .add("host", "pg.example.com")
                .add("retries", 3)
                .add("creds", Json.object().add("user", "alice").add("password", "s3cret")));
        return data;
    }

    /** The values that are not text must still have their original JSON type. */
    private static void assertTypesKept(JsonObject stored) {
        assertTrue(stored.get("port").isNumber(), "port must stay a number, was: " + stored.get("port"));
        assertEquals(5432, stored.get("port").asInt());
        assertTrue(stored.get("enabled").isBoolean(), "enabled must stay a boolean, was: " + stored.get("enabled"));
        assertTrue(stored.get("hosts").isArray(), "hosts must stay an array, was: " + stored.get("hosts"));
        assertEquals(2, stored.get("hosts").asArray().size());
        assertTrue(stored.get("db").isObject(), "db must stay an object, was: " + stored.get("db"));
        assertTrue(stored.get("db").asObject().get("retries").isNumber(), "db/retries must stay a number");
        assertTrue(stored.get("db").asObject().get("creds").isObject(), "db/creds must stay an object");
    }

    private String read(HashicorpVaultCredentialStore store, String alias) throws Exception {
        PasswordCredential credential = store.retrieve(alias, PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR,
                null, protection());
        assertNotNull(credential, "alias " + alias + " does not resolve to a credential");
        return String.valueOf(credential.getPassword(ClearPassword.class).getPassword());
    }

    private Vault rawVault() throws Exception {
        return Vault.create(new VaultConfig().address(vaultTestContainer.getHttpHostAddress()).token("myroot")
                .nameSpace("admin").build());
    }

    private JsonObject readRaw(String path) throws Exception {
        JsonObject data = rawVault().logical().read(path).getDataObject();
        assertNotNull(data, "nothing stored at " + path);
        return data;
    }

    private void writeRaw(String path, Map<String, Object> data) throws Exception {
        rawVault().logical().write(path, data);
    }

    private HashicorpVaultCredentialStore createStore(boolean supportLegacyAliasFormat) throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        if (supportLegacyAliasFormat) {
            attributes.put("support-legacy-alias-format", "true");
        }
        store.initialize(attributes, protection(), new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        return store;
    }

    private CredentialStore.CredentialSourceProtectionParameter protection() throws UnsupportedCredentialTypeException {
        return new CredentialStore.CredentialSourceProtectionParameter(IdentityCredentials.NONE.withCredential(password("myroot")));
    }

    private PasswordCredential password(String password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, WildFlyElytronPasswordProvider.getInstance());
            return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }
}
