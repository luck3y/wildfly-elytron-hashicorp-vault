/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.wildfly.security.hashicorp.vault.VaultTestUtils.startVaultTestContainer;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.json.Json;

/**
 * Reading nested JSON data from a real Vault, through {@link VaultConnector#getSecretData} and through
 * {@link HashicorpVaultCredentialStore#retrieve}. Unlike the tests that supply Java maps directly, the data here
 * goes through the HTTP response and the JSON-to-map conversion.
 * <p>
 * Each credential is read through a store that has not seen the alias before, so no cached value is returned.
 */
public class VaultConnectorNestedDataReadTestCase {

    private VaultContainer<?> vaultTestContainer;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    @Test
    public void testGetSecretDataReturnsNestedMapsAndTextScalars() throws Exception {
        VaultConnector connector = startAndConnect();
        writeRaw("secret/nested", seedData());

        Map<String, Object> data = connector.getSecretData(VaultAlias.parse("#nested?apikey", "KVv2", "secret"));

        assertNotNull(data);
        assertInstanceOf(Map.class, data.get("db"), "db must be a nested map, was: " + data.get("db"));
        Map<?, ?> db = (Map<?, ?>) data.get("db");
        assertEquals("pg.example.com", db.get("host"));
        assertInstanceOf(Map.class, db.get("creds"), "db/creds must be a nested map, was: " + db.get("creds"));
        assertEquals("alice", ((Map<?, ?>) db.get("creds")).get("user"));
        assertEquals("s3cret", ((Map<?, ?>) db.get("creds")).get("password"));
        assertEquals("topsecret", data.get("apikey"));
        assertEquals("5432", data.get("port"));
        assertEquals("true", data.get("enabled"));
        assertEquals("[\"h1\",\"h2\"]", data.get("hosts"));
    }

    @Test
    public void testGetSecretDataResolvesNestedKeyPaths() throws Exception {
        VaultConnector connector = startAndConnect();
        writeRaw("secret/nested", seedData());
        Map<String, Object> data = connector.getSecretData(VaultAlias.parse("#nested?apikey", "KVv2", "secret"));

        assertEquals("alice", VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("db", "creds", "user")));
        assertEquals("pg.example.com", VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("db", "host")));
        assertNull(VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("db")),
                "a key path that ends at an object is not a value");
        assertNull(VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("db", "creds", "missing")));
    }

    @Test
    public void testGetSecretDataLeavesOutJsonNulls() throws Exception {
        VaultConnector connector = startAndConnect();
        Map<String, Object> seed = new HashMap<>();
        seed.put("present", "yes");
        seed.put("absent", Json.NULL);
        writeRaw("secret/withnull", seed);

        Map<String, Object> data = connector.getSecretData(VaultAlias.parse("#withnull?present", "KVv2", "secret"));

        assertEquals("yes", data.get("present"));
        assertFalse(data.containsKey("absent"));
    }

    @Test
    public void testGetSecretDataForMissingSecretIsNull() throws Exception {
        VaultConnector connector = startAndConnect();

        assertNull(connector.getSecretData(VaultAlias.parse("#nothing/here?key", "KVv2", "secret")));
    }

    @Test
    public void testRetrieveNestedValuesThroughTheStore() throws Exception {
        startAndConnect();
        writeRaw("secret/nested", seedData());

        assertEquals("alice", read(createStore(), "#nested?db/creds/user"));
        assertEquals("s3cret", read(createStore(), "#nested?db/creds/password"));
        assertEquals("pg.example.com", read(createStore(), "#nested?db/host"));
        assertEquals("topsecret", read(createStore(), "#nested?apikey"));
        assertNull(retrieve(createStore(), "#nested?db"), "an alias that points at an object is not a credential");
        assertNull(retrieve(createStore(), "#nested?db/creds/missing"));
    }

    /**
     * A key path that tries to go below a value that is not an object cannot be followed, so it resolves to nothing.
     * This is the same answer the Vault CLI gives for a field it cannot find. The values here are the text of a
     * string, number, boolean and array, none of which can hold a key.
     */
    @Test
    public void testKeyPathThroughAScalarIsNotFoundAgainstRealVault() throws Exception {
        startAndConnect();
        writeRaw("secret/nested", seedData());

        // the scalars themselves are readable, so the secret is there and only the deeper path is missing
        assertEquals("topsecret", read(createStore(), "#nested?apikey"));
        assertEquals("5432", read(createStore(), "#nested?port"));
        assertEquals("true", read(createStore(), "#nested?enabled"));

        assertNull(retrieve(createStore(), "#nested?apikey/x"), "cannot go below a string");
        assertNull(retrieve(createStore(), "#nested?port/x"), "cannot go below a number");
        assertNull(retrieve(createStore(), "#nested?enabled/x"), "cannot go below a boolean");
        assertNull(retrieve(createStore(), "#nested?hosts/0"), "cannot go below an array, which is kept as text");
        assertNull(retrieve(createStore(), "#nested?db/host/x"), "cannot go below a string inside an object");
        assertNull(retrieve(createStore(), "#nested?db/creds/user/x/y"), "cannot go several levels below a string");
    }

    /**
     * A key path that ends at an object is not a credential value, however deep the object is and whether or not
     * it has any members, so it resolves to nothing. The alias for a value next to the object, or inside it, still
     * resolves.
     */
    @Test
    public void testKeyPathEndingAtAnObjectIsNotACredentialAgainstRealVault() throws Exception {
        startAndConnect();
        Map<String, Object> seed = seedData();
        seed.put("empty", Json.object());
        seed.put("database/host", "literal-value");
        seed.put("database", Json.object().add("host", "nested-value"));
        writeRaw("secret/nested", seed);

        assertNull(retrieve(createStore(), "#nested?db"), "top-level object");
        assertNull(retrieve(createStore(), "#nested?db/creds"), "object inside an object");
        assertNull(retrieve(createStore(), "#nested?empty"), "object with no members");
        assertNull(retrieve(createStore(), "#nested?database"), "object that has a sibling literal key of similar name");

        // the values around those objects are unaffected
        assertEquals("alice", read(createStore(), "#nested?db/creds/user"));
        assertEquals("pg.example.com", read(createStore(), "#nested?db/host"));
        assertEquals("nested-value", read(createStore(), "#nested?database/host"));
        assertEquals("literal-value", read(createStore(), "#nested?database%2Fhost"));
    }

    /**
     * An unencoded {@code /} is a nested separator and {@code %2F} is a literal slash in the key name. The secret
     * holds a key named {@code database/host}, a key named {@code database%2Fhost}, and a nested {@code database}
     * object with a {@code host}; {@code %252F} is the encoded form of the literal text {@code %2F}.
     */
    @ParameterizedTest
    @CsvSource({
        "#slash?database/host, nested-value",
        "#slash?database%2Fhost, literal-value",
        "#slash?database%2fhost, literal-value",
        "#slash?database%252Fhost, literal-percent-value"
    })
    public void testEncodedSlashAgainstRealVault(String alias, String expected) throws Exception {
        startAndConnect();
        Map<String, Object> seed = new HashMap<>();
        seed.put("database/host", "literal-value");
        seed.put("database%2Fhost", "literal-percent-value");
        seed.put("database", Json.object().add("host", "nested-value"));
        writeRaw("secret/slash", seed);

        assertEquals(expected, read(createStore(), alias));
    }

    /** Nested secret with string leaves and values of every other JSON type. */
    private static Map<String, Object> seedData() {
        Map<String, Object> data = new HashMap<>();
        data.put("apikey", "topsecret");
        data.put("port", 5432);
        data.put("enabled", true);
        data.put("hosts", Json.array("h1", "h2"));
        data.put("db", Json.object()
                .add("host", "pg.example.com")
                .add("creds", Json.object().add("user", "alice").add("password", "s3cret")));
        return data;
    }

    private VaultConnector startAndConnect() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        VaultConnector connector = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "secret/x",
                new SslConfig().verify(true).build(), true);
        connector.configure();
        return connector;
    }

    private void writeRaw(String path, Map<String, Object> data) throws Exception {
        Vault vault = Vault.create(new VaultConfig().address(vaultTestContainer.getHttpHostAddress()).token("myroot")
                .nameSpace("admin").build());
        vault.logical().write(path, data);
    }

    private PasswordCredential retrieve(HashicorpVaultCredentialStore store, String alias) throws Exception {
        return store.retrieve(alias, PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, protection());
    }

    private String read(HashicorpVaultCredentialStore store, String alias) throws Exception {
        PasswordCredential credential = retrieve(store, alias);
        assertNotNull(credential, "alias " + alias + " does not resolve to a credential");
        return String.valueOf(credential.getPassword(ClearPassword.class).getPassword());
    }

    private HashicorpVaultCredentialStore createStore() throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
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
