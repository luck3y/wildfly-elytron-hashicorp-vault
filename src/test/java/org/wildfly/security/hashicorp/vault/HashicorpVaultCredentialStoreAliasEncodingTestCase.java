/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wildfly.security.hashicorp.vault.VaultTestUtils.startVaultTestContainer;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

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

/**
 * Verifies that every alias returned by {@link HashicorpVaultCredentialStore#getAliases} can be passed straight
 * back to the store and reads the credential it was listed for, including when key or secret path names contain
 * characters such as {@code + % ? # / } or a space.
 */
public class HashicorpVaultCredentialStoreAliasEncodingTestCase {

    private VaultContainer<?> vaultTestContainer;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    /**
     * Keys whose names the alias parser would misread if they were listed unencoded. The alias used to store each
     * one is the encoded form; the value stored identifies which key it belongs to.
     */
    @Test
    public void testListedAliasesForAwkwardKeysReadBackTheirOwnValue() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createStore();

        // encoded alias (as a user would write it) -> value
        Map<String, String> stored = new LinkedHashMap<>();
        stored.put("#enc?plain", "v-plain");
        stored.put("#enc?a%2Bb", "v-plus");            // key "a+b"   (must not be read as "a b")
        stored.put("#enc?a%20b", "v-space");           // key "a b"
        stored.put("#enc?a%2520b", "v-literal-pct20"); // key "a%20b" (must not be read as "a b")
        stored.put("#enc?a%2Fb", "v-slash");           // key "a/b"   (must not be read as nested a -> b)
        stored.put("#enc?a%3Fb", "v-question");        // key "a?b"
        stored.put("#enc?a%23b", "v-hash");            // key "a#b"
        stored.put("#enc?100%25", "v-percent");        // key "100%"
        for (Map.Entry<String, String> entry : stored.entrySet()) {
            store.store(entry.getKey(), password(entry.getValue()), null);
        }

        Set<String> aliases = store.getAliases("#enc");

        assertEquals(stored.keySet(), aliases, "listed aliases must be the encoded form of each stored key");
        for (String alias : aliases) {
            assertEquals(stored.get(alias), read(store, alias), "alias " + alias + " must read back its own value");
        }
    }

    /** Secret path names (files and directories) that the alias parser would misread if listed unencoded. */
    @Test
    public void testRecursivelyListedAliasesForAwkwardPathsReadBackTheirOwnValue() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createStore();

        Map<String, String> stored = new LinkedHashMap<>();
        stored.put("#encpath/plain?k", "v-plain");
        stored.put("#encpath/p%2Bq?k", "v-plus");              // secret "p+q"    (must not be read as "p q")
        stored.put("#encpath/my%20app?k", "v-space");          // secret "my app"
        stored.put("#encpath/50%25off?k", "v-percent");        // secret "50%off"
        stored.put("#encpath/dir%2Bone/inner?k", "v-dir-plus"); // directory "dir+one"
        stored.put("#encpath/100%25dir/inner?k", "v-dir-pct");  // directory "100%dir"
        stored.put("#encpath/a%20dir/in%20ner?k", "v-dir-space");
        for (Map.Entry<String, String> entry : stored.entrySet()) {
            store.store(entry.getKey(), password(entry.getValue()), null);
        }

        Set<String> aliases = store.getAliases("#encpath", true, 3);

        assertEquals(stored.keySet(), aliases, "listed aliases must be the encoded form of each stored secret path");
        for (String alias : aliases) {
            assertEquals(stored.get(alias), read(store, alias), "alias " + alias + " must read back its own value");
        }
    }

    @Test
    public void testPlainAliasesAreListedUnchanged() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createStore();
        store.store("#plainapp/sub?key1", password("one"), null);
        store.store("#plainapp?key2", password("two"), null);

        Set<String> aliases = store.getAliases("#plainapp", true, 1);

        assertTrue(aliases.contains("#plainapp?key2"));
        assertTrue(aliases.contains("#plainapp/sub?key1"));
    }

    /**
     * A secret that holds a key literally named {@code database/host} next to a nested {@code database} object.
     * Listing must keep the literal key (encoded) distinct from the nested path, must list the nested value but not
     * the object that holds it, and every listed alias must read back its own value.
     */
    @Test
    public void testListedAliasKeepsLiteralSlashKeyDistinctFromNestedPath() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        Map<String, Object> seed = new HashMap<>();
        seed.put("database/host", "literal-value");
        seed.put("database%2Fhost", "literal-percent-value");
        seed.put("database", Json.object().add("host", "nested-value"));
        seed.put("plain", "plain-value");
        Vault.create(new VaultConfig().address(vaultTestContainer.getHttpHostAddress()).token("myroot")
                .nameSpace("admin").build()).logical().write("secret/mixed", seed);
        HashicorpVaultCredentialStore store = createStore();

        Set<String> aliases = store.getAliases("#mixed");

        assertEquals(Set.of("#mixed?database%2Fhost", "#mixed?database%252Fhost", "#mixed?database/host", "#mixed?plain"),
                aliases, "literal keys must be listed encoded, the nested value by its path, and the object not at all");
        assertFalse(aliases.contains("#mixed?database"), "an object is not a credential, was: " + aliases);
        assertEquals("literal-value", read(store, "#mixed?database%2Fhost"));
        assertEquals("literal-percent-value", read(store, "#mixed?database%252Fhost"));
        assertEquals("plain-value", read(store, "#mixed?plain"));
        assertEquals("nested-value", read(store, "#mixed?database/host"));
        for (String alias : aliases) {
            read(store, alias);
        }
    }

    /** Values at every nesting depth are listed by their full key path, and each reads back its own value. */
    @Test
    public void testListedAliasesIncludeDeeplyNestedValues() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        Map<String, Object> seed = new HashMap<>();
        seed.put("top", "top-value");
        seed.put("a", Json.object()
                .add("b", Json.object().add("c", "deep-value").add("x/y", "deep-literal-slash"))
                .add("empty", Json.object()));
        Vault.create(new VaultConfig().address(vaultTestContainer.getHttpHostAddress()).token("myroot")
                .nameSpace("admin").build()).logical().write("secret/deep", seed);
        HashicorpVaultCredentialStore store = createStore();

        Set<String> aliases = store.getAliases("#deep");

        assertEquals(Set.of("#deep?top", "#deep?a/b/c", "#deep?a/b/x%2Fy"), aliases,
                "objects, including empty ones, must not be listed");
        assertEquals("deep-value", read(store, "#deep?a/b/c"));
        assertEquals("deep-literal-slash", read(store, "#deep?a/b/x%2Fy"));
        assertEquals("top-value", read(store, "#deep?top"));
    }

    private String read(HashicorpVaultCredentialStore store, String alias) throws Exception {
        PasswordCredential credential = store.retrieve(alias, PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR,
                null, protection());
        assertNotNull(credential, "alias " + alias + " was listed but does not resolve to a credential");
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
