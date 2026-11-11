/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.vault.VaultContainer;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.json.Json;
import io.github.jopenlibs.vault.json.JsonObject;
import io.github.jopenlibs.vault.json.JsonValue;

/**
 * Writing a key to a secret, or removing one, must leave the rest of that secret exactly as it was. In
 * particular nested JSON objects must stay objects, and numbers, booleans and arrays must keep their JSON type
 * rather than being turned into text.
 */
public class VaultConnectorNestedDataWriteTestCase {

    private VaultContainer<?> vaultTestContainer;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    @Test
    public void testPutKeyKeepsExistingNestedObjectsAsObjects() throws Exception {
        VaultConnector connector = startAndConnect();
        connector.putSecretData(alias("#nested?db/user"), "alice");
        connector.putSecretData(alias("#nested?db/creds/password"), "s3cret");

        connector.putSecretData(alias("#nested?other"), "x");

        JsonObject stored = readRaw("secret/nested");
        assertTrue(stored.get("db").isObject(), "db must still be a JSON object, was: " + stored.get("db"));
        assertEquals("alice", stored.get("db").asObject().getString("user", null));
        assertTrue(stored.get("db").asObject().get("creds").isObject());
        assertEquals("s3cret", stored.get("db").asObject().get("creds").asObject().getString("password", null));
        assertEquals("x", stored.getString("other", null));
    }

    @Test
    public void testPutIntoNestedObjectKeepsSiblingsAtEveryLevel() throws Exception {
        VaultConnector connector = startAndConnect();
        connector.putSecretData(alias("#siblings?a/b/one"), "1");
        connector.putSecretData(alias("#siblings?a/b/two"), "2");
        connector.putSecretData(alias("#siblings?a/c"), "3");

        JsonObject a = readRaw("secret/siblings").get("a").asObject();
        assertEquals("1", a.get("b").asObject().getString("one", null));
        assertEquals("2", a.get("b").asObject().getString("two", null));
        assertEquals("3", a.getString("c", null));
    }

    @Test
    public void testRemoveKeyKeepsOtherNestedObjectsAsObjects() throws Exception {
        VaultConnector connector = startAndConnect();
        connector.putSecretData(alias("#rm?db/user"), "alice");
        connector.putSecretData(alias("#rm?db/password"), "pw");
        connector.putSecretData(alias("#rm?plain"), "p");

        connector.removeSecretData(alias("#rm?plain"));

        JsonObject stored = readRaw("secret/rm");
        assertNull(stored.get("plain"));
        assertTrue(stored.get("db").isObject(), "db must still be a JSON object, was: " + stored.get("db"));
        assertEquals("alice", stored.get("db").asObject().getString("user", null));
        assertEquals("pw", stored.get("db").asObject().getString("password", null));
    }

    @Test
    public void testRemoveNestedKeyKeepsItsSiblings() throws Exception {
        VaultConnector connector = startAndConnect();
        connector.putSecretData(alias("#rmnested?db/user"), "alice");
        connector.putSecretData(alias("#rmnested?db/password"), "pw");

        connector.removeSecretData(alias("#rmnested?db/user"));

        JsonObject db = readRaw("secret/rmnested").get("db").asObject();
        assertNull(db.get("user"));
        assertEquals("pw", db.getString("password", null));
    }

    @Test
    public void testWritesKeepNumbersBooleansAndArraysTyped() throws Exception {
        VaultConnector connector = startAndConnect();
        Map<String, Object> initial = new HashMap<>();
        initial.put("port", 5432);
        initial.put("enabled", true);
        initial.put("hosts", Json.array("h1", "h2"));
        initial.put("db", Json.object().add("retries", 3).add("tls", false));
        writeRaw("secret/typed", initial);

        connector.putSecretData(alias("#typed?added"), "v");
        assertTypesKept(readRaw("secret/typed"));

        connector.removeSecretData(alias("#typed?added"));
        assertTypesKept(readRaw("secret/typed"));
    }

    private static void assertTypesKept(JsonObject stored) {
        assertTrue(stored.get("port").isNumber(), "port must stay a number, was: " + stored.get("port"));
        assertEquals(5432, stored.get("port").asInt());
        assertTrue(stored.get("enabled").isBoolean(), "enabled must stay a boolean, was: " + stored.get("enabled"));
        assertTrue(stored.get("hosts").isArray(), "hosts must stay an array, was: " + stored.get("hosts"));
        assertEquals(2, stored.get("hosts").asArray().size());
        JsonValue db = stored.get("db");
        assertTrue(db.isObject(), "db must stay an object, was: " + db);
        assertTrue(db.asObject().get("retries").isNumber());
        assertTrue(db.asObject().get("tls").isBoolean());
    }

    private VaultAlias alias(String alias) throws Exception {
        return VaultAlias.parse(alias, "KVv2", "secret");
    }

    private VaultConnector startAndConnect() throws Exception {
        vaultTestContainer = VaultTestUtils.startVaultTestContainer();
        VaultConnector connector = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "secret/x",
                new SslConfig().verify(true).build(), true);
        connector.configure();
        return connector;
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
}
