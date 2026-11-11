/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.wildfly.security.credential.store.CredentialStoreException;

import io.github.jopenlibs.vault.json.Json;
import io.github.jopenlibs.vault.json.JsonObject;

/**
 * Verifies {@link VaultConnector#toDataMap(JsonObject)}: nested JSON objects in a secret must become nested
 * maps so that key paths such as {@code database/credentials/password} can be resolved.
 */
public class VaultConnectorDataMapTestCase {

    private static final String SECRET = "{\"db\":{\"host\":\"h1\",\"creds\":{\"user\":\"u\",\"password\":\"p\"}},"
            + "\"port\":5432,\"flag\":true,\"nothing\":null,\"list\":[1,2],\"multi\":\"l1\\nl2\",\"a/b\":\"slash\"}";

    private static Map<String, Object> data() {
        return VaultConnector.toDataMap(Json.parse(SECRET).asObject());
    }

    @Test
    void testNestedObjectsBecomeNestedMaps() {
        Object db = data().get("db");
        assertInstanceOf(Map.class, db);
        assertInstanceOf(Map.class, ((Map<?, ?>) db).get("creds"));
    }

    @Test
    void testNestedKeyPathResolves() throws CredentialStoreException {
        Map<String, Object> data = data();

        assertEquals("u", VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("db", "creds", "user")));
        assertEquals("p", VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("db", "creds", "password")));
        assertEquals("h1", VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("db", "host")));
    }

    @Test
    void testKeyPathToAnObjectIsNotAValue() throws CredentialStoreException {
        assertNull(VaultKeyPathOperations.resolveKeyPathSegments(data(), List.of("db")));
    }

    @Test
    void testKeyContainingSlashIsOneSegment() throws CredentialStoreException {
        assertEquals("slash", VaultKeyPathOperations.resolveKeyPathSegments(data(), List.of("a/b")));
    }

    @Test
    void testScalarsKeepTheTextTheVaultClientGave() {
        Map<String, Object> data = data();

        assertEquals("5432", data.get("port"));
        assertEquals("true", data.get("flag"));
        assertEquals("[1,2]", data.get("list"));
        assertEquals("l1\nl2", data.get("multi"));
    }

    @Test
    void testJsonNullIsLeftOut() {
        assertFalse(data().containsKey("nothing"));
    }
}
