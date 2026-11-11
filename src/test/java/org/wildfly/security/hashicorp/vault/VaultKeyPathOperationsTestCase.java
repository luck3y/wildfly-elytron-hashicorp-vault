/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Unit tests for {@link VaultKeyPathOperations} key path operations.
 *
 * <p>This test class covers:
 * <ul>
 *   <li>Simple key lookups (with and without dots in key names)</li>
 *   <li>Nested JSON path traversal (single and multi-level)</li>
 *   <li>Mixed scenarios (nested paths with dots in key names)</li>
 *   <li>Edge cases (empty paths, non-existent keys, non-map values, null values)</li>
 *   <li>Set and remove operations for nested values</li>
 * </ul>
 *
 * <p>Test coverage target: >95% for {@link VaultKeyPathOperations} class
 */
public class VaultKeyPathOperationsTestCase {

    private Map<String, Object> testData;

    @BeforeEach
    void setUp() {
        // Create test data structure matching the specification
        Map<String, Object> credentials = new HashMap<>();
        credentials.put("user", "admin");
        credentials.put("pass", "secret");

        Map<String, Object> database = new HashMap<>();
        database.put("host", "prod.db.com");
        database.put("port", 5432);
        database.put("credentials", credentials);

        Map<String, Object> myApp = new HashMap<>();
        myApp.put("config.key", "value123");

        testData = new HashMap<>();
        testData.put("password", "secret123");
        testData.put("db.host", "localhost");
        testData.put("database", database);
        testData.put("my.app", myApp);
    }

    // ========================================================================
    // Simple Key Tests
    // ========================================================================

    @Test
    void testSimpleKeyWithoutDots() throws CredentialStoreException {
        // Top-level key without dots
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "password");
        assertEquals("secret123", result);
    }

    @Test
    void testSimpleKeyWithDots() throws CredentialStoreException {
        // Top-level key with dots - literal match
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "db.host");
        assertEquals("localhost", result);
    }

    @Test
    void testSimpleKeyNotFound() throws CredentialStoreException {
        // Key that doesn't exist
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "nonexistent");
        assertNull(result);
    }

    @Test
    void testSimpleKeyWithDotsNotFound() throws CredentialStoreException {
        // Key with dots that doesn't exist
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "not.found");
        assertNull(result);
    }

    // ========================================================================
    // Nested Path Tests
    // ========================================================================

    @Test
    void testSingleLevelNesting() throws CredentialStoreException {
        // Single-level nested path
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "database/host");
        assertEquals("prod.db.com", result);
    }

    @Test
    void testSingleLevelNestingInteger() throws CredentialStoreException {
        // Single-level nested path with integer value
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "database/port");
        assertEquals("5432", result);
    }

    @Test
    void testMultiLevelNesting() throws CredentialStoreException {
        // Multi-level nested path (2 levels)
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "database/credentials/user");
        assertEquals("admin", result);
    }

    @Test
    void testDeepNesting() throws CredentialStoreException {
        // Deep nesting (3 levels)
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "database/credentials/pass");
        assertEquals("secret", result);
    }

    @Test
    void testNestedPathNotFound() throws CredentialStoreException {
        // Nested path where intermediate key doesn't exist
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "database/nonexistent/key");
        assertNull(result);
    }

    @Test
    void testNestedPathLeafNotFound() throws CredentialStoreException {
        // Nested path where leaf key doesn't exist
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "database/credentials/nonexistent");
        assertNull(result);
    }

    // ========================================================================
    // Mixed Tests (Nested Paths with Dots in Key Names)
    // ========================================================================

    @Test
    void testNestedPathWithDotsInKeyName() throws CredentialStoreException {
        // Nested path where segment contains dots
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "my.app/config.key");
        assertEquals("value123", result);
    }

    @Test
    void testComplexNestedWithDots() throws CredentialStoreException {
        // Add more complex nested structure with dots
        Map<String, Object> teamAlpha = new HashMap<>();
        teamAlpha.put("app.config", "alpha-value");
        testData.put("team.alpha", teamAlpha);

        String result = VaultKeyPathOperations.resolveKeyPath(testData, "team.alpha/app.config");
        assertEquals("alpha-value", result);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    @Test
    void testNullKeyPath() {
        // Null key path should throw exception
        assertThrows(CredentialStoreException.class, () -> {
            VaultKeyPathOperations.resolveKeyPath(testData, null);
        });
    }

    @Test
    void testEmptyKeyPath() {
        // Empty key path should throw exception
        assertThrows(CredentialStoreException.class, () -> {
            VaultKeyPathOperations.resolveKeyPath(testData, "");
        });
    }

    @Test
    void testNullData() throws CredentialStoreException {
        // Null data map should return null
        String result = VaultKeyPathOperations.resolveKeyPath(null, "password");
        assertNull(result);
    }

    @Test
    void testEmptySegmentInPath() {
        // Key path with empty segment (e.g., "database//host")
        assertThrows(CredentialStoreException.class, () -> {
            VaultKeyPathOperations.resolveKeyPath(testData, "database//host");
        });
    }

    @Test
    void testLeadingSlash() {
        // Key path starting with slash
        assertThrows(CredentialStoreException.class, () -> {
            VaultKeyPathOperations.resolveKeyPath(testData, "/database/host");
        });
    }

    @Test
    void testTrailingSlash() throws CredentialStoreException {
        // Key path ending with slash - trailing empty strings are removed by split()
        // so this is equivalent to "database/host"
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "database/host/");
        assertEquals("prod.db.com", result);
    }

    @Test
    void testNonMapValueInTraversalPath() throws CredentialStoreException {
        // Try to traverse through a non-map value
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "password/subkey");
        assertNull(result);
    }

    @Test
    void testNonMapIntermediateValue() throws CredentialStoreException {
        // Try to traverse through an integer value
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "database/port/subkey");
        assertNull(result);
    }

    @Test
    void testNullValueInData() throws CredentialStoreException {
        // Add null value to test data
        testData.put("nullValue", null);
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "nullValue");
        assertNull(result);
    }

    @Test
    void testNullValueInNestedPath() throws CredentialStoreException {
        // Add null value in nested structure
        Map<String, Object> database = child(testData, "database");
        database.put("nullField", null);

        String result = VaultKeyPathOperations.resolveKeyPath(testData, "database/nullField");
        assertNull(result);
    }

    // ========================================================================
    // Set Nested Value Tests
    // ========================================================================

    @Test
    void testSetSimpleValue() throws CredentialStoreException {
        Map<String, Object> data = new HashMap<>();
        VaultKeyPathOperations.setNestedValue(data, "password", "newSecret");

        assertEquals("newSecret", data.get("password"));
    }

    @Test
    void testSetNestedValueCreatesStructure() throws CredentialStoreException {
        Map<String, Object> data = new HashMap<>();
        VaultKeyPathOperations.setNestedValue(data, "database/host", "localhost");

        assertTrue(data.containsKey("database"));
        assertTrue(data.get("database") instanceof Map);
        Map<String, Object> database = child(data, "database");
        assertEquals("localhost", database.get("host"));
    }

    @Test
    void testSetDeepNestedValue() throws CredentialStoreException {
        Map<String, Object> data = new HashMap<>();
        VaultKeyPathOperations.setNestedValue(data, "database/credentials/password", "secret");

        Map<String, Object> database = child(data, "database");
        Map<String, Object> credentials = child(database, "credentials");
        assertEquals("secret", credentials.get("password"));
    }

    @Test
    void testSetValueWithDotsInSegment() throws CredentialStoreException {
        Map<String, Object> data = new HashMap<>();
        VaultKeyPathOperations.setNestedValue(data, "my.app/config.key", "value");

        assertTrue(data.containsKey("my.app"));
        Map<String, Object> myApp = child(data, "my.app");
        assertEquals("value", myApp.get("config.key"));
    }

    @Test
    void testSetValueReplacesNonMapValue() throws CredentialStoreException {
        Map<String, Object> data = new HashMap<>();
        data.put("database", "stringValue");

        VaultKeyPathOperations.setNestedValue(data, "database/host", "localhost");

        assertTrue(data.get("database") instanceof Map);
        Map<String, Object> database = child(data, "database");
        assertEquals("localhost", database.get("host"));
    }

    @Test
    void testSetValueNullKeyPath() {
        Map<String, Object> data = new HashMap<>();
        assertThrows(CredentialStoreException.class, () -> {
            VaultKeyPathOperations.setNestedValue(data, null, "value");
        });
    }

    @Test
    void testSetValueEmptyKeyPath() {
        Map<String, Object> data = new HashMap<>();
        assertThrows(CredentialStoreException.class, () -> {
            VaultKeyPathOperations.setNestedValue(data, "", "value");
        });
    }

    @Test
    void testSetValueNullData() {
        assertThrows(IllegalArgumentException.class, () -> {
            VaultKeyPathOperations.setNestedValue(null, "key", "value");
        });
    }

    @Test
    void testSetValueEmptySegment() {
        Map<String, Object> data = new HashMap<>();
        assertThrows(CredentialStoreException.class, () -> {
            VaultKeyPathOperations.setNestedValue(data, "database//host", "value");
        });
    }

    // ========================================================================
    // Remove Nested Value Tests
    // ========================================================================

    @Test
    void testRemoveSimpleValue() throws CredentialStoreException {
        Map<String, Object> data = new HashMap<>();
        data.put("password", "secret");

        boolean removed = VaultKeyPathOperations.removeNestedValue(data, "password");
        assertTrue(removed);
        assertFalse(data.containsKey("password"));
    }

    @Test
    void testRemoveNestedValue() throws CredentialStoreException {
        Map<String, Object> credentials = new HashMap<>();
        credentials.put("user", "admin");
        credentials.put("pass", "secret");

        Map<String, Object> data = new HashMap<>();
        data.put("credentials", credentials);

        boolean removed = VaultKeyPathOperations.removeNestedValue(data, "credentials/pass");
        assertTrue(removed);
        assertFalse(credentials.containsKey("pass"));
        assertTrue(credentials.containsKey("user")); // Other keys preserved
    }

    @Test
    void testRemoveDeepNestedValue() throws CredentialStoreException {
        boolean removed = VaultKeyPathOperations.removeNestedValue(testData, "database/credentials/pass");
        assertTrue(removed);

        Map<String, Object> database = child(testData, "database");
        Map<String, Object> credentials = child(database, "credentials");
        assertFalse(credentials.containsKey("pass"));
        assertTrue(credentials.containsKey("user")); // Other keys preserved
    }

    @Test
    void testRemoveNonExistentSimpleKey() throws CredentialStoreException {
        boolean removed = VaultKeyPathOperations.removeNestedValue(testData, "nonexistent");
        assertFalse(removed);
    }

    @Test
    void testRemoveNonExistentNestedKey() throws CredentialStoreException {
        boolean removed = VaultKeyPathOperations.removeNestedValue(testData, "database/nonexistent");
        assertFalse(removed);
    }

    @Test
    void testRemoveFromNonExistentPath() throws CredentialStoreException {
        boolean removed = VaultKeyPathOperations.removeNestedValue(testData, "nonexistent/path/key");
        assertFalse(removed);
    }

    @Test
    void testRemoveFromNonMapValue() throws CredentialStoreException {
        boolean removed = VaultKeyPathOperations.removeNestedValue(testData, "password/subkey");
        assertFalse(removed);
    }

    @Test
    void testRemoveNullKeyPath() {
        assertThrows(CredentialStoreException.class, () -> {
            VaultKeyPathOperations.removeNestedValue(testData, null);
        });
    }

    @Test
    void testRemoveEmptyKeyPath() {
        assertThrows(CredentialStoreException.class, () -> {
            VaultKeyPathOperations.removeNestedValue(testData, "");
        });
    }

    @Test
    void testRemoveNullData() throws CredentialStoreException {
        boolean removed = VaultKeyPathOperations.removeNestedValue(null, "key");
        assertFalse(removed);
    }

    @Test
    void testRemoveEmptySegment() {
        assertThrows(CredentialStoreException.class, () -> {
            VaultKeyPathOperations.removeNestedValue(testData, "database//host");
        });
    }

    // ========================================================================
    // Additional Edge Cases
    // ========================================================================

    @Test
    void testVeryDeepNesting() throws CredentialStoreException {
        // Create a very deep nested structure (5 levels)
        Map<String, Object> level5 = new HashMap<>();
        level5.put("value", "deep");

        Map<String, Object> level4 = new HashMap<>();
        level4.put("level5", level5);

        Map<String, Object> level3 = new HashMap<>();
        level3.put("level4", level4);

        Map<String, Object> level2 = new HashMap<>();
        level2.put("level3", level3);

        Map<String, Object> level1 = new HashMap<>();
        level1.put("level2", level2);

        testData.put("level1", level1);

        String result = VaultKeyPathOperations.resolveKeyPath(testData, "level1/level2/level3/level4/level5/value");
        assertEquals("deep", result);
    }

    @Test
    void testSpecialCharactersInKeyName() throws CredentialStoreException {
        // Keys can contain special characters (already URL-decoded at this point)
        testData.put("key with spaces", "value1");
        testData.put("key#with#hash", "value2");
        testData.put("key?with?question", "value3");

        assertEquals("value1", VaultKeyPathOperations.resolveKeyPath(testData, "key with spaces"));
        assertEquals("value2", VaultKeyPathOperations.resolveKeyPath(testData, "key#with#hash"));
        assertEquals("value3", VaultKeyPathOperations.resolveKeyPath(testData, "key?with?question"));
    }

    @Test
    void testBooleanValue() throws CredentialStoreException {
        testData.put("enabled", true);
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "enabled");
        assertEquals("true", result);
    }

    @Test
    void testNumericValue() throws CredentialStoreException {
        testData.put("count", 42);
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "count");
        assertEquals("42", result);
    }

    @Test
    void testDoubleValue() throws CredentialStoreException {
        testData.put("price", 19.99);
        String result = VaultKeyPathOperations.resolveKeyPath(testData, "price");
        assertEquals("19.99", result);
    }

    /** The nested map stored under the key; fails the test if there is none. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> child(Map<String, Object> parent, String key) {
        Object value = parent.get(key);
        assertTrue(value instanceof Map, key + " must be a nested map, was: " + value);
        return (Map<String, Object>) value;
    }
}
