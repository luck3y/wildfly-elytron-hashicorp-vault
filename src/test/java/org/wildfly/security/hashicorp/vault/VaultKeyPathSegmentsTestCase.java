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
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Verifies the segment based {@link VaultKeyPathOperations} methods, which allow a single
 * segment to contain a literal {@code /} (an alias key path using {@code %2F}) as opposed to
 * the string based methods where every {@code /} is a nesting separator.
 */
public class VaultKeyPathSegmentsTestCase {

    private Map<String, Object> data;

    @BeforeEach
    void setUp() {
        data = new HashMap<>();
        data.put("database/host", "literal-value");
        Map<String, Object> database = new HashMap<>();
        database.put("host", "nested-value");
        data.put("database", database);
        Map<String, Object> slashParent = new HashMap<>();
        slashParent.put("child/leaf", "deep-literal");
        data.put("parent/dir", slashParent);
    }

    // ========================================================================
    // resolve
    // ========================================================================

    @Test
    void testResolveLiteralSlashSegment() throws CredentialStoreException {
        assertEquals("literal-value", VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("database/host")));
    }

    @Test
    void testResolveNestedSegments() throws CredentialStoreException {
        assertEquals("nested-value", VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("database", "host")));
    }

    @Test
    void testResolveMixedLiteralSlashAndNestedSegments() throws CredentialStoreException {
        assertEquals("deep-literal",
                VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("parent/dir", "child/leaf")));
    }

    @Test
    void testResolveStringFormTreatsEverySlashAsSeparator() throws CredentialStoreException {
        // The string based variant has no way to express a literal slash
        assertEquals("nested-value", VaultKeyPathOperations.resolveKeyPath(data, "database/host"));
    }

    @Test
    void testResolveSegmentsMissingAndNonLeaf() throws CredentialStoreException {
        assertNull(VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("database/missing")));
        assertNull(VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("database")));
        assertNull(VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("database/host", "deeper")));
    }

    @Test
    void testResolveSegmentsNullData() throws CredentialStoreException {
        assertNull(VaultKeyPathOperations.resolveKeyPathSegments(null, List.of("a")));
    }

    @Test
    void testResolveSegmentsInvalidInput() {
        assertThrows(CredentialStoreException.class, () -> VaultKeyPathOperations.resolveKeyPathSegments(data, null));
        assertThrows(CredentialStoreException.class, () -> VaultKeyPathOperations.resolveKeyPathSegments(data, List.of()));
        assertThrows(CredentialStoreException.class, () -> VaultKeyPathOperations.resolveKeyPathSegments(data, List.of("database", "")));
    }

    // ========================================================================
    // set
    // ========================================================================

    @Test
    void testSetLiteralSlashSegmentCreatesFlatKey() throws CredentialStoreException {
        Map<String, Object> target = new HashMap<>();

        VaultKeyPathOperations.setNestedValueSegments(target, List.of("a/b"), "v");

        assertEquals(Map.of("a/b", "v"), target);
    }

    @Test
    void testSetNestedSegmentsCreatesNestedMaps() throws CredentialStoreException {
        Map<String, Object> target = new HashMap<>();

        VaultKeyPathOperations.setNestedValueSegments(target, List.of("a", "b"), "v");

        assertEquals(Map.of("a", Map.of("b", "v")), target);
    }

    @Test
    void testSetMixedSegmentsDoesNotTouchSiblingNestedKey() throws CredentialStoreException {
        VaultKeyPathOperations.setNestedValueSegments(data, List.of("database/host"), "updated-literal");

        assertEquals("updated-literal", data.get("database/host"));
        assertEquals("nested-value", ((Map<?, ?>) data.get("database")).get("host"));
    }

    @Test
    void testSetSegmentsInvalidInput() {
        assertThrows(CredentialStoreException.class, () -> VaultKeyPathOperations.setNestedValueSegments(data, List.of(), "v"));
        assertThrows(CredentialStoreException.class, () -> VaultKeyPathOperations.setNestedValueSegments(data, List.of("a", ""), "v"));
    }

    @Test
    void testSetThenResolveRoundTrip() throws CredentialStoreException {
        Map<String, Object> target = new HashMap<>();
        VaultKeyPathOperations.setNestedValueSegments(target, List.of("x/y", "z"), "v");

        assertEquals("v", VaultKeyPathOperations.resolveKeyPathSegments(target, List.of("x/y", "z")));
        assertNull(VaultKeyPathOperations.resolveKeyPathSegments(target, List.of("x", "y", "z")));
    }

    // ========================================================================
    // remove
    // ========================================================================

    @Test
    void testRemoveLiteralSlashSegmentLeavesNestedKey() throws CredentialStoreException {
        boolean removed = VaultKeyPathOperations.removeNestedValueSegments(data, List.of("database/host"));

        assertTrue(removed);
        assertFalse(data.containsKey("database/host"));
        assertEquals("nested-value", ((Map<?, ?>) data.get("database")).get("host"));
    }

    @Test
    void testRemoveNestedSegmentsLeavesLiteralSlashKey() throws CredentialStoreException {
        boolean removed = VaultKeyPathOperations.removeNestedValueSegments(data, List.of("database", "host"));

        assertTrue(removed);
        assertEquals("literal-value", data.get("database/host"));
        assertFalse(((Map<?, ?>) data.get("database")).containsKey("host"));
    }

    @Test
    void testRemoveMixedSegments() throws CredentialStoreException {
        assertTrue(VaultKeyPathOperations.removeNestedValueSegments(data, List.of("parent/dir", "child/leaf")));
        assertTrue(((Map<?, ?>) data.get("parent/dir")).isEmpty());
    }

    @Test
    void testRemoveSegmentsMissing() throws CredentialStoreException {
        assertFalse(VaultKeyPathOperations.removeNestedValueSegments(data, List.of("nope/nope")));
        assertFalse(VaultKeyPathOperations.removeNestedValueSegments(data, List.of("database/host", "deeper")));
        assertFalse(VaultKeyPathOperations.removeNestedValueSegments(null, List.of("a")));
    }

    @Test
    void testRemoveSegmentsInvalidInput() {
        assertThrows(CredentialStoreException.class, () -> VaultKeyPathOperations.removeNestedValueSegments(data, null));
        assertThrows(CredentialStoreException.class, () -> VaultKeyPathOperations.removeNestedValueSegments(data, List.of()));
        assertThrows(CredentialStoreException.class, () -> VaultKeyPathOperations.removeNestedValueSegments(data, List.of("database", "")));
    }
}
