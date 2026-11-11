/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Utility class for performing key path operations on Vault secret data.
 *
 * <p>This package-private class provides three core operations for working with Vault secret data:
 * <ul>
 *   <li>{@link #resolveKeyPath(Map, String)} - Read: extracts values from secret data</li>
 *   <li>{@link #setNestedValue(Map, String, String)} - Write: sets values in secret data</li>
 *   <li>{@link #removeNestedValue(Map, String)} - Remove: removes values from secret data</li>
 * </ul>
 *
 * <p><b>Operation Modes:</b> All three methods support two modes of key path resolution:
 * <ul>
 *   <li><b>Simple key lookup:</b> When the key path contains no {@code /} separator,
 *       performs a direct lookup in the data map. This supports keys with dots in their names.</li>
 *   <li><b>Nested JSON traversal:</b> When the key path contains {@code /} separators,
 *       traverses nested maps using each segment as a key. Dots within segments are preserved
 *       as part of the key name.</li>
 * </ul>
 *
 * <p><b>Examples:</b>
 * <pre>
 * Map<String, Object> data = Map.of(
 *     "password", "secret123",
 *     "db.host", "localhost",
 *     "database", Map.of(
 *         "host", "prod.db.com",
 *         "credentials", Map.of(
 *             "user", "admin",
 *             "pass", "secret"
 *         )
 *     ),
 *     "my.app", Map.of(
 *         "config.key", "value123"
 *     )
 * );
 *
 * // Simple key lookups (no / in key path)
 * resolveKeyPath(data, "password")           → "secret123"
 * resolveKeyPath(data, "db.host")            → "localhost"  (dots in key name)
 *
 * // Nested JSON traversal (with / in key path)
 * resolveKeyPath(data, "database/host")                    → "prod.db.com"
 * resolveKeyPath(data, "database/credentials/pass")        → "secret"
 * resolveKeyPath(data, "my.app/config.key")                → "value123"  (dots in segment)
 *
 * // Write operations
 * setNestedValue(data, "newKey", "value")                  // Simple set
 * setNestedValue(data, "app/config/timeout", "30")         // Creates nested structure
 *
 * // Remove operations
 * removeNestedValue(data, "password")                      // Remove simple key
 * removeNestedValue(data, "database/credentials/pass")     // Remove nested value
 * </pre>
 */
class VaultKeyPathOperations {

    /**
     * Split a key path on {@code /} into segments. A key path without {@code /} yields a single segment.
     * Trailing empty segments are dropped (as with {@link String#split(String)}).
     */
    private static List<String> splitKeyPath(String keyPath) throws CredentialStoreException {
        if (keyPath == null || keyPath.isEmpty()) {
            throw ROOT_LOGGER.keyPathCannotBeNullOrEmpty();
        }
        return Arrays.asList(keyPath.split("/"));
    }

    private static void checkSegmentsNotEmpty(List<String> segments) throws CredentialStoreException {
        if (segments == null || segments.isEmpty()) {
            throw ROOT_LOGGER.keyPathCannotBeNullOrEmpty();
        }
    }

    /**
     * Extract value from Vault secret data using key path.
     *
     * <p>The key path is split on {@code /} and each segment is used as a key while
     * traversing nested maps. A key path without {@code /} is a simple lookup
     * (supporting dots in key names). This method treats every {@code /} as a separator;
     * use {@link #resolveKeyPathSegments(Map, List)} when a segment may itself contain a slash.
     *
     * @param data the secret data map from Vault
     * @param keyPath the key path from alias (after ? delimiter, already URL-decoded)
     * @return the extracted value as a string, or {@code null} if not found
     * @throws CredentialStoreException if keyPath is null or empty
     */
    public static String resolveKeyPath(Map<String, Object> data, String keyPath) throws CredentialStoreException {
        return resolveKeyPathSegments(data, splitKeyPath(keyPath));
    }

    /**
     * Extract value from Vault secret data using already-decoded key path segments.
     * Each segment is used verbatim as a map key, so a segment may contain a literal {@code /}.
     *
     * @param data the secret data map from Vault
     * @param segments the decoded key path segments
     * @return the extracted value as a string, or {@code null} if not found
     * @throws CredentialStoreException if segments is null or empty, or a segment is empty
     */
    public static String resolveKeyPathSegments(Map<String, Object> data, List<String> segments) throws CredentialStoreException {
        checkSegmentsNotEmpty(segments);
        String keyPath = String.join("/", segments);

        if (data == null) {
            ROOT_LOGGER.debugf("Key path '%s' not found - secret data is null", keyPath);
            return null;
        }

        ROOT_LOGGER.debugf("Resolving key path: %s", keyPath);

        int nestingLevel = segments.size();

        // Warn about deep nesting (>5 levels), but only if debug is enabled
        if (nestingLevel > 5) {
            if (ROOT_LOGGER.isDebugEnabled()) {
                ROOT_LOGGER.deepKeyPathNesting(keyPath, nestingLevel);
            }
        }

        ROOT_LOGGER.debugf("Traversing nested key path with %d segments", nestingLevel);

        Object current = data;

        for (int i = 0; i < segments.size(); i++) {
            String segment = segments.get(i);

            // Validate segment is not empty
            if (segment.isEmpty()) {
                throw ROOT_LOGGER.keyPathContainsEmptySegment(keyPath);
            }

            if (!(current instanceof Map)) {
                // Can't traverse further - not a map
                ROOT_LOGGER.debugf("Key path '%s' not found - cannot traverse further at segment '%s'", keyPath, segment);
                return null;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> currentMap = (Map<String, Object>) current;

            // Look up this segment (segment can contain dots)
            current = currentMap.get(segment);

            if (current == null) {
                ROOT_LOGGER.debugf("Key path '%s' not found - segment '%s' does not exist", keyPath, segment);
                return null;
            }

            // If this is the last segment, return the value
            if (i == segments.size() - 1) {
                if (current instanceof Map) {
                    // Key path is incomplete - points to a nested structure, not a leaf value
                    ROOT_LOGGER.debugf("Key path '%s' points to a nested structure, not a credential value", keyPath);
                    return null;
                }
                ROOT_LOGGER.debugf("Key path '%s' resolved successfully", keyPath);
                return current.toString();
            }
        }

        return null;
    }

    /**
     * Set a value in Vault secret data using key path.
     * Creates nested maps as needed for nested paths.
     *
     * @param data the secret data map to modify
     * @param keyPath the key path (after ? delimiter, already URL-decoded)
     * @param value the value to set
     * @throws CredentialStoreException if keyPath is null or empty
     */
    public static void setNestedValue(Map<String, Object> data, String keyPath, String value) throws CredentialStoreException {
        setNestedValueSegments(data, splitKeyPath(keyPath), value);
    }

    /**
     * Set a value in Vault secret data using already-decoded key path segments.
     * Each segment is used verbatim as a map key, so a segment may contain a literal {@code /}.
     *
     * @param data the secret data map to modify
     * @param segments the decoded key path segments
     * @param value the value to set
     * @throws CredentialStoreException if segments is null or empty, or a segment is empty
     */
    @SuppressWarnings("unchecked")
    public static void setNestedValueSegments(Map<String, Object> data, List<String> segments, String value) throws CredentialStoreException {
        checkSegmentsNotEmpty(segments);
        checkNotNullParam("data", data);

        String keyPath = String.join("/", segments);
        Map<String, Object> current = data;

        for (int i = 0; i < segments.size(); i++) {
            String segment = segments.get(i);

            // Validate segment is not empty
            if (segment == null || segment.isEmpty()) {
                throw ROOT_LOGGER.keyPathContainsEmptySegment(keyPath);
            }

            // If this is the last segment, set the value
            if (i == segments.size() - 1) {
                current.put(segment, value);
                return;
            }

            // Not the last segment - need to traverse or create nested map
            Object next = current.get(segment);
            if (next == null) {
                // Create new nested map
                Map<String, Object> newMap = new java.util.HashMap<>();
                current.put(segment, newMap);
                current = newMap;
            } else if (next instanceof Map) {
                // Traverse into existing map
                current = (Map<String, Object>) next;
            } else {
                // Existing value is not a map - replace it with a map
                Map<String, Object> newMap = new java.util.HashMap<>();
                current.put(segment, newMap);
                current = newMap;
            }
        }
    }

    /**
     * Remove a value from Vault secret data using key path.
     * For nested paths, removes the leaf value but preserves parent maps.
     *
     * @param data the secret data map to modify
     * @param keyPath the key path (after ? delimiter, already URL-decoded)
     * @return true if a value was removed, false if the key path didn't exist
     * @throws CredentialStoreException if keyPath is null or empty
     */
    public static boolean removeNestedValue(Map<String, Object> data, String keyPath) throws CredentialStoreException {
        return removeNestedValueSegments(data, splitKeyPath(keyPath));
    }

    /**
     * Remove a value from Vault secret data using already-decoded key path segments.
     * Each segment is used verbatim as a map key, so a segment may contain a literal {@code /}.
     *
     * @param data the secret data map to modify
     * @param segments the decoded key path segments
     * @return true if a value was removed, false if the key path didn't exist
     * @throws CredentialStoreException if segments is null or empty, or a segment is empty
     */
    @SuppressWarnings("unchecked")
    public static boolean removeNestedValueSegments(Map<String, Object> data, List<String> segments) throws CredentialStoreException {
        checkSegmentsNotEmpty(segments);
        if (data == null) {
            return false;
        }

        String keyPath = String.join("/", segments);
        Map<String, Object> current = data;

        for (int i = 0; i < segments.size(); i++) {
            String segment = segments.get(i);

            // Validate segment is not empty
            if (segment == null || segment.isEmpty()) {
                throw ROOT_LOGGER.keyPathContainsEmptySegment(keyPath);
            }

            // If this is the last segment, remove it
            if (i == segments.size() - 1) {
                return current.remove(segment) != null;
            }

            // Not the last segment - need to traverse
            Object next = current.get(segment);
            if (next == null || !(next instanceof Map)) {
                // Path doesn't exist or can't traverse further
                return false;
            }

            current = (Map<String, Object>) next;
        }

        return false;
    }
}
