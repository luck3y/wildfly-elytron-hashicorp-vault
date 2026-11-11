/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Unit tests for {@link VaultAlias} parsing logic.
 *
 * <p>This test class covers:
 * <ul>
 *   <li>Valid format parsing (simple keys, nested keys, URL encoding)</li>
 *   <li>Invalid format detection and error messages</li>
 *   <li>Legacy format support and deprecation</li>
 *   <li>Default value application</li>
 *   <li>Edge cases and special characters</li>
 * </ul>
 *
 * <p>Test coverage target: >95% for {@link VaultAlias} class
 */
public class VaultAliasParsingTestCase {

    // ========================================================================
    // Valid Format Tests - Simple Keys
    // ========================================================================

    @Test
    void testMinimalFormat() throws CredentialStoreException {
        // Minimal format: #secret?key
        VaultAlias alias = VaultAlias.parse("#secret?key");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("secret", alias.getSecretPath());
        assertEquals("key", alias.getKeyPath());
    }

    @Test
    void testMinimalFormatWithoutHash() throws CredentialStoreException {
        // Minimal format without # prefix: secret?key
        VaultAlias alias = VaultAlias.parse("secret?key");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("secret", alias.getSecretPath());
        assertEquals("key", alias.getKeyPath());
    }

    @Test
    void testSecretPathWithSlashesWithoutHash() throws CredentialStoreException {
        // Secret path with slashes, no # prefix: myapp/database?password
        VaultAlias alias = VaultAlias.parse("myapp/database?password");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("myapp/database", alias.getSecretPath());
        assertEquals("password", alias.getKeyPath());
    }

    @Test
    void testDotsInSecretPath() throws CredentialStoreException {
        // Dots in secret path: #my.app.config?password
        VaultAlias alias = VaultAlias.parse("#my.app.config?password");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("my.app.config", alias.getSecretPath());
        assertEquals("password", alias.getKeyPath());
    }

    @Test
    void testDotsInKeyName() throws CredentialStoreException {
        // Dots in key name: #myapp?db.host
        VaultAlias alias = VaultAlias.parse("#myapp?db.host");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("myapp", alias.getSecretPath());
        assertEquals("db.host", alias.getKeyPath());
    }

    @Test
    void testUrlEncodedSpace() throws CredentialStoreException {
        // URL-encoded space: #test%20path?password
        VaultAlias alias = VaultAlias.parse("#test%20path?password");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("test path", alias.getSecretPath());
        assertEquals("password", alias.getKeyPath());
    }

    @Test
    void testWithEngineType() throws CredentialStoreException {
        // With engine type: engine=KVv1#secret?key
        VaultAlias alias = VaultAlias.parse("engine=KVv1#secret?key");

        assertNotNull(alias);
        assertEquals("KVv1", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("secret", alias.getSecretPath());
        assertEquals("key", alias.getKeyPath());
    }

    @Test
    void testWithCustomMount() throws CredentialStoreException {
        // With custom mount: @custom#secret?key
        VaultAlias alias = VaultAlias.parse("@custom#secret?key");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("custom", alias.getMountPath());
        assertEquals("secret", alias.getSecretPath());
        assertEquals("key", alias.getKeyPath());
    }

    @Test
    void testEverythingExplicit() throws CredentialStoreException {
        // Everything explicit: engine=KVv2@team/vault#app.db.config?api.key
        VaultAlias alias = VaultAlias.parse("engine=KVv2@team/vault#app.db.config?api.key");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("team/vault", alias.getMountPath());
        assertEquals("app.db.config", alias.getSecretPath());
        assertEquals("api.key", alias.getKeyPath());
    }

    @Test
    void testMultipleUrlEncodedChars() throws CredentialStoreException {
        // Multiple URL-encoded chars: @mount%2Fname#secret%20path?key
        VaultAlias alias = VaultAlias.parse("@mount%2Fname#secret%20path?key");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("mount/name", alias.getMountPath());
        assertEquals("secret path", alias.getSecretPath());
        assertEquals("key", alias.getKeyPath());
    }

    // ========================================================================
    // Valid Format Tests - Nested Keys
    // ========================================================================

    @Test
    void testSimpleNestedKey() throws CredentialStoreException {
        // Simple nested: #myapp?database/host
        VaultAlias alias = VaultAlias.parse("#myapp?database/host");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("myapp", alias.getSecretPath());
        assertEquals("database/host", alias.getKeyPath());
    }

    @Test
    void testDeepNesting() throws CredentialStoreException {
        // Deep nesting: #myapp?app/config/database/host
        VaultAlias alias = VaultAlias.parse("#myapp?app/config/database/host");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("myapp", alias.getSecretPath());
        assertEquals("app/config/database/host", alias.getKeyPath());
    }

    @Test
    void testNestedWithDotsInKeys() throws CredentialStoreException {
        // Nested with dots in keys: #services?my.app/config.key
        VaultAlias alias = VaultAlias.parse("#services?my.app/config.key");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("services", alias.getSecretPath());
        assertEquals("my.app/config.key", alias.getKeyPath());
    }

    @Test
    void testComplexNestedFormat() throws CredentialStoreException {
        // Complex: engine=KVv2@prod#app.v2?database/credentials/password
        VaultAlias alias = VaultAlias.parse("engine=KVv2@prod#app.v2?database/credentials/password");

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("prod", alias.getMountPath());
        assertEquals("app.v2", alias.getSecretPath());
        assertEquals("database/credentials/password", alias.getKeyPath());
    }

    // ========================================================================
    // URL Encoding Tests (Critical - Decode After Split)
    // ========================================================================

    @Test
    void testUrlEncodedSpaceDecoding() throws CredentialStoreException {
        // Test %20 (space) decoding
        VaultAlias alias = VaultAlias.parse("#test%20path?key");

        assertEquals("test path", alias.getSecretPath());
    }

    @Test
    void testUrlEncodedHashDecoding() throws CredentialStoreException {
        // Test %23 (#) decoding - # is encoded in secret path
        VaultAlias alias = VaultAlias.parse("#test%23path?key");

        assertEquals("test#path", alias.getSecretPath());
    }

    @Test
    void testUrlEncodedQuestionMarkDecoding() throws CredentialStoreException {
        // Test %3F (?) decoding - ? is encoded in secret path
        VaultAlias alias = VaultAlias.parse("#test%3Fpath?key");

        assertEquals("test?path", alias.getSecretPath());
    }

    @Test
    void testDoubleEncodedPercent() throws CredentialStoreException {
        // Test %2520 (encoded %) - user encoded % as %25
        VaultAlias alias = VaultAlias.parse("#test%2520path?key");

        // Should decode to "test%20path" (one level of decoding)
        assertEquals("test%20path", alias.getSecretPath());
    }

    @Test
    void testUrlEncodedAtSign() throws CredentialStoreException {
        // Test %40 (@) decoding in mount path
        VaultAlias alias = VaultAlias.parse("@mount%40name#secret?key");

        assertEquals("mount@name", alias.getMountPath());
    }

    @Test
    void testUrlEncodedSlash() throws CredentialStoreException {
        // Test %2F (/) decoding in secret path
        VaultAlias alias = VaultAlias.parse("#test%2Fpath?key");

        assertEquals("test/path", alias.getSecretPath());
    }

    @Test
    void testMultipleEncodedCharsInDifferentSegments() throws CredentialStoreException {
        // Test multiple encoded chars across different segments
        VaultAlias alias = VaultAlias.parse("@mount%20path#secret%23name?key%3Fname");

        assertEquals("mount path", alias.getMountPath());
        assertEquals("secret#name", alias.getSecretPath());
        assertEquals("key?name", alias.getKeyPath());
    }

    // ========================================================================
    // Invalid Format Tests
    // ========================================================================

    @Test
    void testHashRequiredAfterMountPath() {
        // When @ mount path is present, # is required before secret path
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("@custom-mountsecret?key"));

        // Should indicate missing # delimiter
        assertNotNull(ex.getMessage());
    }

    @Test
    void testMissingQuestionMarkBeforeKeyPath() {
        // Missing ? before key path: #secret
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("#secret"));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testMissingDelimiterAfterEngine() {
        // Missing delimiter after engine=: engine=KVv1secret
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("engine=KVv1secret"));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testEmptySecretPath() {
        // Empty secret path: ?key
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("?key"));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testEmptyKeyPath() {
        // Empty key path: #secret?
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("#secret?"));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testEmptySegmentInKeyPath() {
        // Empty segment in key path: #secret?/key
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("#secret?/key"));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testEmptySegmentInMiddleOfKeyPath() {
        // Empty segment in middle: #secret?key//value
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("#secret?key//value"));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testNullAlias() {
        // Null alias
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse(null));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testEmptyAlias() {
        // Empty alias
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse(""));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testInvalidEngineType() {
        // Invalid engine type: engine=InvalidType#secret?key
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("engine=InvalidType#secret?key"));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testEmptyEngineType() {
        // Empty engine type: engine=#secret?key
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("engine=#secret?key"));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testEmptyMountPath() {
        // Empty mount path: @#secret?key
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("@#secret?key"));

        assertNotNull(ex.getMessage());
    }
    @Test
    void testEngineTypeToVersionWithValidTypes() throws CredentialStoreException {
        // Test valid engine types
        VaultAlias aliasV1 = VaultAlias.parse("engine=KVv1#secret?key");
        assertEquals(1, aliasV1.getKvVersion());

        VaultAlias aliasV2 = VaultAlias.parse("engine=KVv2#secret?key");
        assertEquals(2, aliasV2.getKvVersion());
    }

    @Test
    void testEngineTypeToVersionWithInvalidType() {
        // Test that engineTypeToVersion throws exception for invalid engine type
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.engineTypeToVersion("InvalidType"));

        assertNotNull(ex.getMessage());
    }

    @Test
    void testEngineTypeToVersionWithNullType() {
        // Test that engineTypeToVersion throws exception for null
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.engineTypeToVersion(null));

        assertNotNull(ex.getMessage());
    }


    // ========================================================================
    // Legacy Format Tests
    // ========================================================================

    @Test
    void testSimpleLegacyFormat() throws CredentialStoreException {
        // Simple legacy format: myapp/db.password
        VaultAlias alias = VaultAlias.parse(
            "myapp/db.password", "KVv2", "secret", true);

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("myapp/db", alias.getSecretPath());
        assertEquals("password", alias.getKeyPath());
    }

    @Test
    void testLegacyWithDotsInSecretPath() throws CredentialStoreException {
        // Legacy with dots in secret path: app.config.key
        VaultAlias alias = VaultAlias.parse(
            "app.config.key", "KVv2", "secret", true);

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("app.config", alias.getSecretPath());
        assertEquals("key", alias.getKeyPath());
    }

    @Test
    void testLegacyWithMultipleDots() throws CredentialStoreException {
        // Legacy with multiple dots: my.app.db.password
        VaultAlias alias = VaultAlias.parse(
            "my.app.db.password", "KVv2", "secret", true);

        assertNotNull(alias);
        assertEquals("KVv2", alias.getEngineType());
        assertEquals("secret", alias.getMountPath());
        assertEquals("my.app.db", alias.getSecretPath());
        assertEquals("password", alias.getKeyPath());
    }

    @Test
    void testLegacyFormatNotSupportedThrowsException() {
        // Legacy format with support disabled should throw exception
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse(
                "myapp/db.password", "KVv2", "secret", false));

        assertNotNull(ex.getMessage());
        // Message should include migration guidance
    }

    @Test
    void testLegacyFormatWithoutDotThrowsException() {
        // Invalid legacy format (no dot): myapp
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse(
                "myapp", "KVv2", "secret", true));

        assertNotNull(ex.getMessage());
    }

    /**
     * The legacy format splits on the last dot, wherever it is. These aliases parsed this way in 1.1.0.CR3 and
     * existing configurations may depend on it, so the split must not change even where the result looks odd:
     * the text after the last dot becomes the key path, and a {@code /} in it is nested traversal.
     */
    @Test
    void testLegacyDotBeforeLastSlashSplitsOnLastDotLikeCr3() throws CredentialStoreException {
        VaultAlias alias = VaultAlias.parse("my.app/config", "KVv2", "secret", true);

        assertEquals("secret", alias.getMountPath());
        assertEquals("my", alias.getSecretPath());
        assertEquals("app/config", alias.getKeyPath());
        assertEquals(List.of("app", "config"), alias.getKeyPathSegments());
    }

    @Test
    void testLegacyLastDotSplitWithSeveralSlashesLikeCr3() throws CredentialStoreException {
        VaultAlias deep = VaultAlias.parse("a.b/c/d", "KVv2", "secret", true);
        assertEquals("a", deep.getSecretPath());
        assertEquals(List.of("b", "c", "d"), deep.getKeyPathSegments());

        // the last dot is the one that counts, so an earlier dot stays in the secret path
        VaultAlias twoDots = VaultAlias.parse("x.y/z.w/v", "KVv2", "secret", true);
        assertEquals("x.y/z", twoDots.getSecretPath());
        assertEquals(List.of("w", "v"), twoDots.getKeyPathSegments());
    }

    @Test
    void testLegacyDotBeforeLastSlashStillRejectedWhenLegacyDisabled() {
        // With legacy support off the alias is rejected as legacy, as in CR3, and not reported as something else
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("my.app/config", "KVv2", "secret", false));
        assertTrue(ex.getMessage().contains("my?app/config"), "was: " + ex.getMessage());
    }

    @Test
    void testLegacyDotInSecretPathWithKey() throws CredentialStoreException {
        VaultAlias alias = VaultAlias.parse(
            "my.app/config.password", "KVv2", "secret", true);

        assertEquals("secret", alias.getMountPath());
        assertEquals("my.app/config", alias.getSecretPath());
        assertEquals("password", alias.getKeyPath());
    }

    /**
     * Legacy aliases are URL-decoded, as they were in 1.1.0.CR3, and existing configurations may depend on it.
     * The legacy key is decoded as a whole and then split on {@code /}, so an encoded {@code %2F} in a legacy key
     * is nested traversal. That differs from the new format, where {@code %2F} is a literal slash in the key name.
     */
    @Test
    void testLegacyFormatIsUrlDecodedLikeCr3() throws CredentialStoreException {
        VaultAlias alias = VaultAlias.parse(
            "a+b/c%20d.pass%2Fword", "KVv2", "secret", true);

        assertEquals("a b/c d", alias.getSecretPath());
        assertEquals("pass/word", alias.getKeyPath());
        assertEquals(List.of("pass", "word"), alias.getKeyPathSegments());
    }

    @Test
    void testLegacyPlusAndEncodedSpaceDecodeLikeCr3() throws CredentialStoreException {
        assertEquals("a b", VaultAlias.parse("a+b.key", "KVv2", "secret", true).getSecretPath());
        assertEquals("x y", VaultAlias.parse("x%20y.k", "KVv2", "secret", true).getSecretPath());
    }

    @Test
    void testLegacyKeyWithTrailingEncodedSlashStillRejectedLikeCr3() {
        // decoded to "b/", which has an empty segment
        assertThrows(CredentialStoreException.class,
            () -> VaultAlias.parse("a.b%2F", "KVv2", "secret", true));
    }

    @Test
    void testNewFormatEncodedSlashStaysLiteralWhileLegacyDoesNot() throws CredentialStoreException {
        VaultAlias newFormat = VaultAlias.parse("#a?k%2Fz", "KVv2", "secret", true);
        VaultAlias legacy = VaultAlias.parse("a.k%2Fz", "KVv2", "secret", true);

        assertEquals(List.of("k/z"), newFormat.getKeyPathSegments());
        assertEquals(List.of("k", "z"), legacy.getKeyPathSegments());
    }

    @Test
    void testNewFormatIsStillUrlDecodedWithLegacySupport() throws CredentialStoreException {
        VaultAlias alias = VaultAlias.parse(
            "#a+b?pass%2Fword", "KVv2", "secret", true);

        assertEquals("a b", alias.getSecretPath());
        assertEquals("pass/word", alias.getKeyPath());
    }

    @Test
    void testNewFormatNotTreatedAsLegacy() throws CredentialStoreException {
        // New format should not be treated as legacy even with legacy support enabled
        VaultAlias alias = VaultAlias.parse(
            "#myapp?password", "KVv2", "secret", true);

        assertNotNull(alias);
        assertEquals("myapp", alias.getSecretPath());
        assertEquals("password", alias.getKeyPath());
    }

    // ========================================================================
    // Default Value Tests
    // ========================================================================

    @Test
    void testCustomDefaultEngineType() throws CredentialStoreException {
        // Test custom default engine type
        VaultAlias alias = VaultAlias.parse("#secret?key", "KVv1", "secret");

        assertEquals("KVv1", alias.getEngineType());
    }

    @Test
    void testCustomDefaultMountPath() throws CredentialStoreException {
        // Test custom default mount path
        VaultAlias alias = VaultAlias.parse("#secret?key", "KVv2", "custom-mount");

        assertEquals("custom-mount", alias.getMountPath());
    }

    @Test
    void testExplicitEngineOverridesDefault() throws CredentialStoreException {
        // Explicit engine type should override default
        VaultAlias alias = VaultAlias.parse("engine=KVv1#secret?key", "KVv2", "secret");

        assertEquals("KVv1", alias.getEngineType());
    }

    @Test
    void testExplicitMountOverridesDefault() throws CredentialStoreException {
        // Explicit mount path should override default
        VaultAlias alias = VaultAlias.parse("@custom#secret?key", "KVv2", "secret");

        assertEquals("custom", alias.getMountPath());
    }

    // ========================================================================
    // Edge Cases and Special Characters
    // ========================================================================

    @Test
    void testSecretPathWithSlashes() throws CredentialStoreException {
        // Secret path with slashes: #team/app/database?password
        VaultAlias alias = VaultAlias.parse("#team/app/database?password");

        assertEquals("team/app/database", alias.getSecretPath());
    }

    @Test
    void testMountPathWithSlashes() throws CredentialStoreException {
        // Mount path with slashes: @team/backend#secret?key
        VaultAlias alias = VaultAlias.parse("@team/backend#secret?key");

        assertEquals("team/backend", alias.getMountPath());
    }

    @Test
    void testKeyPathWithMultipleLevels() throws CredentialStoreException {
        // Key path with multiple levels: #secret?a/b/c/d/e
        VaultAlias alias = VaultAlias.parse("#secret?a/b/c/d/e");

        assertEquals("a/b/c/d/e", alias.getKeyPath());
    }

    @Test
    void testAllComponentsWithSpecialChars() throws CredentialStoreException {
        // All components with special characters (URL-encoded)
        VaultAlias alias = VaultAlias.parse(
            "engine=KVv2@mount%20path#secret%23name?key%2Fname");

        assertEquals("KVv2", alias.getEngineType());
        assertEquals("mount path", alias.getMountPath());
        assertEquals("secret#name", alias.getSecretPath());
        assertEquals("key/name", alias.getKeyPath());
    }

    @Test
    void testSingleCharacterComponents() throws CredentialStoreException {
        // Single character components: #a?b
        VaultAlias alias = VaultAlias.parse("#a?b");

        assertEquals("a", alias.getSecretPath());
        assertEquals("b", alias.getKeyPath());
    }

    @Test
    void testVeryLongPaths() throws CredentialStoreException {
        // Very long paths
        String longSecret = "a".repeat(100);
        String longKey = "b".repeat(100);
        VaultAlias alias = VaultAlias.parse("#" + longSecret + "?" + longKey);

        assertEquals(longSecret, alias.getSecretPath());
        assertEquals(longKey, alias.getKeyPath());
    }

    @Test
    void testNumericComponents() throws CredentialStoreException {
        // Numeric components: #123/456?789
        VaultAlias alias = VaultAlias.parse("#123/456?789");

        assertEquals("123/456", alias.getSecretPath());
        assertEquals("789", alias.getKeyPath());
    }

    @Test
    void testUnderscoresAndHyphens() throws CredentialStoreException {
        // Underscores and hyphens: #my_app-v2?db_host-primary
        VaultAlias alias = VaultAlias.parse("#my_app-v2?db_host-primary");

        assertEquals("my_app-v2", alias.getSecretPath());
        assertEquals("db_host-primary", alias.getKeyPath());
    }
}
