/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Verifies that an alias built by {@link VaultPath#toAlias(String, String)}, which is how the credential store
 * reports aliases from {@code getAliases()}, parses back to exactly the secret path and key it was built from.
 *
 * <p>Needs no running Vault.
 */
public class VaultAliasRoundTripTestCase {

    /** Names that contain characters the alias parser decodes or treats as delimiters. */
    private static final String[] AWKWARD_NAMES = {
        "plain", "a+b", "a b", "a%20b", "a%2Bb", "a%2520b", "100%", "50%off", "a?b", "a#b", "a@b", "a=b",
        "a&b", "a;b", "caf\u00e9", "\u65e5\u672c\u8a9e", "a\"b", "a'b", "a\\b", "a.b", "a:b", "~tilde", " leading", "trailing "
    };

    @ParameterizedTest
    @ValueSource(strings = {
        "plain", "a+b", "a b", "a%20b", "a%2Bb", "a%2520b", "100%", "50%off", "a/b", "a?b", "a#b", "a@b", "a=b",
        "a&b", "a;b", "caf\u00e9", "\u65e5\u672c\u8a9e", "a\"b", "a'b", "a\\b", "a.b", "a:b", "~tilde", " leading", "trailing "
    })
    void testKeyRoundTrips(String key) throws CredentialStoreException {
        VaultAlias alias = VaultAlias.parse(VaultPath.toAlias("app", key));

        assertEquals("app", alias.getSecretPath());
        assertEquals(List.of(key), alias.getKeyPathSegments(), "key must come back as one segment, unchanged");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "plain", "a+b", "a b", "a%20b", "a%2Bb", "100%", "50%off", "a?b", "a#b", "a@b", "caf\u00e9", "\u65e5\u672c\u8a9e", "a.b"
    })
    void testSecretPathSegmentRoundTrips(String segment) throws CredentialStoreException {
        String secretPath = "top/" + segment + "/leaf";

        VaultAlias alias = VaultAlias.parse(VaultPath.toAlias(secretPath, "k"));

        assertEquals(secretPath, alias.getSecretPath());
        assertEquals(List.of("k"), alias.getKeyPathSegments());
    }

    @Test
    void testEveryAwkwardNameInEveryPosition() throws CredentialStoreException {
        for (String path : AWKWARD_NAMES) {
            for (String key : AWKWARD_NAMES) {
                VaultAlias alias = VaultAlias.parse(VaultPath.toAlias(path, key));

                assertEquals(path, alias.getSecretPath(), "secret path for alias " + VaultPath.toAlias(path, key));
                assertEquals(List.of(key), alias.getKeyPathSegments(), "key for alias " + VaultPath.toAlias(path, key));
            }
        }
    }

    @Test
    void testSlashInKeyIsEncodedSoItIsNotANestedPath() {
        assertEquals("#app?a%2Fb", VaultPath.toAlias("app", "a/b"));
    }

    @Test
    void testSlashInSecretPathStaysASeparator() {
        assertEquals("#one/two?k", VaultPath.toAlias("one/two", "k"));
    }

    @Test
    void testSpaceIsPercent20NotPlus() {
        assertEquals("#my%20app?a%20b", VaultPath.toAlias("my app", "a b"));
        assertFalse(VaultPath.toAlias("my app", "a b").contains("+"));
    }

    @Test
    void testLiteralPlusIsEncodedSoItIsNotReadAsASpace() {
        assertEquals("#app?a%2Bb", VaultPath.toAlias("app", "a+b"));
    }

    @Test
    void testPercentIsEncodedSoItIsNotReadAsAnEscape() {
        assertEquals("#app?a%2520b", VaultPath.toAlias("app", "a%20b"));
        assertEquals("#app?100%25", VaultPath.toAlias("app", "100%"));
    }

    @Test
    void testDelimitersAreEncoded() {
        assertEquals("#app?a%3Fb", VaultPath.toAlias("app", "a?b"));
        assertEquals("#app?a%23b", VaultPath.toAlias("app", "a#b"));
        assertEquals("#app?a%40b", VaultPath.toAlias("app", "a@b"));
    }

    @Test
    void testPlainNamesAreUnchanged() {
        assertEquals("#testing1?top_secret", VaultPath.toAlias("testing1", "top_secret"));
        assertEquals("#app1/subapp1?key3", VaultPath.toAlias("app1/subapp1", "key3"));
    }

    @Test
    void testEncodePathKeepsEmptyAndTrailingSegments() {
        assertEquals("", VaultPath.encodePath(""));
        assertEquals("a/b/", VaultPath.encodePath("a/b/"));
    }

    /** The three spellings documented in docs/alias-format.md, side by side. */
    @Test
    void testSlashSpellingsAreThreeDifferentKeyPaths() throws CredentialStoreException {
        assertEquals(List.of("database", "host"), VaultAlias.parse("#app?database/host").getKeyPathSegments(),
                "unencoded slash is nested traversal");
        assertEquals(List.of("database/host"), VaultAlias.parse("#app?database%2Fhost").getKeyPathSegments(),
                "%2F is a literal slash in the key name");
        assertEquals(List.of("database%2Fhost"), VaultAlias.parse("#app?database%252Fhost").getKeyPathSegments(),
                "%252F is the literal text %2F in the key name");

        assertEquals("#app?database%2Fhost", VaultPath.toAlias("app", "database/host"));
        assertEquals("#app?database%252Fhost", VaultPath.toAlias("app", "database%2Fhost"));
    }
}
