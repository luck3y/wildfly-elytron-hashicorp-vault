/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.wildfly.security.credential.store.CredentialStoreException;

/**
 * Verifies how percent-encoding is decoded for each component of an alias or path
 * (engine type, mount path, secret path and key path), and in particular that the key path
 * is split on unencoded {@code /} <em>before</em> each segment is decoded.
 */
public class VaultPathEncodingTestCase {

    // ========================================================================
    // Key path: unencoded / separates segments, %2F stays inside a segment
    // ========================================================================

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "#s?a/b           | a,b",
        "#s?a%2Fb         | a/b",
        "#s?a%2fb         | a/b",
        "#s?a%2Fb/c       | a/b,c",
        "#s?a/b%2Fc       | a,b/c",
        "#s?a%2Fb/c%2Fd   | a/b,c/d",
        "#s?a%2F%2Fb      | a//b",
        "#s?%2F           | /",
        "#s?a/%2F         | a,/",
        "#s?%2F/a         | /,a",
        "#s?a%2Fb%2Fc     | a/b/c",
    })
    void testKeyPathSegmentsSplitBeforeDecoding(String alias, String expectedSegments) throws CredentialStoreException {
        VaultAlias parsed = VaultAlias.parse(alias);

        assertEquals(List.of(expectedSegments.split(",")), parsed.getKeyPathSegments());
    }

    @Test
    void testKeyPathEncodedSlashIsIndistinguishableInJoinedForm() throws CredentialStoreException {
        // getKeyPath() is the "/"-joined display form; it deliberately loses the distinction
        assertEquals("a/b", VaultAlias.parse("#s?a%2Fb").getKeyPath());
        assertEquals("a/b", VaultAlias.parse("#s?a/b").getKeyPath());
    }

    @ParameterizedTest
    @CsvSource({
        "#s?/a",
        "#s?a/",
        "#s?a//b",
        "#s?/",
        "#s?a/%2F/",
    })
    void testKeyPathEmptyUnencodedSegmentRejected(String alias) {
        assertThrows(CredentialStoreException.class, () -> VaultAlias.parse(alias));
    }

    @Test
    void testAliasesDifferingOnlyInEncodedSlashAreNotEqual() throws CredentialStoreException {
        VaultAlias nested = VaultAlias.parse("#s?database/host");
        VaultAlias literal = VaultAlias.parse("#s?database%2Fhost");

        assertNotEquals(nested, literal);
    }

    @Test
    void testEncodedSlashCaseInsensitiveHexAliasesAreEqual() throws CredentialStoreException {
        VaultAlias upper = VaultAlias.parse("#s?database%2Fhost");
        VaultAlias lower = VaultAlias.parse("#s?database%2fhost");

        assertEquals(upper, lower);
        assertEquals(upper.hashCode(), lower.hashCode());
    }

    @Test
    void testCreateSplitsKeyPathOnEveryUnencodedSlash() throws CredentialStoreException {
        // create() takes already-decoded components: every "/" is a nesting separator
        VaultAlias alias = VaultAlias.create("KVv2", "secret", "myapp", "a/b/c");

        assertEquals(List.of("a", "b", "c"), alias.getKeyPathSegments());
        assertEquals("a/b/c", alias.getKeyPath());
    }

    @Test
    void testCreateEmptyKeyPathSegmentRejected() {
        assertThrows(CredentialStoreException.class, () -> VaultAlias.create("KVv2", "secret", "myapp", "a//b"));
    }

    // ========================================================================
    // Other key path characters
    // ========================================================================

    @ParameterizedTest
    @CsvSource({
        "#s?a%3Fb,    a?b",
        "#s?a%23b,    a#b",
        "#s?a%40b,    a@b",
        "#s?a%20b,    a b",
        "#s?a%25b,    a%b",
        "#s?a%2520b,  a%20b",
        "#s?a%2Bb,    a+b",
        "#s?caf%C3%A9, café",
    })
    void testKeyPathSingleSegmentDecoding(String alias, String expectedKey) throws CredentialStoreException {
        VaultAlias parsed = VaultAlias.parse(alias);

        assertEquals(List.of(expectedKey), parsed.getKeyPathSegments());
    }

    @Test
    void testKeyPathInvalidPercentSequenceKeptAsIs() throws CredentialStoreException {
        assertEquals(List.of("a%ZZ"), VaultAlias.parse("#s?a%ZZ").getKeyPathSegments());
        assertEquals(List.of("a%"), VaultAlias.parse("#s?a%").getKeyPathSegments());
    }

    // ========================================================================
    // Engine type, mount path and secret path
    // ========================================================================

    @Test
    void testEngineTypeIsUrlDecoded() throws CredentialStoreException {
        // KV%76%32 -> KVv2
        VaultAlias alias = VaultAlias.parse("engine=KV%76%32@secret#myapp?key");

        assertEquals("KVv2", alias.getEngineType());
    }

    @Test
    void testEncodedEngineTypeStillValidated() {
        // %58 -> X, so the decoded engine type is "KVvX" which is not a valid engine
        assertThrows(CredentialStoreException.class, () -> VaultAlias.parse("engine=KVv%58@secret#myapp?key"));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "@my%20mount#s?k       | my mount",
        "@my%2Fmount#s?k       | my/mount",
        "@my%2fmount#s?k       | my/mount",
        "@team/backend#s?k     | team/backend",
        "@team%2Fbackend#s?k   | team/backend",
        "@m%40x#s?k            | m@x",
        "@m%23x#s?k            | m#x",
        "@m%3Fx#s?k            | m?x",
        "@m%25x#s?k            | m%x",
        "@m%C3%A9#s?k          | mé",
    })
    void testMountPathDecoding(String alias, String expectedMount) throws CredentialStoreException {
        assertEquals(expectedMount, VaultAlias.parse(alias).getMountPath());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "#my%20app?k           | my app",
        "#my/app?k             | my/app",
        "#my%2Fapp?k           | my/app",
        "#my%2fapp?k           | my/app",
        "#my%23app?k           | my#app",
        "#my%3Fapp?k           | my?app",
        "#my%40app?k           | my@app",
        "#my%25app?k           | my%app",
        "#my%2520app?k         | my%20app",
        "#caf%C3%A9?k          | café",
    })
    void testSecretPathDecoding(String alias, String expectedSecret) throws CredentialStoreException {
        assertEquals(expectedSecret, VaultAlias.parse(alias).getSecretPath());
    }

    @Test
    void testEncodedDelimitersDoNotChangeParsingStructure() throws CredentialStoreException {
        // Encoded @, #, ? and / in every component must not be treated as delimiters
        VaultAlias alias = VaultAlias.parse("engine=KVv1@m%40%23%3F%2Fx#s%40%23%3F%2Fy?k%40%23%3F%2Fz");

        assertEquals("KVv1", alias.getEngineType());
        assertEquals("m@#?/x", alias.getMountPath());
        assertEquals("s@#?/y", alias.getSecretPath());
        assertEquals(List.of("k@#?/z"), alias.getKeyPathSegments());
    }

    @Test
    void testInvalidPercentSequenceInMountAndSecretKeptAsIs() throws CredentialStoreException {
        VaultAlias alias = VaultAlias.parse("@m%ZZ#s%?k");

        assertEquals("m%ZZ", alias.getMountPath());
        assertEquals("s%", alias.getSecretPath());
    }

    // ========================================================================
    // VaultPath (no key path)
    // ========================================================================

    @Test
    void testVaultPathMountAndSecretDecoding() throws CredentialStoreException {
        VaultPath path = VaultPath.parse("@my%20mount#my%2Fapp%20config", "KVv2", "secret", false);

        assertEquals("my mount", path.getMountPath());
        assertEquals("my/app config", path.getSecretPath());
    }
}
