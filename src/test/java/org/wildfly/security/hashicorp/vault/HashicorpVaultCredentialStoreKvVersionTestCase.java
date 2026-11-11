/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.hashicorp.vault.KvVersionTestHelper.KvVersion;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Parameterized test suite for {@link HashicorpVaultCredentialStore} covering both KV v1 and KV v2 engines.
 *
 * <p>This test class uses JUnit 5's {@code @ParameterizedTest} to run the same test logic
 * against different Vault configurations:
 * <ul>
 *   <li>KV v1 only</li>
 *   <li>KV v2 only (default)</li>
 *   <li>Mixed environment (both v1 and v2 at different mounts)</li>
 * </ul>
 *
 * <p><strong>Test Coverage:</strong>
 * <ul>
 *   <li>Credential store operations (store, retrieve, remove)</li>
 *   <li>Alias listing (recursive and non-recursive)</li>
 *   <li>Multi-key credential handling</li>
 *   <li>Path-based operations</li>
 * </ul>
 */
public class HashicorpVaultCredentialStoreKvVersionTestCase {

    private VaultContainer<?> vaultContainer;

    @AfterEach
    public void cleanup() {
        if (vaultContainer != null) {
            vaultContainer.stop();
        }
    }

    /**
     * Provides test configurations for parameterized tests.
     */
    static Stream<Arguments> kvVersionConfigurations() {
        return Stream.of(
            // KV v1 only
            Arguments.of(new VaultContainerKvV1<>(VaultContainerVersion.IMAGE), "secret", KvVersion.V1),

            // KV v2 only (using standard VaultContainer which defaults to v2)
            Arguments.of(new VaultContainer<>(VaultContainerVersion.IMAGE)
                .withVaultToken("myroot")
                .withInitCommand(
                    "secrets enable transit",
                    "write -f transit/keys/my-key",
                    "kv put secret/testing1 top_secret=password123",
                    "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                ), "secret", KvVersion.V2),

            // Mixed: KV v1 at secret-v1/
            Arguments.of(new VaultContainerKvMixed<>(VaultContainerVersion.IMAGE), "secret-v1", KvVersion.V1),

            // Mixed: KV v2 at secret/
            Arguments.of(new VaultContainerKvMixed<>(VaultContainerVersion.IMAGE), "secret", KvVersion.V2)
        );
    }

    private HashicorpVaultCredentialStore createCredentialStore(VaultContainer<?> container, KvVersion version, String mountPath) throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();

        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", container.getHttpHostAddress());
        attributes.put("namespace", "admin");
        // Set default engine type based on the KV version being tested
        String engineType = version == KvVersion.V1 ? "KVv1" : "KVv2";
        attributes.put("default-engine-type", engineType);
        attributes.put("default-mount-path", mountPath);
        store.initialize(attributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))),
            new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        return store;
    }

    private PasswordCredential createCredentialFromPassword(String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR,
            WildFlyElytronPasswordProvider.getInstance());
        return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())));
    }

    private CredentialStore.CredentialSourceProtectionParameter createProtectionParameter(String token)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new CredentialStore.CredentialSourceProtectionParameter(
            IdentityCredentials.NONE.withCredential(createCredentialFromPassword(token)));
    }

    // =====================================================================
    // Basic Credential Store Operations
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Retrieve credential from {1}")
    @MethodSource("kvVersionConfigurations")
    public void testCredentialStoreRetrieve(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);
        PasswordCredential credential = store.retrieve(
            "#testing1?top_secret",
            PasswordCredential.class,
            ClearPassword.ALGORITHM_CLEAR,
            null,
            null);

        assertNotNull(credential, String.format("Should retrieve credential from %s", version));
        assertEquals("password123", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()),
            String.format("Should retrieve correct password from %s", version));
    }

    @ParameterizedTest(name = "[{2}] Store credential to {1}")
    @MethodSource("kvVersionConfigurations")
    public void testCredentialStorePut(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);

        // Store a new credential
        store.store("#testing1?test_secret", createCredentialFromPassword("testPassword"), null);

        // Retrieve and verify
        PasswordCredential credential = store.retrieve(
            "#testing1?test_secret",
            PasswordCredential.class,
            ClearPassword.ALGORITHM_CLEAR,
            null,
            createProtectionParameter("myroot"));

        assertNotNull(credential, String.format("Should store credential in %s", version));
        assertEquals("testPassword", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()),
            String.format("Should retrieve stored password from %s", version));
    }

    @ParameterizedTest(name = "[{2}] Store multiple credentials maintains existing keys at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testPutMaintainsExistingKeys(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);

        // Store two credentials at the same path
        store.store("#myapp?mp", createCredentialFromPassword("password1"), null);
        store.store("#myapp?mp2", createCredentialFromPassword("password2"), null);

        // Verify both exist
        PasswordCredential credential1 = store.retrieve(
            "#myapp?mp",
            PasswordCredential.class,
            ClearPassword.ALGORITHM_CLEAR,
            null,
            createProtectionParameter("myroot"));
        assertNotNull(credential1, String.format("First credential should exist in %s", version));

        PasswordCredential credential2 = store.retrieve(
            "#myapp?mp2",
            PasswordCredential.class,
            ClearPassword.ALGORITHM_CLEAR,
            null,
            createProtectionParameter("myroot"));
        assertNotNull(credential2, String.format("Second credential should exist in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Remove credential keeps other keys at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testRemoveKeepsOtherKeys(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);

        // Store two credentials
        store.store("#myapp?mp", createCredentialFromPassword("password1"), null);
        store.store("#myapp?mp2", createCredentialFromPassword("password2"), null);

        // Remove one
        store.remove("#myapp?mp2", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);

        // Verify first still exists
        PasswordCredential remaining = store.retrieve(
            "#myapp?mp",
            PasswordCredential.class,
            ClearPassword.ALGORITHM_CLEAR,
            null,
            createProtectionParameter("myroot"));
        assertNotNull(remaining, String.format("Remaining credential should exist in %s", version));
        assertEquals("password1", String.valueOf(remaining.getPassword(ClearPassword.class).getPassword()));

        // Verify second is gone
        PasswordCredential removed = store.retrieve(
            "#myapp?mp2",
            PasswordCredential.class,
            ClearPassword.ALGORITHM_CLEAR,
            null,
            createProtectionParameter("myroot"));
        assertNull(removed, String.format("Removed credential should not exist in %s", version));
    }

    // =====================================================================
    // Alias Listing Operations
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Get aliases with path at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetAliasesWithPath(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);

        Set<String> aliases = store.getAliases("#testing1");
        assertNotNull(aliases, String.format("Should return aliases in %s", version));
        assertFalse(aliases.isEmpty(), String.format("Should have aliases in %s", version));
        assertTrue(aliases.contains("#testing1?top_secret"),
            String.format("Should contain expected alias in %s", version));

        // Verify it doesn't contain aliases from other paths
        assertFalse(aliases.contains("#testing2?dbuser"),
            String.format("Should not contain aliases from other paths in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Get aliases for multiple paths at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetAliasesMultiplePaths(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);

        // Get aliases from testing1
        Set<String> aliases1 = store.getAliases("#testing1");
        assertTrue(aliases1.contains("#testing1?top_secret"));
        assertFalse(aliases1.contains("#testing2?dbuser"));

        // Get aliases from testing2
        Set<String> aliases2 = store.getAliases("#testing2");
        assertTrue(aliases2.contains("#testing2?dbuser"));
        assertTrue(aliases2.contains("#testing2?jmsuser"));
        assertFalse(aliases2.contains("#testing1?top_secret"));
    }

    @ParameterizedTest(name = "[{2}] Get aliases non-recursive at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetAliasesNonRecursive(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);

        Set<String> aliases1 = store.getAliases("#testing1");
        Set<String> aliases2 = store.getAliases("#testing1", false, 0);

        assertEquals(aliases1, aliases2,
            String.format("Non-recursive should match default behavior in %s", version));
        assertTrue(aliases2.contains("#testing1?top_secret"));
    }

    @ParameterizedTest(name = "[{2}] Get aliases recursive depth 0 at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetAliasesRecursiveDepth0(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);

        // Create nested structure
        store.store("#app1?key1", createCredentialFromPassword("value1"), null);
        store.store("#app1?key2", createCredentialFromPassword("value2"), null);
        store.store("#app1/subapp?key3", createCredentialFromPassword("value3"), null);

        Set<String> aliases = store.getAliases("#app1", true, 0);

        assertTrue(aliases.contains("#app1?key1"),
            String.format("Should contain top-level key1 in %s", version));
        assertTrue(aliases.contains("#app1?key2"),
            String.format("Should contain top-level key2 in %s", version));
        assertFalse(aliases.contains("#app1/subapp?key3"),
            String.format("Should not include nested keys at depth 0 in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Get aliases recursive depth 1 at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetAliasesRecursiveDepth1(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);

        // Create nested structure
        store.store("#app1?key1", createCredentialFromPassword("value1"), null);
        store.store("#app1/subapp1?key2", createCredentialFromPassword("value2"), null);
        store.store("#app1/subapp1/deep?key3", createCredentialFromPassword("value3"), null);

        Set<String> aliases = store.getAliases("#app1", true, 1);

        assertTrue(aliases.contains("#app1?key1"),
            String.format("Should contain top-level key in %s", version));
        assertTrue(aliases.contains("#app1/subapp1?key2"),
            String.format("Should contain depth-1 key in %s", version));
        assertFalse(aliases.contains("#app1/subapp1/deep?key3"),
            String.format("Should not include depth-2 keys in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Get aliases recursive multiple subpaths at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetAliasesRecursiveMultipleSubpaths(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);

        // Create multiple subpaths at same level
        store.store("#app1?key1", createCredentialFromPassword("value1"), null);
        store.store("#app1/subapp1?key2", createCredentialFromPassword("value2"), null);
        store.store("#app1/subapp2?key3", createCredentialFromPassword("value3"), null);
        store.store("#app1/subapp3?key4", createCredentialFromPassword("value4"), null);

        Set<String> aliases = store.getAliases("#app1", true, 1);

        assertEquals(4, aliases.size(),
            String.format("Should find all 4 aliases in %s", version));
        assertTrue(aliases.contains("#app1?key1"));
        assertTrue(aliases.contains("#app1/subapp1?key2"));
        assertTrue(aliases.contains("#app1/subapp2?key3"));
        assertTrue(aliases.contains("#app1/subapp3?key4"));
    }

    /**
     * Test that no-arg getAliases() lists aliases from the configured default mount,
     * including nested paths, and that returned aliases can be used to retrieve credentials.
     */
    @ParameterizedTest(name = "[{2}] No-arg getAliases at configured default mount {1}")
    @MethodSource("kvVersionConfigurations")
    public void testNoArgGetAliasesWithNestedSecrets(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        HashicorpVaultCredentialStore store = createCredentialStore(vaultContainer, version, mountPath);

        // Store a nested secret at depth 2 (root -> app1 -> sub1 -> db)
        store.store("#app1/sub1/db?password", createCredentialFromPassword("nestedpass"), null);

        Set<String> aliases = store.getAliases();
        assertNotNull(aliases, String.format("Aliases should not be null for %s", version));

        // Predefined initial secrets at default mount root level
        assertTrue(aliases.contains("#testing1?top_secret"),
            String.format("Should contain top-level alias in %s at mount %s", version, mountPath));
        assertTrue(aliases.contains("#testing2?dbuser"),
            String.format("Should contain top-level alias in %s at mount %s", version, mountPath));

        // Nested secret
        assertTrue(aliases.contains("#app1/sub1/db?password"),
            String.format("Should contain nested alias across recursive levels in %s at mount %s", version, mountPath));

        // Verify retrieval using the returned alias
        PasswordCredential credential = store.retrieve(
            "#app1/sub1/db?password",
            PasswordCredential.class,
            ClearPassword.ALGORITHM_CLEAR,
            null,
            null);
        assertNotNull(credential, String.format("Should retrieve nested credential from %s", version));
        assertEquals("nestedpass", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()),
            String.format("Should retrieve correct password for nested alias in %s", version));
    }
}
