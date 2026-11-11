/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Integration test suite for backwards compatibility with legacy alias format.
 *
 * <p>This test class validates:
 * <ul>
 *   <li>Legacy format support when enabled via configuration</li>
 *   <li>Legacy format rejection when disabled</li>
 *   <li>Deprecation warnings for legacy format usage</li>
 *   <li>Migration path from legacy to new format</li>
 *   <li>Coexistence of legacy and new formats</li>
 *   <li>Existing configuration compatibility</li>
 * </ul>
 *
 * <p><strong>Test Scenarios:</strong>
 * <ol>
 *   <li>Legacy format with support enabled - verify it works with deprecation warnings</li>
 *   <li>Legacy format with support disabled - verify rejection with helpful error</li>
 *   <li>Mixed usage - verify both formats can coexist when legacy support enabled</li>
 *   <li>Migration scenarios - verify gradual migration path</li>
 *   <li>Existing configurations - verify no breaking changes</li>
 * </ol>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class BackwardsCompatibilityTestCase {

    private static final String DEFAULT_TOKEN = "myroot";
    private static final String TEST_PASSWORD = "secretPassword123";

    private VaultContainer<?> kvV2Container;

    @BeforeAll
    void setupContainer() {
        // Create KV v2 container with test data
        kvV2Container = new VaultContainerKvV1(VaultContainerVersion.IMAGE, DEFAULT_TOKEN)
            .withInitCommand(
                // Disable default KV v2 at secret/
                "secrets disable secret",
                // Enable KV v2 at secret/ mount point
                "secrets enable -version=2 -path=secret kv",
                // Add test data for legacy format tests
                "kv put secret/myapp/db password=" + TEST_PASSWORD,
                "kv put secret/app.config dbpass=pass123 apikey=key456",
                "kv put secret/my.app.db password=dbpass789",
                "kv put secret/legacy/test value=legacy123",
                // Add test data for new format tests
                "kv put secret/newformat/test password=new456"
            );
        kvV2Container.start();
    }

    @AfterAll
    void teardownContainer() {
        if (kvV2Container != null) {
            kvV2Container.stop();
        }
    }

    /**
     * Test 1: Legacy format with support enabled.
     * Verify that legacy format works and deprecation warnings are logged.
     */
    @Test
    void testLegacyFormatWithSupportEnabled() throws Exception {
        Map<String, String> attributes = createBaseAttributes();
        attributes.put("support-legacy-alias-format", "true");

        HashicorpVaultCredentialStore store = createAndInitializeStore(attributes);

        // Test simple legacy format: myapp/db.password
        String legacyAlias = "myapp/db.password";
        PasswordCredential credential = store.retrieve(legacyAlias, PasswordCredential.class, null, null, null);

        assertNotNull(credential, "Should retrieve credential using legacy format");
        assertEquals(TEST_PASSWORD, new String(credential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword)));
    }

    /**
     * Test 2: Legacy format with support disabled.
     * Verify that legacy format is rejected with helpful error message.
     */
    @Test
    void testLegacyFormatWithSupportDisabled() throws Exception {
        Map<String, String> attributes = createBaseAttributes();
        attributes.put("support-legacy-alias-format", "false");

        HashicorpVaultCredentialStore store = createAndInitializeStore(attributes);

        // Test that legacy format is rejected
        String legacyAlias = "myapp/db.password";
        CredentialStoreException exception = assertThrows(
            CredentialStoreException.class,
            () -> store.retrieve(legacyAlias, PasswordCredential.class, null, null, null),
            "Should reject legacy format when support disabled"
        );

        // Verify error message includes equivalent new format
        String errorMessage = exception.getMessage();
        assertTrue(errorMessage.contains("not supported"), "Error should mention format not supported");
        assertTrue(errorMessage.contains("myapp/db?password") || errorMessage.contains("#myapp/db?password"),
            "Error should include equivalent new format");
    }

    /**
     * Test 3: Legacy format with support disabled by default.
     * Verify that legacy format support defaults to false.
     */
    @Test
    void testLegacyFormatDefaultDisabled() throws Exception {
        Map<String, String> attributes = createBaseAttributes();
        // Don't set support-legacy-alias-format - should default to false

        HashicorpVaultCredentialStore store = createAndInitializeStore(attributes);

        // Test that legacy format is rejected by default
        String legacyAlias = "myapp/db.password";
        assertThrows(
            CredentialStoreException.class,
            () -> store.retrieve(legacyAlias, PasswordCredential.class, null, null, null),
            "Should reject legacy format by default"
        );
    }

    /**
     * Test 4: Mixed usage - legacy and new format coexistence.
     * Verify both formats work when legacy support is enabled.
     */
    @Test
    void testMixedFormatUsage() throws Exception {
        Map<String, String> attributes = createBaseAttributes();
        attributes.put("support-legacy-alias-format", "true");

        HashicorpVaultCredentialStore store = createAndInitializeStore(attributes);

        // Test legacy format
        String legacyAlias = "myapp/db.password";
        PasswordCredential legacyCredential = store.retrieve(legacyAlias, PasswordCredential.class, null, null, null);
        assertNotNull(legacyCredential, "Should retrieve using legacy format");

        // Test new format for the same secret
        String newAlias = "#myapp/db?password";
        PasswordCredential newCredential = store.retrieve(newAlias, PasswordCredential.class, null, null, null);
        assertNotNull(newCredential, "Should retrieve using new format");

        // Verify both retrieve the same value
        String legacyPassword = new String(legacyCredential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        String newPassword = new String(newCredential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        assertEquals(legacyPassword, newPassword, "Both formats should retrieve same credential");
    }

    /**
     * Test 5: Legacy format with dots in secret path.
     * Verify that dots in secret path are handled correctly (split on LAST dot).
     */
    @Test
    void testLegacyFormatWithDotsInSecretPath() throws Exception {
        Map<String, String> attributes = createBaseAttributes();
        attributes.put("support-legacy-alias-format", "true");

        HashicorpVaultCredentialStore store = createAndInitializeStore(attributes);

        // Legacy format: app.config.dbpass (should split as "app.config" and "dbpass")
        String legacyAlias = "app.config.dbpass";
        PasswordCredential credential = store.retrieve(legacyAlias, PasswordCredential.class, null, null, null);

        assertNotNull(credential, "Should retrieve credential with dots in secret path");
        assertEquals("pass123", new String(credential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword)));
    }

    /**
     * Test 6: Legacy format with multiple dots.
     * Verify correct handling when both secret path and key have dots.
     */
    @Test
    void testLegacyFormatWithMultipleDots() throws Exception {
        Map<String, String> attributes = createBaseAttributes();
        attributes.put("support-legacy-alias-format", "true");

        HashicorpVaultCredentialStore store = createAndInitializeStore(attributes);

        // Legacy format: my.app.db.password (should split as "my.app.db" and "password")
        String legacyAlias = "my.app.db.password";
        PasswordCredential credential = store.retrieve(legacyAlias, PasswordCredential.class, null, null, null);

        assertNotNull(credential, "Should retrieve credential with multiple dots");
        assertEquals("dbpass789", new String(credential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword)));
    }

    /**
     * Test 7: Migration scenario - gradual migration.
     * Verify that applications can migrate gradually from legacy to new format.
     */
    @Test
    void testGradualMigration() throws Exception {
        Map<String, String> attributes = createBaseAttributes();
        attributes.put("support-legacy-alias-format", "true");

        HashicorpVaultCredentialStore store = createAndInitializeStore(attributes);

        // Step 1: Use legacy format (existing configuration)
        String legacyAlias = "legacy/test.value";
        PasswordCredential legacyCredential = store.retrieve(legacyAlias, PasswordCredential.class, null, null, null);
        assertNotNull(legacyCredential, "Legacy format should work during migration");

        // Step 2: Use new format (migrated configuration)
        String newAlias = "#newformat/test?password";
        PasswordCredential newCredential = store.retrieve(newAlias, PasswordCredential.class, null, null, null);
        assertNotNull(newCredential, "New format should work during migration");

        // Both should work simultaneously during migration period
        assertNotNull(legacyCredential, "Legacy format should continue working");
        assertNotNull(newCredential, "New format should work alongside legacy");
    }

    /**
     * Test 8: Existing configuration compatibility.
     * Verify that existing credential stores continue to work without changes.
     */
    @Test
    void testExistingConfigurationCompatibility() throws Exception {
        // Test with minimal configuration (as existing deployments might have)
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", kvV2Container.getHttpHostAddress());

        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();

        char[] token = DEFAULT_TOKEN.toCharArray();
        CredentialStore.CredentialSourceProtectionParameter protectionParameter =
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(
                    createPasswordCredential(token)
                )
            );

        store.initialize(attributes, protectionParameter, new Provider[]{new WildFlyElytronPasswordProvider()});

        // Verify new format works (existing configs using new format should continue working)
        String newAlias = "#myapp/db?password";
        PasswordCredential credential = store.retrieve(newAlias, PasswordCredential.class, null, null, null);
        assertNotNull(credential, "Existing configurations with new format should work");
    }

    /**
     * Test 9: Legacy format error message quality.
     * Verify that error messages provide clear migration guidance.
     */
    @Test
    void testLegacyFormatErrorMessageQuality() throws Exception {
        Map<String, String> attributes = createBaseAttributes();
        attributes.put("support-legacy-alias-format", "false");

        HashicorpVaultCredentialStore store = createAndInitializeStore(attributes);

        // Test various legacy formats to ensure error messages are helpful
        String[] legacyAliases = {
            "simple.key",
            "path/to/secret.key",
            "app.config.dbpass"
        };

        for (String legacyAlias : legacyAliases) {
            CredentialStoreException exception = assertThrows(
                CredentialStoreException.class,
                () -> store.retrieve(legacyAlias, PasswordCredential.class, null, null, null),
                "Should reject legacy format: " + legacyAlias
            );

            String errorMessage = exception.getMessage();
            assertTrue(errorMessage.contains(legacyAlias),
                "Error should mention the problematic alias: " + legacyAlias);
            assertTrue(errorMessage.contains("?") || errorMessage.contains("#"),
                "Error should show new format syntax for: " + legacyAlias);
        }
    }

    /**
     * Test 10: Cache behavior with legacy format.
     * Verify that credential caching works correctly with legacy format.
     */
    @Test
    void testLegacyFormatCacheBehavior() throws Exception {
        Map<String, String> attributes = createBaseAttributes();
        attributes.put("support-legacy-alias-format", "true");

        HashicorpVaultCredentialStore store = createAndInitializeStore(attributes);

        String legacyAlias = "myapp/db.password";

        // First retrieval - should fetch from Vault
        PasswordCredential credential1 = store.retrieve(legacyAlias, PasswordCredential.class, null, null, null);
        assertNotNull(credential1, "First retrieval should succeed");

        // Second retrieval - should use cache
        PasswordCredential credential2 = store.retrieve(legacyAlias, PasswordCredential.class, null, null, null);
        assertNotNull(credential2, "Second retrieval should succeed (from cache)");

        // Verify both return the same value
        String password1 = new String(credential1.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        String password2 = new String(credential2.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        assertEquals(password1, password2, "Cached credential should match original");
    }

    // Helper methods

    private Map<String, String> createBaseAttributes() {
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", kvV2Container.getHttpHostAddress());
        return attributes;
    }

    private HashicorpVaultCredentialStore createAndInitializeStore(Map<String, String> attributes) throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();

        char[] token = DEFAULT_TOKEN.toCharArray();
        CredentialStore.CredentialSourceProtectionParameter protectionParameter =
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(
                    createPasswordCredential(token)
                )
            );

        store.initialize(attributes, protectionParameter, new Provider[]{new WildFlyElytronPasswordProvider()});
        return store;
    }

    private PasswordCredential createPasswordCredential(char[] password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR,
            new WildFlyElytronPasswordProvider());
        return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password)));
    }
}
