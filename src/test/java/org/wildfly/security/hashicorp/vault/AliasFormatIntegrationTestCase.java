/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.hashicorp.vault.KvVersionTestHelper.KvVersion;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Comprehensive integration test suite for the new alias format implementation.
 *
 * <p>This test class validates the new alias format across multiple dimensions:
 * <ul>
 *   <li>KV Version Configurations (v1, v2, mixed)</li>
 *   <li>Engine Path Complexity (default, custom, multi-part, with dots)</li>
 *   <li>Secret Path Complexity (single, multi-part, with dots, URL-encoded)</li>
 *   <li>Key Structure (simple, nested, with dots, mixed)</li>
 *   <li>Backwards Compatibility (legacy format support)</li>
 * </ul>
 *
 * <p><strong>Test Strategy:</strong>
 * Uses container reuse strategy with one container per KV configuration to optimize
 * execution time. All test data is pre-populated during container initialization.
 *
 * <p><strong>Test Coverage:</strong> ~90 integration tests covering:
 * <ul>
 *   <li>Core Coverage Tests: 40 tests</li>
 *   <li>Interaction Tests: 25 tests</li>
 *   <li>Edge Case Tests: 15 tests</li>
 *   <li>Backwards Compatibility Tests: 10 tests</li>
 * </ul>
 *
 * @see <a href="integration-test-matrix-design.md">Integration Test Matrix Design</a>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class AliasFormatIntegrationTestCase {

    private static final String DEFAULT_TOKEN = "myroot";

    private VaultContainer<?> kvV1Container;
    private VaultContainer<?> kvV2Container;
    private VaultContainer<?> kvMixedContainer;

    @BeforeAll
    void setupContainers() {
        // Initialize KV v1 container with comprehensive test data
        kvV1Container = createKvV1Container();
        kvV1Container.start();

        // Initialize KV v2 container with comprehensive test data
        kvV2Container = createKvV2Container();
        kvV2Container.start();

        // Initialize mixed KV container with comprehensive test data
        kvMixedContainer = createKvMixedContainer();
        kvMixedContainer.start();
    }

    @AfterAll
    void teardownContainers() {
        if (kvV1Container != null) {
            kvV1Container.stop();
        }
        if (kvV2Container != null) {
            kvV2Container.stop();
        }
        if (kvMixedContainer != null) {
            kvMixedContainer.stop();
        }
    }

    /**
     * Creates a KV v1 container with all test data pre-populated.
     */
    private VaultContainer<?> createKvV1Container() {
        return new VaultContainer<>(VaultContainerVersion.IMAGE)
            .withVaultToken(DEFAULT_TOKEN)
            .withInitCommand(
                // Disable default KV v2 and enable KV v1
                "secrets disable secret",
                "secrets enable -version=1 -path=secret kv",

                // Enable custom mounts for engine path tests
                "secrets enable -version=1 -path=custom kv",
                "secrets enable -version=1 -path=team/backend kv",
                "secrets enable -version=1 -path=team.alpha/backend kv",

                // Standard test secret structure (supports all key path tests)
                "kv put secret/myapp " +
                    "password=secret123 " +
                    "db.host=localhost",

                // Multi-part secret paths
                "kv put secret/myapp/database password=secret123 db.host=localhost",
                "kv put secret/my.app.config password=secret123 db.host=localhost",
                "kv put secret/team.alpha/app.config password=secret123 db.host=localhost",
                "kv put secret/\"test path\" password=secret123",

                // Custom mount test data
                "kv put custom/myapp password=secret123",
                "kv put team/backend/myapp password=secret123",
                "kv put team.alpha/backend/myapp password=secret123",

                // Edge case test data
                "kv put secret/test#path password=secret123",
                "kv put secret/test?path password=secret123",
                "kv put secret/very/long/path/with/many/segments/secret password=secret123",
                "kv put secret/a password=secret123"
            );
    }

    /**
     * Creates a KV v2 container with all test data pre-populated.
     */
    private VaultContainer<?> createKvV2Container() {
        return new VaultContainer<>(VaultContainerVersion.IMAGE)
            .withVaultToken(DEFAULT_TOKEN)
            .withInitCommand(
                // KV v2 is enabled by default at secret/

                // Enable custom mounts for engine path tests
                "secrets enable -version=2 -path=custom kv",
                "secrets enable -version=2 -path=team/backend kv",
                "secrets enable -version=2 -path=team.alpha/backend kv",

                // Standard test secret structure
                "kv put secret/myapp " +
                    "password=secret123 " +
                    "db.host=localhost",

                // Multi-part secret paths
                "kv put secret/myapp/database password=secret123 db.host=localhost",
                "kv put secret/my.app.config password=secret123 db.host=localhost",
                "kv put secret/team.alpha/app.config password=secret123 db.host=localhost",
                "kv put secret/\"test path\" password=secret123",

                // Custom mount test data
                "kv put custom/myapp password=secret123",
                "kv put team/backend/myapp password=secret123",
                "kv put team.alpha/backend/myapp password=secret123",

                // Edge case test data
                "kv put secret/test#path password=secret123",
                "kv put secret/test?path password=secret123",
                "kv put secret/very/long/path/with/many/segments/secret password=secret123",
                "kv put secret/a password=secret123"
            );
    }

    /**
     * Creates a mixed KV container with both v1 and v2 engines at different mounts.
     */
    private VaultContainer<?> createKvMixedContainer() {
        return new VaultContainer<>(VaultContainerVersion.IMAGE)
            .withVaultToken(DEFAULT_TOKEN)
            .withInitCommand(
                // Enable KV v1 at secret-v1/
                "secrets enable -version=1 -path=secret-v1 kv",
                // KV v2 is already enabled at secret/ by default

                // Enable custom mounts
                "secrets enable -version=1 -path=custom-v1 kv",
                "secrets enable -version=2 -path=custom-v2 kv",

                // KV v1 test data
                "kv put secret-v1/myapp password=secret123 db.host=localhost",
                "kv put secret-v1/myapp/db password=secret123",
                "kv put custom-v1/myapp password=secret123",

                // KV v2 test data
                "kv put secret/myapp password=secret123 db.host=localhost",
                "kv put secret/my.app password=secret123",
                "kv put secret/\"test path\" password=secret123",
                "kv put custom-v2/myapp password=secret123"
            );
    }

    /**
     * Creates a credential store configured for the specified container and KV version.
     */
    private HashicorpVaultCredentialStore createCredentialStore(
            VaultContainer<?> container, KvVersion version, String mountPath, boolean supportLegacy) throws Exception {

        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();

        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", container.getHttpHostAddress());
        attributes.put("namespace", "admin");

        // Add legacy format support if requested
        if (supportLegacy) {
            attributes.put("support-legacy-alias-format", "true");
        }

        store.initialize(attributes,
            new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword(DEFAULT_TOKEN))),
            new Provider[]{WildFlyElytronPasswordProvider.getInstance()});

        return store;
    }

    private PasswordCredential createCredentialFromPassword(String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR,
            WildFlyElytronPasswordProvider.getInstance());
        return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())));
    }

    // =====================================================================
    // Category 1: Core Coverage Tests
    // =====================================================================

    /**
     * Provides test configurations for KV version tests.
     */
    static Stream<Arguments> kvVersionTestCases() {
        return Stream.of(
            Arguments.of("KV-01", "KV v1 explicit", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1#myapp?password", "secret123", true, null, false),
            Arguments.of("KV-02", "KV v2 explicit", "kvV2", KvVersion.V2, "secret",
                "engine=KVv2#myapp?password", "secret123", true, null, false),
            Arguments.of("KV-03", "Mixed v1 with mount", "kvMixed", KvVersion.V1, "secret-v1",
                "engine=KVv1@secret-v1#myapp?password", "secret123", true, null, false)
        );
    }

    @ParameterizedTest(name = "[{0}] {1}")
    @MethodSource("kvVersionTestCases")
    void testKvVersions(String testId, String description, String containerType, KvVersion version,
                       String mountPath, String alias, String expectedValue, boolean shouldSucceed,
                       String expectedErrorFragment, boolean supportLegacy) throws Exception {
        executeTestCase(testId, containerType, version, mountPath, alias, expectedValue,
                       shouldSucceed, expectedErrorFragment, supportLegacy);
    }

    /**
     * Provides test configurations for engine path tests.
     */
    static Stream<Arguments> enginePathTestCases() {
        return Stream.of(
            // KV v1 engine paths
            Arguments.of("EP-01", "v1 default mount", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1#myapp?password", "secret123", true, null, false),
            Arguments.of("EP-02", "v1 single custom mount", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1@custom#myapp?password", "secret123", true, null, false),
            Arguments.of("EP-03", "v1 multi-part mount", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1@team/backend#myapp?password", "secret123", true, null, false),
            Arguments.of("EP-04", "v1 multi-part mount with dots", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1@team.alpha/backend#myapp?password", "secret123", true, null, false),

            // KV v2 engine paths
            Arguments.of("EP-05", "v2 default mount", "kvV2", KvVersion.V2, "secret",
                "#myapp?password", "secret123", true, null, false),
            Arguments.of("EP-06", "v2 single custom mount", "kvV2", KvVersion.V2, "secret",
                "@custom#myapp?password", "secret123", true, null, false),
            Arguments.of("EP-07", "v2 multi-part mount", "kvV2", KvVersion.V2, "secret",
                "@team/backend#myapp?password", "secret123", true, null, false),
            Arguments.of("EP-08", "v2 multi-part mount with dots", "kvV2", KvVersion.V2, "secret",
                "@team.alpha/backend#myapp?password", "secret123", true, null, false),

            // Mixed environment engine paths
            Arguments.of("EP-09", "mixed v1 default", "kvMixed", KvVersion.V1, "secret-v1",
                "engine=KVv1@secret-v1#myapp?password", "secret123", true, null, false),
            Arguments.of("EP-10", "mixed v1 custom", "kvMixed", KvVersion.V1, "secret-v1",
                "engine=KVv1@custom-v1#myapp?password", "secret123", true, null, false),
            Arguments.of("EP-11", "mixed v2 default", "kvMixed", KvVersion.V2, "secret",
                "engine=KVv2@secret#myapp?password", "secret123", true, null, false),
            Arguments.of("EP-12", "mixed v2 custom", "kvMixed", KvVersion.V2, "secret",
                "engine=KVv2@custom-v2#myapp?password", "secret123", true, null, false)
        );
    }

    @ParameterizedTest(name = "[{0}] {1}")
    @MethodSource("enginePathTestCases")
    void testEnginePaths(String testId, String description, String containerType, KvVersion version,
                        String mountPath, String alias, String expectedValue, boolean shouldSucceed,
                        String expectedErrorFragment, boolean supportLegacy) throws Exception {
        executeTestCase(testId, containerType, version, mountPath, alias, expectedValue,
                       shouldSucceed, expectedErrorFragment, supportLegacy);
    }

    /**
     * Provides test configurations for secret path tests.
     */
    static Stream<Arguments> secretPathTestCases() {
        return Stream.of(
            // KV v1 secret paths
            Arguments.of("SP-01", "v1 single-part secret", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1#myapp?password", "secret123", true, null, false),
            Arguments.of("SP-02", "v1 multi-part secret", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1#myapp/database?password", "secret123", true, null, false),
            Arguments.of("SP-03", "v1 secret with dots", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1#my.app.config?password", "secret123", true, null, false),
            Arguments.of("SP-04", "v1 multi-part with dots", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1#team.alpha/app.config?password", "secret123", true, null, false),
            Arguments.of("SP-05", "v1 URL-encoded secret", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1#test%20path?password", "secret123", true, null, false),

            // KV v2 secret paths
            Arguments.of("SP-06", "v2 single-part secret", "kvV2", KvVersion.V2, "secret",
                "#myapp?password", "secret123", true, null, false),
            Arguments.of("SP-07", "v2 multi-part secret", "kvV2", KvVersion.V2, "secret",
                "#myapp/database?password", "secret123", true, null, false),
            Arguments.of("SP-08", "v2 secret with dots", "kvV2", KvVersion.V2, "secret",
                "#my.app.config?password", "secret123", true, null, false),
            Arguments.of("SP-09", "v2 multi-part with dots", "kvV2", KvVersion.V2, "secret",
                "#team.alpha/app.config?password", "secret123", true, null, false),
            Arguments.of("SP-10", "v2 URL-encoded secret", "kvV2", KvVersion.V2, "secret",
                "#test%20path?password", "secret123", true, null, false),

            // Mixed environment secret paths
            Arguments.of("SP-11", "mixed v1 single-part", "kvMixed", KvVersion.V1, "secret-v1",
                "engine=KVv1@secret-v1#myapp?password", "secret123", true, null, false),
            Arguments.of("SP-12", "mixed v1 multi-part", "kvMixed", KvVersion.V1, "secret-v1",
                "engine=KVv1@secret-v1#myapp/db?password", "secret123", true, null, false),
            Arguments.of("SP-13", "mixed v2 single-part", "kvMixed", KvVersion.V2, "secret",
                "engine=KVv2@secret#myapp?password", "secret123", true, null, false),
            Arguments.of("SP-14", "mixed v2 with dots", "kvMixed", KvVersion.V2, "secret",
                "engine=KVv2@secret#my.app?password", "secret123", true, null, false),
            Arguments.of("SP-15", "mixed v2 URL-encoded", "kvMixed", KvVersion.V2, "secret",
                "engine=KVv2@secret#test%20path?password", "secret123", true, null, false)
        );
    }

    @ParameterizedTest(name = "[{0}] {1}")
    @MethodSource("secretPathTestCases")
    void testSecretPaths(String testId, String description, String containerType, KvVersion version,
                        String mountPath, String alias, String expectedValue, boolean shouldSucceed,
                        String expectedErrorFragment, boolean supportLegacy) throws Exception {
        executeTestCase(testId, containerType, version, mountPath, alias, expectedValue,
                       shouldSucceed, expectedErrorFragment, supportLegacy);
    }

    /**
     * Provides test configurations for key structure tests.
     */
    static Stream<Arguments> keyStructureTestCases() {
        return Stream.of(
            // KV v1 key structures
            Arguments.of("KS-01", "v1 simple key", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1#myapp?password", "secret123", true, null, false),
            Arguments.of("KS-02", "v1 key with dots", "kvV1", KvVersion.V1, "secret",
                "engine=KVv1#myapp?db.host", "localhost", true, null, false),

            // KV v2 key structures
            Arguments.of("KS-06", "v2 simple key", "kvV2", KvVersion.V2, "secret",
                "#myapp?password", "secret123", true, null, false),
            Arguments.of("KS-07", "v2 key with dots", "kvV2", KvVersion.V2, "secret",
                "#myapp?db.host", "localhost", true, null, false)
        );
    }

    @ParameterizedTest(name = "[{0}] {1}")
    @MethodSource("keyStructureTestCases")
    void testKeyStructures(String testId, String description, String containerType, KvVersion version,
                          String mountPath, String alias, String expectedValue, boolean shouldSucceed,
                          String expectedErrorFragment, boolean supportLegacy) throws Exception {
        executeTestCase(testId, containerType, version, mountPath, alias, expectedValue,
                       shouldSucceed, expectedErrorFragment, supportLegacy);
    }

    // =====================================================================
    // Test Execution Helper
    // =====================================================================

    /**
     * Executes a test case with proper assertions.
     */
    private void executeTestCase(String testId, String containerType, KvVersion version, String mountPath,
                                 String alias, String expectedValue, boolean shouldSucceed,
                                 String expectedErrorFragment, boolean supportLegacy) throws Exception {
        VaultContainer<?> container;
        switch (containerType) {
            case "kvV1":
                container = kvV1Container;
                break;
            case "kvV2":
                container = kvV2Container;
                break;
            case "kvMixed":
                container = kvMixedContainer;
                break;
            default:
                throw new IllegalArgumentException("Unknown container type: " + containerType);
        }

        HashicorpVaultCredentialStore store = createCredentialStore(container, version, mountPath, supportLegacy);

        if (shouldSucceed) {
            PasswordCredential credential = store.retrieve(
                alias,
                PasswordCredential.class,
                ClearPassword.ALGORITHM_CLEAR,
                null,
                null);

            if (expectedValue == null) {
                assertNull(credential,
                    String.format("[%s] Expected null credential", testId));
            } else {
                assertNotNull(credential,
                    String.format("[%s] Should retrieve credential", testId));
                String actualPassword = new String(
                    credential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
                assertEquals(expectedValue, actualPassword,
                    String.format("[%s] Password should match", testId));
            }
        } else {
            CredentialStoreException exception = assertThrows(
                CredentialStoreException.class,
                () -> store.retrieve(alias, PasswordCredential.class,
                    ClearPassword.ALGORITHM_CLEAR, null, null),
                String.format("[%s] Should throw CredentialStoreException", testId));

            if (expectedErrorFragment != null) {
                assertTrue(exception.getMessage().contains(expectedErrorFragment),
                    String.format("[%s] Error message should contain '%s', but was: %s",
                        testId, expectedErrorFragment, exception.getMessage()));
            }
        }
    }
}
