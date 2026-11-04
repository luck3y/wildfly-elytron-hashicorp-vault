/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Map;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.interfaces.ClearPassword;

import io.github.jopenlibs.vault.SslConfig;

/**
 * Verifies that URL-encoding in the key path segment of a vault alias controls
 * how the key is resolved against the secret data map.
 *
 * <p>An unencoded {@code /} in the key path is a nested JSON separator:
 * {@code secret?database/host} resolves {@code data["database"]["host"]}.
 *
 * <p>A percent-encoded {@code %2F} (or {@code %2f}) represents a literal slash
 * in the key name: {@code secret?database%2Fhost} resolves {@code data["database/host"]}.
 *
 * <p>Uses an in-memory {@link VaultConnector} stub so the test does not require
 * a running Vault instance.
 */
public class VaultEncodedSlashRetrievalTestCase {

    /**
     * @param input    alias string — {@code /} means nested traversal, {@code %2F} means literal slash
     * @param expected the credential value that should be resolved from the mock data
     */
    @ParameterizedTest
    @CsvSource({
        "secret?database/host, nested-value",      // unencoded / → nested: data["database"]["host"]
        "secret?database%2Fhost, literal-value",    // %2F → literal key: data["database/host"]
        "secret?database%2fhost, literal-value"     // %2f (lowercase) → same as %2F
    })
    void testResolveLiteralAndNestedKeys(String input, String expected) throws Exception {
        Map<String, Object> data = Map.of(
                "database/host", "literal-value",
                "database", Map.of("host", "nested-value"));
        VaultConnector connector = new VaultConnector("http://dummy", "token", null, new SslConfig(), true) {
            @Override
            public void configure() {
            }

            @Override
            public Map<String, Object> getSecretData(VaultPath path) {
                return data;
            }
        };
        VaultCredentialSource source = new VaultCredentialSource(connector, input);

        PasswordCredential credential = source.getCredential(PasswordCredential.class, null, null);

        assertNotNull(credential);
        assertEquals(expected, new String(credential.getPassword(ClearPassword.class).getPassword()));
    }
}
