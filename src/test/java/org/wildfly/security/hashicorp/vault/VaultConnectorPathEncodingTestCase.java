/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.wildfly.security.credential.store.CredentialStoreException;

import io.github.jopenlibs.vault.SslConfig;

/**
 * Verifies the URL-encoding applied by {@link VaultConnector#constructVaultPath(VaultPath)} when
 * the decoded mount and secret path are turned back into a Vault API path.
 *
 * <p>Needs no running Vault: the connector is only constructed, never configured.
 */
public class VaultConnectorPathEncodingTestCase {

    private VaultConnector connector;

    @BeforeEach
    void setUp() {
        connector = new VaultConnector("http://dummy", "token", null, new SslConfig(), true);
    }

    private String apiPath(String alias) throws CredentialStoreException {
        return connector.constructVaultPath(VaultAlias.parse(alias));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "#plain?k                 | secret/plain",
        "#my/app?k                | secret/my/app",
        "#my%20app?k              | secret/my%20app",
        "#my%20app/db%20config?k  | secret/my%20app/db%20config",
        "@my%20mount#app?k        | my%20mount/app",
        "@team/backend#app?k      | team/backend/app",
        "#a%23b?k                 | secret/a%23b",
        "#a%3Fb?k                 | secret/a%3Fb",
        "#a%40b?k                 | secret/a%40b",
        "#a%25b?k                 | secret/a%25b",
        "#a%2Bb?k                 | secret/a%2Bb",
        "#caf%C3%A9?k             | secret/caf%C3%A9",
    })
    void testMountAndSecretAreEncodedPerSegment(String alias, String expectedApiPath) throws CredentialStoreException {
        assertEquals(expectedApiPath, apiPath(alias));
    }

    @Test
    void testSpaceEncodedAsPercent20NotPlus() throws CredentialStoreException {
        assertEquals("secret/a%20b", apiPath("#a%20b?k"));
    }

    @Test
    void testEncodedSlashInSecretPathBecomesPathSeparator() throws CredentialStoreException {
        // %2F is decoded when the alias is parsed and the decoded path is split per segment when
        // re-encoded, so it ends up as a normal path separator in the API path.
        assertEquals("secret/my/app", apiPath("#my%2Fapp?k"));
    }

    @Test
    void testRoundTripThroughParseAndEncodeIsStable() throws CredentialStoreException {
        String first = apiPath("#a%20b%23c/d%3Fe?k");
        assertEquals("secret/a%20b%23c/d%3Fe", first);
    }

    @Test
    void testTrailingSlashesNormalised() throws CredentialStoreException {
        VaultPath path = VaultPath.create("KVv2", "secret/", "/app/db");

        assertEquals("secret/app/db", connector.constructVaultPath(path));
    }
}
