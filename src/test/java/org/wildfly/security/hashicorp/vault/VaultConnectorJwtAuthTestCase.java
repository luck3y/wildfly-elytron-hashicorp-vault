/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.hashicorp.vault.auth.JwtAuthConfig;
import org.wildfly.security.hashicorp.vault.auth.JwtGenerator;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

/**
 * Set of tests verifying functionality of VaultConnector when using TLS certificate authentication method
 */
public class VaultConnectorJwtAuthTestCase {

    private VaultContainerHttps<?> vaultTestContainer;

    private static SslConfig permissibleSslAuthConfig;

    private static JwtConfig validJwtConfig;

    private static final String BOUND_ISSUER = "testIssuer";
    private static final String BOUND_AUDIENCES = "boundAudiences";
    private static final String USER_CLAIM = "testUserClaim";

    private static final String ROLE_NAME = "testRole";

    private static KeyPair jwtKeyPair;

    @BeforeAll
    public static void setup() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        jwtKeyPair = keyPairGenerator.generateKeyPair();
    }

    @BeforeEach
    public void beforeEach() throws IOException, VaultException, JoseException {
        vaultTestContainer = new VaultContainerHttps<>(VaultContainerVersion.IMAGE)
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 ttl=30m top_secret=password123",
                        "kv put secret/testing2 ttl=30m dbuser=secretpass jmsuser=jmspass",
                        "kv put secret/my-secret ttl=30m my-value=s3cr3t",
                        "audit enable file file_path=/tmp/vault_audit.log"
                );

        new JwtAuthConfig.Builder(ROLE_NAME)
                .boundAudiences(BOUND_AUDIENCES)
                .policies("admin")
                .userClaim("sub")
                .jwtValidationPubkeys(keyToPem("RS256", jwtKeyPair.getPublic().getEncoded()))
                .build()
                .configure(this.vaultTestContainer);

        permissibleSslAuthConfig = new SslConfig()
                //to enable HTTPS
                .pemFile(vaultTestContainer.getHttpsTrustFile().toFile())
                .verify(true)
                .build();

        validJwtConfig = new JwtConfig(new JwtGenerator.Builder()
                        .issuer(BOUND_ISSUER)
                        .subject(USER_CLAIM)
                        .audience(BOUND_AUDIENCES)
                        .build()
                        .generateJwt(jwtKeyPair.getPrivate()),
                ROLE_NAME, "jwt");

        vaultTestContainer.start();
    }

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    /**
     * Helper method to get a secret value using the new alias-based API.
     */
    private String getSecret(VaultConnector connector, String path, String key) throws CredentialStoreException {
        String secretPath = path.substring(path.indexOf('/') + 1);
        String aliasString = "#" + secretPath + "?" + key;
        VaultAlias alias = VaultAlias.parse(aliasString, "KVv2", "secret");
        Map<String, Object> data = connector.getSecretData(alias);
        if (data == null) {
            return null;
        }
        return VaultKeyPathOperations.resolveKeyPath(data, key);
    }

    /**
     * Helper method to remove a secret value using the new alias-based API.
     */
    private void removeSecret(VaultConnector connector, String path, String key) throws CredentialStoreException {
        String secretPath = path.substring(path.indexOf('/') + 1);
        String aliasString = "#" + secretPath + "?" + key;
        VaultAlias alias = VaultAlias.parse(aliasString, "KVv2", "secret");
        connector.removeSecretData(alias);
    }

    /**
     * Configure vault connector with proper HTTPS config and try to log in using valid JWT
     * Test will succeed wince everything is configured properly
     */
    @Test
    public void testGetSecretFromVaultService() throws Exception {
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), validJwtConfig, null, permissibleSslAuthConfig);
        vaultService.configure();
        assertEquals("password123", getSecret(vaultService, "secret/testing1", "top_secret"));
    }

    /**
     * Configure vault connector with proper HTTPS config and try to log in using invalid JWT
     * Test will fail since the connector will try to use the JWT to authenticate.
     */
    @Test
    public void testGetSecretFromVaultServiceInvalidJwtToken() throws Exception {
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), new JwtConfig("someInvalidToken", ROLE_NAME, "jwt"), null, permissibleSslAuthConfig);
        vaultService.configure();
        assertThrows(CredentialStoreException.class, () -> getSecret(vaultService, "secret/testing1", "top_secret"),
                "Correct SSL HTTPS config was provided but JWT was invalid. This should fail.");
    }

    /**
     * Configure vault connector with HTTPS SSL config and valid JWT token. Try to obtain a secret from the vault and then
     * remove it. Validate the new value of obtained secret is null.
     * Test will succeed when the secret is obtained removed and obtained again.
     */
    @Test
    public void testRemoveSecretFromVaultService() throws Exception {
        final VaultConnector vaultService = new VaultConnector(vaultTestContainer.composeHttpsHostAddress(), validJwtConfig, null, permissibleSslAuthConfig);
        vaultService.configure();

        final String originalSecret = getSecret(vaultService, "secret/testing1", "top_secret");
        assertEquals("password123", originalSecret);

        removeSecret(vaultService, "secret/testing1", "top_secret");

        assertNull(getSecret(vaultService, "secret/testing1", "top_secret"));
    }

    private static String keyToPem(String header, byte[] encoded) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        return "-----BEGIN " + header + "-----\n" + b64 + "\n-----END " + header + "-----\n";
    }

}
