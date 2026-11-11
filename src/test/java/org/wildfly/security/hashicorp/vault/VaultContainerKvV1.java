/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import org.jboss.logging.Logger;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.hashicorp.vault.logging.JbossLoggingLogConsumer;

/**
 * Represents a {@link VaultContainer} configured with KV Secrets Engine v1.
 *
 * <p>This container is configured to use KV v1 at the default "secret/" mount point.
 * KV v1 uses direct paths without the "/data/" or "/metadata/" segments used in v2.
 *
 * <p><strong>Key Differences from KV v2:</strong>
 * <ul>
 *   <li>API Path: {@code /v1/secret/path/to/secret} (no "/data/" segment)</li>
 *   <li>No versioning support - modifications overwrite the entire secret</li>
 *   <li>No metadata endpoint</li>
 *   <li>Simpler data structure - direct key-value pairs</li>
 * </ul>
 *
 * <p><strong>Usage Example:</strong>
 * <pre>{@code
 * VaultContainerKvV1 container = new VaultContainerKvV1(VaultContainerVersion.IMAGE);
 * container.start();
 * // Use container.getHttpHostAddress() to connect
 * // Use container.getToken() to authenticate
 * }</pre>
 */
public class VaultContainerKvV1<SELF extends VaultContainerKvV1<SELF>> extends VaultContainer<SELF> {

    private static final String DEFAULT_TOKEN = "myroot";
    private static final String KV_V1_MOUNT = "secret";

    /**
     * Creates a Vault container with KV v1 engine enabled at the default "secret/" mount.
     *
     * @param dockerImageName the Docker image name (e.g., {@link VaultContainerVersion#IMAGE})
     */
    public VaultContainerKvV1(String dockerImageName) {
        this(dockerImageName, DEFAULT_TOKEN);
    }

    /**
     * Creates a Vault container with KV v1 engine enabled at the default "secret/" mount.
     *
     * @param dockerImageName the Docker image name (e.g., {@link VaultContainerVersion#IMAGE})
     * @param token the root token to use for authentication
     */
    public VaultContainerKvV1(String dockerImageName, String token) {
        super(dockerImageName);

        this.withVaultToken(token)
            .withLogConsumer(new JbossLoggingLogConsumer(Logger.getLogger("KV_V1_VAULT_CONTAINER")))
            .withInitCommand(
                // Disable the default KV v2 engine at secret/
                "secrets disable secret",
                // Enable KV v1 at secret/ mount point
                "secrets enable -version=1 -path=" + KV_V1_MOUNT + " kv",
                // Add test data using KV v1 paths (no /data/ segment)
                "kv put " + KV_V1_MOUNT + "/testing1 top_secret=password123",
                "kv put " + KV_V1_MOUNT + "/testing2 dbuser=secretpass jmsuser=jmspass",
                "kv put " + KV_V1_MOUNT + "/my-secret my-value=s3cr3t",
                // Enable transit engine for encryption tests
                "secrets enable transit",
                "write -f transit/keys/my-key"
            );
    }

    /**
     * Returns the KV engine mount path.
     *
     * @return the mount path (default: "secret")
     */
    public String getKvMountPath() {
        return KV_V1_MOUNT;
    }

    /**
     * Returns the KV engine version.
     *
     * @return the version number (1 for KV v1)
     */
    public int getKvVersion() {
        return 1;
    }

    /**
     * Returns the root token used for authentication.
     *
     * @return the root token
     */
    public String getToken() {
        return DEFAULT_TOKEN;
    }

    @Override
    public String toString() {
        return String.format("VaultContainerKvV1{image=%s, kvVersion=1, mountPath=%s, token=%s, testData=[testing1, testing2, my-secret]}",
                getDockerImageName(), KV_V1_MOUNT, DEFAULT_TOKEN);
    }
}
