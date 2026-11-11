/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import org.jboss.logging.Logger;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.hashicorp.vault.logging.JbossLoggingLogConsumer;

/**
 * Represents a {@link VaultContainer} configured with both KV v1 and KV v2 engines
 * at different mount points.
 *
 * <p>This container enables testing of mixed-version environments where both KV v1
 * and v2 engines coexist. This is a common real-world scenario during migrations
 * or in organizations with different teams using different versions.
 *
 * <p><strong>Mount Points:</strong>
 * <ul>
 *   <li><strong>KV v1:</strong> {@code secret-v1/} - Uses direct paths without versioning</li>
 *   <li><strong>KV v2:</strong> {@code secret/} - Uses /data/ and /metadata/ paths with versioning</li>
 * </ul>
 *
 * <p><strong>Path Examples:</strong>
 * <ul>
 *   <li>KV v1: {@code /v1/secret-v1/path/to/secret}</li>
 *   <li>KV v2: {@code /v1/secret/data/path/to/secret}</li>
 * </ul>
 *
 * <p><strong>Usage Example:</strong>
 * <pre>{@code
 * VaultContainerKvMixed container = new VaultContainerKvMixed(VaultContainerVersion.IMAGE);
 * container.start();
 *
 * // Access KV v1 secrets
 * String v1Mount = container.getKvV1MountPath(); // "secret-v1"
 *
 * // Access KV v2 secrets
 * String v2Mount = container.getKvV2MountPath(); // "secret"
 * }</pre>
 */
public class VaultContainerKvMixed<SELF extends VaultContainerKvMixed<SELF>> extends VaultContainer<SELF> {

    private static final String DEFAULT_TOKEN = "myroot";
    private static final String KV_V1_MOUNT = "secret-v1";
    private static final String KV_V2_MOUNT = "secret";

    /**
     * Creates a Vault container with both KV v1 and v2 engines enabled at different mount points.
     *
     * @param dockerImageName the Docker image name (e.g., {@link VaultContainerVersion#IMAGE})
     */
    public VaultContainerKvMixed(String dockerImageName) {
        this(dockerImageName, DEFAULT_TOKEN);
    }

    /**
     * Creates a Vault container with both KV v1 and v2 engines enabled at different mount points.
     *
     * @param dockerImageName the Docker image name (e.g., {@link VaultContainerVersion#IMAGE})
     * @param token the root token to use for authentication
     */
    public VaultContainerKvMixed(String dockerImageName, String token) {
        super(dockerImageName);

        this.withVaultToken(token)
            .withLogConsumer(new JbossLoggingLogConsumer(Logger.getLogger("KV_MIXED_VAULT_CONTAINER")))
            .withInitCommand(
                // Enable KV v1 at a separate mount point first
                "secrets enable -version=1 -path=" + KV_V1_MOUNT + " kv",

                // Upgrade the default "secret/" mount from KV v1 to KV v2
                "kv enable-versioning " + KV_V2_MOUNT,

                // Add test data to KV v2 mount (kv put handles /data/ path automatically)
                "kv put " + KV_V2_MOUNT + "/testing1 top_secret=password123",
                "kv put " + KV_V2_MOUNT + "/testing2 dbuser=secretpass jmsuser=jmspass",
                "kv put " + KV_V2_MOUNT + "/my-secret my-value=s3cr3t",

                // Add test data to KV v1 mount
                "kv put " + KV_V1_MOUNT + "/testing1 top_secret=password123",
                "kv put " + KV_V1_MOUNT + "/testing2 dbuser=secretpass jmsuser=jmspass",
                "kv put " + KV_V1_MOUNT + "/my-secret my-value=s3cr3t",

                // Enable transit engine for encryption tests
                "secrets enable transit",
                "write -f transit/keys/my-key"
            );
    }

    /**
     * Returns the KV v1 engine mount path.
     *
     * @return the KV v1 mount path (default: "secret-v1")
     */
    public String getKvV1MountPath() {
        return KV_V1_MOUNT;
    }

    /**
     * Returns the KV v2 engine mount path.
     *
     * @return the KV v2 mount path (default: "secret")
     */
    public String getKvV2MountPath() {
        return KV_V2_MOUNT;
    }

    /**
     * Returns the root token used for authentication.
     *
     * @return the root token
     */
    public String getToken() {
        return DEFAULT_TOKEN;
    }

    /**
     * Helper method to determine if a given path uses the v1 mount.
     *
     * @param path the secret path to check
     * @return true if the path starts with the v1 mount point
     */
    public boolean isV1Path(String path) {
        return path != null && path.startsWith(KV_V1_MOUNT + "/");
    }

    /**
     * Helper method to determine if a given path uses the v2 mount.
     *
     * @param path the secret path to check
     * @return true if the path starts with the v2 mount point
     */
    public boolean isV2Path(String path) {
        return path != null && path.startsWith(KV_V2_MOUNT + "/");
    }

    @Override
    public String toString() {
        return String.format("VaultContainerKvMixed{image=%s, kvV1Mount=%s, kvV2Mount=%s, token=%s, testData=[testing1, testing2, my-secret] in both mounts}",
                getDockerImageName(), KV_V1_MOUNT, KV_V2_MOUNT, DEFAULT_TOKEN);
    }
}
