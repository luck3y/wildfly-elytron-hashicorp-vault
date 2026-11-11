/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.vault.VaultContainer;

public class VaultTestUtils {

    private static final String[] SEED_COMMANDS = {
            "kv put secret/testing1 top_secret=password123",
            "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
    };

    private static SharedVaultContainer shared;

    /**
     * Returns a Vault test container with the predefined secrets {@code secret/testing1} and {@code secret/testing2}
     * and nothing else under {@code secret/}.
     *
     * <p>One container is started per JVM and reused, because starting a container takes longer than most of the
     * tests that use it. Every call restores the {@code secret/} mount to that seeded state, so a test sees the same
     * data whether it runs first or last. {@code stop()} on the returned container does nothing; the container is
     * stopped when the JVM exits.
     *
     * <p>Tests that change anything other than the {@code secret/} data, such as policies, tokens or other mounts,
     * must start their own container instead.
     */
    public static synchronized VaultContainer<?> startVaultTestContainer() {
        if (shared == null || !shared.isRunning()) {
            shared = new SharedVaultContainer();
            shared.start();
            SharedVaultContainer container = shared;
            Runtime.getRuntime().addShutdownHook(new Thread(container::stopForReal, "shared-vault-container-stop"));
        } else {
            shared.resetSecrets();
        }
        return shared;
    }

    /** A Vault container that is shared by many tests, so it ignores {@code stop()} until the JVM exits. */
    private static final class SharedVaultContainer extends VaultContainer<SharedVaultContainer> {

        SharedVaultContainer() {
            super(VaultContainerVersion.IMAGE);
            withVaultToken("myroot");
            withInitCommand(
                    "secrets enable transit",
                    "write -f transit/keys/my-key",
                    SEED_COMMANDS[0],
                    SEED_COMMANDS[1]
            );
        }

        /** Throw away everything under {@code secret/} and write the seed secrets again. */
        void resetSecrets() {
            StringBuilder script = new StringBuilder("vault secrets disable secret && vault secrets enable -version=2 -path=secret kv");
            for (String seed : SEED_COMMANDS) {
                script.append(" && vault ").append(seed);
            }
            try {
                ExecResult result = execInContainer("sh", "-c", script.toString());
                if (result.getExitCode() != 0) {
                    throw new IllegalStateException("Could not reset the shared Vault container: " + result.getStderr());
                }
            } catch (IOException e) {
                throw new IllegalStateException("Could not reset the shared Vault container", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while resetting the shared Vault container", e);
            }
        }

        @Override
        public void stop() {
            // Shared between tests: stopped by the shutdown hook instead.
        }

        void stopForReal() {
            super.stop();
        }
    }

    /**
     * Remove directory and its content
     * @param dir directory to cleanup
     */
    public static void cleanupDir(final Path dir) {
        if (!Files.exists(dir)) return;

        try (Stream<Path> paths = Files.walk(dir)) {
            // Delete in reverse order (children first, then parent)
            paths.sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            throw new RuntimeException("Failed to delete " + path, e);
                        }
                    });
        } catch (IOException e) {
            throw new RuntimeException("Failed to walk directory " + dir, e);
        }
    }
}
