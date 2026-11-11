/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

/**
 * The Vault container image that every test container is started from.
 *
 * <p>The version comes from the Maven property {@code version.vault.container} in {@code pom.xml}, which Surefire
 * passes to the tests as the system property {@value #VERSION_PROPERTY}. To try another version, override the Maven
 * property: {@code mvn test -Dversion.vault.container=1.21.0}. When the tests run outside Maven, for example from an
 * IDE, the system property is absent and {@value #DEFAULT_VERSION} is used instead; keep it equal to the value in
 * {@code pom.xml}.
 *
 * <p>Tests must build their containers from {@link #IMAGE} and must not name an image themselves.
 */
public final class VaultContainerVersion {

    /** System property that carries the Maven property {@code version.vault.container} into the test JVM. */
    public static final String VERSION_PROPERTY = "vault.container.version";

    /** Used when {@link #VERSION_PROPERTY} is not set. */
    static final String DEFAULT_VERSION = "2.2.1";

    /** The Vault version the test containers run. */
    public static final String VERSION = System.getProperty(VERSION_PROPERTY, DEFAULT_VERSION);

    /** The Docker image name, with the tag, to pass to the Vault test container constructors. */
    public static final String IMAGE = "hashicorp/vault:" + VERSION;

    private VaultContainerVersion() {
    }
}
