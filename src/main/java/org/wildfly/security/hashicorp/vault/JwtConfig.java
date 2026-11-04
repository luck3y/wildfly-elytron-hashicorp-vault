/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.common.Assert.checkNotNullParam;
import org.wildfly.common.annotation.NotNull;

/**
 * Simple encapsulation of JWT login configuration
 */
public final class JwtConfig {

    private final String jwt;
    private final String jwtRole;
    private final String jwtProvider;

    public JwtConfig(@NotNull String jwt, @NotNull String jwtRole, @NotNull String jwtProvider) {
        this.jwt = checkRequired("jwt", jwt);
        this.jwtRole = checkRequired("jwtRole", jwtRole);
        this.jwtProvider = checkRequired("jwtProvider", jwtProvider);
    }

    private String checkRequired(String paramName, String value) throws IllegalArgumentException {
        checkNotNullParam(paramName, value);
        if (value.trim().isEmpty()) {
            throw new IllegalArgumentException("Parameter '" + paramName + "' must not be empty or blank");
        }
        return value;
    }

    public String getJwt() {
        return jwt;
    }

    public String getJwtRole() {
        return jwtRole;
    }

    public String getJwtProvider() {
        return jwtProvider;
    }
}
