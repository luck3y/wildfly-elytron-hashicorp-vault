#!/usr/bin/env bash
#
# Copyright The WildFly Authors
# SPDX-License-Identifier: Apache-2.0
#
# Runs the interactive VaultPathShell (src/test/java/.../VaultPathShell.java).
# Compiles the project and resolves the classpath via Maven on first use (or with --rebuild).
# On a terminal it offers readline-style editing and Up/Down history (JLine); piped input still works.
#
# Usage: src/test/vault-path-shell.sh [--rebuild] [--live [--url URL] [--token TOKEN]]
#
#   (no flags)   parse aliases/paths only; no Vault connection
#   --live       also look each entry up in a running Vault (default http://127.0.0.1:8200).
#                The token comes from --token or, preferably, the VAULT_TOKEN environment variable.
#   --rebuild    discard the cached classpath and rebuild first
#
# All other arguments are passed to the shell; run with --help for details.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CP_FILE="${PROJECT_DIR}/target/vault-path-shell.classpath"
MAIN_CLASS="org.wildfly.security.hashicorp.vault.VaultPathShell"

ARGS=()
for arg in "$@"; do
    if [[ "${arg}" == "--rebuild" ]]; then
        rm -f "${CP_FILE}"
    else
        ARGS+=("${arg}")
    fi
done

if [[ ! -f "${CP_FILE}" || ! -d "${PROJECT_DIR}/target/test-classes" ]]; then
    echo "Building project and resolving classpath..." >&2
    mvn -q -f "${PROJECT_DIR}/pom.xml" test-compile dependency:build-classpath \
        -Dmdep.outputFile="${CP_FILE}" -Dmdep.includeScope=test >&2
fi

# --enable-native-access: JLine uses the foreign-function API for terminal control and the JDK warns without it.
exec java --enable-native-access=ALL-UNNAMED \
    -cp "${PROJECT_DIR}/target/test-classes:${PROJECT_DIR}/target/classes:$(cat "${CP_FILE}")" \
    "${MAIN_CLASS}" ${ARGS[@]+"${ARGS[@]}"}
