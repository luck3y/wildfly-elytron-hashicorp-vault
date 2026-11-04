/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.wildfly.security.credential.store.CredentialStoreException;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.json.Json;
import io.github.jopenlibs.vault.json.JsonObject;
import io.github.jopenlibs.vault.json.JsonValue;

/**
 * Interactive utility for experimenting with Vault alias and path syntax.
 *
 * <p>Reads one alias or path per line, parses it with the same code the credential store uses and
 * prints the resulting components together with the Vault API path. Exit with {@code exit},
 * {@code quit} or Ctrl-D.
 *
 * <p>On a terminal, input has readline-style editing (cursor keys, Home/End, Ctrl-A/E/K/W, ...) and
 * Up/Down arrow history, plus Ctrl-R reverse search. History is kept for the session only. When
 * input is piped, plain line reading is used.
 *
 * <p>By default no Vault server is contacted. With {@code --live} the shell also connects to a
 * running Vault (for example {@code vault server -dev}) and looks every entry up twice:
 * <ul>
 *   <li><b>stored</b> - the value as it is held in Vault, read from the raw JSON of the HTTP
 *       response by following the key path through the real JSON structure;</li>
 *   <li><b>api</b> - the value the credential store gets: the secret fetched through
 *       {@link VaultConnector} (the Vault Java client) and resolved with
 *       {@link VaultKeyPathOperations}.</li>
 * </ul>
 * and reports whether the two differ. Values are printed in clear text, so use it only against a
 * Vault whose contents you are happy to see on screen.
 *
 * <p>Input format: {@code [engine=TYPE][@mount-path]#secret-path[?key-path]}. A line containing
 * {@code ?} is parsed as an alias, any other line as a path without a key.
 */
public final class VaultPathShell {

    private static final String PROMPT = "vault-path> ";
    private static final String DEFAULT_URL = "http://127.0.0.1:8200";
    private static final String TOKEN_ENV = "VAULT_TOKEN";
    private static final String NOT_FOUND = "(not found)";

    private static final String USAGE =
            "Usage: VaultPathShell [--live [--url URL] [--token TOKEN]]\n"
            + "  --live          also connect to a running Vault and look up each entry\n"
            + "  --url URL       Vault address (default " + DEFAULT_URL + ", or VAULT_ADDR)\n"
            + "  --token TOKEN   token to authenticate with (default: the " + TOKEN_ENV + " environment variable)\n"
            + "                  Prefer the environment variable: command-line arguments are visible to other users in the process list.";

    private static final String HELP =
            "Enter a vault alias or path: [engine=TYPE][@mount-path]#secret-path[?key-path]\n"
            + "  Characters that are delimiters (# ? @ /) must be percent-encoded when part of a name.\n"
            + "  Examples:\n"
            + "    #myapp/database?password\n"
            + "    engine=KVv1@secret-v1#my%20app?db.host\n"
            + "    #myapp?nested/key%2Fwith%2Fslash\n"
            + "    #myapp/database                 (path without key)\n"
            + "Commands: help, exit, quit (or Ctrl-D)";

    private VaultPathShell() {
    }

    public static void main(String[] args) throws IOException {
        boolean live = false;
        String url = null;
        String token = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--live":
                    live = true;
                    break;
                case "--url":
                    url = optionValue(args, ++i);
                    break;
                case "--token":
                    token = optionValue(args, ++i);
                    break;
                case "--help":
                case "-h":
                    System.out.println(USAGE);
                    return;
                default:
                    usageError("Unknown argument: " + args[i]);
            }
        }
        if (!live && (url != null || token != null)) {
            usageError("--url and --token only apply together with --live");
        }

        PrintStream out = System.out;
        VaultConnector connector;
        RawVault raw = null;
        if (live) {
            if (url == null) {
                url = System.getenv("VAULT_ADDR") != null ? System.getenv("VAULT_ADDR") : DEFAULT_URL;
            }
            if (token == null) {
                token = System.getenv(TOKEN_ENV);
            }
            if (token == null || token.isBlank()) {
                usageError("--live needs a token: pass --token or set " + TOKEN_ENV);
            }
            connector = new VaultConnector(url, token, null, new SslConfig(), true);
            connector.configure();
            try {
                // Connectivity and authentication check: logs in and lists the default mount.
                connector.listSecretsAtPath(VaultConstants.DEFAULT_MOUNT_PATH, "", VaultConstants.ENGINE_TYPE_KV_V2);
            } catch (CredentialStoreException | RuntimeException e) {
                System.err.println("Could not connect to Vault at " + url + ": " + e.getMessage());
                System.exit(1);
                return;
            }
            raw = new RawVault(url, token);
            out.println("Connected to Vault at " + url);
        } else {
            // Only used for constructVaultPath(); this connector never contacts Vault.
            connector = new VaultConnector("http://localhost", "unused", null, new SslConfig(), true);
        }

        try (Terminal terminal = TerminalBuilder.builder().system(true).build()) {
            LineReader reader = LineReaderBuilder.builder().terminal(terminal).build();
            out.println("Vault path builder" + (live ? " (live)" : "")
                    + ". Type 'help' for usage, 'exit' or Ctrl-D to quit.");
            while (true) {
                String line;
                try {
                    line = reader.readLine(PROMPT);
                } catch (UserInterruptException e) { // Ctrl-C discards the current line
                    continue;
                } catch (EndOfFileException e) { // Ctrl-D
                    break;
                }
                line = line.strip();
                if (line.isEmpty()) {
                    continue;
                }
                if (line.equals("exit") || line.equals("quit")) {
                    break;
                }
                if (line.equals("help")) {
                    out.println(HELP);
                    continue;
                }
                handle(line, connector, raw, out);
            }
        }
    }

    private static String optionValue(String[] args, int index) {
        if (index >= args.length) {
            usageError("Missing value for " + args[index - 1]);
        }
        return args[index];
    }

    private static void usageError(String message) {
        System.err.println(message);
        System.err.println(USAGE);
        System.exit(2);
    }

    /** @param raw the raw Vault client, or {@code null} when not running with {@code --live} */
    private static void handle(String input, VaultConnector connector, RawVault raw, PrintStream out) {
        try {
            if (input.indexOf('?') != -1) {
                VaultAlias alias = VaultAlias.parse(input);
                printPath(alias, connector, out);
                out.println("  key segments: " + alias.getKeyPathSegments());
                if (raw != null) {
                    lookupAlias(alias, connector, raw, out);
                }
            } else {
                VaultPath path = VaultPath.parse(input, VaultConstants.ENGINE_TYPE_KV_V2,
                        VaultConstants.DEFAULT_MOUNT_PATH, false, false, VaultPath.class);
                printPath(path, connector, out);
                if (raw != null) {
                    lookupPath(path, connector, raw, out);
                }
            }
        } catch (CredentialStoreException | IOException | RuntimeException e) {
            out.println("  error: " + e.getMessage());
        }
    }

    private static void printPath(VaultPath path, VaultConnector connector, PrintStream out) {
        out.println("  engine:       " + path.getEngineType());
        out.println("  mount:        " + path.getMountPath());
        out.println("  secret:       " + path.getSecretPath());
        out.println("  api path:     " + connector.constructVaultPath(path));
    }

    /**
     * Prints the value as stored in Vault and the value the credential store would get through the
     * API client, and says whether they differ.
     */
    private static void lookupAlias(VaultAlias alias, VaultConnector connector, RawVault raw, PrintStream out)
            throws CredentialStoreException, IOException {
        JsonObject storedFields = raw.read(alias);
        Map<String, Object> apiData = connector.getSecretData(alias);
        if (storedFields == null && apiData == null) {
            out.println("  live:         secret not found");
            return;
        }

        JsonValue storedJson = storedFields == null ? null : storedJson(storedFields, alias.getKeyPathSegments());
        String stored = text(storedJson);
        String api = VaultKeyPathOperations.resolveKeyPathSegments(apiData, alias.getKeyPathSegments());
        boolean storedIsObject = storedJson != null && storedJson.isObject();

        out.println("  stored value: " + show(stored) + "   (as held in Vault)");
        if (storedIsObject) {
            out.println("  credential store value: (object, not a credential value)");
        } else {
            out.println("  credential store value: " + show(api));
        }
        if (storedIsObject || Objects.equals(stored, api)) {
            out.println("  differs:      no");
        } else {
            out.println("  differs:      YES");
        }
        if (stored == null && storedFields != null) {
            out.println("  keys stored:  " + new TreeSet<>(storedFields.names()));
        }
    }

    /**
     * Lists the sub-paths under the path and, if the path is itself a secret, every top-level key
     * with its stored value. Where the API client returns something different, that is shown too.
     */
    private static void lookupPath(VaultPath path, VaultConnector connector, RawVault raw, PrintStream out)
            throws CredentialStoreException, IOException {
        List<String> children = connector.listSecretsAtPath(path.getMountPath(), path.getSecretPath(), path.getEngineType());
        out.println("  live list:    " + (children.isEmpty() ? "(nothing)" : children));
        if (path.getSecretPath().isEmpty()) {
            return;
        }

        JsonObject storedFields = raw.read(path);
        Map<String, Object> apiData = connector.getSecretData(path);
        if (storedFields == null && apiData == null) {
            return;
        }

        Set<String> keys = new TreeSet<>();
        if (storedFields != null) {
            keys.addAll(storedFields.names());
        }
        if (apiData != null) {
            keys.addAll(apiData.keySet());
        }
        out.println("  live data (as stored in Vault):");
        for (String key : keys) {
            JsonValue storedValue = storedFields == null ? null : storedFields.get(key);
            String stored = text(storedValue);
            Object apiObject = apiData == null ? null : apiData.get(key);
            String api = apiObject == null ? null : apiObject.toString();
            out.println("    " + key + " = " + show(stored));
            if (storedValue != null && storedValue.isObject()) {
                out.println("      credential store: (object, not a credential value)");
            } else if (!Objects.equals(stored, api)) {
                out.println("      credential store gives: " + show(api));
            }
        }
    }

    /** Follows the key path through the real JSON structure of the stored secret. */
    private static JsonValue storedJson(JsonObject fields, List<String> segments) {
        JsonValue current = fields;
        for (String segment : segments) {
            if (current == null || !current.isObject()) {
                return null;
            }
            current = current.asObject().get(segment);
        }
        return current;
    }

    /** Text of a JSON value: strings unquoted, everything else (numbers, booleans, objects, arrays) as JSON. */
    private static String text(JsonValue value) {
        if (value == null || value.isNull()) {
            return null;
        }
        return value.isString() ? value.asString() : value.toString();
    }

    private static String show(String value) {
        return value == null ? NOT_FOUND : value;
    }

    /**
     * Reads a secret straight from the Vault HTTP API and parses the response itself, so the result
     * reflects what Vault stores and not what the Vault Java client makes of it.
     */
    private static final class RawVault {

        private final String url;
        private final String token;
        private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

        RawVault(String url, String token) {
            this.url = url.replaceAll("/+$", "");
            this.token = token;
        }

        /** Returns the secret's fields exactly as stored, or {@code null} if the secret does not exist. */
        JsonObject read(VaultPath path) throws IOException {
            boolean kv2 = VaultConstants.ENGINE_TYPE_KV_V2.equals(path.getEngineType());
            String target = url + "/v1/" + encode(path.getMountPath()) + (kv2 ? "/data/" : "/") + encode(path.getSecretPath());
            HttpRequest request = HttpRequest.newBuilder(URI.create(target))
                    .timeout(Duration.ofSeconds(10))
                    .header("X-Vault-Token", token)
                    .GET()
                    .build();
            HttpResponse<String> response;
            try {
                response = client.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while reading " + target, e);
            }
            if (response.statusCode() == 404) {
                return null;
            }
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode() + " reading " + target);
            }

            JsonValue data = Json.parse(response.body()).asObject().get("data");
            if (kv2 && data != null && data.isObject()) {
                data = data.asObject().get("data"); // KV v2 wraps the fields in data.data; null for a deleted version
            }
            return data == null || !data.isObject() ? null : data.asObject();
        }

        private static String encode(String path) {
            String[] segments = path.split("/", -1);
            StringBuilder encoded = new StringBuilder();
            for (int i = 0; i < segments.length; i++) {
                if (i > 0) {
                    encoded.append('/');
                }
                encoded.append(URLEncoder.encode(segments[i], StandardCharsets.UTF_8).replace("+", "%20"));
            }
            return encoded.toString();
        }
    }
}
