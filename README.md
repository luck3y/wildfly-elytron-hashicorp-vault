# WildFly HashiCorp Vault Credential Store

A credential store implementation for WildFly that integrates with HashiCorp Vault for secure credential storage and retrieval.

## Requirements

- HashiCorp Vault server
- WildFly server
- Java
- Maven
- Vault Java driver

## Build the project

### Prerequisites

- Java 25 (or later)
- Maven 3.9+
- HashiCorp Vault server (for testing)

### Simple Build and Test

The simplest way to build and test the project:

```bash
git clone <repository-url>
cd wildfly-elytron-hashicorp-vault
mvn clean install
```

This will:
- Compile the code with Java 25
- Target Java 17 bytecode (for backward compatibility)
- Run tests with Java 25

### Multi-Version Testing (Optional)

To test with specific Java versions (17, 21, or 25), you need to set up Maven toolchains:

1. **Install multiple JDK versions**:
   - Java 17, 21, and 25
   - Both Temurin and Semeru distributions (for full CI compatibility)
   - Download from [Adoptium](https://adoptium.net/) or [IBM Semeru](https://developer.ibm.com/languages/java/semeru-runtimes/)

2. **Configure Maven toolchains**:
   - Copy `toolchains.xml.template` to `~/.m2/toolchains.xml`
   - Update the `<jdkHome>` paths to match your JDK installations
   - Verify: `mvn toolchains:display-toolchains`

3. **Test with specific Java version**:
   ```bash
   # Test with Java 17
   mvn clean test -Djdk.test.version=17

   # Test with Java 21
   mvn clean test -Djdk.test.version=21

   # Test with Java 25 (default)
   mvn clean test -Djdk.test.version=25

   # Test with specific distribution
   mvn clean test -Djdk.test.version=21 -Djdk.test.vendor=semeru
   ```

For more details on multi-version testing, see the [toolchains.xml.template](toolchains.xml.template) file.

# Important

Adding a credential store to the Elytron subsystem is only a preview of what we are working on. Using it this way is not recommended. We are currently developing a dedicated feature pack with a vault subsystem that will offer more configuration options.


## Configuration

### 1. Add the Credential Store to WildFly

Connect to the CLI and add the HashiCorp Vault credential store to your WildFly configuration:

```bash
# Using WildFly CLI
$WILDFLY_HOME/bin/jboss-cli.sh --connect
/subsystem=elytron/credential-store=vault-token-store:add-alias(alias=vault-token, secret-value=hvs.your-vault-token-here)

module add --name=io.github.jopenlibs.vault --resources=/path/to/vault-java-driver/vault-java-driver-x.y.z.jar

module add --name=org.wildfly.vaultcredentialstore --resources=/path/to/repo/target/wildfly-elytron-hashicorp-vault-1.0-SNAPSHOT.jar --dependencies=org.wildfly.security.elytron,io.github.jopenlibs.vault

/subsystem=elytron/provider-loader=vaultProviderLoader:add(class-names=[org.wildfly.security.hashicorp.vault.HashicorpVaultCredentialStoreProvider],module=org.wildfly.vaultcredentialstore)

/subsystem=elytron/credential-store=vault-store:add(providers=vaultProviderLoader,implementation-properties={host-address="https://localhost:9200", trust-store-path="/path/to/client.truststore.jks"},type=HashicorpVaultCredentialStore,credential-reference={clear-text="myroot"})
```

Example result configuration (`standalone.xml` or `domain.xml`):

```xml
<subsystem xmlns="urn:wildfly:elytron:15.0">
    ...
    <credential-stores>
        <credential-store name="vault-store"
                         type="HashicorpVaultCredentialStore"
                         providers="vaultProviderLoader">
            <implementation-properties>
                <property name="host-address" value="https://vault.example.com:8200"/>
                <property name="namespace" value="production"/>
                <property name="trust-store-path" value="/path/to/vault-truststore.jks"/>
                <property name="key-store-path" value="/path/to/vault-keystore.jks"/>
                <property name="key-store-pass" value="keystore-password"/>
            </implementation-properties>
            <credential-reference clear-text="root-token-id"/>
        </credential-store>
    ...
</subsystem>
```

### 2. Use the Credential Store

Reference credentials from Vault in your WildFly configuration using the alias format.

#### Alias Format

The credential store supports a structured alias format for referencing secrets:

```
[engine=TYPE][@mount-path][#]secret-path?key-path
```

**Simple examples:**
```
myapp/database?password              # Simple key
myapp/config?database/host           # Nested JSON path
services?my.app/config.key           # Nested with dots in keys
myapp/config?database%2Fhost         # Literal key named "database/host" (%2F is not a nested path)
```

**Advanced examples:**
```
engine=KVv1#old-app/config?api_key   # Specify engine type
@prod/secrets#myapp/db?password      # Custom mount path
```

For complete alias format documentation, see [`docs/alias-format.md`](docs/alias-format.md).

#### Legacy Format Support

The legacy format (`secret-path.key`) is supported for backward compatibility when `support-legacy-alias-format` is enabled. See [`docs/migration.md`](docs/migration.md) for migration guidance.

#### Using Credentials

Reference credentials from Vault in your WildFly configuration:

```xml
<!-- Example: Database connection using Vault-stored password -->
<subsystem xmlns="urn:jboss:domain:datasources:7.0">
    <datasources>
        <datasource jndi-name="java:jboss/datasources/MyAppDS" pool-name="MyAppDS">
            <connection-url>jdbc:postgresql://localhost:5432/myapp</connection-url>
            <driver>postgresql</driver>
            <security>
                <user-name>dbuser</user-name>
                <credential-reference store="vault-store" alias="myapp/database?password"/>
            </security>
        </datasource>
    </datasources>
</subsystem>

<!-- Example: Security domain using Vault-stored LDAP password -->
<subsystem xmlns="urn:wildfly:elytron:15.0">
    <security-domains>
        <security-domain name="MyAppDomain" default-realm="ldap-realm"/>
    </security-domains>
    <security-realms>
        <ldap-realm name="ldap-realm" dir-context="ldap-connection">
            <identity-mapping rdn-identifier="uid" search-base-dn="ou=users,dc=example,dc=com"/>
        </ldap-realm>
    </security-realms>
    <dir-contexts>
        <dir-context name="ldap-connection" url="ldap://ldap.example.com:389">
            <credential-reference store="vault-store" alias="ldap/config?bind_password"/>
        </dir-context>
    </dir-contexts>
</subsystem>
```

## Configuration Properties

| Property | Required | Description | Example |
|----------|----------|-------------|---------|
| `host-address` | Yes | Vault server URL | `https://vault.example.com:8200` |
| `namespace` | No | Vault namespace (Enterprise) | `production` |
| `trust-store-path` | No | Path to trust store for SSL | `/path/to/truststore.jks` |
| `trust-store-pass` | No | Trust store password | `truststore-password` |
| `key-store-path` | No | Path to key store for client auth | `/path/to/keystore.jks` |
| `key-store-pass` | No | Key store password | `keystore-password` |
| `support-legacy-alias-format` | No | Enable legacy format support | `true` or `false` |
| `default-engine-type` | No | Default secret engine type | `KVv2` (default), `KVv1`, etc. |
| `default-mount-path` | No | Default mount path | `secret` (default) |

## Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

- **[Alias Format Specification](docs/alias-format.md)** - Complete guide to the alias format syntax, examples, and best practices
- **[Configuration Guide](docs/configuration.md)** - Detailed configuration parameters and examples
- **[Migration Guide](docs/migration.md)** - Step-by-step guide for migrating from legacy format

For complete configuration documentation, see [`docs/configuration.md`](docs/configuration.md).

## Quickstart example

You can run a vault container with Docker to try this library:

```bash
docker run --cap-add=IPC_LOCK  -p 8200:8200 -p 9200:9200 -e 'VAULT_DEV_LISTEN_ADDRESS=localhost:8200' -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot'  -e 'VAULT_LOCAL_CONFIG={"listener":[{"tcp":{"address":"0.0.0.0:9200","tls_cert_file":"/vault/config/tls/vault_server.cer", "tls_key_file":"/vault/config/tls/private_key.pem"}}]}' -v $(pwd):"/vault/config/tls":Z  hashicorp/vault
```

Run the above in the folder where you have your server certificate and private key. You can configure a credential store that connects to the above with e.g.:

```bash
/subsystem=elytron/credential-store=vault_store:add(providers=vaultProviderLoader,implementation-properties={host-address="https://localhost:9200", trust-store-path="/path/to/client.truststore.jks"},type=HashicorpVaultCredentialStore,credential-reference={clear-text="myroot"})
```

## Using Podman instead of Docker

To use Podman instead of Docker on Linux:

Start the Podman daemon in the background:
```bash
$ systemctl --user start podman.socket &
```

Set the DOCKER_HOST environmental variable:
```bash
$ export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
```
See https://podman-desktop.io/tutorial/testcontainers-with-podman for more details.

## License

Licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.