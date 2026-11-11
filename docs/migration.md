# Migration Guide: Legacy to New Alias Format

## Overview

This guide helps you migrate from the legacy alias format to the new structured format. The new format provides better support for nested JSON paths, dots in key names, and multiple secret engines.

## Format Comparison

### Legacy Format
```
secret-path.key
```

The legacy format uses a dot (`.`) to separate the secret path from the key name. This creates ambiguity when paths or keys contain dots.

### New Format
```
[engine=TYPE][@mount-path][#]secret-path?key-path
```

The new format uses explicit delimiters:
- `?` separates secret path from key path
- `#` marks the start of the secret path (optional in simple cases)
- `@` specifies custom mount paths
- `engine=` specifies the secret engine type

## Why Migrate?

### Problems with Legacy Format

1. **Ambiguous with dots:** `my.app.db.password` - which dot separates path from key?
2. **No nested JSON support:** Cannot traverse nested JSON structures
3. **No engine type support:** Assumes KVv2 engine
4. **No custom mount support:** Assumes `secret` mount
5. **Limited flexibility:** Cannot handle complex Vault configurations

### Benefits of New Format

1. **Unambiguous parsing:** Clear delimiters for all components
2. **Nested JSON support:** Use `/` to traverse nested structures
3. **Dots in keys work naturally:** `?db.host` looks up key literally named "db.host"
4. **Multiple engine support:** Specify engine type per-alias
5. **Custom mount paths:** Use different mount paths per-alias
6. **Future-proof:** Extensible for new Vault features

## Migration Strategy

### Phase 1: Enable Legacy Support (Recommended)

During migration, enable legacy format support to avoid breaking existing configurations:

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault.company.com:8200"/>
        <property name="support-legacy-alias-format" value="true"/>
    </implementation-properties>
</credential-store>
```

**Note:** The `support-legacy-alias-format` parameter defaults to `false` (legacy format disabled). Set it to `true` to enable legacy format support during migration.

### Phase 2: Convert Aliases

Convert your aliases one at a time, testing each conversion:

#### Simple Conversions

| Legacy Format | New Format | Notes |
|---------------|------------|-------|
| `myapp/db.password` | `myapp/db?password` | Simple key |
| `app.config.key` | `app.config?key` | Dots in secret path |
| `my.app.db.pass` | `my.app.db?pass` | Multiple dots in path |

#### Nested JSON Conversions

If your Vault secrets contain nested JSON, you can now access nested values:

**Legacy (only top-level keys):**
```
myapp/config.database_host
```

**New (can access nested values):**
```
myapp/config?database/host
```

Given Vault secret:
```json
{
  "database": {
    "host": "localhost",
    "port": 5432
  }
}
```

### Phase 3: Test Thoroughly

After converting each alias:

1. **Test retrieval:** Verify the credential is retrieved correctly
2. **Test application:** Ensure the application works with the new alias
3. **Check logs:** Look for any warnings or errors
4. **Document changes:** Keep track of converted aliases

### Phase 4: Disable Legacy Support

Once all aliases are converted and tested:

```xml
<credential-store name="vault-store"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault.company.com:8200"/>
        <property name="support-legacy-alias-format" value="false"/>
    </implementation-properties>
</credential-store>
```

## Conversion Examples

### Example 1: Simple Database Password

**Legacy:**
```
myapp/database.password
```

**Vault Secret:**
```json
{
  "password": "secret123",
  "username": "admin"
}
```

**New Format:**
```
myapp/database?password
```

**Explanation:** The `?` clearly separates the secret path (`myapp/database`) from the key (`password`).

### Example 2: Dots in Secret Path

**Legacy:**
```
my.app.config.api_key
```

**Vault Secret Path:** `my.app.config`
**Key:** `api_key`

**New Format:**
```
my.app.config?api_key
```

**Explanation:** Dots in the secret path work naturally. The `?` delimiter makes it clear where the path ends and the key begins.

### Example 3: Nested JSON Access

**Legacy (couldn't access nested values):**
```
myapp/config.database_host
```

This required flattening the JSON in Vault:
```json
{
  "database_host": "localhost",
  "database_port": "5432"
}
```

**New Format (can access nested values):**
```
myapp/config?database/host
myapp/config?database/port
```

Now you can use natural JSON structure:
```json
{
  "database": {
    "host": "localhost",
    "port": 5432
  }
}
```

### Example 4: Key with Dots

**Legacy:**
```
services.db.host
```

**Ambiguity:** Is the secret path `services.db` with key `host`, or `services` with key `db.host`?

**New Format (secret path: `services`, key: `db.host`):**
```
services?db.host
```

**New Format (secret path: `services.db`, key: `host`):**
```
services.db?host
```

**Explanation:** The `?` delimiter removes all ambiguity.

### Example 5: Nested with Dots in Keys

**Vault Secret:**
```json
{
  "my.app": {
    "config.key": "value123"
  }
}
```

**New Format:**
```
services?my.app/config.key
```

**Explanation:**
- `my.app` is a literal key name (contains dot)
- `/` traverses into that key
- `config.key` is another literal key name (contains dot)

### Example 6: Custom Engine Type

**Legacy (no engine type support):**
```
old-secrets.api_key
```

**New Format (KVv1 engine):**
```
engine=KVv1#old-secrets?api_key
```

**Explanation:** The `engine=` prefix specifies KVv1, and `#` is required when using prefixes.

### Example 7: Custom Mount Path

**Legacy (no mount path support):**
```
myapp/database.password
```

**New Format (custom mount):**
```
@prod/secrets#myapp/database?password
```

**Explanation:** The `@` prefix specifies a custom mount path, and `#` is required when using prefixes.

## Detection Logic

The implementation automatically detects which format is being used:

### New Format Indicators
An alias is considered **new format** if it contains any of:
- `?` (key path delimiter)
- `#` (secret path marker)
- `@` (mount path prefix)
- Starts with `engine=`

### Legacy Format
If none of the above indicators are present AND the alias contains a dot (`.`), it is treated as **legacy format** (split on last dot).

**Important:** Legacy format support must be explicitly enabled via the `support-legacy-alias-format` configuration parameter. When disabled (default in stable releases), aliases without new format indicators will be rejected with an error message providing the correct new format.

### Examples

```
myapp/database?password          → New format (contains ?)
#myapp/database?password         → New format (contains # and ?)
@custom#myapp/db?pass            → New format (contains @, #, and ?)
engine=KVv1#secret?key           → New format (starts with engine=)
myapp/database.password          → Legacy format (no indicators)
my.app.config.key                → Legacy format (no indicators)
```

## Common Migration Scenarios

### Scenario 1: Simple Application

**Before:**
```xml
<credential-store name="vault-store" type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault.company.com:8200"/>
    </implementation-properties>
</credential-store>
```

**Aliases:**
- `myapp/database.password`
- `myapp/api.key`

**After:**
```xml
<credential-store name="vault-store" type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault.company.com:8200"/>
        <property name="support-legacy-alias-format" value="false"/>
    </implementation-properties>
</credential-store>
```

**New Aliases:**
- `myapp/database?password`
- `myapp/api?key`

### Scenario 2: Multiple Applications with Nested Secrets

**Before (flattened structure):**

Vault secrets:
```json
{
  "db_host": "localhost",
  "db_port": "5432",
  "db_user": "admin",
  "db_pass": "secret"
}
```

Aliases:
- `myapp/config.db_host`
- `myapp/config.db_port`
- `myapp/config.db_user`
- `myapp/config.db_pass`

**After (nested structure):**

Vault secrets:
```json
{
  "database": {
    "host": "localhost",
    "port": 5432,
    "credentials": {
      "user": "admin",
      "pass": "secret"
    }
  }
}
```

New aliases:
- `myapp/config?database/host`
- `myapp/config?database/port`
- `myapp/config?database/credentials/user`
- `myapp/config?database/credentials/pass`

### Scenario 3: Mixed Engine Types

**Before (all KVv2):**
- `old-app/config.key`
- `new-app/config.key`

**After (mixed engines):**
- `engine=KVv1#old-app/config?key` (legacy app uses KVv1)
- `new-app/config?key` (new app uses KVv2 default)

## Testing Your Migration

### 1. Create a Test Credential Store

```xml
<credential-store name="vault-store-test"
                  type="hashicorp-vault">
    <implementation-properties>
        <property name="host-address" value="https://vault-test.company.com:8200"/>
        <property name="support-legacy-alias-format" value="true"/>
    </implementation-properties>
</credential-store>
```

### 2. Test Both Formats Side-by-Side

Create test secrets in Vault:
```bash
vault kv put secret/test/migration password=test123
```

Test both formats:
- Legacy: `test/migration.password`
- New: `test/migration?password`

### 3. Verify Retrieval

Use WildFly CLI to test:
```bash
/subsystem=elytron/credential-store=vault-store-test:read-alias(alias=test/migration?password)
```

### 4. Test Application Integration

Deploy your application with the new aliases and verify functionality.

### 5. Monitor Logs

Check for warnings or errors related to alias parsing:
```bash
grep -i "vault\|alias" server.log
```

## Rollback Plan

If you encounter issues during migration:

### 1. Re-enable Legacy Support

```xml
<property name="support-legacy-alias-format" value="true"/>
```

### 2. Revert Aliases

Change aliases back to legacy format temporarily.

### 3. Investigate Issues

- Check logs for specific errors
- Verify Vault secret structure
- Test individual aliases
- Review URL encoding

### 4. Retry Migration

Once issues are resolved, retry the migration process.

## Best Practices

### 1. Migrate Gradually

Don't convert all aliases at once. Migrate one application or service at a time.

### 2. Test in Non-Production First

Always test migrations in development or staging environments first.

### 3. Document Your Aliases

Keep a mapping of old to new aliases:

```
# Migration Mapping
myapp/database.password → myapp/database?password
myapp/api.key → myapp/api?key
services.auth.token → services/auth?token
```

### 4. Use Nested Paths When Appropriate

Take advantage of nested JSON support to organize secrets better:

**Before:**
```
myapp/config.db_host
myapp/config.db_port
myapp/config.api_key
myapp/config.api_secret
```

**After:**
```
myapp/config?database/host
myapp/config?database/port
myapp/config?api/key
myapp/config?api/secret
```

### 5. Plan for URL Encoding

If your paths contain special characters, plan for URL encoding:

```
test path → test%20path
test#path → test%23path
test?path → test%3Fpath
test%path → test%25path
test+path → test%2Bpath
```

Key names follow the same rules, plus one more: an unencoded `/` in a key path is nested traversal, so a key whose
name contains a slash must be written with `%2F`:

```
?database/host      → nested: data["database"]["host"]
?database%2Fhost    → literal key "database/host"
?database%252Fhost  → literal key "database%2Fhost"
```

## Timeline Recommendations

### Week 1-2: Planning
- Review all existing aliases
- Identify conversion patterns
- Plan testing strategy
- Set up test environment

### Week 3-4: Testing
- Enable legacy support in test environment
- Convert and test aliases in test environment
- Document any issues
- Refine conversion approach

### Week 5-6: Staging Migration
- Enable legacy support in staging
- Convert aliases in staging
- Test applications thoroughly
- Monitor for issues

### Week 7-8: Production Migration
- Enable legacy support in production
- Convert aliases in production (gradually)
- Monitor applications closely
- Keep legacy support enabled

### Week 9+: Cleanup
- After stable period (2-4 weeks), disable legacy support
- Remove legacy format documentation from internal docs
- Update runbooks and procedures

## Troubleshooting

### Issue: Alias Not Found After Conversion

**Symptoms:** Application can't retrieve credential after converting alias.

**Solutions:**
1. Verify the secret exists in Vault at the specified path
2. Check for typos in the new alias
3. Verify URL encoding if path contains special characters
4. Test the alias using WildFly CLI
5. Check Vault logs for access attempts

### Issue: Wrong Value Retrieved

**Symptoms:** Credential is retrieved but has wrong value.

**Solutions:**
1. Verify the key path is correct
2. Check if you need nested path (`/`) vs simple key, and whether a key name that contains a slash is written as `%2F`
3. Inspect the actual Vault secret structure
4. Test key path resolution separately

### Issue: Legacy Format Still Being Used

**Symptoms:** New format aliases not working, legacy format still works.

**Solutions:**
1. Verify `support-legacy-alias-format` is set correctly
2. Check if alias contains new format indicators (`?`, `#`, `@`, `engine=`)
3. Review alias detection logic
4. Check for configuration caching issues

### Issue: URL Encoding Problems

**Symptoms:** Paths with special characters not working.

**Solutions:**
1. Verify special characters are URL-encoded (`#` → `%23`, `?` → `%3F`, `%` → `%25`, `+` → `%2B`)
2. Check that spaces are encoded as `%20` (an unencoded `+` is read as a space)
3. Test with simple paths first, then add encoding
4. Review URL encoding documentation

### Issue: Checking Logs and Enabling Debug Logging

**When to use:** Any troubleshooting scenario - logs provide detailed information about what's happening.

**Log File Locations:**
- **Standalone mode:** `$JBOSS_HOME/standalone/log/server.log`
- **Domain mode:** `$JBOSS_HOME/domain/servers/{server-name}/log/server.log`

**Enable Debug Logging:**

Add to your WildFly configuration (standalone.xml or domain.xml):

```xml
<subsystem xmlns="urn:jboss:domain:logging:8.0">
    <logger category="org.wildfly.security.hashicorp.vault">
        <level name="DEBUG"/>
    </logger>
</subsystem>
```

Or use CLI:

```bash
/subsystem=logging/logger=org.wildfly.security.hashicorp.vault:add(level=DEBUG)
reload
```

**Enable Trace Logging (for detailed operations):**

```bash
/subsystem=logging/logger=org.wildfly.security.hashicorp.vault:write-attribute(name=level,value=TRACE)
reload
```

**What to Look For:**

1. **Configuration Issues:**
   ```
   ELYHCVT0024: Failed to configure Vault connection to https://vault.example.com:8200
   ```
   Check: host-address, port, TLS settings, authentication

2. **Authentication Problems:**
   ```
   ELYHCVT0034: All login strategies failed
   ```
   Check: vault token, TLS certificates, authentication-context

3. **Alias Format Issues:**
   ```
   ELYHCVT0074: Invalid alias format: ...
   ```
   Check: alias syntax, delimiters, URL encoding

4. **Secret Not Found:**
   ```
   ELYHCVT0029: Secret not found at path: secret/myapp/database
   ```
   Check: path exists in Vault, permissions, KV version

5. **Legacy Format Warnings:**
   ```
   ELYHCVT0072: Legacy alias format detected: 'secret.myapp.password'
   ```
   Action: Migrate to new format

**Troubleshooting Workflow:**

1. Check server.log for ELYHCVT error codes
2. Enable DEBUG logging if needed
3. Reproduce the issue
4. Look for error messages with context
5. Enable TRACE logging for detailed operation flow
6. Check Vault audit logs for corresponding access attempts

## Support and Resources

### Documentation
- [Alias Format Specification](alias-format.md)
- [Configuration Guide](configuration.md)
- [WildFly Elytron Documentation](https://docs.wildfly.org/elytron/)

### Getting Help
- Check server logs for detailed error messages
- Review Vault audit logs for access patterns
- Test aliases using WildFly CLI for debugging
- Consult WildFly community forums

## Deprecation Timeline

### Current Status
- **Legacy format:** Supported (with `support-legacy-alias-format=true`)
- **New format:** Fully supported and recommended

### Future Plans
- **Next major version:** Legacy format deprecated (warning messages)
- **Following major version:** Legacy format removed

**Recommendation:** Migrate to new format as soon as practical to avoid future compatibility issues.

## Summary

The new alias format provides significant improvements over the legacy format:

✅ **Unambiguous parsing** - Clear delimiters for all components
✅ **Nested JSON support** - Access deeply nested values
✅ **Dots in keys** - No restrictions on naming
✅ **Multiple engines** - Support for all Vault secret engines
✅ **Custom mounts** - Flexible mount path configuration
✅ **Future-proof** - Extensible for new features

Migration is straightforward with legacy format support enabled during the transition period. Follow this guide to ensure a smooth migration process.