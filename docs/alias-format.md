# Vault Alias Format Specification

## Overview

The WildFly Elytron HashiCorp Vault credential store uses a structured alias format to reference secrets stored in HashiCorp Vault. This format supports multiple secret engines, custom mount paths, nested JSON traversal, and maintains backward compatibility with the legacy format.

## Syntax

```
[engine=TYPE][@mount-path][#]secret-path?key-path
```

### Components

- **`engine=TYPE`** (optional) - Specifies the Vault secret engine type
- **`@mount-path`** (optional) - Specifies a custom mount path
- **`#`** (optional/required) - Secret path marker (see rules below)
- **`secret-path`** (required) - Path to the secret in Vault
- **`?`** (required) - Key path delimiter
- **`key-path`** (required) - Path to the specific value within the secret

### Rules for `#` Delimiter

- **Optional** when alias starts with secret path: `myapp/database?password`
- **Required** when `engine=` is present: `engine=KVv1#secret?key`
- **Required** when `@` is present: `@custom#secret?key`

### Defaults

- **Engine:** `KVv2` (if `engine=` omitted)
- **Mount:** `secret` (if `@` omitted)
- **Key:** REQUIRED (no default)

## Delimiters Explained

### `engine=` - Engine Type Prefix
Specifies the Vault secret engine type. Supported values:
- `KVv2` - Key-Value version 2 (default, recommended)
- `KVv1` - Key-Value version 1 (for legacy Vault configurations)

### `@` - Mount Path Delimiter
Indicates a custom mount path. The mount path follows the `@` and ends at the `#`.

### `#` - Secret Path Marker
Separates the mount path from the secret path. Required when using `engine=` or `@` prefixes.

### `?` - Key Path Delimiter
Separates the secret path from the key path. Always required.

### `/` - JSON Path Traversal
Within the key path, an unencoded `/` indicates nested JSON traversal. A percent-encoded `%2F` is a literal slash
that is part of a key name (see [Slash and Percent in Key Names](#4-slash-and-percent-in-key-names)).

## Key Path Syntax

Key paths support two modes:

### 1. Simple Key (Literal Match)
Use when the JSON key itself contains dots:
```
?db.host          → Look for key literally named "db.host"
?my.app.config    → Look for key literally named "my.app.config"
```

### 2. Nested Path (JSON Traversal)
Use `/` to traverse nested JSON objects:
```
?database/host    → Traverse: data["database"]["host"]
?app/config/key   → Traverse: data["app"]["config"]["key"]
```

### 3. Nested with Dots in Keys
Combine both approaches:
```
?my.app/config.key    → Traverse: data["my.app"]["config.key"]
?config/db.host       → Traverse: data["config"]["db.host"]
```

### 4. Slash and Percent in Key Names

The key path is split on `/` **before** each segment is URL-decoded. This is what lets an alias tell a nested
path apart from a key whose name contains a slash or a percent sign. The same three spellings apply to any key:

| Alias key path | Meaning | Looks up |
|----------------|---------|----------|
| `?database/host` | Nested traversal | `data["database"]["host"]` |
| `?database%2Fhost` | Literal key named `database/host` | `data["database/host"]` |
| `?database%252Fhost` | Literal key named `database%2Fhost` | `data["database%2Fhost"]` |

`%2F` and `%2f` are equivalent. `%252F` is `%2F` with its `%` encoded as `%25`: the segment is decoded exactly
once, so the result is the literal text `%2F`, which is **not** decoded a second time into a slash.

Given Vault secret:

```json
{
    "database/host": "literal-slash",
    "database": { "host": "nested" },
    "database%2Fhost": "literal-percent"
}
```

```
myapp?database/host        → "nested"
myapp?database%2Fhost      → "literal-slash"
myapp?database%252Fhost    → "literal-percent"
```

All three can exist in the same secret without conflict.

`getAliases()` returns aliases in this same encoded form, so every alias it returns can be passed straight back to
`retrieve()` and reads the value it was listed for. It lists every value, including values inside nested JSON
objects, but not the objects themselves, because an object is not a credential. In the secret above it lists:

```
#myapp?database/host        → "nested"          (nested value, listed by its full key path)
#myapp?database%2Fhost      → "literal-slash"   (literal key, slash encoded)
#myapp?database%252Fhost    → "literal-percent"
```

and does not list `#myapp?database`, which points at an object. Names without special characters are listed
unchanged.

The same rule applies to the other characters that have a meaning in an alias. Encode them in a key name when
they are part of the name:

| Key name contains | Write in the alias | Why |
|-------------------|--------------------|-----|
| `/` | `%2F` | An unencoded `/` is nested traversal |
| `%` | `%25` | `%` followed by two hex digits is an escape sequence; any other `%` leaves the whole segment undecoded |
| `+` | `%2B` | An unencoded `+` is decoded as a space |
| space | `%20` | |
| `?` | `%3F` | `?` separates the secret path from the key path |
| `#` | `%23` | |

## Examples

### Simple Keys (Top-Level)

```
# Minimal format (# is optional)
myapp/database?password

# Key with dots (literal match)
myapp/database?db.host

# With # (also valid)
#myapp/config?api_key

# Key with multiple dots
services?my.app.config.value

# URL-encoded space in secret path
test%20path?password
```

### Nested JSON Paths

Given Vault secret: `{"database": {"host": "localhost", "port": 5432}}`

```
myapp/config?database/host     → "localhost"
myapp/config?database/port     → "5432"
```

Given Vault secret: `{"app": {"prod": {"key": "secret"}}}`

```
services?app/prod/key          → "secret"
```

### Mixed: Nested Path with Dots in Keys

Given Vault secret: `{"team": {"my.app": {"key": "value"}}}`

```
services?team/my.app/key       → "value"
# The dot in "my.app" is part of the key name, not a path separator
```

Given Vault secret: `{"db.config": {"host": "localhost"}}`

```
myapp?db.config/host           → "localhost"
# "db.config" is a literal key name, "/" traverses into it
```

### Real-World Examples

```
# Simple format (most common - no # needed)
myapp/database?password
myapp/config?database/connection/password
services/auth?jwt/signing/key

# With explicit engine type (# required)
engine=KVv2#myapp/database?password
engine=KVv1#old-app/config?api.key.v2

# With custom mount (# required)
@prod/vault#myapp/database?password
@team/backend#services/auth?jwt/signing/key

# Everything explicit
engine=KVv2@company/prod#division/team?app.config/db.settings/password

# URL-encoded characters in paths
test%20path?password                    # Space in path
test%23path?key                         # # in path
@mount%2Fname#secret%20path?db.host     # Multiple encoded chars
```

### Edge Cases

```
# If user has # in mount name (URL-encode it):
@test%23mount#secret?key

# If user has # in secret path without prefix (# becomes required):
#secret%23path?key

# If user has ? in secret path (URL-encode it):
secret%3Fpath?key

# URL-encoded characters work naturally:
path%20with%20spaces?password
path%2Fwith%2Fslash?key                 # Same secret path as path/with/slash?key
```

## URL Encoding

### When to URL-Encode

You **MUST** URL-encode the following characters in mount paths and secret paths:

| Character | Encoding | When Required |
|-----------|----------|---------------|
| `#` | `%23` | Always in paths |
| `?` | `%3F` | Always in paths (rare) |
| Space | `%20` | Always |
| `%` | `%25` | Always in paths: `%` followed by two hex digits is read as an escape sequence, and a `%` that is not leaves the whole segment undecoded (so `a%20b%zz` keeps its `%20`) |
| `+` | `%2B` | Always in paths: an unencoded `+` is decoded as a space |

In a mount path or secret path, `/` is always a separator. `%2F` is decoded to `/` and is therefore also a
separator, so `path%2Fwith%2Fslash` is the same path as `path/with/slash`. Only the **key path** can hold a
literal slash in a name (see [Slash and Percent in Key Names](#4-slash-and-percent-in-key-names)).

### URL Encoding Examples

```bash
# Creating secrets in Vault with special characters:
vault kv put secret/test%23path key=value    # # encoded as %23
vault kv put secret/test%3Fpath key=value    # ? encoded as %3F
vault kv put secret/test%20path key=value    # space encoded as %20
```

```
# Using the same encoding in aliases:
#test%23path?key
#test%3Fpath?key
#test%20path?password
```

### Important: Decode After Splitting

The implementation decodes URL-encoded segments **after** splitting on delimiters. This prevents double-encoding issues:

```
User provides:  #test%20path?key
Split on ?:     secret="test%20path", key="key"
Decode each:    secret="test path", key="key"
Pass to Vault:  "test path"
Connector:      Re-encodes each path segment to "test%20path" for the request ✓ CORRECT
```

The Vault client library does not encode path components itself, so the credential store encodes each segment of
the mount and secret path when it builds the request URL, for reads, writes, removals and listing. A space is
sent as `%20` (never `+`), and a name such as `100%dir` or `a+b` reaches Vault unchanged.

## Key Path Resolution Algorithm

The key path is split on unencoded `/` first, and then each segment is URL-decoded once. `%2F` therefore stays
inside one segment as a literal slash:

```
keyPath = "database/host"     → segments ["database", "host"]
keyPath = "database%2Fhost"   → segments ["database/host"]
keyPath = "database%252Fhost" → segments ["database%2Fhost"]
```

The key path resolution then follows these rules:

1. **No unencoded `/` in key path** → Direct lookup (supports dots in key name)
   ```
   keyPath = "db.host"
   → data.get("db.host")
   ```

2. **Contains an unencoded `/`** → Traverse the segments one level at a time
   ```
   keyPath = "database/host"
   → data.get("database").get("host")
   ```

3. **Nested with dots** → Each segment can contain dots
   ```
   keyPath = "my.app/config.key"
   → data.get("my.app").get("config.key")
   ```

### Resolution Examples

Given Vault secret data:
```json
{
    "password": "secret123",
    "db.host": "localhost",
    "database": {
        "host": "prod.db.com",
        "port": 5432,
        "credentials": {
            "user": "admin",
            "pass": "secret"
        }
    },
    "my.app": {
        "config.key": "value123"
    }
}
```

Key path resolutions:
```
?password                    → "secret123"
?db.host                     → "localhost"
?database/host               → "prod.db.com"
?database/port               → "5432"
?database/credentials/pass   → "secret"
?my.app/config.key           → "value123"
```

Slash handling, for a secret that has both a nested `database` object and keys named `database/host` and
`database%2Fhost`:
```
?database/host               → nested: data["database"]["host"]
?database%2Fhost             → literal: data["database/host"]
?database%252Fhost           → literal: data["database%2Fhost"]
```

## Values, Objects and Writes

Secrets in a KV engine are JSON documents, and an alias reads or writes one value inside the document.

- **Reading:** a nested JSON object is traversed by the `/` segments of the key path. The value at the end of the
  key path is returned as text: strings as they are, and numbers, booleans and arrays as their JSON text
  (`5432`, `true`, `["a","b"]`).
- **Aliases that end at an object:** a key path that ends at a JSON object (for example `?database` in the secret
  above) is not a credential value, so it resolves to nothing. Use a key path that ends at a leaf
  (`?database/host`). `getAliases()` never lists an object.
- **JSON `null`:** a key whose value is `null` is treated as absent.
- **Storing:** `store()` changes only the value at the key path. Every sibling key, at every level, is written back
  unchanged, and nested objects stay objects. Numbers, booleans and arrays elsewhere in the secret keep their JSON
  type. Missing intermediate objects are created. If an intermediate segment currently holds a plain value, it is
  replaced by an object.
- **Removing:** `remove()` deletes only the value at the key path and leaves its siblings and parent objects in
  place. If the secret becomes empty, the whole secret is deleted.

## Validation Rules

### Required Validations

1. Secret path must not be empty
2. Key path must not be empty
3. Engine type must be valid (if specified)
4. Format must match: `[engine=TYPE][@mount][#]secret?key`

### Key Path Validation

1. **Simple keys:** Any characters except `/` and `?`. To use `/` or `?` in a key name, encode it (`%2F`, `%3F`)
2. **Nested paths:** Segments separated by an unencoded `/`, each segment can contain dots
3. **No empty segments:** `database//host` is invalid

## Migration from Legacy Format

### Legacy Format

The legacy format used a dot (`.`) to separate the secret path from the key:

```
secret-path.key
```

### Detection Strategy

The implementation automatically detects the format:

- **New format** if alias contains: `?`, `#`, `@`, or starts with `engine=`
- **Legacy format** if none of the above indicators are present AND the alias contains a dot (`.`). The alias is split
  on its **last** dot, wherever that is, as it always has been. In `my.app/config` the last dot is before the slash,
  so the secret is `my` and the key path is `app/config`. Prefer the new format for such names, for example
  `my.app/config?key`.

A legacy alias is URL-decoded exactly as it was before: `+` becomes a space and `%xx` is decoded, and the legacy key
is decoded **before** it is split on `/`. So in a legacy alias `%2F` in the key is nested traversal, unlike the new
format where `%2F` in a key path is a literal slash. This is kept so that existing configurations behave as they did.

**Important:** Legacy format support must be explicitly enabled via the `support-legacy-alias-format` configuration parameter. When disabled (default in stable releases), aliases without new format indicators will be rejected with an error message providing the correct new format.

### Migration Examples

| Legacy Format | New Format | Notes |
|---------------|------------|-------|
| `myapp/db.password` | `myapp/db?password` | Simple key |
| `app.config.key` | `app.config?key` | Dots in secret path |
| `my.app.db.pass` | `my.app.db?pass` | Multiple dots |
| `app/config.key` | `app?config/key` | Nested key path |

See [migration.md](migration.md) for detailed migration guidance.

## EBNF Grammar

```ebnf
alias          = [engine-spec] [mount-spec] [hash] secret-spec key-spec
engine-spec    = "engine=" engine-type
mount-spec     = "@" mount-path
hash           = "#"
secret-spec    = secret-path
key-spec       = "?" key-path

engine-type    = "KVv1" | "KVv2"
mount-path     = path-segment *("/" path-segment)
secret-path    = path-segment *("/" path-segment)
key-path       = key-segment *("/" key-segment)
path-segment   = 1*path-char
key-segment    = 1*key-char
path-char      = ALPHA / DIGIT / "-" / "_" / "." / ":" / <any char except "#" and "?">
key-char       = ALPHA / DIGIT / "-" / "_" / "." / ":" / <any char except "/" and "?">
```

## Advantages

### 1. Handles All Real-World Cases
- ✅ Paths with dots: `my.app.config?password`
- ✅ Keys with dots: `?db.host` (literal key name)
- ✅ Nested JSON: `?database/host` (traverse)
- ✅ Nested with dots: `?my.app/config.key` (both!)
- ✅ URL-encoded paths work perfectly
- ✅ Hierarchical paths: `@team/app#service/db?password`
- ✅ No restrictions on user naming conventions

### 2. Unambiguous Parsing
- `?` requires encoding as `%3F` in actual paths → safe delimiter
- `#` is fragment identifier → safe delimiter
- `@` is clear "at location" marker
- `/` in key path means JSON traversal
- `%2F` in key path means a literal slash in the key name; `%252F` means the literal text `%2F`
- No `/` in key path means literal key lookup
- No ambiguity with URL-encoded characters
- Decode-after-split prevents double-encoding

### 3. Flexible Key Resolution
- Simple keys work naturally (even with dots)
- Nested paths use intuitive `/` separator
- Dots in nested keys work automatically
- No escaping needed for common cases

### 4. Future-Proof
- Supports any Vault secret engine type
- Handles arbitrary path complexity
- Handles arbitrary JSON nesting
- Extensible format

### 5. Backward Compatible
- Legacy format still works via detection
- Gradual migration path
- No breaking changes required

### 6. User-Friendly
- No restrictions on dots in paths
- No restrictions on dots in keys
- URL-encoded paths work naturally
- Clear, readable format
- Single-character delimiters (concise)
- Minimal encoding requirements (only for rare `#`, `?`, `%`, `+` and, in key names, `/`)
- Intuitive nested path syntax

## See Also

- [Configuration Guide](configuration.md) - Credential store configuration parameters
- [Migration Guide](migration.md) - Migrating from legacy format
- [WildFly Elytron Documentation](https://docs.wildfly.org/elytron/)