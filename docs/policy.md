# Policy reference

A policy is a JSON file, loaded from `.honeylock/policy.json` unless `--policy` says otherwise. Missing fields fall back to the defaults below, so a partial file is valid.

```json
{
  "allowedTools": [],
  "deniedTools": [],
  "deniedKeys": [],
  "egressTools": ["send", "post", "upload", "http", "fetch", "request", "webhook", "email", "message"],
  "maxArgBytes": 1000000
}
```

## Fields

### `allowedTools`

Array of tool names. When non-empty, anything not listed is refused. `*` at the end matches a prefix.

```json
{ "allowedTools": ["read_*", "list_*", "search"] }
```

This is the strongest control in the file, because it fails closed on tools you have never seen. It is also the one that breaks most often when a server adds a tool, so pair it with `honeylock pin` reviews.

### `deniedTools`

Same matching rules, checked before the allowlist. A denied tool is refused even if it also matches an allow pattern.

```json
{ "deniedTools": ["shell_exec", "delete_*", "drop_*"] }
```

### `deniedKeys`

Argument keys refused anywhere in the arguments object, at any depth. Useful when a tool legitimately exists but must never receive a particular field.

```json
{ "deniedKeys": ["env", "credentials", "authorization", "private_key"] }
```

Matching is exact and case-insensitive on the last path segment, so a nested `{"config": {"env": "..."}}` is caught.

### `egressTools`

Substrings. If the tool name contains one of them (case-insensitive), high-entropy argument values are blocked instead of merely suspicious. This is how `send_webhook` and `upload_file` get treated differently from `checksum_file`.

```json
{ "egressTools": ["send", "post", "upload", "webhook", "email", "http", "slack", "telegram"] }
```

Keep this list close to reality. Every name you add reduces false negatives on exfiltration and increases the chance of a false positive on legitimate opaque identifiers.

### `maxArgBytes`

Upper bound on the serialized arguments of one call. Larger calls are refused before any detector runs. This is a denial-of-service control more than a security one, but it also stops "send the whole repository" as a single argument.

## `--workspace`

Not part of the JSON file, because it is a property of the machine, not the project:

```bash
honeylock proxy --workspace /home/you/projects -- <server command>
```

Every path-shaped argument is resolved against this root, and anything that lands outside it is refused. Defaults to the current directory.

## Recipes

### Filesystem server, least privilege

```json
{
  "allowedTools": ["read_file", "read_multiple_files", "list_directory", "directory_tree", "search_files"],
  "deniedTools": ["write_file", "edit_file", "move_file", "create_directory"],
  "maxArgBytes": 262144
}
```

### Database server

```json
{
  "allowedTools": ["query_*", "list_tables", "describe_table"],
  "deniedTools": ["execute", "write_query"],
  "deniedKeys": ["connection_string", "password"]
}
```

### Anything that talks to the internet

```json
{
  "allowedTools": ["fetch", "search"],
  "egressTools": ["fetch", "search", "http", "send"],
  "maxArgBytes": 65536
}
```

## Gotchas

- **An empty allowlist is not "deny all".** It means "no allowlist". Set `deniedTools` or accept everything that passes the detectors.
- **Patterns are prefixes, not globs.** `read_*` works, `*_file` does not.
- **Denied keys match the last segment.** Use exact key names, not paths.
- **Policies are not validated at startup beyond types.** A typo in a field name is silently ignored. Diff the file after editing.

## Learn mode (planned)

v0.4 will observe a session and propose a policy file. Until then, the honest way to write one is to read the server's `tools/list` and decide, tool by tool, what a compromised model should not be able to do.
