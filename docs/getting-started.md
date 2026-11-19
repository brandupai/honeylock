# Getting started

Five minutes, from zero to a proxied server with a ledger you can verify.

## 1. Install

```bash
npm install -g honeylock
honeylock version
```

Requires Node 20.11 or newer. There are no runtime dependencies and no install hooks.

## 2. Wrap a server

Take the command your client already runs, and put `honeylock proxy --` in front of it.

```bash
# before
npx -y @modelcontextprotocol/server-filesystem ~/projects

# after
honeylock proxy -- npx -y @modelcontextprotocol/server-filesystem ~/projects
```

Then update the client configuration to run the `honeylock` command instead:

```json
{
  "mcpServers": {
    "files": {
      "command": "honeylock",
      "args": ["proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/you/projects"]
    }
  }
}
```

The first run creates `.honeylock/` in the working directory and pins the server's tool definitions.

## 3. Watch what happens

Diagnostics go to stderr, and the client shows them if you run it from a terminal.

```
[honeylock] key: /home/you/.honeylock/ledger.key
[honeylock] pinned 14 tool definition(s) for "npx" (trust on first use)
[honeylock] blocked read_file: block (path-traversal:path escapes workspace root (passwd) @args.path)
```

`block` refusals reach the model as a normal JSON-RPC error, so it sees the refusal and can try something else. It does not crash the session.

## 4. Read the ledger

```bash
honeylock verify
# ok: 42 events, head 2cb29fe7f1895489, key from /home/you/.honeylock/ledger.key
```

One JSON object per line:

```json
{"seq":3,"ts":"2026-11-19T16:44:39.937Z","type":"block","data":{"tool":"send_webhook","findings":[{"detector":"secret-egress","reason":"AWS access key id in tool arguments","where":"args.payload"}]},"prev":"0eadd3ae...","hmac":"7f31c0..."}
```

`prev` is the previous event's `hmac`, so removing, reordering or editing a line breaks the chain.

## 5. Tighten the policy

Start from the example:

```bash
mkdir -p .honeylock
cp node_modules/honeylock/examples/policy.json .honeylock/policy.json
```

```json
{
  "allowedTools": ["read_*", "list_*", "search", "query_*"],
  "deniedTools": ["shell_exec", "delete_*"],
  "deniedKeys": ["env", "credentials"],
  "maxArgBytes": 1000000
}
```

An empty `allowedTools` means "anything not denied". Set it when you want least privilege; that is the setting that catches a tool you never expected to be called.

## 6. Choose the workspace root

Paths are checked against `--workspace`, which defaults to the current directory.

```bash
honeylock proxy --workspace /home/you/projects -- npx -y @modelcontextprotocol/server-filesystem /home/you/projects
```

If the server is allowed to read outside that directory, the root is wrong. Point it at the widest directory the server legitimately needs.

## 7. Use it in CI

```bash
HONEYLOCK_LEDGER_KEY="$LEDGER_KEY" \
  honeylock proxy --on-review deny --policy .honeylock/policy.json -- docker run --rm -i my-mcp-server
```

Exit codes: `0` clean session, `1` verification failure (`honeylock verify`), `2` startup error such as a command that cannot be spawned.

`--on-review deny` is already the default. In CI there is nobody to approve, so keep it.

## 8. Reproduce the numbers

```bash
honeylock benchmark --iterations 500 --json benchmark.json
```

That runs `attacks/vectors.json` through the detectors, compares each verdict with the expected one, and prints p50/p99 per phase. Any mismatch exits `1`, so it can gate a release.
