# Troubleshooting

## The client hangs or says the server sent invalid JSON

Something wrote to `stdout` that is not a JSON-RPC frame. It is almost always a `console.log` added to the code, or the server printing a banner at startup.

Check with:

```bash
honeylock proxy -- node -e 'console.log("oops"); setInterval(()=>{},1000)'
```

You will see the stray line pass through, and a correct client will choke on it. Fix the source: diagnostics belong on stderr, which `honeylock` forwards untouched.

## Everything is blocked

Look at the first ledger entry:

```bash
jq -r 'select(.type=="block") | [.ts, .data.tool, .data.findings[0].detector, .data.findings[0].reason] | @tsv' .honeylock/ledger.jsonl | head
```

- `policy` and "tool is not in the allowlist": your `allowedTools` is too narrow, or the server renamed a tool.
- `path-traversal` and "path escapes workspace root": `--workspace` is not the directory the server actually works in. Common when the client starts the server from `/`.
- `secret-egress` and "high-entropy value passed to an egress-capable tool": a hash or an opaque ID is being sent somewhere. Narrow `egressTools` rather than disabling the detector. High-entropy detection is the one that most often needs tuning.
- `shell-injection` and "command substitution": a legitimate tool uses `$(...)`. That is a `review` verdict, denied by default; decide per tool with an allowlist entry.

## "definition is not pinned"

A tool's name, description or schema changed since it was pinned. That is the rug-pull check working.

```bash
honeylock pin -- <the same server command>
```

Read the diff in `git diff .honeylock/lock.json` before you accept. If you did not update the server, do not accept: investigate what changed.

## `honeylock verify` says "signature mismatch"

Either the file was edited after the fact, or the key is different from the one that wrote it. Check which key you are using:

```bash
honeylock verify        # prints the key source
echo $HONEYLOCK_LEDGER_KEY | wc -c
```

If you rotated keys, verify the old ledger with the old key. If you have no idea what changed, treat the ledger as untrustworthy from that line onwards.

## "refusing to append to a ledger that does not verify"

The proxy refuses to extend a chain that is already broken, which is deliberate: appending would launder the damage. Move the file aside and start a new one.

```bash
mv .honeylock/ledger.jsonl .honeylock/ledger-broken-$(date +%s).jsonl
```

## "ledger is locked by another writer"

Another proxy has held `ledger.jsonl.lock` for more than five seconds. Locks older than ten seconds are taken over automatically, so this usually means a slow disk or a very busy shared ledger. Give each server its own file with `--ledger`, or delete a lock you know is orphaned.

## Windows: paths or exit codes look odd

- Path containment compares resolved strings, so a case-insensitive filesystem can produce a false negative (a file differing only in case is treated as outside). Report it if you hit it.
- Shell detection understands both separators, but PowerShell-specific syntax is not modelled. Treat `shell-injection` as weaker on Windows.
- If `npm test` fails only on the glob, run `node --test "dist/test/*.test.js"` directly; the quoted pattern is expanded by Node 22+.

## Performance is worse than the README numbers

Check the shape of your arguments, not the machine. A 1 MB argument is 3 000 times slower than a 1 KB one. If your tool calls carry large payloads, the cost is in `collect` and `decode`, and the fix is to cap `maxArgBytes` and pass references instead of bodies.

## The server works without the proxy but not through it

Run the same command with the proxy and watch stderr:

```bash
honeylock proxy -- <command> 2>proxy.log
tail -20 proxy.log
```

Common causes: a server that requires a TTY, a server that reads `process.stdin` in raw mode, or a command that writes more than `--max-bytes` in one frame. Raise the limit explicitly if the last one applies, and report it: the default should be comfortable for real servers.

## Nothing appears in `.honeylock/`

The proxy creates it in the working directory of the process, which is the client's directory, not yours. Either pass absolute paths (`--ledger`, `--lock`, `--policy`) or set the client's working directory.
