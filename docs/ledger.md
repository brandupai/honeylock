# The ledger

Every decision is written to `.honeylock/ledger.jsonl` before the client is told about it. The file is append-only, one JSON object per line, and each line is signed with a key that is not stored next to it.

## Format

```json
{
  "seq": 7,
  "ts": "2026-11-19T16:44:39.947Z",
  "type": "block",
  "data": { "tool": "read_file", "findings": [{ "detector": "path-traversal", "reason": "path escapes workspace root", "where": "args.path" }] },
  "prev": "0eadd3aeeaeb8293c3a814b0d24c3e98a8455430b9bc7d...",
  "hmac": "f1dbf81398277957d1663856d763799fbd59afc656fca2a17b3c8b4db0820f82"
}
```

The signature is:

```
HMAC-SHA256(key, seq + "\n" + ts + "\n" + type + "\n" + canonicalJSON(data) + "\n" + prev)
```

`canonicalJSON` sorts object keys, so the same event always produces the same signature on every platform.

## Several proxies, one ledger

Wrapping more than one server from the same folder makes every proxy append to the same file. Appends take a lock file (`ledger.jsonl.lock`) and continue from the real tail, so the chain stays single and verifiable. A lock left by a crashed proxy is taken over after 10 seconds. If an append waits more than 5 seconds for the lock it fails with `ledger is locked by another writer`, and the proxy logs it on `stderr`. One ledger per server (`--ledger`) avoids the shared lock entirely.

## Event types

| Type | When | Useful for |
|---|---|---|
| `allow` | A call passed every detector | Reconstructing normal behaviour |
| `block` | A call was refused | The incident itself |
| `review-denied` | A detector asked for a human and none was available | Tuning false positives |
| `review-allowed` | `--on-review allow` let a flagged call through | Explaining a decision after the fact |
| `pin` | First sight of a server | When you started trusting which definitions |
| `tool-drift` | Changed, added or removed tools | The rug-pull moment |
| `invalid` | Malformed JSON-RPC, batch item, oversize frame | Client or attacker probing |
| `session-end` | The server process exited | Session boundaries |
| `error` | Startup failure | Diagnosing a bad command |

## What it proves

- The sequence of decisions in this file is intact: no line edited, reordered or inserted after the fact, and no gap in the middle.
- Each line was written by something holding the key.

## What it does not prove

- That the events were written honestly in the first place. A compromised proxy writes convincing lies.
- That nothing happened outside the proxy. A direct network call by the server does not appear here.
- That the file is complete. Deleted trailing lines are only detectable with an external anchor: after a truncation `honeylock verify` still says `ok`, with a smaller event count.

If you need more than that, export the head hash.

## Key management

Resolution order:

1. `HONEYLOCK_LEDGER_KEY` (any string of 16+ characters).
2. `--key <file>`.
3. `~/.honeylock/ledger.key`, created with mode `0600` on first run.

```bash
export HONEYLOCK_LEDGER_KEY="$(openssl rand -hex 32)"
```

For a team, keep the key in a secret manager and inject it at runtime. For a single machine, the default key file is fine, and it keeps the ledger usable if the repository is shared.

Losing the key means the old ledger can no longer be verified. That is the point: a verifier that works without the key proves nothing.

## Rotating

There is no rotation command in v0.1. The supported pattern is:

```bash
mv .honeylock/ledger.jsonl .honeylock/ledger-2026-11.jsonl
honeylock verify --ledger .honeylock/ledger-2026-11.jsonl   # with the old key
# start a new ledger with a new key
```

Record the head hash of the closed file somewhere outside the machine, and include it in the new ledger's first event by hand if you need a link between them.

## Anchoring

A chain is only as strong as its head. Publish it:

```bash
tail -1 .honeylock/ledger.jsonl | jq -r .hmac
```

Put that in a commit message, a signed tag, a gist you do not control, or a ticket. Now deleting the tail requires changing a record you do not own.

## Querying

It is JSONL, so the tools are already on the machine:

```bash
# everything blocked today
jq -r 'select(.type=="block") | [.ts, .data.tool, .data.findings[0].detector] | @tsv' .honeylock/ledger.jsonl

# how often each detector fired
jq -r 'select(.type=="block") | .data.findings[].detector' .honeylock/ledger.jsonl | sort | uniq -c | sort -rn

# when the tool definitions changed
jq -r 'select(.type=="tool-drift") | [.ts, .data.server, (.data.changes|length)] | @tsv' .honeylock/ledger.jsonl
```

That third query is the one worth putting in a weekly habit: it answers "did anything about my tools change without me noticing".
