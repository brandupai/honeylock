# Contributing

The most useful contribution is a **failing vector**: an input that gets the wrong verdict, added to `attacks/vectors.json` with an `expect` value and a one-line `why`. A bug report in prose is hard to act on; a vector with a failing benchmark is a fix waiting to happen.

## Setup

```bash
git clone https://github.com/brandupai/honeylock
cd honeylock
npm ci
npm run build
npm test
node dist/src/index.js benchmark
```

Node 20.11 or newer. There are no runtime dependencies and there will not be any; `scripts/check-deps.js` enforces it, along with a ban on install hooks.

## Adding a vector

```json
{
  "id": "path-07",
  "category": "path-traversal",
  "tool": "read_file",
  "args": { "path": "docs/..%2f..%2fetc/passwd" },
  "expect": "block",
  "why": "partially encoded separator inside a plausible path"
}
```

Rules:

- `id` is `category-number`. Do not renumber existing vectors.
- Include a **benign** vector whenever you loosen a detector. Over-blocking is a security failure too, because a tool that cries wolf gets turned off.
- `why` explains the attack, not the regex.
- No weaponised payloads. No live exfiltration URLs, no real credentials, no code that would work against a third party. Canaries are fine if they are obviously fake and point at a domain you own.

## Changing a detector

A detector is a pure function from `(call, refs, context)` to `Finding[]`. Keep it that way:

- No network, no writes, no `Date.now()` in the decision path.
- Filesystem access only for `realpath` on paths that already exist.
- Return `review` when a human should decide, `block` when there is no legitimate reason to proceed.
- Never include the matched value in `reason`. It ends up in the ledger, and the ledger ends up in bug reports.

Any change needs a positive and a negative test in `test/detectors.test.ts`, and a vector if it is a new attack shape.

## Changing the proxy

`src/proxy.ts` holds the invariants that matter: clean `stdout`, streaming size cap, batch unpacking, record-before-refuse, fail closed. Tests there spawn real processes rather than mocks, because the protocol is the product. If you add a transport, add a fixture server that misbehaves, not only one that cooperates.

## Style

- TypeScript strict, no `any` in new code without a comment explaining the boundary it crosses.
- Comments explain why, not what.
- Commit messages: what changed and why it matters, in the imperative.

## Review criteria

A change is ready when:

1. `npm test` and `npm run benchmark` pass on Linux, macOS and Windows (CI runs all three).
2. No new dependency, including a devDependency that runs at install time.
3. Any new claim in the docs is backed by a number the benchmark prints, or by a test.
4. The README's "What this does not do" section is still true.

Point 4 is the one reviewers should be strictest about. A tool like this loses its value the moment its documentation is more confident than its code.

## Security reports

Do not open a public issue for a bypass. See [SECURITY.md](SECURITY.md).
