# Changelog

Dates are ISO. This project follows [Semantic Versioning](https://semver.org/).

## Unreleased (0.1.1)

### Fixed

- **Ledger with several writers.** Proxies sharing one ledger file each kept their own sequence number, so `verify` failed and the next proxy refused to start. Appends now take a lock file and continue from the real tail. Cost: ledger append p50 about 8.5 µs to about 18 µs on Linux x64, Node 22 (three runs each).
- **Pinning with paginated `tools/list`.** Later pages were reported as added tools, and a changed tool on an earlier page was unblocked by a later page. The pin is now compared against the whole listing, and `honeylock pin` follows `nextCursor`.
- **SQL comment handling.** `#` and `--` inside strings, and Postgres `#>` / `#-` operators, were treated as comments and hid a following `DROP`. SQL is now split into code and comments with quoting respected. A destructive statement inside a comment is a `review`.
- **Secrets**: percent-encoded keys are decoded, and base64 is decoded up to three layers (was two).
- **Paths**: `file://` URLs, `~` and `$HOME` are expanded before the containment check.
- **README** claimed that truncation of the ledger is caught. It is not, without an external head hash. The text now says so.

### Changed

- 33 vectors (8 benign) and 44 tests. `test/vectors.test.ts` runs the whole vector file as part of the suite and the CI.
- Shell and SQL limitations that were found while testing are now listed in the README.

## 0.1.0 — 2026-11-19

First public version. Scope was chosen so that everything shipped is measured, and everything unmeasured is listed as missing.

### Added

- **stdio proxy** for MCP servers: newline-delimited JSON-RPC, batch unpacking, 4 MB frame cap enforced while streaming, clean `stdout`, diagnostics on `stderr`.
- **Detectors**, pure functions with timings per phase:
  - `path-traversal`: iterative percent decoding, Windows separators, NUL bytes, `realpath` symlink resolution.
  - `shell-injection`: quote and flag normalisation, recursive delete, piped-to-shell, reverse shells, eval, log tampering.
  - `sql-obfuscation`: comment stripping before matching, unbounded delete/update, union and tautology patterns.
  - `unicode-smuggling`: tag characters, zero-width, BiDi controls.
  - `secret-egress`: known key formats, private key headers, JWTs, database URLs, decoded base64/hex layers, entropy for egress-capable tools.
  - `policy`: allowlist, denylist, denied argument keys, argument size cap.
- **Tool pinning**: `tools/list` hashed per server, changed and added tools blocked until accepted, `honeylock pin` to review and accept.
- **Ledger**: HMAC-SHA256 chained JSONL, `honeylock verify`, key from `HONEYLOCK_LEDGER_KEY`, `--key`, or `~/.honeylock/ledger.key` at mode `0600`.
- **Benchmark**: 23 vectors (5 benign), per-phase p50/p99, JSON output, non-zero exit on a verdict mismatch.
- **CLI**: `proxy`, `pin`, `verify`, `benchmark`, `version`, `help`.
- **Docs**: getting started, policy reference, ledger, threat model, FAQ, troubleshooting, architecture, three diagrams.
- **CI**: Linux, macOS and Windows on Node 20, 22 and 24; dependency and install-hook check.
- **Tests**: 30, covering decoders, every detector with positive and negative cases, ledger tampering and reordering, pinning, and end-to-end proxy runs including a simulated rug pull.

### Known limitations

No HTTP/SSE transport. No interactive approver, so `review` is denied. No canary tokens. Path containment is string based, so a case-insensitive filesystem can produce a false negative. Detectors are heuristics and documented as such. See the README for the full list.

### Measured

23/23 vectors matched. Pipeline p50 2.9 µs and p99 38.6 µs for typical frames; 872 µs at 100 KB and 8.8 ms at 1 MB of arguments, on Linux arm64 with Node 24.21.
