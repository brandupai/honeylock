# Changelog

Dates are ISO. This project follows [Semantic Versioning](https://semver.org/).

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
