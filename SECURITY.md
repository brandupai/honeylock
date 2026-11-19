# Security policy

## Reporting a vulnerability

Do not open a public issue for a bypass. Report it privately to the maintainer listed in `package.json`, or through GitHub's private vulnerability reporting on this repository.

Include: the version, the policy in use, the `tools/call` frame that gets through, and what you expected. A failing vector added to `attacks/vectors.json` is the most useful thing you can send.

Please give 90 days before public disclosure, or less if a fix ships sooner.

## Scope

In scope: bypasses of a detector, protocol confusion through JSON-RPC framing or batches, ledger forgery that `honeylock verify` accepts, pin bypass without an accepted review, and anything that makes the proxy write non-frames to stdout.

Out of scope: the limitations already listed in the README, denial of service through sheer volume of legitimate calls, and vulnerabilities in the MCP server being proxied.

## Known limitations

The README's "What this does not do" section is part of this policy. A report that restates one of those limitations is not a vulnerability, but a report that shows one of them is worse than described is.
