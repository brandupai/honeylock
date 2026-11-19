# FAQ

**Is this a sandbox?**

No. It inspects arguments, not effects. A command that passes the checks still runs with your permissions.

**Why not just use the client's permission prompts?**

Prompts ask the human per call, which is the right idea and fails in practice: after the twentieth dialog people click approve without reading, and the description in the dialog comes from the server being judged. A policy plus a ledger complements prompts; it does not replace good ones.

**Why zero dependencies?**

Because the tool's only job is to be trusted between two things, and every dependency is another party in that trust relationship. It also means `npx` works with no install step and no supply-chain surface beyond Node itself. The cost is that framing, argument parsing and process plumbing are all in this repository, which is more code to review — hence the size is stated up front.

**Does it slow my agent down?**

Measured, on Linux arm64 with Node 24: 2.9 µs p50 for a normal-sized tool call, 872 µs p50 at 100 KB of arguments, 8.8 ms at 1 MB. Compare that with a network round trip to any hosted model. The full table is in the README, and `honeylock benchmark` reproduces it on your machine.

**How many false positives should I expect?**

Unknown, and that is a gap. v0.1 ships 23 vectors, of which five are benign cases used to catch over-blocking. v0.2 adds a corpus of real tool calls and a published false-positive rate, because a security tool that cries wolf gets switched off, and a switched-off tool protects nothing.

**It blocked something legitimate. What do I do?**

Read the reason in the ledger entry: it names the detector and the argument path. Then either tighten the policy (add a narrower `allowedTools` entry), or widen the detector by sending a vector that shows the legitimate shape. Do not reach for `--on-review allow` first; it turns a refusal into a warning with the same false-positive rate.

**Why is a tool blocked after I updated my MCP server?**

The pin changed. Renaming a tool, rewording a description or adding a parameter all change the hash, and a changed description is precisely how a rug pull rewrites what the model is told. Review the diff and accept:

```bash
honeylock pin -- npx -y @modelcontextprotocol/server-filesystem ~/projects
```

**Can I run it in a pipeline with no TTY?**

Yes. `review` is denied by default, which is what you want with nobody to ask. Pass the key through `HONEYLOCK_LEDGER_KEY` and check the exit code.

**Does it work with HTTP transports?**

Not yet. v0.5. Streamable HTTP needs origin validation, session rewriting, resumability and careful token handling; doing half of it would be worse than doing none.

**How is this different from an MCP gateway?**

Gateways run many servers, handle auth and routing, and usually live in a container or a service. This is one process on one stdio pipe with no configuration server, whose interesting output is a file you can read. If you need central policy for twenty servers, use a gateway. If you need a checkpoint that fits in a code review, this is aimed at you.

**What is the licence, and can I use it commercially?**

MIT. Yes.

**Who is behind it?**

An open-source project with no company attached. That is worth knowing when you decide how much to rely on it in production.

**Why "honeylock"?**

It points at the two ideas the tool is built on: a canary (honey) for stolen credentials, and a lock for what a tool is allowed to do. Checked on 19 November 2026, the npm name `honeylock` is free and the GitHub handle has only a handful of unrelated repositories. If the name changes, the repository and package move together.
