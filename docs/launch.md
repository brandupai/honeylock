# Launch copy

Ready-to-paste text for the places this gets announced. Edit the parts in `[brackets]` before sending. Everything claimed here appears in the README with a number or a test behind it; please keep it that way.

## One line

> A tiny, zero-dependency proxy for MCP servers that blocks tool-call exfiltration and leaves a tamper-evident ledger.

## Short description (GitHub, npm, directories)

> honeylock sits between an MCP client and an MCP server and inspects every `tools/call`. It blocks path escapes, obfuscated shell, destructive SQL, invisible Unicode and secrets leaving the machine, pins tool definitions so a rug pull is visible, and signs every decision into a hash-chained ledger. Zero runtime dependencies, stdio only, MIT.

## Long description

> MCP gave models a way to call tools. It did not give anyone a checkpoint in the middle.
>
> honeylock is that checkpoint. One small process on the stdio pipe, no dependencies, no configuration server. It sees every JSON-RPC frame, normalises the arguments (percent decoding, quote breaking, SQL comments, invisible Unicode, base64 layers) and refuses the calls that look like an injection or an exfiltration. Refusals reach the model as an ordinary error, so the session keeps working.
>
> Two things make it different from a gateway. First, it pins what the server claims its tools do: a changed description or a new tool is blocked until a human looks, because that is exactly how a rug pull works. Second, every decision is signed into a hash-chained ledger, so "what happened" has an answer after the fact.
>
> It is not a sandbox and it does not claim immunity from prompt injection. The README lists what it does not do before it lists what it does.

## Hacker News

**Title:** Show HN: HoneyLock, a zero-dependency proxy that blocks MCP tool-call exfiltration

**Body:**

> I kept reading about MCP servers being given file and shell access, and noticed there was nothing in the middle: the client decides, the server executes, and the only thing between a poisoned document and your SSH key is the model's judgment.
>
> So I built a filter for the stdio pipe. It is not a gateway: one process, no dependencies, no config server. It normalises tool arguments and refuses the obvious shapes of attack (path escapes including double-encoded and Windows separators, quote-broken shell, SQL hidden behind comments, Unicode tag characters, keys and high-entropy blobs headed for an egress tool). It also pins `tools/list` so a server that quietly rewrites a tool description gets blocked, and writes every decision to an HMAC-chained log.
>
> The part I would most like feedback on is honesty of claims. I deliberately did not write "100% detection" anywhere. There is a benchmark with 23 vectors (5 of them benign, to catch over-blocking), p50 is 2.9 µs for a normal call, but 8.8 ms for a 1 MB argument, and the README says so. The threat model lists what is out of scope, including exfiltration that never touches a tool call.
>
> Missing on purpose in v0.1: HTTP/SSE, an interactive approver, canary tokens. Those are the roadmap. What I am unsure about is whether the detectors are the right six, and whether anyone would actually accept "blocked until reviewed" for pin drift in a CI pipeline.
>
> Repo: [link]

## Reddit, r/mcp

**Title:** I put a filter on the MCP stdio pipe: pins tool definitions and blocks exfiltration shapes

> Short version: `honeylock proxy -- npx -y @modelcontextprotocol/server-filesystem ~/projects` and every `tools/call` is inspected before it is forwarded.
>
> It does four things people asked for in other threads: path containment against a workspace root (with the encoded and Windows variants), tool-definition pinning with drift blocked until accepted, secret-shaped and high-entropy payload detection, and a signed log of every decision you can verify later.
>
> It does not do HTTP transports yet, and it has no interactive approval, so a "needs review" verdict is denied by default. That is a real limitation, not a design preference.
>
> Happy to be told the detectors are the wrong six.

## Reddit, r/netsec

**Title:** A heuristic checkpoint for MCP tool calls, with a signed decision log

> Not a sandbox, not a gateway, not a model. It is a stdio proxy that normalises tool arguments and applies six rule-based detectors, with per-phase latency numbers and a threat model that states what it cannot see.
>
> The interesting bit for this audience might be the pinning: `tools/list` is hashed per server, and changed or added tools are blocked until reviewed, because a modified description is a prompt injection that survives every content filter.
>
> The ledger is HMAC-chained with the key outside the file, so editing a line is detectable, and I am explicit that it is tamper-evident and not tamper-proof.
>
> Bypasses welcome. A failing vector in `attacks/vectors.json` is the best bug report.

## LinkedIn

> Most teams adopting MCP servers have the same gap: the agent decides, the server executes, and nothing in between checks the call.
>
> I published honeylock, a small open-source checkpoint for that gap. It sits on the stdio pipe, inspects every tool call, blocks the common exfiltration shapes, pins tool definitions so a silent update cannot widen what a tool does, and signs every decision into a verifiable log.
>
> Zero dependencies, so it is short enough to audit. And an unusually honest README: what it catches, the measured latency at 1 KB and at 1 MB, and a list of what it deliberately does not do. [link]

## X / Mastodon

> Built a checkpoint for MCP tool calls: normalises arguments, blocks path escapes, obfuscated shell, hidden Unicode and secrets heading out, pins tool definitions against rug pulls, and signs every decision into a hash-chained log.
>
> Zero dependencies. 23 vectors, 30 tests, p50 2.9 µs.
>
> It is not a sandbox and the README says so. [link]

## 30-second demo script

```
$ honeylock proxy -- npx -y @modelcontextprotocol/server-filesystem ~/projects
[honeylock] pinned 14 tool definition(s) for "npx" (trust on first use)
[honeylock] blocked read_file: block (path-traversal:path escapes workspace root @args.path)
[honeylock] blocked send_webhook: block (secret-egress:AWS access key id in tool arguments)

$ honeylock verify
ok: 5 events, head 2cb29fe7f1895489
```

Say: "the model asked for `../../etc/passwd`, it got a normal error back, and the decision is in a log I can prove was not edited."

## Portuguese, short

> O MCP deu aos modelos uma forma de chamar ferramentas. Não deu a ninguém um ponto de controlo no meio. O honeylock é isso: um processo pequeno no pipe stdio, sem dependências, que inspeciona cada `tools/call`, bloqueia fugas de caminho, shell ofuscado, Unicode invisível e segredos a sair, fixa as definições das ferramentas para que uma atualização silenciosa não as alargue, e assina cada decisão num registo encadeado.
>
> Não é uma sandbox e não promete imunidade a prompt injection. O README diz o que não faz antes de dizer o que faz.

## Assets

| File | Use |
|---|---|
| `docs/assets/logo-lockup.svg` | Mark plus wordmark, transparent, brand brown |
| `docs/assets/logo-mark.svg` | Square mark, 256×256, brand brown |
| `docs/assets/logo-mark-amber.svg` | Square mark, 256×256, amber for dark backgrounds |
| `docs/assets/favicon.svg` | App icon and site favicon, amber tile with brown mark |
| `docs/assets/social-card.png` | Social preview, 1280×640, exported by the designer |
| `docs/assets/social-card.svg` | Same card as vector source |
| `docs/assets/architecture.svg` | README body, slides |
| `docs/assets/decision-flow.svg` | Explaining what happens to one call |
| `docs/assets/latency.svg` | The performance argument, log scale |
| `docs/assets/source/*.svg` | Designer exports kept for provenance, not for publishing |

## Brand

| Token | Hex | Use |
|---|---|---|
| Amber | `#F8AC00` | Mark on dark, favicon tile, highlights |
| Brown | `#9F5007` | Mark and wordmark on light, diagram accent |
| Ink | `#1C1508` | Body text |
| Muted | `#7A6748` | Captions and secondary text |
| Paper | `#FFFCF4` | Light surfaces |

Assets are generated from the designer's CorelDRAW export by `build-brand.py` at the repository root, which crops the artwork, drops the page background and the duplicate swatch, and writes the lockup, the marks and the social card. Re-run it after any logo change rather than editing the SVGs by hand.

The name is styled **HoneyLock** in the logo and in prose; the package, the command and the paths stay lowercase (`honeylock`, `.honeylock/`).

GitHub only accepts a PNG for the social preview: upload `docs/assets/social-card.png` in the repository settings, under Social preview.
