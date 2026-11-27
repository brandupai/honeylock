import { spawn } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import type { Ledger } from "./ledger";
import { acceptServer, blockedFromChanges, compareTools, formatChanges, loadLock, saveLock, type McpTool } from "./lock";
import { evaluate, summarize } from "./pipeline";
import type { Policy } from "./types";

export interface ProxyOptions {
  command: string[];
  policy: Policy;
  ledger: Ledger;
  lockPath: string;
  serverName: string;
  /** What to do when a detector asks for a human: v0.1 has no approver, so deny by default. */
  onReview: "deny" | "allow";
  maxMessageBytes: number;
  strictPins: boolean;
}

const BLOCK_CODE = -32001;
const INVALID_CODE = -32600;
const PARSE_CODE = -32700;

function log(message: string): void {
  process.stderr.write(`[honeylock] ${message}\n`);
}

function errorResponse(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

interface LineOptions {
  maxBytes: number;
  onLine: (line: string) => void;
  onOverflow: (bytes: number) => void;
}

/** Splits a byte stream into lines, with a hard cap so one frame cannot exhaust memory. */
function pipeLines(stream: Readable, opts: LineOptions): void {
  let pending: Buffer[] = [];
  let size = 0;
  stream.on("data", (chunk: Buffer) => {
    let start = 0;
    for (let i = 0; i < chunk.length; i++) {
      if (chunk[i] !== 0x0a) continue;
      pending.push(chunk.subarray(start, i));
      const line = Buffer.concat(pending).toString("utf8").replace(/\r$/, "");
      pending = [];
      size = 0;
      start = i + 1;
      opts.onLine(line);
    }
    if (start < chunk.length) {
      const rest = chunk.subarray(start);
      pending.push(rest);
      size += rest.length;
      if (size > opts.maxBytes) {
        const overflowed = size;
        pending = [];
        size = 0;
        opts.onOverflow(overflowed);
      }
    }
  });
}

export function startProxy(opts: ProxyOptions): Promise<number> {
  const [cmd, ...args] = opts.command;
  if (!cmd) throw new Error("no server command given");

  const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
  const blockedTools = new Set<string>();
  const pending = new Map<string, string>();

  const client = process.stdout as Writable;
  const send = (msg: unknown): void => {
    if (!client.writable) return;
    client.write(`${JSON.stringify(msg)}\n`);
  };
  const forward = (msg: unknown): void => {
    if (child.stdin.writable) child.stdin.write(`${JSON.stringify(msg)}\n`);
  };
  const record = (type: string, data: Record<string, unknown>): void => {
    try {
      opts.ledger.append(type, data);
    } catch (err) {
      log(`ledger write failed: ${(err as Error).message}`);
    }
  };

  const ctx = { policy: opts.policy, root: opts.policy.workspaceRoot };

  /**
   * One tools/list can span several pages (nextCursor). The pin is compared against
   * everything seen so far in the listing, never against a single page, so a
   * changed tool on page 2 cannot be unblocked by page 3, and tools on later pages
   * are not mistaken for additions.
   */
  interface Listing {
    tools: Map<string, McpTool>;
    firstPin: boolean | undefined;
    reported: Set<string>;
  }
  let listing: Listing | undefined;

  const handlePin = (tools: McpTool[], final: boolean): void => {
    const current: Listing = listing ?? (listing = { tools: new Map(), firstPin: undefined, reported: new Set() });
    for (const tool of tools) current.tools.set(tool.name, tool);
    const all = [...current.tools.values()];
    const lock = loadLock(opts.lockPath);
    if (current.firstPin === undefined) current.firstPin = lock.servers[opts.serverName] === undefined;

    if (current.firstPin) {
      saveLock(opts.lockPath, acceptServer(lock, opts.serverName, all));
      if (final) {
        record("pin", { server: opts.serverName, tools: all.length, mode: "tofu" });
        log(`pinned ${all.length} tool definition(s) for "${opts.serverName}" (trust on first use)`);
      }
      return;
    }

    const { changes, next } = compareTools(lock, opts.serverName, all, { partial: !final });
    const blockedNow = blockedFromChanges(changes);
    // While pages are still arriving, keep blocking tools from the previous listing
    // that this listing has not reached yet.
    if (!final) for (const name of blockedTools) if (!current.tools.has(name)) blockedNow.add(name);
    blockedTools.clear();
    for (const name of blockedNow) blockedTools.add(name);

    const fresh = changes.filter((c) => !current.reported.has(`${c.kind}:${c.tool}`));
    if (changes.length === 0) return;

    saveLock(opts.lockPath, next);
    if (fresh.length === 0) return;
    for (const c of fresh) current.reported.add(`${c.kind}:${c.tool}`);
    record("tool-drift", {
      server: opts.serverName,
      changes: fresh.map((c) => ({ tool: c.tool, kind: c.kind, fields: c.fields })),
    });
    log(`tool definitions changed for "${opts.serverName}"; blocking until reviewed:`);
    log(formatChanges(fresh));
    log("review with `honeylock pin -- <server command>` once you accept the change");
  };

  const classify = (item: unknown): { forward?: unknown; responses: unknown[] } => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      record("invalid", { reason: "not a JSON-RPC object" });
      return { responses: [errorResponse(null, INVALID_CODE, "honeylock: invalid JSON-RPC message")] };
    }
    const msg = item as Record<string, unknown>;
    const method = typeof msg["method"] === "string" ? msg["method"] : undefined;
    const id = msg["id"];

    if (msg["jsonrpc"] !== "2.0") {
      record("invalid", { reason: "missing jsonrpc 2.0" });
      return { responses: [errorResponse(id, INVALID_CODE, "honeylock: invalid JSON-RPC message")] };
    }

    if (method !== "tools/call") {
      if (method === "tools/list") {
        const listParams = msg["params"];
        const cursor = listParams !== null && typeof listParams === "object" ? (listParams as Record<string, unknown>)["cursor"] : undefined;
        if (cursor === undefined) listing = undefined; // a new listing starts at the first page
      }
      if (method && id !== undefined) pending.set(String(id), method);
      return { forward: msg, responses: [] };
    }

    const params = (msg["params"] ?? {}) as Record<string, unknown>;
    const toolName = params["name"];
    if (typeof toolName !== "string") {
      record("block", { reason: "tools/call without a tool name" });
      return {
        responses: [errorResponse(id, INVALID_CODE, "honeylock: tools/call without params.name")],
      };
    }

    if (blockedTools.has(toolName)) {
      record("block", { tool: toolName, reason: "tool definition changed since pin" });
      return {
        responses: [errorResponse(id, BLOCK_CODE, `honeylock: blocked: "${toolName}" definition is not pinned`)],
      };
    }

    const decision = evaluate({ id: id as string | number | null, tool: toolName, args: params["arguments"] }, ctx);

    if (decision.verdict === "block") {
      record("block", {
        tool: toolName,
        verdict: decision.verdict,
        findings: decision.findings.map((f) => ({ detector: f.detector, reason: f.reason, where: f.where })),
        ms: Number(((decision.phasesUs["collect"] ?? 0) + (decision.phasesUs["scan"] ?? 0)) / 1000).toFixed(2),
      });
      log(`blocked ${toolName}: ${summarize(decision)}`);
      return {
        responses: [errorResponse(id, BLOCK_CODE, `honeylock: blocked: ${summarize(decision)}`)],
      };
    }

    if (decision.verdict === "review" && opts.onReview === "deny") {
      record("review-denied", { tool: toolName, findings: decision.findings });
      log(`needs review, denied (no interactive approver): ${summarize(decision)}`);
      return {
        responses: [errorResponse(id, BLOCK_CODE, `honeylock: needs approval: ${summarize(decision)}`)],
      };
    }

    record(decision.verdict === "review" ? "review-allowed" : "allow", {
      tool: toolName,
      findings: decision.findings.map((f) => ({ detector: f.detector, reason: f.reason })),
    });
    if (id !== undefined) pending.set(String(id), "tools/call");
    return { forward: msg, responses: [] };
  };

  const handleClientLine = (raw: string): void => {
    const line = raw.trim();
    if (line === "") return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      record("invalid", { reason: "json parse error" });
      send(errorResponse(null, PARSE_CODE, "honeylock: parse error"));
      return;
    }
    if (Array.isArray(parsed)) {
      const allowed: unknown[] = [];
      for (const item of parsed) {
        const { forward: keep, responses } = classify(item);
        if (keep !== undefined) allowed.push(keep);
        for (const response of responses) send(response);
      }
      if (allowed.length > 0) forward(allowed);
      return;
    }
    const { forward: keep, responses } = classify(parsed);
    for (const response of responses) send(response);
    if (keep !== undefined) forward(keep);
  };

  const handleServerLine = (raw: string): void => {
    const line = raw.trim();
    if (line === "") return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      log("server sent a line that is not JSON; passing it through untouched");
      client.write(`${line}\n`);
      return;
    }
    const obj = parsed as Record<string, unknown>;
    const id = obj["id"];
    if (id !== undefined && id !== null) {
      const method = pending.get(String(id));
      pending.delete(String(id));
      const result = obj["result"] as Record<string, unknown> | undefined;
      const tools = result?.["tools"];
      if (method === "tools/list" && Array.isArray(tools)) {
        const nextCursor = result?.["nextCursor"];
        handlePin(tools as McpTool[], typeof nextCursor !== "string" || nextCursor === "");
      }
    }
    client.write(`${line}\n`);
  };

  pipeLines(process.stdin, {
    maxBytes: opts.maxMessageBytes,
    onLine: handleClientLine,
    onOverflow: () => {
      record("block", { reason: "client message exceeded max size" });
      log(`client message exceeded ${opts.maxMessageBytes} bytes; dropped`);
    },
  });

  pipeLines(child.stdout, {
    maxBytes: opts.maxMessageBytes,
    onLine: handleServerLine,
    onOverflow: () => log(`server message exceeded ${opts.maxMessageBytes} bytes; dropped`),
  });

  child.stderr.on("data", (chunk: Buffer) => process.stderr.write(chunk));

  child.on("error", (err) => {
    log(`cannot start server: ${err.message}`);
    process.exitCode = 2;
    record("error", { reason: "spawn failed" });
  });

  process.stdin.on("end", () => child.stdin.end());
  process.on("SIGINT", () => child.kill("SIGINT"));

  return new Promise<number>((resolve) => {
    child.on("close", (code) => {
      record("session-end", { exitCode: code ?? -1 });
      resolve(code ?? 0);
    });
  });
}
