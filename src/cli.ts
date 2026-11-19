import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import * as path from "node:path";
import { formatReport, runBenchmark, writeReport } from "./benchmark";
import { Ledger, loadLedgerKey, verifyLedgerFile } from "./ledger";
import { acceptServer, loadLock, saveLock, type McpTool } from "./lock";
import { startProxy } from "./proxy";
import { DEFAULT_POLICY, type Policy } from "./types";

const VERSION = "0.1.0";

interface ParsedArgs {
  command: string;
  flags: Map<string, string | true>;
  rest: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
  const separator = argv.indexOf("--");
  const head = separator === -1 ? argv : argv.slice(0, separator);
  const rest = separator === -1 ? [] : argv.slice(separator + 1);
  const flags = new Map<string, string | true>();
  const positional: string[] = [];

  for (let i = 0; i < head.length; i++) {
    const arg = head[i] ?? "";
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      if (eq !== -1) {
        flags.set(arg.slice(2, eq), arg.slice(eq + 1));
        continue;
      }
      const name = arg.slice(2);
      const next = head[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags.set(name, next);
        i++;
      } else {
        flags.set(name, true);
      }
      continue;
    }
    positional.push(arg);
  }

  return { command: positional[0] ?? "help", flags, rest };
}

function flagString(flags: Map<string, string | true>, name: string): string | undefined {
  const value = flags.get(name);
  return typeof value === "string" ? value : undefined;
}

function flagBool(flags: Map<string, string | true>, name: string): boolean {
  return flags.has(name) && flags.get(name) !== "false";
}

function loadPolicy(flags: Map<string, string | true>): Policy {
  const file = flagString(flags, "policy") ?? ".honeylock/policy.json";
  const workspaceRoot = realpathSync(path.resolve(flagString(flags, "workspace") ?? process.cwd()));
  let fromFile: Partial<Policy> = {};
  if (existsSync(file)) {
    fromFile = JSON.parse(readFileSync(file, "utf8")) as Partial<Policy>;
  }
  return {
    ...DEFAULT_POLICY,
    ...fromFile,
    workspaceRoot,
    maxArgBytes: Number(fromFile.maxArgBytes ?? DEFAULT_POLICY.maxArgBytes),
  };
}

function help(): string {
  return [
    `honeylock ${VERSION} - a tiny MCP proxy with a tamper-evident ledger`,
    "",
    "Usage:",
    "  honeylock proxy [options] -- <server command>   run a stdio MCP server through the proxy",
    "  honeylock pin [options] -- <server command>     review and accept current tool definitions",
    "  honeylock verify [options]                      verify the ledger chain",
    "  honeylock benchmark [options]                   run the adversarial vectors and print latencies",
    "",
    "Options:",
    "  --policy <file>        policy JSON (default .honeylock/policy.json)",
    "  --lock <file>          tool pin file (default .honeylock/lock.json)",
    "  --ledger <file>        ledger file (default .honeylock/ledger.jsonl)",
    "  --key <file>           ledger key file (default ~/.honeylock/ledger.key)",
    "  --server <name>        name used in the lock file (default: server command)",
    "  --workspace <dir>      root that file paths must stay inside (default: cwd)",
    "  --on-review allow|deny what to do when a detector asks for a human (default: deny)",
    "  --max-bytes <n>        max size of one JSON-RPC message (default: 4194304)",
    "  --strict-pins          also block tools that were added since the pin",
    "  --iterations <n>       benchmark iterations per vector (default: 500)",
    "  --json <file>          benchmark: write the full report as JSON",
    "",
    "Exit codes: 0 ok, 1 blocked or verification failure, 2 startup error.",
  ].join("\n");
}

function ledgerPath(flags: Map<string, string | true>): string {
  return flagString(flags, "ledger") ?? ".honeylock/ledger.jsonl";
}

function ensureDir(file: string): void {
  mkdirSync(path.dirname(path.resolve(file)), { recursive: true, mode: 0o700 });
}

async function discoverTools(command: string[], timeoutMs = 8000): Promise<McpTool[]> {
  const [cmd, ...args] = command;
  if (!cmd) throw new Error("no server command given");
  const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });

  return new Promise<McpTool[]>((resolve, reject) => {
    let buffer = "";
    let stage: "init" | "list" = "init";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`server did not answer tools/list within ${timeoutMs} ms`));
    }, timeoutMs);

    const done = (tools: McpTool[]): void => {
      clearTimeout(timer);
      child.kill();
      resolve(tools);
    };

    child.stdout.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      let index = buffer.indexOf("\n");
      while (index !== -1) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        index = buffer.indexOf("\n");
        if (line === "") continue;
        let msg: Record<string, unknown>;
        try {
          msg = JSON.parse(line) as Record<string, unknown>;
        } catch {
          continue;
        }
        if (stage === "init" && msg["id"] === 1) {
          stage = "list";
          child.stdin.write(
            `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} })}\n`,
          );
          child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })}\n`);
          continue;
        }
        if (stage === "list" && msg["id"] === 2) {
          const result = msg["result"] as Record<string, unknown> | undefined;
          const tools = result?.["tools"];
          if (Array.isArray(tools)) done(tools as McpTool[]);
          else reject(new Error("tools/list returned no tools array"));
          return;
        }
      }
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "honeylock", version: VERSION } },
      })}\n`,
    );
  });
}

async function main(argv: string[]): Promise<number> {
  const { command, flags, rest } = parseArgs(argv);

  switch (command) {
    case "help":
    case "--help":
      process.stdout.write(`${help()}\n`);
      return 0;

    case "version":
    case "--version":
      process.stdout.write(`${VERSION}\n`);
      return 0;

    case "verify": {
      const file = ledgerPath(flags);
      if (!existsSync(file)) {
        process.stdout.write(`no ledger at ${file}\n`);
        return 0;
      }
      const { key, source } = loadLedgerKey(flagString(flags, "key"));
      const result = verifyLedgerFile(file, key);
      if (result.ok) {
        const last = result.records[result.records.length - 1];
        process.stdout.write(
          `ok: ${result.records.length} events, head ${last ? last.hmac.slice(0, 16) : "genesis"}, key from ${source}\n`,
        );
        return 0;
      }
      process.stderr.write(`ledger does not verify: ${result.error ?? "unknown error"}\n`);
      return 1;
    }

    case "benchmark": {
      const policy = loadPolicy(flags);
      const iterations = Number(flagString(flags, "iterations") ?? 500);
      const ledgerFile = flagString(flags, "bench-ledger");
      const local = path.resolve(__dirname, "../../attacks/vectors.json");
      const report = runBenchmark({
        file: existsSync(local) ? local : path.resolve("attacks/vectors.json"),
        policy,
        iterations: Number.isFinite(iterations) && iterations > 0 ? iterations : 500,
        ledgerFile,
      });
      process.stdout.write(`${formatReport(report)}\n`);
      const jsonFile = flagString(flags, "json");
      if (jsonFile) {
        writeReport(report, jsonFile);
        process.stdout.write(`\nfull report written to ${jsonFile}\n`);
      }
      return report.passed === report.total ? 0 : 1;
    }

    case "pin": {
      if (rest.length === 0) {
        process.stderr.write("usage: honeylock pin -- <server command>\n");
        return 2;
      }
      const server = flagString(flags, "server") ?? path.basename(rest[0] ?? "server");
      const lockFile = flagString(flags, "lock") ?? ".honeylock/lock.json";
      const tools = await discoverTools(rest);
      const lock = acceptServer(loadLock(lockFile), server, tools);
      ensureDir(lockFile);
      saveLock(lockFile, lock);
      process.stdout.write(`pinned ${tools.length} tool definition(s) for "${server}" in ${lockFile}\n`);
      return 0;
    }

    case "proxy": {
      if (rest.length === 0) {
        process.stderr.write("usage: honeylock proxy -- <server command>\n");
        return 2;
      }
      const policy = loadPolicy(flags);
      const file = ledgerPath(flags);
      ensureDir(file);
      const { key, source } = loadLedgerKey(flagString(flags, "key"));
      process.stderr.write(`[honeylock] key: ${source}\n`);
      const ledger = new Ledger(file, key);
      const maxBytes = Number(flagString(flags, "max-bytes") ?? 4 * 1024 * 1024);
      return await startProxy({
        command: rest,
        policy,
        ledger,
        lockPath: flagString(flags, "lock") ?? ".honeylock/lock.json",
        serverName: flagString(flags, "server") ?? path.basename(rest[0] ?? "server"),
        onReview: flagString(flags, "on-review") === "allow" ? "allow" : "deny",
        maxMessageBytes: Number.isFinite(maxBytes) ? maxBytes : 4 * 1024 * 1024,
        strictPins: flagBool(flags, "strict-pins"),
      });
    }

    default:
      process.stderr.write(`unknown command: ${command}\n\n${help()}\n`);
      return 2;
  }
}

export function run(argv: string[]): void {
  main(argv)
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err: unknown) => {
      process.stderr.write(`[honeylock] ${(err as Error).message}\n`);
      process.exitCode = 2;
    });
}
