import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { verifyLedgerFile } from "../src/ledger";

const entry = path.resolve(__dirname, "../src/index.js");
const fixture = path.resolve(__dirname, "../../test/fixtures/server.js");
const TEST_KEY = "test-key-0123456789abcdef0123456789";

interface Envelope {
  id?: unknown;
  method?: unknown;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

class Harness {
  readonly messages: Envelope[] = [];
  readonly stderr: string[] = [];
  private buffer = "";

  constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    readonly dir: string,
  ) {
    child.stdout.on("data", (chunk: Buffer) => {
      this.buffer += chunk.toString("utf8");
      let index = this.buffer.indexOf("\n");
      while (index !== -1) {
        const line = this.buffer.slice(0, index).trim();
        this.buffer = this.buffer.slice(index + 1);
        index = this.buffer.indexOf("\n");
        if (line !== "") this.messages.push(JSON.parse(line) as Envelope);
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      this.stderr.push(chunk.toString("utf8"));
    });
  }

  send(message: unknown): void {
    this.child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  async waitFor(predicate: (m: Envelope) => boolean, label: string, timeoutMs = 8000): Promise<Envelope> {
    const started = Date.now();
    for (;;) {
      const found = this.messages.find(predicate);
      if (found) return found;
      if (Date.now() - started > timeoutMs) {
        throw new Error(`timed out waiting for ${label}. stderr: ${this.stderr.join("")}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  async close(): Promise<number | null> {
    this.child.stdin.end();
    return await new Promise<number | null>((resolve) => this.child.on("close", (code) => resolve(code)));
  }
}

function startProxy(dir: string, env: NodeJS.ProcessEnv = {}): Harness {
  const child = spawn(
    process.execPath,
    [
      entry,
      "proxy",
      "--workspace",
      dir,
      "--lock",
      path.join(dir, "lock.json"),
      "--ledger",
      path.join(dir, "ledger.jsonl"),
      "--server",
      "fixture",
      "--",
      process.execPath,
      fixture,
    ],
    {
      env: { ...process.env, HONEYLOCK_LEDGER_KEY: TEST_KEY, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  return new Harness(child, dir);
}

function tempDir(): string {
  return mkdtempSync(path.join(os.tmpdir(), "honeylock-proxy-"));
}

test("allowed calls pass through, malicious ones are blocked and logged", async () => {
  const dir = tempDir();
  const harness = startProxy(dir);

  harness.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } });
  await harness.waitFor((m) => m.id === 1, "initialize response");

  harness.send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  const list = await harness.waitFor((m) => m.id === 2, "tools/list response");
  assert.equal((list.result?.["tools"] as unknown[]).length, 3);
  assert.ok(existsSync(path.join(dir, "lock.json")), "first run should write the pin file");

  harness.send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "echo", arguments: { text: "hi" } } });
  const allowed = await harness.waitFor((m) => m.id === 3, "allowed call");
  assert.equal(allowed.error, undefined);
  assert.ok(JSON.stringify(allowed.result).includes("called:echo"));

  harness.send({
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: { name: "read_file", arguments: { path: "../../etc/passwd" } },
  });
  const blocked = await harness.waitFor((m) => m.id === 4, "blocked call");
  assert.equal(blocked.error?.code, -32001);
  assert.match(blocked.error?.message ?? "", /path-traversal/);

  const code = await harness.close();
  assert.equal(code, 0);

  const verified = verifyLedgerFile(path.join(dir, "ledger.jsonl"), Buffer.from(TEST_KEY, "utf8"));
  assert.equal(verified.ok, true);
  assert.ok(verified.records.some((r) => r.type === "block"));
  assert.ok(verified.records.some((r) => r.type === "allow"));
  rmSync(dir, { recursive: true, force: true });
});

test("a JSON-RPC batch is unpacked and only the malicious item is refused", async () => {
  const dir = tempDir();
  const harness = startProxy(dir);

  harness.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  await harness.waitFor((m) => m.id === 1, "initialize response");
  harness.send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  await harness.waitFor((m) => m.id === 2, "tools/list response");

  harness.send([
    { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "echo", arguments: { text: "ok" } } },
    {
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "send_webhook", arguments: { payload: "AKIAIOSFODNN7EXAMPLE" } },
    },
  ]);

  const ok = await harness.waitFor((m) => m.id === 5, "batch item that should pass");
  assert.equal(ok.error, undefined);
  const refused = await harness.waitFor((m) => m.id === 6, "batch item that should be blocked");
  assert.equal(refused.error?.code, -32001);

  const code = await harness.close();
  assert.equal(code, 0);
  rmSync(dir, { recursive: true, force: true });
});

test("a changed tool description is blocked until it is reviewed", async () => {
  const dir = tempDir();

  const first = startProxy(dir);
  first.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  await first.waitFor((m) => m.id === 1, "initialize response");
  first.send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  await first.waitFor((m) => m.id === 2, "tools/list response");
  assert.equal(await first.close(), 0);

  const second = startProxy(dir, { RUGPULL: "1" });
  second.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  await second.waitFor((m) => m.id === 1, "initialize response");
  second.send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  await second.waitFor((m) => m.id === 2, "tools/list response");

  second.send({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "read_file", arguments: { path: "docs/a.md" } },
  });
  const refused = await second.waitFor((m) => m.id === 3, "call to a changed tool");
  assert.equal(refused.error?.code, -32001);
  assert.match(refused.error?.message ?? "", /not pinned/);

  assert.equal(await second.close(), 0);
  rmSync(dir, { recursive: true, force: true });
});

async function listAllPages(h: Harness, firstId: number): Promise<void> {
  let cursor: string | undefined;
  let id = firstId;
  for (let guard = 0; guard < 10; guard++) {
    h.send({ jsonrpc: "2.0", id, method: "tools/list", params: cursor === undefined ? {} : { cursor } });
    const page = await h.waitFor((m) => m.id === id, `tools/list page ${id}`);
    const next = page.result?.["nextCursor"];
    if (typeof next !== "string") return;
    cursor = next;
    id++;
  }
  throw new Error("too many pages");
}

test("a changed tool on a later page of a paginated tools/list stays blocked", async () => {
  const dir = tempDir();

  const first = startProxy(dir, { PAGINATE: "1" });
  first.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  await first.waitFor((m) => m.id === 1, "initialize response");
  await listAllPages(first, 10);
  assert.equal(await first.close(), 0);

  const second = startProxy(dir, { PAGINATE: "1", RUGPULL: "1" });
  second.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  await second.waitFor((m) => m.id === 1, "initialize response");
  await listAllPages(second, 10);

  second.send({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "read_file", arguments: { path: "docs/a.md" } },
  });
  const refused = await second.waitFor((m) => m.id === 3, "call to a changed tool");
  assert.equal(refused.error?.code, -32001);
  assert.match(refused.error?.message ?? "", /not pinned/);

  assert.equal(await second.close(), 0);
  rmSync(dir, { recursive: true, force: true });
});

test("an unchanged paginated server is not blocked on later pages", async () => {
  const dir = tempDir();

  const first = startProxy(dir, { PAGINATE: "1" });
  first.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  await first.waitFor((m) => m.id === 1, "initialize response");
  await listAllPages(first, 10);
  assert.equal(await first.close(), 0);

  const second = startProxy(dir, { PAGINATE: "1" });
  second.send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  await second.waitFor((m) => m.id === 1, "initialize response");
  await listAllPages(second, 10);

  second.send({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "send_webhook", arguments: { payload: "hello" } },
  });
  const ok = await second.waitFor((m) => m.id === 3, "call to an unchanged tool");
  assert.equal(ok.error, undefined);

  assert.equal(await second.close(), 0);
  rmSync(dir, { recursive: true, force: true });
});
