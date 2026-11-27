import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { Ledger, verifyLedgerFile } from "../src/ledger";

const key = Buffer.from("test-key-0123456789abcdef0123456789", "utf8");
const otherKey = Buffer.from("other-key-0123456789abcdef012345678", "utf8");

function tempLedger(): { dir: string; file: string } {
  const dir = mkdtempSync(path.join(os.tmpdir(), "honeylock-ledger-"));
  return { dir, file: path.join(dir, "ledger.jsonl") };
}

test("an append-only chain verifies", () => {
  const { dir, file } = tempLedger();
  const ledger = new Ledger(file, key);
  ledger.append("allow", { tool: "read_file" });
  ledger.append("block", { tool: "send_webhook", reason: "secret in args" });

  const result = verifyLedgerFile(file, key);
  assert.equal(result.ok, true);
  assert.equal(result.records.length, 2);
  assert.equal(result.records[1]?.seq, 2);
  rmSync(dir, { recursive: true, force: true });
});

test("editing a past event breaks verification", () => {
  const { dir, file } = tempLedger();
  const ledger = new Ledger(file, key);
  ledger.append("allow", { tool: "read_file" });
  ledger.append("block", { tool: "send_webhook" });

  const lines = readFileSync(file, "utf8").trimEnd().split("\n");
  const first = JSON.parse(lines[0] ?? "{}") as { data: { tool: string } };
  first.data.tool = "totally_benign";
  lines[0] = JSON.stringify(first);
  writeFileSync(file, `${lines.join("\n")}\n`);

  const result = verifyLedgerFile(file, key);
  assert.equal(result.ok, false);
  assert.match(result.error ?? "", /signature mismatch/);
  rmSync(dir, { recursive: true, force: true });
});

test("a forged chain signed with another key is rejected", () => {
  const { dir, file } = tempLedger();
  const ledger = new Ledger(file, key);
  ledger.append("allow", { tool: "read_file" });
  const result = verifyLedgerFile(file, otherKey);
  assert.equal(result.ok, false);
  rmSync(dir, { recursive: true, force: true });
});

test("reordering events is detected", () => {
  const { dir, file } = tempLedger();
  const ledger = new Ledger(file, key);
  ledger.append("allow", { tool: "a" });
  ledger.append("allow", { tool: "b" });
  const lines = readFileSync(file, "utf8").trimEnd().split("\n");
  writeFileSync(file, `${[lines[1], lines[0]].join("\n")}\n`);
  const result = verifyLedgerFile(file, key);
  assert.equal(result.ok, false);
  rmSync(dir, { recursive: true, force: true });
});

test("appending to a tampered ledger is refused", () => {
  const { dir, file } = tempLedger();
  const ledger = new Ledger(file, key);
  ledger.append("allow", { tool: "a" });
  writeFileSync(file, `${readFileSync(file, "utf8")}{"seq":2}\n`);
  assert.throws(() => new Ledger(file, key), /does not verify/);
  rmSync(dir, { recursive: true, force: true });
});

test("two writers sharing one file still produce a chain that verifies", () => {
  const { dir, file } = tempLedger();
  const a = new Ledger(file, key);
  const b = new Ledger(file, key);
  a.append("allow", { who: "a", n: 1 });
  b.append("allow", { who: "b", n: 1 });
  a.append("block", { who: "a", n: 2 });
  b.append("allow", { who: "b", n: 2 });

  const result = verifyLedgerFile(file, key);
  assert.equal(result.ok, true, result.error);
  assert.deepEqual(result.records.map((r) => r.seq), [1, 2, 3, 4]);
  rmSync(dir, { recursive: true, force: true });
});

test("a stale lock left by a crashed writer does not block appends forever", () => {
  const { dir, file } = tempLedger();
  const ledger = new Ledger(file, key);
  ledger.append("allow", { n: 1 });
  writeFileSync(`${file}.lock`, "99999999\n");
  const old = new Date(Date.now() - 60_000);
  utimesSync(`${file}.lock`, old, old);
  ledger.append("allow", { n: 2 });
  assert.equal(verifyLedgerFile(file, key).ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test("verify reports the event count so the head can be anchored elsewhere", () => {
  const { dir, file } = tempLedger();
  const ledger = new Ledger(file, key);
  ledger.append("allow", { n: 1 });
  ledger.append("allow", { n: 2 });
  const lines = readFileSync(file, "utf8").trimEnd().split("\n");
  // Dropping the tail still verifies: a hash chain alone cannot see it. This test
  // documents that limit so nobody claims truncation is detected.
  writeFileSync(file, `${lines[0]}\n`);
  const result = verifyLedgerFile(file, key);
  assert.equal(result.ok, true);
  assert.equal(result.records.length, 1);
  rmSync(dir, { recursive: true, force: true });
});

test("four processes appending at the same time leave one verifiable chain", async () => {
  const { dir, file } = tempLedger();
  const ledgerModule = path.resolve(__dirname, "../src/ledger.js");
  const script = `
    const { Ledger } = require(${JSON.stringify(ledgerModule)});
    const l = new Ledger(${JSON.stringify(file)}, Buffer.from(${JSON.stringify(key.toString("utf8"))}, "utf8"));
    for (let i = 0; i < 150; i++) l.append("allow", { pid: process.pid, i });
  `;
  const exits = await Promise.all(
    [0, 1, 2, 3].map(
      () =>
        new Promise<number | null>((resolve) => {
          const child = spawn(process.execPath, ["-e", script], { stdio: "ignore" });
          child.on("close", (code) => resolve(code));
        }),
    ),
  );
  assert.deepEqual(exits, [0, 0, 0, 0]);
  const result = verifyLedgerFile(file, key);
  assert.equal(result.ok, true, result.error);
  assert.equal(result.records.length, 600);
  rmSync(dir, { recursive: true, force: true });
});
