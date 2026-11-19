import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
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
