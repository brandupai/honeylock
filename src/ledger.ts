import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { stableStringify } from "./util";

export interface LedgerEvent {
  seq: number;
  ts: string;
  type: string;
  data: Record<string, unknown>;
}

export interface LedgerRecord extends LedgerEvent {
  prev: string;
  hmac: string;
}

const GENESIS = "genesis";
const KEY_BYTES = 32;

/**
 * The ledger is an HMAC-chained JSONL file. The chain alone only proves internal
 * coherence; the key is what makes editing an old line detectable. Keep the key
 * outside the ledger directory, or pass it through HONEYLOCK_LEDGER_KEY.
 */
export class Ledger {
  private seq = 0;
  private lastHmac = GENESIS;

  constructor(
    readonly file: string,
    private readonly key: Buffer,
  ) {
    if (existsSync(file)) {
      const existing = verifyLedgerFile(file, key);
      if (!existing.ok) {
        throw new Error(`refusing to append to a ledger that does not verify: ${existing.error}`);
      }
      const last = existing.records[existing.records.length - 1];
      if (last) {
        this.seq = last.seq;
        this.lastHmac = last.hmac;
      }
    }
  }

  append(type: string, data: Record<string, unknown>): LedgerRecord {
    const event: LedgerEvent = { seq: this.seq + 1, ts: new Date().toISOString(), type, data };
    const record: LedgerRecord = { ...event, prev: this.lastHmac, hmac: signRecord(event, this.lastHmac, this.key) };
    appendFileSync(this.file, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    this.seq = event.seq;
    this.lastHmac = record.hmac;
    return record;
  }
}

function macInput(event: LedgerEvent, prev: string): string {
  return `${event.seq}\n${event.ts}\n${event.type}\n${stableStringify(event.data)}\n${prev}`;
}

function signRecord(event: LedgerEvent, prev: string, key: Buffer): string {
  return createHmac("sha256", key).update(macInput(event, prev)).digest("hex");
}

export interface VerifyResult {
  ok: boolean;
  records: LedgerRecord[];
  error?: string;
}

export function verifyLedgerFile(file: string, key: Buffer): VerifyResult {
  if (!existsSync(file)) return { ok: true, records: [] };
  const lines = readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "");
  const records: LedgerRecord[] = [];
  let prev = GENESIS;
  let expectedSeq = 1;
  for (const line of lines) {
    let record: LedgerRecord;
    try {
      record = JSON.parse(line) as LedgerRecord;
    } catch {
      return { ok: false, records, error: `line ${expectedSeq} is not valid JSON` };
    }
    if (record.seq !== expectedSeq) {
      return { ok: false, records, error: `line ${expectedSeq} has seq ${record.seq} (gap or reorder)` };
    }
    if (record.prev !== prev) {
      return { ok: false, records, error: `line ${record.seq} does not chain to the previous hash` };
    }
    const expected = signRecord(
      { seq: record.seq, ts: record.ts, type: record.type, data: record.data },
      prev,
      key,
    );
    if (!safeEqualHex(expected, record.hmac)) {
      return { ok: false, records, error: `line ${record.seq} signature mismatch (edited or signed with another key)` };
    }
    records.push(record);
    prev = record.hmac;
    expectedSeq++;
  }
  return { ok: true, records };
}

function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}

export function defaultKeyPath(): string {
  return path.join(os.homedir(), ".honeylock", "ledger.key");
}

/** Env var wins; otherwise a 0600 key file is created once, outside the ledger directory. */
export function loadLedgerKey(explicitPath?: string): { key: Buffer; source: string } {
  const fromEnv = process.env["HONEYLOCK_LEDGER_KEY"];
  if (fromEnv && fromEnv.length >= 16) {
    return { key: Buffer.from(fromEnv, "utf8"), source: "HONEYLOCK_LEDGER_KEY" };
  }
  const file = explicitPath ?? defaultKeyPath();
  if (existsSync(file)) {
    const hex = readFileSync(file, "utf8").trim();
    if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error(`ledger key file is malformed: ${file}`);
    return { key: Buffer.from(hex, "hex"), source: file };
  }
  const key = randomBytes(KEY_BYTES);
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, `${key.toString("hex")}\n`, { mode: 0o600 });
  return { key, source: `${file} (newly generated)` };
}
