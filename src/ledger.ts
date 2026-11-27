import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  existsSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
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
/** A lock older than this was left by a crashed writer and is taken over. */
const LOCK_STALE_MS = 10_000;
/** How long one append waits for another writer before giving up. */
const LOCK_WAIT_MS = 5_000;

/**
 * The ledger is an HMAC-chained JSONL file. The chain alone only proves internal
 * coherence; the key is what makes editing an old line detectable. Keep the key
 * outside the ledger directory, or pass it through HONEYLOCK_LEDGER_KEY.
 */
export class Ledger {
  private seq = 0;
  private lastHmac = GENESIS;
  /** File size right after our own last write; any other size means someone else appended. */
  private knownSize = 0;

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
      this.knownSize = statSync(file).size;
    }
  }

  /**
   * Appends one signed record. Several proxies may share one ledger file (one per
   * wrapped server is the normal setup), so the append takes a lock file and, if
   * another writer has added records since our last write, continues the chain
   * from the real tail instead of from stale in-memory state.
   */
  append(type: string, data: Record<string, unknown>): LedgerRecord {
    const release = this.acquireLock();
    try {
      const size = existsSync(this.file) ? statSync(this.file).size : 0;
      if (size !== this.knownSize) this.resyncFromTail(size);
      const event: LedgerEvent = { seq: this.seq + 1, ts: new Date().toISOString(), type, data };
      const record: LedgerRecord = { ...event, prev: this.lastHmac, hmac: signRecord(event, this.lastHmac, this.key) };
      const line = `${JSON.stringify(record)}\n`;
      appendFileSync(this.file, line, { mode: 0o600 });
      this.seq = event.seq;
      this.lastHmac = record.hmac;
      this.knownSize = size + Buffer.byteLength(line);
      return record;
    } finally {
      release();
    }
  }

  private acquireLock(): () => void {
    const lockPath = `${this.file}.lock`;
    const deadline = Date.now() + LOCK_WAIT_MS;
    for (;;) {
      try {
        const fd = openSync(lockPath, "wx", 0o600);
        closeSync(fd);
        return () => {
          try {
            unlinkSync(lockPath);
          } catch {
            // Already gone (taken over as stale): nothing to release.
          }
        };
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        try {
          if (Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS) {
            unlinkSync(lockPath);
            continue;
          }
        } catch {
          continue; // The holder released it between our open and our stat.
        }
        if (Date.now() > deadline) throw new Error(`ledger is locked by another writer: ${lockPath}`);
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2);
      }
    }
  }

  /** Reads only the last record, checks its own signature, and continues from it. */
  private resyncFromTail(size: number): void {
    if (size === 0) {
      this.seq = 0;
      this.lastHmac = GENESIS;
      return;
    }
    const last = readLastRecord(this.file, size);
    const expected = signRecord({ seq: last.seq, ts: last.ts, type: last.type, data: last.data }, last.prev, this.key);
    if (!safeEqualHex(expected, last.hmac)) {
      throw new Error("refusing to append: the ledger tail does not verify (edited or signed with another key)");
    }
    this.seq = last.seq;
    this.lastHmac = last.hmac;
  }
}

function readLastRecord(file: string, size: number): LedgerRecord {
  const fd = openSync(file, "r");
  try {
    const total = fstatSync(fd).size;
    let end = Math.min(size, total);
    const chunks: Buffer[] = [];
    let found = false;
    while (end > 0 && !found) {
      const start = Math.max(0, end - 65_536);
      const buf = Buffer.alloc(end - start);
      readSync(fd, buf, 0, buf.length, start);
      chunks.unshift(buf);
      const text = Buffer.concat(chunks).toString("utf8").replace(/\n+$/, "");
      found = text.includes("\n") || start === 0;
      end = start;
    }
    const text = Buffer.concat(chunks).toString("utf8").replace(/\n+$/, "");
    const line = text.slice(text.lastIndexOf("\n") + 1);
    return JSON.parse(line) as LedgerRecord;
  } finally {
    closeSync(fd);
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
