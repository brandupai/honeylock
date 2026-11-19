import { createHash } from "node:crypto";

/** JSON with sorted object keys, so equal structures always hash equally. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const v = obj[key];
    if (v === undefined) continue;
    parts.push(`${JSON.stringify(key)}:${stableStringify(v)}`);
  }
  return `{${parts.join(",")}}`;
}

export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Shannon entropy in bits per character. */
export function entropyBitsPerChar(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export interface StringRef {
  /** Dotted path inside the arguments, e.g. "args.query" or "args.files[2]". */
  where: string;
  value: string;
}

const MAX_DEPTH = 32;
const MAX_REFS = 4000;

/** Collects every string (and key) reachable from a value, with a path for reporting. */
export function collectStrings(value: unknown, root = "args"): StringRef[] {
  const out: StringRef[] = [];
  const walk = (v: unknown, where: string, depth: number): void => {
    if (out.length >= MAX_REFS || depth > MAX_DEPTH) return;
    if (typeof v === "string") {
      out.push({ where, value: v });
      return;
    }
    if (typeof v === "number" || typeof v === "boolean" || v === null || v === undefined) return;
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) walk(v[i], `${where}[${i}]`, depth + 1);
      return;
    }
    if (typeof v === "object") {
      for (const [k, child] of Object.entries(v as Record<string, unknown>)) {
        out.push({ where: `${where}.${k}`, value: k });
        walk(child, `${where}.${k}`, depth + 1);
      }
    }
  };
  walk(value, root, 0);
  return out;
}

export function truncateForLog(s: string, max = 160): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}… (${s.length} chars)`;
}
