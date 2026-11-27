/**
 * Normalization helpers. Every one of these is cheap by default and only does
 * real work when the input actually contains something worth decoding, which is
 * what keeps the fast path fast.
 */

const MAX_DECODE_PASSES = 3;

/** Decodes %XX sequences repeatedly, so `%252e%252e` becomes `..`. */
export function percentDecodeIterative(input: string, passes = MAX_DECODE_PASSES): string {
  let current = input;
  for (let i = 0; i < passes; i++) {
    if (!current.includes("%")) return current;
    let next: string;
    try {
      next = decodeURIComponent(current);
    } catch {
      // A stray % is not an escape; decode only the valid triplets.
      next = current.replace(/%([0-9a-fA-F]{2})/g, (_m, hex: string) =>
        String.fromCharCode(Number.parseInt(hex, 16)),
      );
    }
    if (next === current) return current;
    current = next;
  }
  return current;
}

/**
 * Removes quoting and backslash escapes, collapses whitespace, and merges runs of
 * single-letter flags: `r'm' -r -f` -> `rm -rf`.
 */
export function normalizeShell(input: string): string {
  let s = input.replace(/\\\r?\n/g, " ").replace(/\\/g, "");
  s = s.replace(/['"]/g, "");
  s = s.replace(/[ \t]+/g, " ").trim();
  const tokens = s.split(" ");
  const out: string[] = [];
  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i] ?? "";
    if (/^-[a-zA-Z]$/.test(token)) {
      const letters: string[] = [];
      while (i < tokens.length && /^-[a-zA-Z]$/.test(tokens[i] ?? "")) {
        letters.push((tokens[i] ?? "").slice(1));
        i++;
      }
      out.push(`-${letters.sort().join("")}`);
      continue;
    }
    out.push(token);
    i++;
  }
  return out.join(" ");
}

export interface SqlScan {
  /** The statement with comments removed. Quoted text is kept as written. */
  code: string;
  /** The body of every comment that was removed. */
  comments: string[];
}

/**
 * Splits SQL into code and comments without being fooled by quoting: a `--` or `#`
 * inside a string literal is not a comment, and `#>` / `#-` are Postgres operators.
 * A MySQL executable comment (`/*!50000 ... *\/`) runs, so its body counts as code.
 * Anything ambiguous between dialects is kept visible to the detectors, never hidden.
 */
export function scanSql(input: string): SqlScan {
  let code = "";
  const comments: string[] = [];
  const n = input.length;
  let i = 0;
  while (i < n) {
    const ch = input.charAt(i);
    if (ch === "'" || ch === '"' || ch === "`") {
      let j = i + 1;
      while (j < n) {
        const c = input.charAt(j);
        if (c === "\\" && ch !== "`") {
          j += 2;
          continue;
        }
        if (c === ch) {
          if (input.charAt(j + 1) === ch) {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      code += input.slice(i, Math.min(j + 1, n));
      i = j + 1;
      continue;
    }
    if (ch === "/" && input.charAt(i + 1) === "*") {
      const end = input.indexOf("*/", i + 2);
      const body = input.slice(i + 2, end === -1 ? n : end);
      i = end === -1 ? n : end + 2;
      if (body.startsWith("!")) code += ` ${body.replace(/^!\d*/, "")} `;
      else {
        comments.push(body);
        code += " ";
      }
      continue;
    }
    const lineComment =
      (ch === "-" && input.charAt(i + 1) === "-") ||
      (ch === "#" && input.charAt(i + 1) !== ">" && input.charAt(i + 1) !== "-");
    if (lineComment) {
      let end = input.indexOf("\n", i);
      if (end === -1) end = n;
      comments.push(input.slice(i + (ch === "#" ? 1 : 2), end));
      code += " ";
      i = end;
      continue;
    }
    code += ch;
    i++;
  }
  return { code, comments };
}

/** Drops SQL comments and collapses whitespace: `DROP/**\/TABLE` -> `DROP TABLE`. */
export function stripSqlComments(input: string): string {
  return scanSql(input).code.replace(/\s+/g, " ").trim();
}

export interface InvisibleHit {
  codePoint: number;
  category: "tag" | "zero-width" | "bidi";
}

/** Finds Unicode used for smuggling: tag chars, zero-width chars and BiDi controls. */
export function findInvisibleChars(input: string): InvisibleHit[] {
  const hits: InvisibleHit[] = [];
  for (const ch of input) {
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;
    if (cp >= 0xe0000 && cp <= 0xe007f) hits.push({ codePoint: cp, category: "tag" });
    else if (
      (cp >= 0x200b && cp <= 0x200f) ||
      (cp >= 0x2060 && cp <= 0x2064) ||
      cp === 0xfeff ||
      cp === 0x180e ||
      cp === 0x00ad
    )
      hits.push({ codePoint: cp, category: "zero-width" });
    else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069))
      hits.push({ codePoint: cp, category: "bidi" });
    if (hits.length > 64) break;
  }
  return hits;
}

const BASE64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/;
const HEX_RE = /^(?:[0-9a-fA-F]{2})+$/;

export function looksBase64(s: string): boolean {
  return s.length >= 16 && s.length % 4 !== 1 && BASE64_RE.test(s);
}

/** Decodes base64 layers and hex, so a doubly encoded secret is still visible in plain text. */
export function decodeLayers(input: string, depth = 3): string[] {
  const results: string[] = [];
  let current = input;
  for (let level = 0; level < depth; level++) {
    if (!looksBase64(current)) break;
    let decoded: string;
    try {
      decoded = Buffer.from(current.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    } catch {
      break;
    }
    if (!isMostlyPrintable(decoded)) break;
    // Only accept a layer that re-encodes to the same string: otherwise it is
    // a false positive on something that merely looks like base64.
    const canonical = Buffer.from(decoded, "utf8").toString("base64").replace(/=+$/, "");
    const normalised = current.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
    if (canonical !== normalised) break;
    results.push(decoded);
    current = decoded;
  }
  if (HEX_RE.test(input) && input.length >= 16) {
    const decoded = Buffer.from(input, "hex").toString("utf8");
    if (isMostlyPrintable(decoded)) results.push(decoded);
  }
  return results;
}

export function isMostlyPrintable(s: string): boolean {
  if (s.length === 0) return false;
  let printable = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp === 9 || cp === 10 || cp === 13 || (cp >= 0x20 && cp !== 0x7f)) printable++;
  }
  return printable / s.length > 0.85;
}
