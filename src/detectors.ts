import { realpathSync } from "node:fs";
import * as path from "node:path";
import {
  decodeLayers,
  findInvisibleChars,
  looksBase64,
  normalizeShell,
  percentDecodeIterative,
  stripSqlComments,
} from "./decode";
import type { Finding, Policy, ToolCall } from "./types";
import { collectStrings, entropyBitsPerChar, type StringRef } from "./util";

export interface DetectorContext {
  policy: Policy;
  /** Real path of the workspace root, already resolved. */
  root: string;
  /** Set of secret literals loaded from a file, used by the taint detector. */
  taintHashes?: Set<string>;
}

export type Detector = (call: ToolCall, refs: StringRef[], ctx: DetectorContext) => Finding[];

const PATH_KEY_RE = /(path|file|dir|folder|dest|target|source|src|out|output|root|include|template)/i;
const COMMAND_KEY_RE = /(command|cmd|script|shell|exec|run|args|argv|line|code)/i;
const SQL_KEY_RE = /(sql|query|statement|filter|where)/i;

function looksLikePath(value: string): boolean {
  if (value.length < 3 || value.length > 4096) return false;
  if (value.includes("://")) return false;
  if (value.startsWith("/") || value.startsWith("./") || value.startsWith("../") || value.startsWith("~")) return true;
  if (value.includes("\\")) return true;
  return /^[\w.@%-]+(\/[\w.@ %-]+)+$/.test(value) && value.includes("/");
}

function sameCase(a: string, b: string): boolean {
  // Windows paths are case-insensitive and realpath preserves the on-disk case.
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function isInside(root: string, target: string): boolean {
  if (sameCase(target, root)) return true;
  const withSep = root.endsWith(path.sep) ? root : root + path.sep;
  return process.platform === "win32"
    ? target.toLowerCase().startsWith(withSep.toLowerCase())
    : target.startsWith(withSep);
}

/**
 * Resolves symlinks even when the leaf does not exist yet.
 *
 * `realpathSync` throws on a missing file, which used to let `link/not-there`
 * through while `link/passwd` was blocked. Resolving the deepest existing
 * ancestor and re-joining the remainder closes that gap.
 */
function realpathDeepest(target: string): string | null {
  const rest: string[] = [];
  let current = target;
  for (;;) {
    try {
      const real = realpathSync(current);
      return rest.length === 0 ? real : path.join(real, ...rest.reverse());
    } catch {
      const parent = path.dirname(current);
      if (parent === current) return null;
      rest.push(path.basename(current));
      current = parent;
    }
  }
}

/** Encoded traversal, symlink escape, NUL bytes. */
export const pathTraversal: Detector = (_call, refs, ctx) => {
  const findings: Finding[] = [];
  for (const ref of refs) {
    const keyLooksPathy = PATH_KEY_RE.test(ref.where.split(".").pop() ?? "");
    if (!keyLooksPathy && !looksLikePath(ref.value)) continue;
    if (!looksLikePath(ref.value) && !keyLooksPathy) continue;

    const decoded = percentDecodeIterative(ref.value);
    if (decoded.includes("\u0000")) {
      findings.push({
        detector: "path-traversal",
        verdict: "block",
        reason: "NUL byte in path argument",
        where: ref.where,
      });
      continue;
    }
    const unixish = decoded.replace(/\\/g, "/");
    const resolved = path.isAbsolute(unixish) ? path.normalize(unixish) : path.resolve(ctx.root, unixish);
    if (!isInside(ctx.root, resolved)) {
      findings.push({
        detector: "path-traversal",
        verdict: "block",
        reason: `path escapes workspace root (${path.basename(resolved)})`,
        where: ref.where,
      });
      continue;
    }
    const real = realpathDeepest(resolved);
    if (real !== null && !isInside(ctx.root, real)) {
      findings.push({
        detector: "path-traversal",
        verdict: "block",
        reason: "symlink resolves outside workspace root",
        where: ref.where,
      });
    }
  }
  return findings;
};

const SHELL_BLOCKS: Array<{ re: RegExp; reason: string }> = [
  { re: /(^|[;&|]\s*)rm\s+-[a-z]*r[a-z]*f|(^|[;&|]\s*)rm\s+-[a-z]*f[a-z]*r/, reason: "recursive delete" },
  { re: /\b(curl|wget)\b[^|]*\|\s*(ba|z|fi)?sh\b/, reason: "remote content piped to a shell" },
  { re: /\bbase64\s+(-d|-D|--decode)\b[^|]*\|\s*(ba)?sh\b/, reason: "base64 payload piped to a shell" },
  { re: /\bchmod\s+(-R\s+)?777\b/, reason: "world-writable permissions" },
  { re: /\bnc\b[^|]*\s-[a-z]*e\b/, reason: "reverse shell via netcat" },
  { re: /\bmkfifo\b|\bncat\b[^|]*\s-e\b/, reason: "reverse shell helper" },
  { re: /\beval\b/, reason: "eval of dynamic content" },
  { re: /\bdd\b[^|]*\bif=\/dev\/zero\b/, reason: "disk filling command" },
  { re: />\s*\/etc\//, reason: "write into /etc" },
  { re: /\bhistory\s+-c\b|\bunset\s+HISTFILE\b/, reason: "log tampering" },
];

const SHELL_REVIEWS: Array<{ re: RegExp; reason: string }> = [
  { re: /\$\([^)]*\)|`[^`]*`/, reason: "command substitution" },
  { re: /\bsh\s+-c\b|\bbash\s+-c\b/, reason: "inline shell invocation" },
  { re: /\bsudo\b/, reason: "privilege escalation" },
];

export const shellInjection: Detector = (_call, refs) => {
  const findings: Finding[] = [];
  for (const ref of refs) {
    const keyLooksCommandy = COMMAND_KEY_RE.test(ref.where.split(".").pop() ?? "");
    const hasMetachars = /[|;&`]|\$\(/.test(ref.value);
    if (!keyLooksCommandy && !hasMetachars) continue;
    const normalized = normalizeShell(ref.value);
    for (const rule of SHELL_BLOCKS) {
      if (rule.re.test(normalized)) {
        findings.push({
          detector: "shell-injection",
          verdict: "block",
          reason: rule.reason,
          where: ref.where,
        });
      }
    }
    for (const rule of SHELL_REVIEWS) {
      if (rule.re.test(normalized)) {
        findings.push({
          detector: "shell-injection",
          verdict: "review",
          reason: rule.reason,
          where: ref.where,
        });
      }
    }
  }
  return findings;
};

const SQL_BLOCKS: Array<{ re: RegExp; reason: string }> = [
  { re: /\b(drop|truncate)\s+(table|database|schema)\b/, reason: "schema destruction" },
  { re: /\bdelete\s+from\s+[\w."`]+\s*(;|$)/, reason: "unbounded delete" },
  { re: /\bunion\s+(all\s+)?select\b/, reason: "union-based injection" },
  { re: /\bor\s+1\s*=\s*1\b|\bor\s+'1'\s*=\s*'1'/, reason: "tautology injection" },
  { re: /\bupdate\s+[\w."`]+\s+set\b(?![\s\S]*\bwhere\b)/, reason: "unbounded update" },
];

export const sqlObfuscation: Detector = (_call, refs) => {
  const findings: Finding[] = [];
  for (const ref of refs) {
    const keyLooksSql = SQL_KEY_RE.test(ref.where.split(".").pop() ?? "");
    const looksSql = /\b(select|insert|update|delete|drop|truncate|alter)\b/i.test(ref.value);
    if (!keyLooksSql && !looksSql) continue;
    const stripped = stripSqlComments(ref.value).toUpperCase();
    for (const rule of SQL_BLOCKS) {
      if (rule.re.test(stripped.toLowerCase())) {
        findings.push({
          detector: "sql-obfuscation",
          verdict: "block",
          reason: rule.reason,
          where: ref.where,
        });
      }
    }
    if (stripped !== ref.value.toUpperCase() && /\b(drop|union|delete|update)\b/.test(stripped)) {
      findings.push({
        detector: "sql-obfuscation",
        verdict: "review",
        reason: "SQL comments hide a sensitive statement",
        where: ref.where,
      });
    }
  }
  return findings;
};

const SECRET_PATTERNS: Array<{ re: RegExp; reason: string }> = [
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, reason: "private key material" },
  { re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, reason: "AWS access key id" },
  { re: /\bsk-[A-Za-z0-9_-]{16,}\b/, reason: "API key with sk- prefix" },
  { re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/, reason: "GitHub token" },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, reason: "Slack token" },
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, reason: "JWT" },
  { re: /postgres(?:ql)?:\/\/[^\s:@]+:[^\s@]+@/, reason: "database URL with password" },
];

/** High-entropy tokens are only a block when the tool can send data out. */
export const secretEgress: Detector = (call, refs, ctx) => {
  const findings: Finding[] = [];
  const tool = call.tool.toLowerCase();
  const canEgress = ctx.policy.egressTools.some((t) => tool.includes(t.toLowerCase()));

  for (const ref of refs) {
    const variants = [ref.value, ...decodeLayers(ref.value)];
    for (const value of variants) {
      for (const pattern of SECRET_PATTERNS) {
        if (pattern.re.test(value)) {
          findings.push({
            detector: "secret-egress",
            verdict: "block",
            reason: `${pattern.reason} in tool arguments`,
            where: ref.where,
          });
        }
      }
      if (!canEgress) continue;
      for (const token of value.match(/[A-Za-z0-9+/=_-]{24,}/g) ?? []) {
        if (!looksBase64(token)) continue;
        if (entropyBitsPerChar(token) < 4.3) continue;
        if (new Set(token).size < 8) continue;
        findings.push({
          detector: "secret-egress",
          verdict: "block",
          reason: "high-entropy value passed to an egress-capable tool",
          where: ref.where,
        });
        break;
      }
    }
  }
  return findings;
};

export const unicodeSmuggling: Detector = (_call, refs) => {
  const findings: Finding[] = [];
  for (const ref of refs) {
    const hits = findInvisibleChars(ref.value);
    if (hits.length === 0) continue;
    const categories = [...new Set(hits.map((h) => h.category))].join(", ");
    findings.push({
      detector: "unicode-smuggling",
      verdict: "block",
      reason: `invisible Unicode in arguments (${categories}, ${hits.length} chars)`,
      where: ref.where,
    });
  }
  return findings;
};

/** Allowlist, denylist, denied argument keys and payload size. */
export const policyRules: Detector = (call, refs, ctx) => {
  const findings: Finding[] = [];
  const denied = ctx.policy.deniedTools.find((t) => matchesTool(t, call.tool));
  if (denied) {
    findings.push({
      detector: "policy",
      verdict: "block",
      reason: `tool denied by policy (${denied})`,
    });
  }
  if (ctx.policy.allowedTools.length > 0 && !ctx.policy.allowedTools.some((t) => matchesTool(t, call.tool))) {
    findings.push({
      detector: "policy",
      verdict: "block",
      reason: "tool is not in the allowlist",
    });
  }
  for (const ref of refs) {
    const last = (ref.where.split(".").pop() ?? "").toLowerCase();
    const hit = ctx.policy.deniedKeys.find((k) => k.toLowerCase() === last);
    if (hit) {
      findings.push({
        detector: "policy",
        verdict: "block",
        reason: `argument key denied by policy (${hit})`,
        where: ref.where,
      });
    }
  }
  const size = Buffer.byteLength(JSON.stringify(call.args) ?? "", "utf8");
  if (size > ctx.policy.maxArgBytes) {
    findings.push({
      detector: "policy",
      verdict: "block",
      reason: `arguments exceed max size (${size} > ${ctx.policy.maxArgBytes} bytes)`,
    });
  }
  return findings;
};

function matchesTool(pattern: string, tool: string): boolean {
  const p = pattern.toLowerCase();
  const t = tool.toLowerCase();
  if (p === t) return true;
  if (p.endsWith("*")) return t.startsWith(p.slice(0, -1));
  return false;
}

export const DETECTORS: Detector[] = [
  policyRules,
  unicodeSmuggling,
  pathTraversal,
  shellInjection,
  sqlObfuscation,
  secretEgress,
];

export function collectRefs(args: unknown): StringRef[] {
  return collectStrings(args);
}
