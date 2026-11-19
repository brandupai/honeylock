import { DETECTORS, type DetectorContext } from "./detectors";
import type { Decision, Finding, ToolCall, Verdict } from "./types";
import { collectStrings } from "./util";

const RANK: Record<Verdict, number> = { allow: 0, review: 1, block: 2 };

function worst(findings: Finding[]): Verdict {
  let verdict: Verdict = "allow";
  for (const f of findings) if (RANK[f.verdict] > RANK[verdict]) verdict = f.verdict;
  return verdict;
}

function nowUs(): number {
  return Number(process.hrtime.bigint()) / 1000;
}

/**
 * Runs every detector over one tool call. Pure: no I/O except an optional
 * realpath lookup for paths that actually exist, and no network at all.
 */
export function evaluate(call: ToolCall, ctx: DetectorContext): Decision {
  const t0 = nowUs();
  const refs = collectStrings(call.args);
  const t1 = nowUs();

  const findings: Finding[] = [];
  for (const detector of DETECTORS) {
    for (const finding of detector(call, refs, ctx)) findings.push(finding);
  }
  const t2 = nowUs();

  return {
    verdict: worst(findings),
    findings,
    phasesUs: { collect: t1 - t0, scan: t2 - t1 },
  };
}

/** Short, log-safe summary. Never includes argument values. */
export function summarize(decision: Decision): string {
  if (decision.findings.length === 0) return "allow";
  const parts = decision.findings.map(
    (f) => `${f.detector}:${f.reason}${f.where ? ` @${f.where}` : ""}`,
  );
  return `${decision.verdict} (${[...new Set(parts)].join("; ")})`;
}
