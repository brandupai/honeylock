import { readFileSync, writeFileSync } from "node:fs";
import { evaluate } from "./pipeline";
import { Ledger } from "./ledger";
import type { Policy, Verdict } from "./types";

export interface AttackVector {
  id: string;
  category: string;
  tool: string;
  args: unknown;
  expect: Verdict;
  why: string;
}

export interface VectorResult {
  id: string;
  category: string;
  expect: Verdict;
  got: Verdict;
  pass: boolean;
  findings: string[];
}

export interface Latency {
  count: number;
  p50: number;
  p99: number;
  max: number;
}

export interface BenchmarkReport {
  vectors: VectorResult[];
  passed: number;
  total: number;
  collect: Latency;
  scan: Latency;
  total_: Latency;
  ledgerAppend: Latency;
  iterations: number;
  generatedAt: string;
  node: string;
  platform: string;
}

const WARMUP = 50;

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[index] ?? 0;
}

function summarizeLatency(samples: number[]): Latency {
  const sorted = [...samples].sort((a, b) => a - b);
  return {
    count: sorted.length,
    p50: round(percentile(sorted, 50)),
    p99: round(percentile(sorted, 99)),
    max: round(sorted[sorted.length - 1] ?? 0),
  };
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}

export function loadVectors(file: string): AttackVector[] {
  const parsed = JSON.parse(readFileSync(file, "utf8")) as unknown;
  if (!Array.isArray(parsed)) throw new Error(`${file} must contain a JSON array of vectors`);
  return parsed as AttackVector[];
}

export interface BenchmarkOptions {
  file: string;
  policy: Policy;
  iterations: number;
  ledgerFile?: string;
}

export function runBenchmark(opts: BenchmarkOptions): BenchmarkReport {
  const vectors = loadVectors(opts.file);
  const ctx = { policy: opts.policy, root: opts.policy.workspaceRoot };

  for (let i = 0; i < WARMUP; i++) {
    for (const vector of vectors) evaluate({ tool: vector.tool, args: vector.args }, ctx);
  }

  const collect: number[] = [];
  const scan: number[] = [];
  const totals: number[] = [];
  const results: VectorResult[] = [];

  for (const vector of vectors) {
    let last = evaluate({ tool: vector.tool, args: vector.args }, ctx);
    for (let i = 0; i < opts.iterations; i++) {
      last = evaluate({ tool: vector.tool, args: vector.args }, ctx);
      collect.push(last.phasesUs["collect"] ?? 0);
      scan.push(last.phasesUs["scan"] ?? 0);
      totals.push((last.phasesUs["collect"] ?? 0) + (last.phasesUs["scan"] ?? 0));
    }
    results.push({
      id: vector.id,
      category: vector.category,
      expect: vector.expect,
      got: last.verdict,
      pass: last.verdict === vector.expect,
      findings: [...new Set(last.findings.map((f) => f.detector))],
    });
  }

  const ledgerSamples: number[] = [];
  if (opts.ledgerFile) {
    const ledger = new Ledger(opts.ledgerFile, Buffer.from("benchmark-key-not-a-secret", "utf8"));
    for (let i = 0; i < 200; i++) {
      const start = process.hrtime.bigint();
      ledger.append("bench", { i });
      ledgerSamples.push(Number(process.hrtime.bigint() - start) / 1000);
    }
  }

  return {
    vectors: results,
    passed: results.filter((r) => r.pass).length,
    total: results.length,
    collect: summarizeLatency(collect),
    scan: summarizeLatency(scan),
    total_: summarizeLatency(totals),
    ledgerAppend: summarizeLatency(ledgerSamples),
    iterations: opts.iterations,
    generatedAt: new Date().toISOString(),
    node: process.version,
    platform: `${process.platform} ${process.arch}`,
  };
}

export function formatReport(report: BenchmarkReport): string {
  const lines: string[] = [];
  const width = Math.max(12, ...report.vectors.map((v) => v.id.length));
  lines.push(`${"vector".padEnd(width)}  ${"category".padEnd(20)}  expect  got     result`);
  lines.push(`${"-".repeat(width)}  ${"-".repeat(20)}  ------  ------  ------`);
  for (const v of report.vectors) {
    lines.push(
      `${v.id.padEnd(width)}  ${v.category.padEnd(20)}  ${v.expect.padEnd(6)}  ${v.got.padEnd(6)}  ${v.pass ? "pass" : "FAIL"}`,
    );
  }
  lines.push("");
  lines.push(`${report.passed}/${report.total} vectors matched the expected verdict`);
  lines.push("");
  lines.push(`latency in microseconds, ${report.iterations} iterations per vector after ${WARMUP} warm-up runs`);
  lines.push(`  collect args  p50 ${report.collect.p50}  p99 ${report.collect.p99}  max ${report.collect.max}`);
  lines.push(`  detectors     p50 ${report.scan.p50}  p99 ${report.scan.p99}  max ${report.scan.max}`);
  lines.push(`  pipeline      p50 ${report.total_.p50}  p99 ${report.total_.p99}  max ${report.total_.max}`);
  if (report.ledgerAppend.count > 0) {
    lines.push(
      `  ledger append p50 ${report.ledgerAppend.p50}  p99 ${report.ledgerAppend.p99}  max ${report.ledgerAppend.max}`,
    );
  }
  lines.push(`  node ${report.node} on ${report.platform}`);
  return lines.join("\n");
}

export function writeReport(report: BenchmarkReport, file: string): void {
  writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`);
}
