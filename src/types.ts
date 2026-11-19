export type Verdict = "allow" | "review" | "block";

export interface Finding {
  /** Stable detector id, e.g. "path-traversal". */
  detector: string;
  verdict: Verdict;
  /** Human-readable, safe to show to a user. Never contains secret values. */
  reason: string;
  /** Where it was found, e.g. 'args.path'. Never contains secret values. */
  where?: string;
}

export interface ToolCall {
  id?: string | number | null;
  tool: string;
  args: unknown;
}

export interface Decision {
  verdict: Verdict;
  findings: Finding[];
  /** Microseconds per phase. Named so the benchmark can publish them separately. */
  phasesUs: Record<string, number>;
}

export interface Policy {
  /** When non-empty, only these tools (or prefixes ending in '*') may run. */
  allowedTools: string[];
  deniedTools: string[];
  /** Tool argument keys that are refused outright, e.g. ["env", "credentials"]. */
  deniedKeys: string[];
  /** Tools considered able to leave the machine; high-entropy args get blocked, not flagged. */
  egressTools: string[];
  /** Absolute root that file paths must stay inside. */
  workspaceRoot: string;
  /** Max serialized argument size, in bytes. */
  maxArgBytes: number;
}

export const DEFAULT_POLICY: Omit<Policy, "workspaceRoot"> = {
  allowedTools: [],
  deniedTools: [],
  deniedKeys: [],
  egressTools: ["send", "post", "upload", "http", "fetch", "request", "webhook", "email", "message"],
  maxArgBytes: 1_000_000,
};
