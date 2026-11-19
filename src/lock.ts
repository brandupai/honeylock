import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { sha256Hex, stableStringify } from "./util";

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface LockedTool {
  name: string;
  hash: string;
  descriptionHash: string;
  schemaHash: string;
}

export interface LockFile {
  version: 1;
  servers: Record<string, { tools: Record<string, LockedTool> }>;
}

export type ChangeKind = "added" | "changed" | "removed";

export interface ToolChange {
  tool: string;
  kind: ChangeKind;
  fields: string[];
}

export function hashTool(tool: McpTool): LockedTool {
  const description = tool.description ?? "";
  const schema = tool.inputSchema ?? {};
  return {
    name: tool.name,
    hash: sha256Hex(stableStringify({ name: tool.name, description, inputSchema: schema })),
    descriptionHash: sha256Hex(description),
    schemaHash: sha256Hex(stableStringify(schema)),
  };
}

export function loadLock(file: string): LockFile {
  if (!existsSync(file)) return { version: 1, servers: {} };
  const parsed = JSON.parse(readFileSync(file, "utf8")) as LockFile;
  if (parsed.version !== 1) throw new Error(`unsupported lock version: ${String(parsed.version)}`);
  return parsed;
}

export function saveLock(file: string, lock: LockFile): void {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(lock, null, 2)}\n`, { mode: 0o644 });
}

export interface CompareResult {
  changes: ToolChange[];
  next: LockFile;
  /** True the first time a server is seen: everything is pinned, nothing is blocked. */
  firstPin: boolean;
}

/**
 * Compares what a server advertises now with what was pinned.
 *
 * - First sight of a server: pin everything (trust on first use).
 * - Changed tool: keep the old pin, report the changed fields. It stays blocked
 *   until the owner accepts it, because a changed description is exactly how a
 *   rug pull changes what the model is told the tool does.
 * - Added tool: reported and left unpinned, so it is blocked until accepted.
 * - Removed tool: reported; nothing to pin.
 */
export function compareTools(lock: LockFile, server: string, tools: McpTool[]): CompareResult {
  const pinned = lock.servers[server]?.tools;
  const firstPin = pinned === undefined;
  const nextTools: Record<string, LockedTool> = {};
  const changes: ToolChange[] = [];
  const seen = new Set<string>();

  for (const tool of tools) {
    seen.add(tool.name);
    const current = hashTool(tool);
    const previous = pinned?.[tool.name];

    if (!previous) {
      if (firstPin) {
        nextTools[tool.name] = current;
      } else {
        changes.push({ tool: tool.name, kind: "added", fields: [] });
      }
      continue;
    }

    if (previous.hash === current.hash) {
      nextTools[tool.name] = previous;
      continue;
    }

    nextTools[tool.name] = previous;
    const fields: string[] = [];
    if (previous.descriptionHash !== current.descriptionHash) fields.push("description");
    if (previous.schemaHash !== current.schemaHash) fields.push("inputSchema");
    if (fields.length === 0) fields.push("name");
    changes.push({ tool: tool.name, kind: "changed", fields });
  }

  for (const name of Object.keys(pinned ?? {})) {
    if (!seen.has(name)) changes.push({ tool: name, kind: "removed", fields: [] });
  }

  const next: LockFile = {
    version: 1,
    servers: { ...lock.servers, [server]: { tools: nextTools } },
  };

  return { changes: firstPin ? [] : changes, next, firstPin };
}

/** Rewrites the pin for one server from its current definitions. */
export function acceptServer(lock: LockFile, server: string, tools: McpTool[]): LockFile {
  return {
    version: 1,
    servers: {
      ...lock.servers,
      [server]: { tools: Object.fromEntries(tools.map((t) => [t.name, hashTool(t)])) },
    },
  };
}

export function blockedFromChanges(changes: ToolChange[]): Set<string> {
  return new Set(changes.filter((c) => c.kind !== "removed").map((c) => c.tool));
}

export function formatChanges(changes: ToolChange[]): string {
  return changes
    .map((c) => `  ${c.kind.padEnd(8)} ${c.tool}${c.fields.length ? ` (${c.fields.join(", ")})` : ""}`)
    .join("\n");
}
