import assert from "node:assert/strict";
import { readFileSync, realpathSync } from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import { evaluate } from "../src/pipeline";
import { DEFAULT_POLICY } from "../src/types";

interface Vector {
  id: string;
  tool: string;
  args: unknown;
  expect: "allow" | "review" | "block";
}

const root = realpathSync(path.resolve(__dirname, "../.."));
const vectors = JSON.parse(readFileSync(path.join(root, "attacks/vectors.json"), "utf8")) as Vector[];

test("every vector in attacks/vectors.json gets its expected verdict", () => {
  assert.ok(vectors.length > 0);
  const wrong: string[] = [];
  for (const v of vectors) {
    const got = evaluate({ tool: v.tool, args: v.args }, { policy: { ...DEFAULT_POLICY, workspaceRoot: root }, root }).verdict;
    if (got !== v.expect) wrong.push(`${v.id}: expected ${v.expect}, got ${got}`);
  }
  assert.deepEqual(wrong, []);
});
