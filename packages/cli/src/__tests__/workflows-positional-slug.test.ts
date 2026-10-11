import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * `wraps email workflows push onboarding` pushed every workflow: the
 * dispatcher passed only `flags.workflow`, never the positional at sub[3],
 * and the unrecognized-argument guard only starts at index 4, so the slug was
 * dropped without a word. `templates push` has always read `sub[3]` first.
 *
 * cli.ts parses real argv and runs at module load, so it cannot be imported
 * and driven; a source-text scan of the workflows group is the cover (same
 * approach as cli-user-input-errors.test.ts).
 */

const cliSource = readFileSync(
  join(import.meta.dirname, "..", "cli.ts"),
  "utf-8"
);

const groupStart = cliSource.indexOf('case "workflows": {');
const groupEnd = cliSource.indexOf('case "logs": {', groupStart);
const workflowsGroup =
  groupStart === -1 || groupEnd === -1
    ? ""
    : cliSource.slice(groupStart, groupEnd);

describe("email workflows dispatch reads the positional slug", () => {
  it("finds the workflows group in cli.ts", () => {
    expect(workflowsGroup).not.toBe("");
  });

  it("validate and push both prefer sub[3] over --workflow", () => {
    const reads = workflowsGroup.match(
      /workflow: sub\[3\] \|\| flags\.workflow,/g
    );
    expect(reads ?? []).toHaveLength(2);
  });

  it("no subcommand passes --workflow alone", () => {
    expect(workflowsGroup).not.toMatch(/workflow: flags\.workflow,/);
  });
});
