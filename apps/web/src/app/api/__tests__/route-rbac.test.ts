/**
 * Route RBAC Enforcement Tests
 *
 * Verifies that every mutating [orgSlug] API route enforces the same role
 * permissions the server actions already do (via checkPermission /
 * requireRoutePermission), and that the underlying permission mapping
 * produces the intended allow/deny decisions for each role.
 *
 * Part 1 (static guard): every route file below must reference
 * requireRoutePermission or checkPermission. This is the regression net —
 * a new mutating route that forgets the gate fails this test. Keep the
 * list in sync when routes are added or removed.
 *
 * Part 2 (behavioral): exercises checkPermission directly for the mapping
 * decisions that matter most (template delete, test-email send, and the
 * marketing-role workflow boundary).
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { checkPermission } from "@/actions/shared/permissions";

const ORG_SLUG_ROOT = path.resolve(import.meta.dirname, "../[orgSlug]");

// The 26 mutating route rows from plan 081. Files with two gated verbs
// (e.g. template PUT + DELETE) appear once here since the guard check is
// per-file, not per-verb.
const GATED_ROUTE_FILES = [
  "emails/templates/[id]/route.ts",
  "emails/templates/[id]/publish/route.ts",
  "emails/templates/[id]/duplicate/route.ts",
  "emails/templates/[id]/save-source/route.ts",
  "emails/templates/[id]/conversation/route.ts",
  "emails/templates/[id]/versions/route.ts",
  "emails/templates/[id]/versions/[versionId]/route.ts",
  "emails/templates/[id]/send-test/route.ts",
  "emails/templates/ai/generate-code/route.ts",
  "emails/templates/ai/validate-image/route.ts",
  "brand-kits/route.ts",
  "brand-kits/[id]/route.ts",
  "brand-kits/[id]/default/route.ts",
  "brand-kits/extract/route.ts",
  "brand-kits/from-template/route.ts",
  "(ee)/workflows/ai/generate/route.ts",
  "aws/validate/route.ts",
  "aws/validate-infrastructure/route.ts",
  "onboarding/complete/route.ts",
  "onboarding/verify-cli/route.ts",
];

/**
 * The AI routes delegate the whole gate — session, membership, permission,
 * quota — to resolveAIRequest, so the guard string no longer appears in the
 * route file itself. Accepting the helper here is only safe because the test
 * below proves the helper actually enforces the permission.
 */
const SHARED_GATE_HELPER = "resolveAIRequest";

describe("Route RBAC — static guard", () => {
  it.each(GATED_ROUTE_FILES)(
    "%s references a permission guard",
    (relativePath) => {
      const fullPath = path.join(ORG_SLUG_ROOT, relativePath);
      const content = readFileSync(fullPath, "utf-8");
      const hasGuard =
        content.includes("requireRoutePermission") ||
        content.includes("checkPermission") ||
        content.includes(SHARED_GATE_HELPER);
      expect(hasGuard).toBe(true);
    }
  );

  it("resolveAIRequest itself enforces the route permission", () => {
    // Without this, accepting the helper above would let a route opt out of
    // RBAC entirely just by importing it.
    const helper = readFileSync(
      path.resolve(import.meta.dirname, "../shared/ai-request.ts"),
      "utf-8"
    );
    expect(helper).toContain("requireRoutePermission");
  });

  it("resolveAIRequest checks the AI quota before parsing a body", () => {
    const helper = readFileSync(
      path.resolve(import.meta.dirname, "../shared/ai-request.ts"),
      "utf-8"
    );
    expect(helper).toContain("checkAiUsageLimit");
  });
});

describe("Route RBAC — behavioral: mapping intent", () => {
  it("denies read-only on templates:delete", () => {
    const result = checkPermission("read-only", "templates", ["delete"]);
    expect(result).not.toBeNull();
    expect(result?.success).toBe(false);
  });

  it("allows owner on templates:delete", () => {
    const result = checkPermission("owner", "templates", ["delete"]);
    expect(result).toBeNull();
  });

  it("denies read-only on broadcasts:send", () => {
    const result = checkPermission("read-only", "broadcasts", ["send"]);
    expect(result).not.toBeNull();
    expect(result?.success).toBe(false);
  });

  it("allows owner on broadcasts:send", () => {
    const result = checkPermission("owner", "broadcasts", ["send"]);
    expect(result).toBeNull();
  });

  it("denies billing on broadcasts:send", () => {
    const result = checkPermission("billing", "broadcasts", ["send"]);
    expect(result).not.toBeNull();
    expect(result?.success).toBe(false);
  });

  it("allows marketing on templates:write", () => {
    const result = checkPermission("marketing", "templates", ["write"]);
    expect(result).toBeNull();
  });

  it("denies marketing on workflows:write (marketing boundary)", () => {
    const result = checkPermission("marketing", "workflows", ["write"]);
    expect(result).not.toBeNull();
    expect(result?.success).toBe(false);
  });

  it("allows member on templates:write", () => {
    const result = checkPermission("member", "templates", ["write"]);
    expect(result).toBeNull();
  });

  it("allows owner on orgSettings:write (onboarding/complete)", () => {
    const result = checkPermission("owner", "orgSettings", ["write"]);
    expect(result).toBeNull();
  });

  it("denies member on orgSettings:write (onboarding/complete)", () => {
    const result = checkPermission("member", "orgSettings", ["write"]);
    expect(result).not.toBeNull();
    expect(result?.success).toBe(false);
  });
});
