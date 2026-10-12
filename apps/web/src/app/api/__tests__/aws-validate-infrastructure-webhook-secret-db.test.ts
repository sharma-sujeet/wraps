/**
 * Which webhook secret validate-infrastructure stores (real DB).
 *
 * Plan 407: every CloudFormation quick-create link for an org carries one
 * stable, server-issued secret, and re-validating the same stack never
 * replaces the secret that stack holds. Seeds its own orgs with a random
 * suffix, so it does not use the fixed-id fixtures from `./setup`.
 */

import {
  awsAccount,
  db,
  organization,
  organizationExtension,
  user,
} from "@wraps/db";
import { eq } from "drizzle-orm";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { getOrCreateCfnWebhookSecret } from "@/lib/aws/cfn-webhook-secret";

const suffix = crypto.randomUUID().slice(0, 8);
const ORG_ID = `webhook-secret-org-${suffix}`;
const ORG_SLUG = `webhook-secret-${suffix}`;
const CONCURRENCY_ORG_ID = `webhook-secret-conc-org-${suffix}`;
const USER_ID = `webhook-secret-user-${suffix}`;

vi.mock("next/headers", () => ({
  headers: () => new Headers(),
}));

const mockSession = (userId: string): any => ({
  user: { id: userId, email: "test@example.com", name: "Test" },
  session: {
    id: "session-123",
    createdAt: new Date(),
    updatedAt: new Date(),
    userId,
    expiresAt: new Date(Date.now() + 86_400_000),
    token: "test-token",
  },
});

vi.mock("@wraps/auth", () => ({
  auth: {
    api: {
      getSession: vi.fn(async () => mockSession(USER_ID)),
    },
  },
}));

vi.mock("@/lib/organization", () => ({
  getOrganizationWithMembership: vi.fn(async (slug: string) => {
    if (slug === ORG_SLUG) {
      return {
        id: ORG_ID,
        name: "Webhook Secret Org",
        slug: ORG_SLUG,
        userRole: "owner",
      };
    }
    return null;
  }),
}));

vi.mock("@/lib/aws/assume-role", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/aws/assume-role")>();
  return {
    ...actual,
    assumeRole: vi.fn(async () => ({
      accessKeyId: "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      sessionToken: "token",
      expiration: new Date(),
    })),
  };
});

vi.mock("@/lib/aws/detect-features", () => ({
  findInfrastructureStack: vi.fn(async () => null),
  detectFeaturesFromOutputs: vi.fn(() => null),
}));

vi.mock("@/lib/activation-tracking", () => ({
  trackAwsConnected: vi.fn(async () => undefined),
}));

vi.mock("@wraps/email", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@wraps/email")>()),
  scanWrapsIdentities: vi.fn(async () => {
    throw new Error("identity scan disabled in this test");
  }),
}));

const ACCOUNT_ID = "444455557407";
const ROLE_ARN = `arn:aws:iam::${ACCOUNT_ID}:role/wraps-console-access-role`;
const SECRET_A = "a".repeat(64);
const SECRET_B = "b".repeat(64);
const SECRET_C = "c".repeat(64);

// aws_account.external_id is globally unique, so every test mints its own.
function newExternalId() {
  return `wraps_${crypto.randomUUID().replaceAll("-", "")}`;
}

function buildRequest(body: Record<string, unknown>) {
  return new Request(
    `http://localhost/api/${ORG_SLUG}/aws/validate-infrastructure`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        roleArn: ROLE_ARN,
        region: "us-east-1",
        ...body,
      }),
    }
  );
}

const context = { params: Promise.resolve({ orgSlug: ORG_SLUG }) };

async function postValidate(body: Record<string, unknown>) {
  const { POST } = await import(
    "../[orgSlug]/aws/validate-infrastructure/route"
  );
  const response = await POST(buildRequest(body), context);
  expect(response.status).toBe(200);
}

async function seedAccount(externalId: string, webhookSecret: string | null) {
  await db.insert(awsAccount).values({
    id: `webhook-secret-acct-${suffix}`,
    organizationId: ORG_ID,
    name: "Webhook Secret Account",
    accountId: ACCOUNT_ID,
    roleArn: ROLE_ARN,
    externalId,
    region: "us-east-1",
    isVerified: true,
    webhookSecret,
  });
}

async function readRow() {
  const [row] = await db
    .select({
      externalId: awsAccount.externalId,
      webhookSecret: awsAccount.webhookSecret,
    })
    .from(awsAccount)
    .where(eq(awsAccount.organizationId, ORG_ID));
  if (!row) {
    throw new Error("row missing");
  }
  return row;
}

describe("aws/validate-infrastructure webhook secret — real DB", () => {
  beforeAll(async () => {
    await db
      .insert(user)
      .values({
        id: USER_ID,
        name: "Webhook Secret User",
        email: `webhook-secret-${suffix}@example.com`,
        emailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      })
      .onConflictDoNothing();
    await db
      .insert(organization)
      .values([
        {
          id: ORG_ID,
          name: "Webhook Secret Org",
          slug: ORG_SLUG,
          createdAt: new Date(),
        },
        {
          id: CONCURRENCY_ORG_ID,
          name: "Webhook Secret Concurrency Org",
          slug: `webhook-secret-conc-${suffix}`,
          createdAt: new Date(),
        },
      ])
      .onConflictDoNothing();
  });

  beforeEach(async () => {
    await db.delete(awsAccount).where(eq(awsAccount.organizationId, ORG_ID));
    await db
      .delete(organizationExtension)
      .where(eq(organizationExtension.organizationId, ORG_ID));
  });

  afterAll(async () => {
    await db.delete(awsAccount).where(eq(awsAccount.organizationId, ORG_ID));
    await db.delete(organization).where(eq(organization.id, ORG_ID));
    await db
      .delete(organization)
      .where(eq(organization.id, CONCURRENCY_ORG_ID));
    await db.delete(user).where(eq(user.id, USER_ID));
  });

  it("stores the org's CloudFormation secret on a first connect from a new client", async () => {
    await postValidate({ externalId: newExternalId() });

    const row = await readRow();
    expect(row.webhookSecret).toBe(await getOrCreateCfnWebhookSecret(ORG_ID));
    expect(row.webhookSecret).toMatch(/^[a-f0-9]{64}$/);
  });

  it("stores the secret every link carried, however many times the page loaded", async () => {
    const firstLoad = await getOrCreateCfnWebhookSecret(ORG_ID);
    const secondLoad = await getOrCreateCfnWebhookSecret(ORG_ID);

    await postValidate({ externalId: newExternalId() });

    const row = await readRow();
    expect(secondLoad).toBe(firstLoad);
    expect(row.webhookSecret).toBe(firstLoad);
  });

  it("keeps the stored secret when the same stack is re-validated with a different body secret", async () => {
    const externalId = newExternalId();
    await seedAccount(externalId, SECRET_A);

    await postValidate({ externalId, webhookSecret: SECRET_B });

    const row = await readRow();
    expect(row.webhookSecret).toBe(SECRET_A);
  });

  it("keeps the stored secret when the same stack is re-validated with no body secret", async () => {
    const externalId = newExternalId();
    await seedAccount(externalId, SECRET_A);

    await postValidate({ externalId });

    const row = await readRow();
    expect(row.webhookSecret).toBe(SECRET_A);
  });

  it("switches to the org's CloudFormation secret when a new stack was launched", async () => {
    await seedAccount(newExternalId(), SECRET_A);
    const relaunchedExternalId = newExternalId();

    await postValidate({ externalId: relaunchedExternalId });

    const row = await readRow();
    expect(row.webhookSecret).toBe(await getOrCreateCfnWebhookSecret(ORG_ID));
    expect(row.webhookSecret).not.toBe(SECRET_A);
    expect(row.externalId).toBe(relaunchedExternalId);
  });

  it("fills in the org's CloudFormation secret when the same stack's stored secret is NULL", async () => {
    const externalId = newExternalId();
    await seedAccount(externalId, null);

    await postValidate({ externalId });

    const row = await readRow();
    expect(row.webhookSecret).toBe(await getOrCreateCfnWebhookSecret(ORG_ID));
  });

  it("honours the secret an old client sends on a first connect", async () => {
    await postValidate({
      externalId: newExternalId(),
      webhookSecret: SECRET_C,
    });

    const row = await readRow();
    expect(row.webhookSecret).toBe(SECRET_C);
  });

  it("returns one secret to concurrent first callers", async () => {
    const secrets = await Promise.all(
      Array.from({ length: 5 }, () =>
        getOrCreateCfnWebhookSecret(CONCURRENCY_ORG_ID)
      )
    );

    expect(new Set(secrets).size).toBe(1);
    expect(secrets[0]).toMatch(/^[a-f0-9]{64}$/);
  });
});
