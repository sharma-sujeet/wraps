import {
  awsAccount,
  db,
  member,
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
import {
  getOwnEmailVerificationStatus,
  sendSimulatorTestEmail,
  sendWelcomeTestEmail,
  verifyOwnEmailIdentity,
} from "../ses-onboarding";

// ─── Test data ──────────────────────────────────────────────────────────────

const testOwner = {
  id: "test-ses-onb-owner-1",
  email: "ses-onb-owner@example.com",
  name: "SES Onboarding Owner",
  emailVerified: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  image: null,
  twoFactorEnabled: false,
  stripeCustomerId: null,
};

const testBillingUser = {
  id: "test-ses-onb-billing-1",
  email: "ses-onb-billing@example.com",
  name: "SES Onboarding Billing",
  emailVerified: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  image: null,
  twoFactorEnabled: false,
  stripeCustomerId: null,
};

const testOrganization = {
  id: "test-ses-onb-org-1",
  name: "SES Onboarding Test Org",
  slug: "ses-onb-test-org",
  createdAt: new Date(),
  logo: null,
  metadata: null,
};

const testOwnerMember = {
  id: "test-ses-onb-owner-member-1",
  organizationId: testOrganization.id,
  userId: testOwner.id,
  role: "owner" as const,
  createdAt: new Date(),
};

const testBillingMember = {
  id: "test-ses-onb-billing-member-1",
  organizationId: testOrganization.id,
  userId: testBillingUser.id,
  role: "billing" as const,
  createdAt: new Date(),
};

// Account with a verified domain (acme.com) carrying its own per-domain
// config set — used for the happy-path / config-set-resolution tests.
const testAwsAccount = {
  id: "test-ses-onb-aws-account-1",
  organizationId: testOrganization.id,
  name: "SES Onboarding AWS Account",
  accountId: "111111111111",
  region: "us-east-1",
  roleArn: "arn:aws:iam::111111111111:role/WrapsRole",
  externalId: "test-ses-onb-external-id-1",
  isVerified: true,
  lastVerifiedAt: new Date(),
  createdBy: testOwner.id,
  createdAt: new Date(),
  updatedAt: new Date(),
  webhookSecret: null,
  features: {
    email: {
      identities: [
        {
          identity: "acme.com",
          type: "DOMAIN" as const,
          configSetName: "wraps-email-acme.com",
        },
      ],
    },
  },
};

// Org with a member but NO verified domain and NO org default sender —
// used for the "no sender resolvable" error paths.
const testOrgNoSender = {
  id: "test-ses-onb-org-no-sender-1",
  name: "SES Onboarding No-Sender Org",
  slug: "ses-onb-no-sender-org",
  createdAt: new Date(),
  logo: null,
  metadata: null,
};

const testOrgNoSenderOwnerMember = {
  id: "test-ses-onb-no-sender-owner-member-1",
  organizationId: testOrgNoSender.id,
  userId: testOwner.id,
  role: "owner" as const,
  createdAt: new Date(),
};

const testAwsAccountNoSender = {
  id: "test-ses-onb-aws-account-no-sender-1",
  organizationId: testOrgNoSender.id,
  name: "No Sender AWS Account",
  accountId: "222222222222",
  region: "us-east-1",
  roleArn: "arn:aws:iam::222222222222:role/WrapsRole",
  externalId: "test-ses-onb-external-id-2",
  isVerified: true,
  lastVerifiedAt: new Date(),
  createdBy: testOwner.id,
  createdAt: new Date(),
  updatedAt: new Date(),
  webhookSecret: null,
  features: { email: { identities: [] } },
};

// Org with a member but NO AWS account at all.
const testOrgNoAccount = {
  id: "test-ses-onb-org-no-account-1",
  name: "SES Onboarding No-Account Org",
  slug: "ses-onb-no-account-org",
  createdAt: new Date(),
  logo: null,
  metadata: null,
};

const testOrgNoAccountOwnerMember = {
  id: "test-ses-onb-no-account-owner-member-1",
  organizationId: testOrgNoAccount.id,
  userId: testOwner.id,
  role: "owner" as const,
  createdAt: new Date(),
};

// Second org (org B) for cross-org IDOR tests.
const orgB = {
  id: "test-ses-onb-org-b-1",
  name: "SES Onboarding Org B",
  slug: "ses-onb-org-b",
  createdAt: new Date(),
  logo: null,
  metadata: null,
};

// ─── Mocks ──────────────────────────────────────────────────────────────────

let currentMockUserId: string | null = testOwner.id;

vi.mock("next/headers", () => ({
  headers: () => new Headers(),
}));

const getUserData = (userId: string | null) => {
  if (userId === testOwner.id) {
    return { email: testOwner.email, name: testOwner.name };
  }
  if (userId === testBillingUser.id) {
    return { email: testBillingUser.email, name: testBillingUser.name };
  }
  return { email: "unknown@example.com", name: "Unknown" };
};

vi.mock("@wraps/auth", () => ({
  auth: {
    api: {
      getSession: vi.fn(async () => {
        if (currentMockUserId === null) {
          return null;
        }
        const userData = getUserData(currentMockUserId);
        return {
          user: {
            id: currentMockUserId,
            email: userData.email,
            name: userData.name,
          },
          session: {
            id: "session-123",
            createdAt: new Date(),
            updatedAt: new Date(),
            userId: currentMockUserId,
            expiresAt: new Date(Date.now() + 86_400_000),
            token: "test-token",
          },
        };
      }),
    },
  },
}));

const mockGetOrAssumeRole = vi.fn();
vi.mock("@/lib/aws/credential-cache", () => ({
  getOrAssumeRole: (...args: unknown[]) => mockGetOrAssumeRole(...args),
}));

const mockTrackFirstEmailSent = vi.fn();
vi.mock("@/lib/activation-tracking", () => ({
  trackFirstEmailSent: (...args: unknown[]) => mockTrackFirstEmailSent(...args),
}));

type SesCommand = {
  _type: string;
  input: Record<string, unknown>;
};

const mockSesSend = vi.fn();

vi.mock("@aws-sdk/client-sesv2", () => ({
  SESv2Client: class {
    send(command: SesCommand) {
      return mockSesSend(command);
    }
  },
  SendEmailCommand: class {
    _type = "SendEmailCommand";
    input: Record<string, unknown>;
    constructor(input: Record<string, unknown>) {
      this.input = input;
    }
  },
  GetEmailIdentityCommand: class {
    _type = "GetEmailIdentityCommand";
    input: { EmailIdentity: string };
    constructor(input: { EmailIdentity: string }) {
      this.input = input;
    }
  },
  CreateEmailIdentityCommand: class {
    _type = "CreateEmailIdentityCommand";
    input: { EmailIdentity: string };
    constructor(input: { EmailIdentity: string }) {
      this.input = input;
    }
  },
}));

// ─── Setup ──────────────────────────────────────────────────────────────────

beforeAll(async () => {
  await db
    .insert(user)
    .values(testOwner)
    .onConflictDoUpdate({
      target: user.id,
      set: { updatedAt: new Date() },
    });
  await db
    .insert(user)
    .values(testBillingUser)
    .onConflictDoUpdate({
      target: user.id,
      set: { updatedAt: new Date() },
    });

  for (const org of [
    testOrganization,
    testOrgNoSender,
    testOrgNoAccount,
    orgB,
  ]) {
    await db
      .insert(organization)
      .values(org)
      .onConflictDoUpdate({
        target: organization.id,
        set: { name: org.name },
      });
  }

  for (const m of [
    testOwnerMember,
    testBillingMember,
    testOrgNoSenderOwnerMember,
    testOrgNoAccountOwnerMember,
  ]) {
    await db
      .insert(member)
      .values(m)
      .onConflictDoUpdate({
        target: member.id,
        set: { role: m.role },
      });
  }

  for (const acct of [testAwsAccount, testAwsAccountNoSender]) {
    await db
      .insert(awsAccount)
      .values(acct)
      .onConflictDoUpdate({
        target: awsAccount.id,
        set: { updatedAt: new Date(), features: acct.features },
      });
  }
});

afterAll(async () => {
  await db.delete(awsAccount).where(eq(awsAccount.id, testAwsAccount.id));
  await db
    .delete(awsAccount)
    .where(eq(awsAccount.id, testAwsAccountNoSender.id));
  await db.delete(member).where(eq(member.id, testOwnerMember.id));
  await db.delete(member).where(eq(member.id, testBillingMember.id));
  await db.delete(member).where(eq(member.id, testOrgNoSenderOwnerMember.id));
  await db.delete(member).where(eq(member.id, testOrgNoAccountOwnerMember.id));
  await db
    .delete(organizationExtension)
    .where(eq(organizationExtension.organizationId, testOrganization.id));
  await db.delete(organization).where(eq(organization.id, testOrganization.id));
  await db.delete(organization).where(eq(organization.id, testOrgNoSender.id));
  await db.delete(organization).where(eq(organization.id, testOrgNoAccount.id));
  await db.delete(organization).where(eq(organization.id, orgB.id));
  await db.delete(user).where(eq(user.id, testOwner.id));
  await db.delete(user).where(eq(user.id, testBillingUser.id));
});

beforeEach(async () => {
  currentMockUserId = testOwner.id;
  mockGetOrAssumeRole.mockReset();
  mockGetOrAssumeRole.mockResolvedValue({
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    sessionToken: "session-token",
  });
  mockSesSend.mockReset();
  mockTrackFirstEmailSent.mockReset();
  mockTrackFirstEmailSent.mockResolvedValue(undefined);

  // No org default sender by default — individual tests opt in.
  await db
    .delete(organizationExtension)
    .where(eq(organizationExtension.organizationId, testOrganization.id));
});

function captureSendInput(command: SesCommand) {
  return command.input as {
    FromEmailAddress?: string;
    Destination?: { ToAddresses?: string[] };
    ConfigurationSetName?: string;
    Content?: {
      Simple?: {
        Body?: { Html?: { Data?: string }; Text?: { Data?: string } };
      };
    };
    EmailTags?: Array<{ Name: string; Value: string }>;
  };
}

// ─── sendSimulatorTestEmail ─────────────────────────────────────────────────

describe("sendSimulatorTestEmail", () => {
  it("sends to the SES simulator success address with a resolved config set", async () => {
    mockSesSend.mockImplementation((command: SesCommand) => {
      if (command._type === "SendEmailCommand") {
        return Promise.resolve({ MessageId: "test-message-id-1" });
      }
      return Promise.reject(new Error(`Unexpected command ${command._type}`));
    });

    const result = await sendSimulatorTestEmail(testOrganization.id);

    expect(result.success).toBe(true);
    expect(mockSesSend).toHaveBeenCalledTimes(1);
    const sent = captureSendInput(mockSesSend.mock.calls[0][0]);
    expect(sent.Destination?.ToAddresses).toEqual([
      "success@simulator.amazonses.com",
    ]);
    expect(sent.Content?.Simple?.Body?.Text?.Data).toBeTruthy();
    expect(sent.EmailTags).toBeTruthy();
    expect(sent.EmailTags?.length).toBeGreaterThan(0);
    // Config set resolved by lookup from the seeded acme.com identity, not
    // the legacy global set.
    expect(sent.ConfigurationSetName).toBe("wraps-email-acme.com");
  });

  it("calls trackFirstEmailSent once with the simulator_test source", async () => {
    mockSesSend.mockResolvedValue({ MessageId: "test-message-id-2" });

    await sendSimulatorTestEmail(testOrganization.id);

    expect(mockTrackFirstEmailSent).toHaveBeenCalledTimes(1);
    expect(mockTrackFirstEmailSent).toHaveBeenCalledWith(
      testOwner.email,
      testOrganization.id,
      { channel: "email", source: "simulator_test" }
    );
  });

  it("returns a typed error and never sends when no sender can be resolved", async () => {
    const result = await sendSimulatorTestEmail(testOrgNoSender.id);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("Verify a domain");
    }
    expect(mockSesSend).not.toHaveBeenCalled();
  });

  it("surfaces a DNS-propagation message on MessageRejected, not a generic failure", async () => {
    mockSesSend.mockImplementation(() => {
      const err = new Error("Email address is not verified");
      err.name = "MessageRejected";
      return Promise.reject(err);
    });

    const result = await sendSimulatorTestEmail(testOrganization.id);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("DNS");
    }
  });

  it("denies a role without broadcasts:send and never sends", async () => {
    currentMockUserId = testBillingUser.id;

    const result = await sendSimulatorTestEmail(testOrganization.id);

    expect(result.success).toBe(false);
    expect(mockSesSend).not.toHaveBeenCalled();
  });

  it("rejects a cross-org call and never sends", async () => {
    // testOwner is not a member of orgB.
    const result = await sendSimulatorTestEmail(orgB.id);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("don't have access");
    }
    expect(mockSesSend).not.toHaveBeenCalled();
  });
});

// ─── verifyOwnEmailIdentity ─────────────────────────────────────────────────

describe("verifyOwnEmailIdentity", () => {
  it("starts verification for the caller's own email", async () => {
    mockSesSend.mockImplementation((command: SesCommand) => {
      if (command._type === "GetEmailIdentityCommand") {
        const err = new Error("NotFoundException");
        err.name = "NotFoundException";
        return Promise.reject(err);
      }
      if (command._type === "CreateEmailIdentityCommand") {
        return Promise.resolve({});
      }
      return Promise.reject(new Error(`Unexpected command ${command._type}`));
    });

    const result = await verifyOwnEmailIdentity(testOrganization.id);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.alreadyVerified).toBe(false);
      expect(result.email).toBe(testOwner.email);
    }
    const createCall = mockSesSend.mock.calls.find(
      (call) => (call[0] as SesCommand)._type === "CreateEmailIdentityCommand"
    );
    expect(createCall).toBeDefined();
    expect(
      (createCall?.[0] as SesCommand).input as { EmailIdentity: string }
    ).toEqual({ EmailIdentity: testOwner.email });
  });

  it("short-circuits when already verified — no CreateEmailIdentity call", async () => {
    mockSesSend.mockImplementation((command: SesCommand) => {
      if (command._type === "GetEmailIdentityCommand") {
        return Promise.resolve({ VerifiedForSendingStatus: true });
      }
      return Promise.reject(new Error(`Unexpected command ${command._type}`));
    });

    const result = await verifyOwnEmailIdentity(testOrganization.id);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.alreadyVerified).toBe(true);
    }
    const createCall = mockSesSend.mock.calls.find(
      (call) => (call[0] as SesCommand)._type === "CreateEmailIdentityCommand"
    );
    expect(createCall).toBeUndefined();
  });

  it("returns a typed error when no AWS account is connected", async () => {
    const result = await verifyOwnEmailIdentity(testOrgNoAccount.id);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("No AWS account connected");
    }
  });

  it("denies a role without awsAccounts:write", async () => {
    currentMockUserId = testBillingUser.id;

    const result = await verifyOwnEmailIdentity(testOrganization.id);

    expect(result.success).toBe(false);
    expect(mockSesSend).not.toHaveBeenCalled();
  });

  it("rejects a cross-org call", async () => {
    const result = await verifyOwnEmailIdentity(orgB.id);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("don't have access");
    }
  });
});

// ─── getOwnEmailVerificationStatus ──────────────────────────────────────────

describe("getOwnEmailVerificationStatus", () => {
  it("returns verified: true when SES reports VerifiedForSendingStatus", async () => {
    mockSesSend.mockResolvedValue({ VerifiedForSendingStatus: true });

    const result = await getOwnEmailVerificationStatus(testOrganization.id);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.verified).toBe(true);
    }
  });

  it("returns verified: false (not an error) on NotFoundException", async () => {
    mockSesSend.mockImplementation(() => {
      const err = new Error("NotFoundException");
      err.name = "NotFoundException";
      return Promise.reject(err);
    });

    const result = await getOwnEmailVerificationStatus(testOrganization.id);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.verified).toBe(false);
    }
  });

  it("returns verified: false on the AWS SDK v3 name:'Error' quirk", async () => {
    mockSesSend.mockImplementation(() => {
      // AWS SDK v3 sometimes returns name: "Error" with the real exception
      // only in the message.
      const err = new Error("NotFoundException: identity not found");
      err.name = "Error";
      return Promise.reject(err);
    });

    const result = await getOwnEmailVerificationStatus(testOrganization.id);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.verified).toBe(false);
    }
  });
});

// ─── sendWelcomeTestEmail ────────────────────────────────────────────────────

describe("sendWelcomeTestEmail", () => {
  it("sends to the caller's own email with a resolved config set on the happy path", async () => {
    mockSesSend.mockImplementation((command: SesCommand) => {
      if (command._type === "SendEmailCommand") {
        return Promise.resolve({ MessageId: "test-message-id-3" });
      }
      return Promise.reject(new Error(`Unexpected command ${command._type}`));
    });

    const result = await sendWelcomeTestEmail(testOrganization.id);

    expect(result.success).toBe(true);
    const sent = captureSendInput(mockSesSend.mock.calls[0][0]);
    expect(sent.Destination?.ToAddresses).toEqual([testOwner.email]);
    expect(sent.Content?.Simple?.Body?.Text?.Data).toBeTruthy();
    expect(sent.EmailTags?.length).toBeGreaterThan(0);
    expect(sent.ConfigurationSetName).toBe("wraps-email-acme.com");

    expect(mockTrackFirstEmailSent).toHaveBeenCalledTimes(1);
    expect(mockTrackFirstEmailSent).toHaveBeenCalledWith(
      testOwner.email,
      testOrganization.id,
      { channel: "email", source: "welcome_test" }
    );
  });

  it("never sends to anyone but the caller's own email", async () => {
    mockSesSend.mockResolvedValue({ MessageId: "test-message-id-4" });

    await sendWelcomeTestEmail(testOrganization.id);

    const sent = captureSendInput(mockSesSend.mock.calls[0][0]);
    expect(sent.Destination?.ToAddresses).toEqual([testOwner.email]);
  });

  it("maps a sandbox MessageRejected send failure to a verify-your-email message", async () => {
    mockSesSend.mockImplementation((command: SesCommand) => {
      if (command._type === "SendEmailCommand") {
        const err = new Error("Email address is not verified");
        err.name = "MessageRejected";
        return Promise.reject(err);
      }
      return Promise.reject(new Error(`Unexpected command ${command._type}`));
    });

    const result = await sendWelcomeTestEmail(testOrganization.id);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("Verify your email");
    }
  });

  it("returns a typed no-sender error when there's no domain, default sender, or verified own identity", async () => {
    mockSesSend.mockImplementation((command: SesCommand) => {
      if (command._type === "GetEmailIdentityCommand") {
        return Promise.resolve({ VerifiedForSendingStatus: false });
      }
      return Promise.reject(new Error(`Unexpected command ${command._type}`));
    });

    const result = await sendWelcomeTestEmail(testOrgNoSender.id);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("Verify a domain");
    }
    const sendCall = mockSesSend.mock.calls.find(
      (call) => (call[0] as SesCommand)._type === "SendEmailCommand"
    );
    expect(sendCall).toBeUndefined();
  });
});
