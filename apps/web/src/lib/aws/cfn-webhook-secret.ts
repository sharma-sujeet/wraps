import { randomBytes } from "node:crypto";
import { db, organizationExtension } from "@wraps/db";
import { eq, isNull } from "drizzle-orm";

/**
 * The webhook secret every CloudFormation quick-create link for this org
 * carries. Stable per org, so a page reload rebuilds the link the customer
 * already launched, and validate-infrastructure stores the same value the
 * stack holds.
 */
export async function getOrCreateCfnWebhookSecret(
  organizationId: string
): Promise<string> {
  const readSecret = async () => {
    const [row] = await db
      .select({ secret: organizationExtension.cfnWebhookSecret })
      .from(organizationExtension)
      .where(eq(organizationExtension.organizationId, organizationId));
    return row?.secret ?? null;
  };

  const existing = await readSecret();
  if (existing) {
    return existing;
  }

  // The IS NULL setWhere makes concurrent first calls safe: only one write
  // lands, and every caller re-reads the winner.
  const candidate = randomBytes(32).toString("hex");
  await db
    .insert(organizationExtension)
    .values({ organizationId, cfnWebhookSecret: candidate })
    .onConflictDoUpdate({
      target: organizationExtension.organizationId,
      set: { cfnWebhookSecret: candidate, updatedAt: new Date() },
      setWhere: isNull(organizationExtension.cfnWebhookSecret),
    });

  const stored = await readSecret();
  if (!stored) {
    throw new Error("CloudFormation webhook secret was not persisted");
  }
  return stored;
}
