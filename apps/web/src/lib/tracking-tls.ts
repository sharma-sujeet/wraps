/**
 * Probes whether a tracking domain is actually served over valid TLS.
 *
 * Plan 302's chosen mechanism for telling a customer which fix is right when
 * SES's tracking `HttpsPolicy` is `OPTIONAL`: this answers the same question
 * a recipient's browser answers when it follows an https:// click link, and
 * needs no new AWS permission. Two alternatives were rejected — see plan 302
 * for the full rationale — one of which (`cloudfront:ListDistributions`)
 * would have exposed every distribution in the customer's account.
 */

import { lookup as dnsLookup } from "node:dns/promises";
import * as tls from "node:tls";
import { blockedIpLabel } from "@/lib/blocked-ip";

export type TrackingTlsResult =
  | { status: "serving" }
  | { status: "not-serving"; reason: string }
  | { status: "unknown"; reason: string };

const TRACKING_TLS_PORT = 443;
const TRACKING_TLS_TIMEOUT_MS = 5000;

/**
 * Opens a TLS handshake against `address` (the DNS-resolved, SSRF-checked
 * IP) with `servername` set to `host` for SNI. Connecting to the checked IP
 * rather than letting Node re-resolve the hostname is what closes the
 * DNS-rebinding window — the IP that is connected to is the IP that was
 * checked. `rejectUnauthorized: true` keeps Node's full chain and hostname
 * validation on, so a handshake failure IS the signal: a certificate error,
 * a refused connection, or a closed port all mean `not-serving`. Only a
 * timeout — genuine uncertainty, not evidence of absence — means `unknown`.
 */
function connectTls(host: string, address: string): Promise<TrackingTlsResult> {
  return new Promise((resolve) => {
    let settled = false;

    const timer = setTimeout(() => {
      finish({ status: "unknown", reason: "TLS handshake timed out" });
    }, TRACKING_TLS_TIMEOUT_MS);

    function finish(result: TrackingTlsResult) {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    }

    const socket = tls.connect(
      {
        host: address,
        port: TRACKING_TLS_PORT,
        servername: host,
        rejectUnauthorized: true,
        timeout: TRACKING_TLS_TIMEOUT_MS,
      },
      () => {
        finish({ status: "serving" });
      }
    );

    socket.on("error", (error: Error) => {
      finish({ status: "not-serving", reason: error.message });
    });

    socket.on("timeout", () => {
      finish({ status: "unknown", reason: "TLS handshake timed out" });
    });
  });
}

/**
 * Resolves `host`, rejects the probe (as `unknown`, opening no connection)
 * if any resolved address is private, loopback, link-local, reserved or multicast (see `@/lib/blocked-ip`),
 * and otherwise opens a TLS handshake to confirm whether the host
 * is actually served over valid HTTPS.
 *
 * Never throws — the contract is that this always resolves to one of the
 * three `TrackingTlsResult` states, so callers never need a try/catch.
 */
export async function probeTrackingTls(
  host: string
): Promise<TrackingTlsResult> {
  let addresses: { address: string; family: number }[];
  try {
    addresses = await dnsLookup(host, { all: true });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    const message = error instanceof Error ? error.message : String(error);
    // ENOTFOUND means the domain does not resolve at all — nothing serves
    // it, so this is a confident `not-serving`. Any other DNS failure
    // (timeout, refused, network blip) is genuine uncertainty.
    if (code === "ENOTFOUND") {
      return { status: "not-serving", reason: `DNS lookup failed: ${message}` };
    }
    return { status: "unknown", reason: `DNS lookup failed: ${message}` };
  }

  if (addresses.length === 0) {
    return { status: "unknown", reason: "DNS lookup returned no addresses" };
  }

  for (const { address } of addresses) {
    const blocked = blockedIpLabel(address);
    if (blocked) {
      return {
        status: "unknown",
        reason: `Resolved address is not eligible to probe (${blocked}): ${address}`,
      };
    }
  }

  return connectTls(host, addresses[0].address);
}
