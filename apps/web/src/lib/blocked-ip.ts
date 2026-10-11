/**
 * Classifies an IP address as blocked for server-side fetches of
 * user-supplied URLs (private, loopback, link-local, reserved, multicast).
 *
 * The range table matches `isBlockedIp` in
 * `apps/api/src/(ee)/workers/workflow-utils.ts` entry for entry, labels
 * included. If you change one, change the other (plan 411 merges them).
 */

import { BlockList, isIP } from "node:net";

// Order matters: the first matching entry's label is returned. `::1` and `::`
// come before `::/96` so they keep the "loopback" label.
const BLOCKED_SUBNETS = [
  { network: "127.0.0.0", prefix: 8, family: "ipv4", label: "loopback" },
  { network: "10.0.0.0", prefix: 8, family: "ipv4", label: "private (10/8)" },
  {
    network: "169.254.0.0",
    prefix: 16,
    family: "ipv4",
    label: "link-local/IMDS",
  },
  { network: "0.0.0.0", prefix: 8, family: "ipv4", label: "unspecified" },
  {
    network: "100.64.0.0",
    prefix: 10,
    family: "ipv4",
    label: "private (100.64/10 CGN)",
  },
  {
    network: "172.16.0.0",
    prefix: 12,
    family: "ipv4",
    label: "private (172.16/12)",
  },
  {
    network: "192.0.0.0",
    prefix: 24,
    family: "ipv4",
    label: "IETF protocol assignments (192.0.0/24)",
  },
  {
    network: "192.168.0.0",
    prefix: 16,
    family: "ipv4",
    label: "private (192.168/16)",
  },
  {
    network: "198.18.0.0",
    prefix: 15,
    family: "ipv4",
    label: "benchmarking (198.18/15)",
  },
  { network: "224.0.0.0", prefix: 4, family: "ipv4", label: "multicast" },
  {
    network: "240.0.0.0",
    prefix: 4,
    family: "ipv4",
    label: "reserved/broadcast (240/4)",
  },
  { network: "::1", prefix: 128, family: "ipv6", label: "loopback" },
  { network: "::", prefix: 128, family: "ipv6", label: "loopback" },
  {
    network: "::",
    prefix: 96,
    family: "ipv6",
    label: "IPv4-compatible (deprecated)",
  },
  { network: "64:ff9b::", prefix: 96, family: "ipv6", label: "NAT64" },
  { network: "fc00::", prefix: 7, family: "ipv6", label: "private (ULA)" },
  { network: "fe80::", prefix: 10, family: "ipv6", label: "link-local" },
  { network: "ff00::", prefix: 8, family: "ipv6", label: "multicast" },
] as const;

// One BlockList per entry so a match can report its label. BlockList matches
// IPv4-mapped IPv6 (::ffff:7f00:1 and ::ffff:127.0.0.1) against IPv4 entries.
const BLOCKED_LISTS = BLOCKED_SUBNETS.map(
  ({ network, prefix, family, label }) => {
    const list = new BlockList();
    list.addSubnet(network, prefix, family);
    return { list, label };
  }
);

/**
 * Returns why `ip` must not be fetched, or `null` when it is a public
 * address. Fails closed: anything that is not an IP literal is blocked.
 */
export function blockedIpLabel(ip: string): string | null {
  const family = isIP(ip);
  if (family === 0) {
    return "not an IP address";
  }
  const type = family === 4 ? "ipv4" : "ipv6";
  for (const { list, label } of BLOCKED_LISTS) {
    if (list.check(ip, type)) {
      return label;
    }
  }
  return null;
}
