import { describe, expect, it } from "vitest";
import { blockedIpLabel } from "../blocked-ip";

describe("blockedIpLabel", () => {
  it("blocks IMDS/link-local (169.254.x.x)", () => {
    expect(blockedIpLabel("169.254.169.254")).toBe("link-local/IMDS");
    expect(blockedIpLabel("169.254.0.1")).toBe("link-local/IMDS");
  });

  it("blocks loopback (127.x.x.x)", () => {
    expect(blockedIpLabel("127.0.0.1")).toBe("loopback");
    expect(blockedIpLabel("127.255.255.255")).toBe("loopback");
  });

  it("blocks unspecified (0.x.x.x)", () => {
    expect(blockedIpLabel("0.0.0.0")).toBe("unspecified");
  });

  it("blocks private 10.0.0.0/8", () => {
    expect(blockedIpLabel("10.0.0.1")).toBe("private (10/8)");
    expect(blockedIpLabel("10.255.255.255")).toBe("private (10/8)");
  });

  it("blocks private 172.16.0.0/12", () => {
    expect(blockedIpLabel("172.16.0.1")).toBe("private (172.16/12)");
    expect(blockedIpLabel("172.31.255.255")).toBe("private (172.16/12)");
  });

  it("does not block 172.15.x or 172.32.x", () => {
    expect(blockedIpLabel("172.15.0.1")).toBeNull();
    expect(blockedIpLabel("172.32.0.1")).toBeNull();
  });

  it("blocks private 192.168.0.0/16", () => {
    expect(blockedIpLabel("192.168.0.1")).toBe("private (192.168/16)");
    expect(blockedIpLabel("192.168.255.255")).toBe("private (192.168/16)");
  });

  it("allows public IPs", () => {
    expect(blockedIpLabel("8.8.8.8")).toBeNull();
    expect(blockedIpLabel("1.1.1.1")).toBeNull();
    expect(blockedIpLabel("93.184.216.34")).toBeNull();
  });

  it("blocks IPv6 loopback (::1, ::)", () => {
    expect(blockedIpLabel("::1")).toBe("loopback");
    expect(blockedIpLabel("::")).toBe("loopback");
  });

  it("blocks IPv6 link-local (fe80:)", () => {
    expect(blockedIpLabel("fe80::1")).toBe("link-local");
  });

  it("blocks IPv6 ULA (fd/fc)", () => {
    expect(blockedIpLabel("fd00::1")).toBe("private (ULA)");
    expect(blockedIpLabel("fc00::1")).toBe("private (ULA)");
  });

  // --- Gap: IPv4-mapped IPv6 ---
  it("blocks IPv4-mapped IPv6 private addresses", () => {
    expect(blockedIpLabel("::ffff:127.0.0.1")).toBeTruthy();
    expect(blockedIpLabel("::ffff:169.254.169.254")).toBeTruthy();
    expect(blockedIpLabel("::ffff:10.0.0.1")).toBeTruthy();
    expect(blockedIpLabel("::ffff:192.168.1.1")).toBeTruthy();
  });

  // --- Gap: AWS VPC/CGN range ---
  it("blocks AWS VPC/CGN range (100.64.0.0/10)", () => {
    expect(blockedIpLabel("100.64.0.1")).toBeTruthy();
    expect(blockedIpLabel("100.127.255.255")).toBeTruthy();
  });

  it("does not block public 100.x outside CGN range", () => {
    expect(blockedIpLabel("100.63.255.255")).toBeNull();
    expect(blockedIpLabel("100.128.0.1")).toBeNull();
  });

  // --- Ranges the string-prefix version missed ---
  it("blocks benchmarking 198.18.0.0/15 and nothing either side of it", () => {
    expect(blockedIpLabel("198.18.0.1")).toBe("benchmarking (198.18/15)");
    expect(blockedIpLabel("198.19.255.255")).toBe("benchmarking (198.18/15)");
    expect(blockedIpLabel("198.17.255.255")).toBeNull();
    expect(blockedIpLabel("198.20.0.1")).toBeNull();
  });

  it("blocks IPv4 multicast (224.0.0.0/4)", () => {
    expect(blockedIpLabel("224.0.0.1")).toBe("multicast");
    expect(blockedIpLabel("239.255.255.250")).toBe("multicast");
  });

  it("blocks reserved and broadcast (240.0.0.0/4)", () => {
    expect(blockedIpLabel("240.0.0.1")).toBe("reserved/broadcast (240/4)");
    expect(blockedIpLabel("255.255.255.255")).toBe(
      "reserved/broadcast (240/4)"
    );
  });

  it("blocks 192.0.0.0/24 but not the neighbouring 192.0.1.x", () => {
    expect(blockedIpLabel("192.0.0.1")).toBe(
      "IETF protocol assignments (192.0.0/24)"
    );
    expect(blockedIpLabel("192.0.1.1")).toBeNull();
  });

  it("blocks IPv6 multicast and NAT64", () => {
    expect(blockedIpLabel("ff02::1")).toBe("multicast");
    // NAT64 of 169.254.169.254
    expect(blockedIpLabel("64:ff9b::a9fe:a9fe")).toBe("NAT64");
  });

  it("blocks the whole fe80::/10 link-local range, not just fe80:", () => {
    expect(blockedIpLabel("fe90::1")).toBe("link-local");
    expect(blockedIpLabel("febf::1")).toBe("link-local");
  });

  it("blocks hex-form IPv4-mapped and IPv4-compatible IPv6", () => {
    expect(blockedIpLabel("::ffff:7f00:1")).toBe("loopback");
    expect(blockedIpLabel("::ffff:a9fe:a9fe")).toBe("link-local/IMDS");
    expect(blockedIpLabel("::127.0.0.1")).toBe("IPv4-compatible (deprecated)");
    expect(blockedIpLabel("::ffff:8.8.8.8")).toBeNull();
  });

  it("fails closed on input that is not an IP address", () => {
    expect(blockedIpLabel("example.com")).toBe("not an IP address");
    expect(blockedIpLabel("")).toBe("not an IP address");
  });

  it("allows public IPv6", () => {
    expect(blockedIpLabel("2606:4700::1111")).toBeNull();
    expect(blockedIpLabel("2001:4860:4860::8888")).toBeNull();
  });
});
