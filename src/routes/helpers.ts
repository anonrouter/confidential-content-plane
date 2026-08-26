import type { FastifyRequest } from "fastify";
import { isIP } from "node:net";
import { z } from "zod";
import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import { hashNetworkFingerprint, hmacSha256 } from "../security/crypto.js";
import { AppError } from "../security/errors.js";

// Typed on z.output so schemas with `.default()`/transforms (input ≠ output)
// resolve to their parsed shape instead of collapsing both onto one type var.
export function parseBody<S extends z.ZodTypeAny>(schema: S, body: unknown): z.output<S> {
  const result = schema.safeParse(body);
  if (!result.success) {
    throw new AppError(400, "invalid_request", "Invalid request");
  }
  return result.data;
}

export interface NetworkFingerprints {
  /** Daily-rotating HMAC of the canonical client address. */
  exact: string;
  /** Daily-rotating HMAC of the IPv4 /24 or IPv6 /64 containing the client. */
  subnet: string;
}

interface NetworkAddressScopes {
  exact: string;
  subnet: string;
}

function ipv4Address(value: string) {
  if (isIP(value) !== 4) return null;
  const octets = value.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return octets;
}

function ipv6Groups(value: string) {
  let address = value.toLowerCase().split("%", 1)[0];
  const dottedSuffix = address.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/)?.[1];
  if (dottedSuffix) {
    const octets = ipv4Address(dottedSuffix);
    if (!octets) return null;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    address = `${address.slice(0, -dottedSuffix.length)}${high}:${low}`;
  }
  if (isIP(address) !== 6) return null;

  const halves = address.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const raw = [...left, ...Array.from({ length: Math.max(0, missing) }, () => "0"), ...right];
  if (raw.length !== 8) return null;
  const groups = raw.map((part) => Number.parseInt(part || "0", 16));
  if (groups.some((part) => !Number.isInteger(part) || part < 0 || part > 0xffff)) return null;
  return groups;
}

/**
 * Produce stable address scopes without retaining the raw address. IPv4-mapped
 * IPv6 addresses collapse to IPv4, so alternate textual encodings cannot mint
 * fresh buckets. User-Agent is intentionally excluded: it is caller-controlled
 * and must never be the only key for a network abuse limit.
 */
export function networkAddressScopes(rawAddress: string): NetworkAddressScopes {
  const address = rawAddress.trim();
  const ipv4 = ipv4Address(address);
  if (ipv4) {
    const exact = ipv4.join(".");
    return { exact, subnet: `${ipv4[0]}.${ipv4[1]}.${ipv4[2]}.0/24` };
  }

  const ipv6 = ipv6Groups(address);
  if (ipv6) {
    const mappedIpv4 = ipv6.slice(0, 5).every((part) => part === 0) && ipv6[5] === 0xffff
      ? [ipv6[6] >> 8, ipv6[6] & 0xff, ipv6[7] >> 8, ipv6[7] & 0xff]
      : null;
    if (mappedIpv4) {
      const exact = mappedIpv4.join(".");
      return { exact, subnet: `${mappedIpv4[0]}.${mappedIpv4[1]}.${mappedIpv4[2]}.0/24` };
    }
    const canonical = ipv6.map((part) => part.toString(16)).join(":");
    const subnet = `${ipv6.slice(0, 4).map((part) => part.toString(16)).join(":")}:0:0:0:0/64`;
    return { exact: canonical, subnet };
  }

  // Fastify supplies a validated socket/proxy address. Keep a deterministic
  // fail-safe for unusual transports without ever exposing the raw value.
  const fallback = address.toLowerCase() || "unknown";
  return { exact: fallback, subnet: fallback };
}

export function networkFingerprints(request: FastifyRequest, config: ContentPlaneConfig): NetworkFingerprints {
  const scopes = networkAddressScopes(request.ip);
  return {
    exact: hashNetworkFingerprint(`exact:${scopes.exact}`, config),
    subnet: hashNetworkFingerprint(`subnet:${scopes.subnet}`, config)
  };
}

/** Backwards-compatible exact-address fingerprint for low-risk call sites. */
export function networkFingerprint(request: FastifyRequest, config: ContentPlaneConfig) {
  return networkFingerprints(request, config).exact;
}

export function subjectHash(subject: string, config: ContentPlaneConfig) {
  return hmacSha256(subject, config.secrets.appSecret);
}

export function postgresConflict(error: unknown) {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === "23505");
}
