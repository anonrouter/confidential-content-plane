// The accepted-measurement policy for AnonRouter's own confidential gateway.
//
// CRITICAL PROPERTY: a verifier must never download this policy from the server
// it is verifying. A gateway that could hand a client the list of builds the
// client will accept could always name itself. The policy therefore ships INSIDE
// the verifying client (SDK, CLI, verify-proxy) or comes from an independently
// distributed, separately signed release manifest.
//
// Nothing in this file reads the network or the filesystem. `loadGatewayPolicy`
// parses an already-obtained document and fails closed on anything unexpected.

import { canonicalGatewayOrigin } from "./binding.js";

/** Platform-level measurements (firmware + OS image), when pinned. */
export interface GatewayPlatformMeasurements {
  /** Accepted MRTD values (48-byte SHA-384 hex). */
  mrTd: string[];
  /**
   * Accepted MRCONFIGID values (48 bytes hex).
   *
   * Measured by the CPU at TD build time, so unlike anything in the event log
   * it cannot be re-narrated by the guest. Observed populated on Phala prod5
   * (dstack-dev-0.5.9): 33 bytes of compressed SEC1 point, zero-padded to 48.
   * Pin the value observed for the platform you reviewed; pin 96 zeros on a
   * stack that leaves it empty, so "empty" is an explicit decision rather than
   * an unchecked field.
   */
  mrConfigId: string[];
  /** Accepted RTMR0 values (virtual firmware / VM configuration). */
  rtmr0: string[];
  /** Accepted RTMR1 values (kernel). */
  rtmr1: string[];
  /** Accepted RTMR2 values (kernel cmdline / initrd). */
  rtmr2: string[];
  /**
   * Accepted dstack OS image hashes (32 bytes hex), as measured in the RTMR3
   * `os-image-hash` event. This names the guest OS in one legible value rather
   * than three opaque registers, and it is what `dstack-mr` reproduces.
   */
  osImageHash: string[];
}

export interface GatewayMeasurementPolicy {
  /** Where this policy came from, for the audit trail. Never a gateway URL. */
  source: string;
  /** Policy version so a stale pin is visible in output. */
  version: string;
  /** Origins this policy authorizes. A quote for another origin fails closed. */
  origins: string[];
  /** Accepted dstack application ids (lowercase hex, no 0x). */
  appIds: string[];
  /** Accepted compose hashes: the exact reviewed configurations. */
  composeHashes: string[];
  /** Accepted AnonRouter release identifiers. */
  releaseIds: string[];
  /**
   * The KMS identity that is allowed to hold this app's derived keys, as it
   * appears in the measured "key-provider" RTMR3 event (the KMS contract's
   * k256 public key for a `kms` provider). Omit only in local development:
   * without it, a CVM whose keys came from a different key provider still
   * passes every other check.
   */
  keyProviderId?: string;
  /** Optional firmware/OS pinning. Omit to accept any platform stack. */
  platform?: GatewayPlatformMeasurements;
  /**
   * Require the TD itself to terminate TLS and to name the certificate the
   * client is using. Fails closed when the platform gateway terminates TLS.
   */
  requireInTeeTls: boolean;
  /**
   * Require the attested app-compose to declare public_logs=false. This turns
   * "we do not publish logs" from a promise into a measured configuration fact.
   */
  requirePrivateLogs: boolean;
  /**
   * Require every image in the attested docker-compose to be pinned by digest.
   * Without this, the compose hash pins a tag that can be repointed later.
   */
  requireDigestPinnedImages: boolean;
  /**
   * Require the quote's signature to be chained to Intel's roots with TCB
   * collateral, so the verdict is `hardware-verified` rather than
   * `provider-attested`.
   *
   * Without this, a client whose DCAP engine is missing, broken, or unbuilt
   * silently accepts at the weaker level and reports success. That is precisely
   * the silent downgrade the definition of done forbids, and it is invisible to
   * a user reading only `status`. Set it true wherever the DCAP verifier is
   * expected to be installed.
   */
  requireHardwareVerified: boolean;
  /** Maximum age of the evidence document itself, in milliseconds. */
  maxEvidenceAgeMs: number;
}

export class GatewayPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GatewayPolicyError";
  }
}

function hexList(field: string, value: unknown, exactChars?: number): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new GatewayPolicyError(`${field} must be a non-empty array`);
  }
  if (value.length > 64) throw new GatewayPolicyError(`${field} must contain at most 64 entries`);
  return value.map((entry) => {
    if (typeof entry !== "string") throw new GatewayPolicyError(`${field} entries must be strings`);
    const normalized = entry.trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(normalized)) throw new GatewayPolicyError(`${field} entries must be hex`);
    if (exactChars !== undefined && normalized.length !== exactChars) {
      throw new GatewayPolicyError(`${field} entries must be ${exactChars} hex characters`);
    }
    return normalized;
  });
}

function stringList(field: string, value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new GatewayPolicyError(`${field} must be a non-empty array`);
  }
  if (value.length > 64) throw new GatewayPolicyError(`${field} must contain at most 64 entries`);
  return value.map((entry) => {
    if (typeof entry !== "string" || entry.trim().length === 0) {
      throw new GatewayPolicyError(`${field} entries must be non-empty strings`);
    }
    return entry.trim();
  });
}

function requiredBoolean(field: string, value: unknown): boolean {
  if (typeof value !== "boolean") throw new GatewayPolicyError(`${field} must be a boolean`);
  return value;
}

/**
 * Parse an untrusted policy document. Every security-relevant switch is
 * REQUIRED — there are no permissive defaults, so a truncated or hand-edited
 * policy cannot silently disable a check.
 */
export function loadGatewayPolicy(input: unknown): GatewayMeasurementPolicy {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new GatewayPolicyError("policy must be a JSON object");
  }
  const raw = input as Record<string, unknown>;
  if (typeof raw.source !== "string" || raw.source.trim().length === 0) {
    throw new GatewayPolicyError("policy.source is required");
  }
  if (typeof raw.version !== "string" || raw.version.trim().length === 0) {
    throw new GatewayPolicyError("policy.version is required");
  }
  const maxAge = raw.maxEvidenceAgeMs;
  if (typeof maxAge !== "number" || !Number.isFinite(maxAge) || maxAge <= 0 || maxAge > 3_600_000) {
    throw new GatewayPolicyError("policy.maxEvidenceAgeMs must be 1..3600000");
  }

  let platform: GatewayPlatformMeasurements | undefined;
  if (raw.platform !== undefined) {
    if (!raw.platform || typeof raw.platform !== "object" || Array.isArray(raw.platform)) {
      throw new GatewayPolicyError("policy.platform must be an object when present");
    }
    const p = raw.platform as Record<string, unknown>;
    platform = {
      mrTd: hexList("policy.platform.mrTd", p.mrTd, 96),
      mrConfigId: hexList("policy.platform.mrConfigId", p.mrConfigId, 96),
      rtmr0: hexList("policy.platform.rtmr0", p.rtmr0, 96),
      rtmr1: hexList("policy.platform.rtmr1", p.rtmr1, 96),
      rtmr2: hexList("policy.platform.rtmr2", p.rtmr2, 96),
      osImageHash: hexList("policy.platform.osImageHash", p.osImageHash, 64)
    };
  }

  return {
    source: raw.source.trim(),
    version: raw.version.trim(),
    origins: stringList("policy.origins", raw.origins).map(canonicalGatewayOrigin),
    appIds: hexList("policy.appIds", raw.appIds),
    composeHashes: hexList("policy.composeHashes", raw.composeHashes, 64),
    releaseIds: stringList("policy.releaseIds", raw.releaseIds),
    ...(raw.keyProviderId === undefined
      ? {}
      : { keyProviderId: hexList("policy.keyProviderId", [raw.keyProviderId])[0] }),
    platform,
    requireInTeeTls: requiredBoolean("policy.requireInTeeTls", raw.requireInTeeTls),
    requirePrivateLogs: requiredBoolean("policy.requirePrivateLogs", raw.requirePrivateLogs),
    requireDigestPinnedImages: requiredBoolean("policy.requireDigestPinnedImages", raw.requireDigestPinnedImages),
    requireHardwareVerified: requiredBoolean("policy.requireHardwareVerified", raw.requireHardwareVerified),
    maxEvidenceAgeMs: maxAge
  };
}
