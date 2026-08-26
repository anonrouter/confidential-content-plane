// Independent, fail-closed verification of AnonRouter GATEWAY attestation.
//
// This is the client side of GET /v1/gateway/attestation. It is deliberately
// pure: no network, no filesystem, no clock except an injected `now`, and no
// dependency on @phala/dstack-sdk. Everything it needs to reach a verdict is
// either in the evidence document, in the locally pinned policy, or recomputed
// from first principles here.
//
// The chain it establishes, in order:
//
//   1. The quote is a structurally valid, non-debug Intel TDX quote.
//   2. Its 64-byte report_data equals SHA-512 of the canonical binding object,
//      so the TD asserted the caller's nonce, the app/instance identity, the
//      compose measurement, the release id, the origin, the application key,
//      and the transport claim — all at once, at quote time.
//   3. The plaintext event log replays to the quote's RTMR0..RTMR3, so the log
//      describes what the hardware actually measured.
//   4. The measured "compose-hash" event equals SHA-256 of the returned
//      app-compose manifest, so the manifest is the one that ran.
//   5. The manifest's own contents satisfy the pinned policy: private logs,
//      digest-pinned images.
//   6. The app id, compose hash, release id, and origin are all on the locally
//      pinned allowlist.
//   7. Optionally, the TD owns the TLS certificate the caller is using.
//
// What this module does NOT do on its own is chain the quote's ECDSA signature
// to Intel's roots. That requires DCAP collateral and is injected through
// TdxChainVerifier — the same pluggable port the provider verifiers use. Without
// it the honest verdict is `provider-attested`, never `hardware-verified`. This
// mirrors the existing policy in docs/TEE_VERIFICATION.md: we do not upgrade a
// claim we did not actually check.

import { check, hexEqual } from "../providers/attestation/checks.js";
import { parseTdxQuote, type TdxChainVerifier } from "../providers/attestation/tdxQuote.js";
import type { AttestationCheck, VerificationLevel } from "../providers/attestation/types.js";
import {
  canonicalGatewayOrigin,
  gatewayBindingHash,
  normalizeGatewayBinding,
  type GatewayAttestationBinding
} from "./binding.js";
import { readAttestedAppCompose, type AttestedAppCompose } from "./appCompose.js";
import { inconsistentRtmr3Events, parseEventLog, replayRtmrs, singleEventPayload } from "./eventLog.js";
import type { GatewayMeasurementPolicy } from "./policy.js";

/** Intel TDX in the TEE type field of a DCAP quote header. */
const TEE_TYPE_TDX = 0x00000081;

/** A vm_config blob is bounded so a hostile response cannot pin the CPU parsing it. */
const MAX_VM_CONFIG_CHARS = 65_536;

/**
 * Read `os_image_hash` out of the served vm_config blob, which arrives as a JSON
 * string (dstack serves it verbatim so its bytes can be re-fed to dstack-mr).
 * Returns null for anything unusable, so the caller records a visible gap rather
 * than treating absence as agreement.
 */
function readVmConfigOsImageHash(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_VM_CONFIG_CHARS) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const value = (parsed as Record<string, unknown>).os_image_hash;
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase().replace(/^0x/, "");
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
}

/** The evidence document returned by GET /v1/gateway/attestation. */
export interface GatewayAttestationEvidence {
  /** The exact object the TD hashed into report_data. */
  binding: unknown;
  /** Raw Intel TDX quote (hex or base64). */
  quote: string;
  /** Event log as a JSON string or an already-parsed array. */
  event_log: unknown;
  /** The measured app-compose manifest string (tcb_info.app_compose). */
  app_compose: unknown;
  /** Wall-clock time the gateway produced this document, epoch ms. */
  issued_at_ms?: unknown;
  /** VM configuration blob, passed through for independent inspection. */
  vm_config?: unknown;
}

export interface GatewayVerificationExpectations {
  /** The exact nonce this client generated and sent. */
  nonce: string;
  /** The exact origin this client connected to. */
  origin: string;
  /** Locally pinned policy. NEVER fetched from the gateway. */
  policy: GatewayMeasurementPolicy;
  /** Injected clock so verification stays pure and testable. */
  now: number;
  /**
   * SHA-256 of the DER SubjectPublicKeyInfo of the certificate this client's
   * TLS session actually used. Supply it to prove the attested TD owns the very
   * connection carrying the request. Undefined means "not observed"; null means
   * "observed and there is none".
   */
  observedTlsSpkiSha256?: string | null;
  /** Optional DCAP chain verifier. Absent means no hardware-verified verdict. */
  chainVerifier?: TdxChainVerifier;
}

export interface GatewayVerificationResult {
  status: "ok" | "failed";
  verificationLevel: VerificationLevel;
  checks: AttestationCheck[];
  /** The first failed required check, or null. Sanitized and content-free. */
  reason: string | null;
  /** Normalized binding, present whenever it parsed. */
  binding: GatewayAttestationBinding | null;
  /** Parsed manifest facts, present whenever the manifest parsed. */
  appCompose: AttestedAppCompose | null;
  /** Measurements read out of the quote, for display and audit. */
  measurements: {
    mrTd: string;
    mrConfigId: string;
    rtmr0: string;
    rtmr1: string;
    rtmr2: string;
    rtmr3: string;
  } | null;
  /** TCB status reported by the chain verifier, when one ran. */
  tcbStatus: string | null;
  policySource: string;
  policyVersion: string;
  verifiedAtMs: number;
}

function failed(
  checks: AttestationCheck[],
  policy: GatewayMeasurementPolicy,
  now: number,
  partial: Partial<GatewayVerificationResult> = {}
): GatewayVerificationResult {
  const firstFailure = checks.find((entry) => entry.required && !entry.passed);
  return {
    status: "failed",
    verificationLevel: "unverified",
    checks,
    reason: firstFailure?.name ?? "verification_failed",
    binding: null,
    appCompose: null,
    measurements: null,
    tcbStatus: null,
    policySource: policy.source,
    policyVersion: policy.version,
    verifiedAtMs: now,
    ...partial
  };
}

/**
 * Verify a gateway attestation document. Never throws on hostile input: every
 * malformed field becomes a failed required check, so a caller that only reads
 * `status` cannot be tricked by an exception path.
 */
export function verifyGatewayAttestation(
  evidence: GatewayAttestationEvidence,
  expectations: GatewayVerificationExpectations
): GatewayVerificationResult {
  const { policy, now } = expectations;
  const checks: AttestationCheck[] = [];

  // --- 1. Binding -----------------------------------------------------------
  let binding: GatewayAttestationBinding;
  try {
    binding = normalizeGatewayBinding(evidence.binding);
    checks.push(check("binding_wellformed", true, true));
  } catch (error) {
    checks.push(check("binding_wellformed", false, true, error instanceof Error ? error.message : undefined));
    return failed(checks, policy, now);
  }

  // --- 2. Quote structure ---------------------------------------------------
  const quote = parseTdxQuote(evidence.quote);
  checks.push(check("quote_parsed", quote !== null, true));
  if (!quote) return failed(checks, policy, now, { binding });

  checks.push(check("quote_is_tdx", quote.teeType === TEE_TYPE_TDX, true, `tee_type=0x${quote.teeType.toString(16)}`));
  // A debug TD lets the host inspect and modify guest memory. Nothing measured
  // inside it is confidential, so this is unconditionally fatal.
  checks.push(check("quote_not_debug", !quote.debugEnabled, true));

  const measurements = {
    mrTd: quote.mrTd,
    mrConfigId: quote.mrConfigId,
    rtmr0: quote.rtmr0,
    rtmr1: quote.rtmr1,
    rtmr2: quote.rtmr2,
    rtmr3: quote.rtmr3
  };

  // --- 3. report_data commits to the whole binding --------------------------
  let bindingHash: string;
  try {
    bindingHash = gatewayBindingHash(binding);
  } catch (error) {
    checks.push(check("binding_hash_computed", false, true, error instanceof Error ? error.message : undefined));
    return failed(checks, policy, now, { binding, measurements });
  }
  checks.push(check("report_data_binds_binding", hexEqual(quote.reportData, bindingHash), true));

  // --- 4. Freshness and origin, checked against what THIS client did --------
  let expectedOrigin: string | null = null;
  try {
    expectedOrigin = canonicalGatewayOrigin(expectations.origin);
  } catch {
    expectedOrigin = null;
  }
  checks.push(check("nonce_matches_request", binding.nonce === expectations.nonce.toLowerCase(), true));
  checks.push(check("origin_matches_connection", expectedOrigin !== null && binding.origin === expectedOrigin, true));

  // --- 5. Event log replays to the quote's registers ------------------------
  let composeHashEvent: string | null = null;
  let instanceIdEvent: string | null = null;
  let appIdEvent: string | null = null;
  let keyProviderEvent: string | null = null;
  let osImageHashEvent: string | null = null;
  let eventLogRead = false;
  try {
    const events = parseEventLog(evidence.event_log);
    const replayed = replayRtmrs(events);
    const replays = hexEqual(replayed[0], quote.rtmr0)
      && hexEqual(replayed[1], quote.rtmr1)
      && hexEqual(replayed[2], quote.rtmr2)
      && hexEqual(replayed[3], quote.rtmr3);
    checks.push(check("event_log_replays_rtmrs", replays, true));

    // Replay alone proves only that the DIGESTS are the measured ones. Each
    // RTMR3 digest must additionally commit to the human-readable name and
    // payload printed beside it, or a genuine quote could be re-served with a
    // rewritten compose-hash payload and still replay correctly.
    const inconsistent = inconsistentRtmr3Events(events);
    checks.push(check(
      "event_digests_commit_to_payloads",
      inconsistent.length === 0,
      true,
      inconsistent.length > 0 ? `${inconsistent.length} RTMR3 event(s) with a non-committing digest` : undefined
    ));

    composeHashEvent = singleEventPayload(events, "compose-hash");
    instanceIdEvent = singleEventPayload(events, "instance-id");
    appIdEvent = singleEventPayload(events, "app-id");
    keyProviderEvent = singleEventPayload(events, "key-provider");
    osImageHashEvent = singleEventPayload(events, "os-image-hash");
    eventLogRead = true;
  } catch (error) {
    const detail = error instanceof Error ? error.message : undefined;
    checks.push(check("event_log_replays_rtmrs", false, true, detail));
    checks.push(check("event_digests_commit_to_payloads", false, true, detail));
  }

  // The compose hash the TD asserted in the binding must be the one hardware
  // measured. Without this the binding could name any configuration it liked.
  checks.push(check(
    "compose_hash_measured_in_rtmr3",
    composeHashEvent !== null && hexEqual(composeHashEvent, binding.compose_hash),
    true
  ));
  // instance-id is measured too; when present it must agree with the binding.
  // "Absent" is only acceptable when the log was actually readable — otherwise
  // an unparsable log would silently satisfy this check.
  checks.push(check(
    "instance_id_measured",
    eventLogRead && (instanceIdEvent === null || hexEqual(instanceIdEvent, binding.instance_id)),
    true,
    instanceIdEvent === null ? "no instance-id event in log" : undefined
  ));
  // app-id is measured independently of the binding, so a TD cannot claim an
  // app identity it was not provisioned with.
  checks.push(check(
    "app_id_measured",
    eventLogRead && appIdEvent !== null && hexEqual(appIdEvent, binding.app_id),
    true
  ));
  // key-provider names who may hold this app's derived keys. A CVM booted under
  // a different key provider is a different trust domain even at the same
  // compose hash, so this is pinned rather than merely reported.
  if (policy.keyProviderId) {
    const expected = policy.keyProviderId.toLowerCase();
    // The payload is a JSON blob ({"name":"kms","id":"<k256 pubkey>"}) encoded
    // as hex, so match on the decoded text rather than the whole-field digest.
    const decoded = keyProviderEvent === null
      ? ""
      : Buffer.from(keyProviderEvent, "hex").toString("utf8").toLowerCase();
    checks.push(check("key_provider_pinned", decoded.includes(expected), true));
  } else {
    checks.push(check(
      "key_provider_pinned",
      false,
      false,
      "policy pins no key provider; a CVM under a different KMS would still pass"
    ));
  }

  // vm_config is what lets someone recompute MRTD and RTMR0..2 offline with
  // dstack-mr. It is served by the CVM, so on its own it is a claim; it becomes
  // evidence only once it agrees with something hardware measured. The measured
  // `os-image-hash` event is that anchor. A CVM that serves a vm_config naming
  // a different OS image than the one it booted would otherwise send an auditor
  // to reproduce the wrong measurements and conclude the quote was forged.
  const vmConfigOsImage = readVmConfigOsImageHash(evidence.vm_config);
  if (osImageHashEvent !== null && vmConfigOsImage !== null) {
    checks.push(check(
      "vm_config_matches_measured_os_image",
      hexEqual(osImageHashEvent, vmConfigOsImage),
      true
    ));
  } else {
    checks.push(check(
      "vm_config_matches_measured_os_image",
      false,
      false,
      osImageHashEvent === null
        ? "no os-image-hash event in the log to anchor vm_config against"
        : "evidence carries no vm_config.os_image_hash, so offline measurement recomputation is unanchored"
    ));
  }

  // --- 6. The manifest is the measured one, and says what it should ---------
  let appCompose: AttestedAppCompose | null = null;
  try {
    appCompose = readAttestedAppCompose(evidence.app_compose);
    checks.push(check("app_compose_parsed", true, true));
  } catch (error) {
    checks.push(check("app_compose_parsed", false, true, error instanceof Error ? error.message : undefined));
  }
  checks.push(check(
    "app_compose_matches_measurement",
    appCompose !== null && hexEqual(appCompose.composeHash, binding.compose_hash),
    true
  ));

  if (policy.requirePrivateLogs) {
    checks.push(check(
      "compose_public_logs_disabled",
      appCompose?.publicLogs === false,
      true,
      appCompose ? `public_logs=${String(appCompose.publicLogs)}` : undefined
    ));
  }
  if (policy.requireDigestPinnedImages) {
    const unpinned = appCompose?.images.filter((image) => !image.digestPinned) ?? [];
    checks.push(check(
      "compose_images_digest_pinned",
      appCompose !== null && appCompose.images.length > 0 && unpinned.length === 0,
      true,
      unpinned.length > 0 ? `${unpinned.length} image reference(s) not digest-pinned` : undefined
    ));
  }

  // --- 7. Locally pinned identity -------------------------------------------
  checks.push(check("app_id_pinned", policy.appIds.some((id) => hexEqual(id, binding.app_id)), true));
  checks.push(check(
    "compose_hash_pinned",
    policy.composeHashes.some((hash) => hexEqual(hash, binding.compose_hash)),
    true
  ));
  checks.push(check("release_pinned", policy.releaseIds.includes(binding.release_id), true));
  checks.push(check("origin_pinned", policy.origins.includes(binding.origin), true));

  if (policy.platform) {
    const { mrTd, mrConfigId, rtmr0, rtmr1, rtmr2, osImageHash } = policy.platform;
    checks.push(check(
      "platform_measurements_pinned",
      mrTd.some((value) => hexEqual(value, quote.mrTd))
      && mrConfigId.some((value) => hexEqual(value, quote.mrConfigId))
      && rtmr0.some((value) => hexEqual(value, quote.rtmr0))
      && rtmr1.some((value) => hexEqual(value, quote.rtmr1))
      && rtmr2.some((value) => hexEqual(value, quote.rtmr2)),
      true
    ));
    // Pinned separately from the registers above because it is the one platform
    // value an operator can read off a release note and compare by eye.
    checks.push(check(
      "os_image_pinned",
      osImageHashEvent !== null && osImageHash.some((value) => hexEqual(value, osImageHashEvent)),
      true,
      osImageHashEvent === null ? "no os-image-hash event in the log" : undefined
    ));
  }

  // --- 8. Transport binding --------------------------------------------------
  if (policy.requireInTeeTls) {
    checks.push(check("transport_terminates_in_tee", binding.transport === "in-tee-tls", true));
    if (expectations.observedTlsSpkiSha256 !== undefined) {
      checks.push(check(
        "tls_certificate_bound_to_quote",
        hexEqual(expectations.observedTlsSpkiSha256, binding.tls_spki_sha256),
        true
      ));
    } else {
      // Advisory: the caller could not observe its own certificate (a browser
      // cannot). Recorded so the gap is visible rather than assumed away.
      checks.push(check("tls_certificate_bound_to_quote", false, false, "caller did not observe its TLS certificate"));
    }
  } else {
    checks.push(check(
      "transport_terminates_in_tee",
      binding.transport === "in-tee-tls",
      false,
      binding.transport === "gateway-tls" ? "TLS terminates at the platform gateway, not inside the TD" : undefined
    ));
  }

  // --- 9. Evidence age (advisory; the nonce is the real freshness proof) ----
  const issuedAt = typeof evidence.issued_at_ms === "number" ? evidence.issued_at_ms : null;
  const age = issuedAt === null ? null : now - issuedAt;
  checks.push(check(
    "evidence_recent",
    age !== null && age >= -60_000 && age <= policy.maxEvidenceAgeMs,
    false,
    age === null ? "no issued_at_ms" : `age_ms=${age}`
  ));

  // --- 10. Hardware chain (pluggable) ---------------------------------------
  let tcbStatus: string | null = null;
  let chainVerified = false;
  if (expectations.chainVerifier) {
    const outcome = expectations.chainVerifier.verifyChain(evidence.quote, undefined);
    chainVerified = outcome.verified;
    tcbStatus = outcome.tcbStatus ?? null;
    checks.push(check("quote_signature_chain", chainVerified, true, tcbStatus ? `tcb=${tcbStatus}` : undefined));
  } else {
    // Required when the policy demands hardware verification, so a client whose
    // DCAP engine is missing or unbuilt fails loudly instead of quietly
    // accepting at the weaker level and reporting success.
    checks.push(check(
      "quote_signature_chain",
      false,
      policy.requireHardwareVerified,
      policy.requireHardwareVerified
        ? "policy requires hardware verification but no DCAP chain verifier was supplied"
        : "no DCAP chain verifier supplied; verdict capped at provider-attested"
    ));
  }

  const requiredFailure = checks.find((entry) => entry.required && !entry.passed);
  if (requiredFailure) {
    return failed(checks, policy, now, { binding, appCompose, measurements, tcbStatus });
  }

  return {
    status: "ok",
    verificationLevel: chainVerified ? "hardware-verified" : "provider-attested",
    checks,
    reason: null,
    binding,
    appCompose,
    measurements,
    tcbStatus,
    policySource: policy.source,
    policyVersion: policy.version,
    verifiedAtMs: now
  };
}

export type { TdxChainVerifier };
