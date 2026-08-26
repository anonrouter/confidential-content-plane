import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  gatewayBindingHash,
  GATEWAY_BINDING_VERSION,
  type GatewayAttestationBinding
} from "../../src/gateway/binding.js";
import { loadGatewayPolicy, type GatewayMeasurementPolicy } from "../../src/gateway/policy.js";
import {
  verifyGatewayAttestation,
  type GatewayAttestationEvidence,
  type GatewayVerificationExpectations
} from "../../src/gateway/verify.js";
import type { TdxChainVerifier } from "../../src/providers/attestation/tdxQuote.js";
import {
  buildAppCompose,
  buildSyntheticEventLog,
  buildSyntheticTdxQuote,
  buildVmConfig,
  rtmr3Event,
  SYNTHETIC_MR_CONFIG_ID,
  SYNTHETIC_OS_IMAGE_HASH
} from "../helpers/syntheticTdxQuote.js";

// Fail-closed acceptance tests for the independent gateway verifier. Every test
// starts from a document that verifies, then breaks exactly one thing and
// asserts the specific required check that catches it. A verifier that silently
// tolerates any of these would let a non-attested data plane pass as attested.

const NONCE = "9".repeat(64);
const ORIGIN = "https://tee.anonrouter.ai";
const APP_ID = "0123456789abcdef0123456789abcdef01234567";
const INSTANCE_ID = "fedcba9876543210fedcba9876543210fedcba98";
const RELEASE_ID = "anonrouter-tee@c7b32e0";
const PUBLIC_KEY = "ab".repeat(32);
const NOW = 1_760_000_000_000;

const compose = buildAppCompose();

function policy(overrides: Partial<GatewayMeasurementPolicy> = {}): GatewayMeasurementPolicy {
  return {
    ...loadGatewayPolicy({
      source: "anonrouter-sdk@test",
      version: "2026.08.17",
      origins: [ORIGIN],
      appIds: [APP_ID],
      composeHashes: [compose.hash],
      releaseIds: [RELEASE_ID],
      requireInTeeTls: false,
      requirePrivateLogs: true,
      requireDigestPinnedImages: true,
      requireHardwareVerified: false,
      maxEvidenceAgeMs: 300_000
    }),
    ...overrides
  };
}

function binding(overrides: Partial<GatewayAttestationBinding> = {}): GatewayAttestationBinding {
  return {
    v: GATEWAY_BINDING_VERSION,
    nonce: NONCE,
    app_id: APP_ID,
    instance_id: INSTANCE_ID,
    compose_hash: compose.hash,
    release_id: RELEASE_ID,
    origin: ORIGIN,
    key_alg: "x25519",
    public_key: PUBLIC_KEY,
    transport: "gateway-tls",
    tls_spki_sha256: null,
    ...overrides
  };
}

interface EvidenceOverrides {
  binding?: GatewayAttestationBinding;
  manifest?: string;
  quoteReportData?: string;
  debug?: boolean;
  teeType?: number;
  extraRtmr3?: ReturnType<typeof rtmr3Event>[];
  composeHashEventPayload?: string;
  tamperComposeEventPayload?: boolean;
  breakRtmr3?: boolean;
  mrConfigId?: string;
  measuredOsImageHash?: string;
  /** The vm_config the CVM serves. `null` omits it entirely. */
  vmConfig?: string | null;
}

function evidence(overrides: EvidenceOverrides = {}): GatewayAttestationEvidence {
  const value = overrides.binding ?? binding();
  const log = buildSyntheticEventLog({
    appId: APP_ID,
    composeHash: overrides.composeHashEventPayload ?? value.compose_hash,
    instanceId: value.instance_id,
    osImageHash: overrides.measuredOsImageHash,
    extraRtmr3: overrides.extraRtmr3
  });
  const events = log.events.map((event) => {
    if (!overrides.tamperComposeEventPayload || event.event !== "compose-hash") return event;
    // Keep the measured digest, rewrite only the readable payload. This is the
    // attack the digest-recomputation check exists to stop.
    return { ...event, event_payload: "c".repeat(64) };
  });
  return {
    binding: value,
    quote: buildSyntheticTdxQuote({
      reportDataHex: overrides.quoteReportData ?? gatewayBindingHash(value),
      rtmr0: log.rtmr0,
      rtmr1: log.rtmr1,
      rtmr2: log.rtmr2,
      rtmr3: overrides.breakRtmr3 ? "f".repeat(96) : log.rtmr3,
      mrConfigId: overrides.mrConfigId,
      debug: overrides.debug,
      teeType: overrides.teeType
    }),
    event_log: JSON.stringify(events),
    app_compose: overrides.manifest ?? compose.manifest,
    issued_at_ms: NOW - 500,
    ...(overrides.vmConfig === null
      ? {}
      : { vm_config: overrides.vmConfig ?? buildVmConfig(overrides.measuredOsImageHash) })
  };
}

/** A policy that additionally pins the platform stack. */
function platformPolicy(overrides: Record<string, unknown> = {}): GatewayMeasurementPolicy {
  const base = evidence();
  const quote = Buffer.from(base.quote, "hex");
  return policy({
    platform: {
      mrTd: [quote.subarray(184, 232).toString("hex")],
      mrConfigId: [SYNTHETIC_MR_CONFIG_ID],
      rtmr0: [quote.subarray(376, 424).toString("hex")],
      rtmr1: [quote.subarray(424, 472).toString("hex")],
      rtmr2: [quote.subarray(472, 520).toString("hex")],
      osImageHash: [SYNTHETIC_OS_IMAGE_HASH],
      ...overrides
    }
  });
}

function expectations(overrides: Partial<GatewayVerificationExpectations> = {}): GatewayVerificationExpectations {
  return { nonce: NONCE, origin: ORIGIN, policy: policy(), now: NOW, ...overrides };
}

function failedCheck(result: ReturnType<typeof verifyGatewayAttestation>, name: string) {
  const entry = result.checks.find((c) => c.name === name);
  expect(entry, `check ${name} missing`).toBeDefined();
  return entry!;
}

describe("gateway attestation verifier", () => {
  it("accepts a well-formed document and caps the verdict at provider-attested", () => {
    const result = verifyGatewayAttestation(evidence(), expectations());
    expect(result.reason).toBeNull();
    expect(result.status).toBe("ok");
    // No DCAP chain verifier was supplied, so hardware-verified must NOT appear.
    expect(result.verificationLevel).toBe("provider-attested");
    expect(result.appCompose?.publicLogs).toBe(false);
    expect(result.appCompose?.images.every((i) => i.digestPinned)).toBe(true);
    expect(result.measurements?.rtmr3).toMatch(/^[0-9a-f]{96}$/);
  });

  it("reports hardware-verified only when a chain verifier actually passes", () => {
    const chainVerifier: TdxChainVerifier = {
      implementation: "test-dcap",
      verifyChain: () => ({ verified: true, tcbStatus: "UpToDate" })
    };
    const ok = verifyGatewayAttestation(evidence(), expectations({ chainVerifier }));
    expect(ok.verificationLevel).toBe("hardware-verified");
    expect(ok.tcbStatus).toBe("UpToDate");

    const rejecting: TdxChainVerifier = {
      implementation: "test-dcap",
      verifyChain: () => ({ verified: false, tcbStatus: "OutOfDate" })
    };
    const bad = verifyGatewayAttestation(evidence(), expectations({ chainVerifier: rejecting }));
    expect(bad.status).toBe("failed");
    expect(bad.reason).toBe("quote_signature_chain");
  });

  // Requirement 8 of the US-West POC: DCAP must be able to reach
  // hardware-verified WITHOUT ever upgrading the transport question. These two
  // properties are independent and the pairing below is the load-bearing one.
  describe("hardware verification and transport stay independent", () => {
    const passingChain: TdxChainVerifier = {
      implementation: "native-dcap",
      verifyChain: () => ({ verified: true, tcbStatus: "UpToDate" })
    };

    it("refuses to silently downgrade when the policy requires hardware", () => {
      // A client whose DCAP engine is missing must fail loudly, not accept at
      // provider-attested and report success.
      const result = verifyGatewayAttestation(
        evidence(),
        expectations({ policy: policy({ requireHardwareVerified: true }) })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("quote_signature_chain");
      expect(failedCheck(result, "quote_signature_chain").detail).toContain("policy requires");
    });

    it("reaches hardware-verified while STILL failing gateway-tls transport", () => {
      // The exact POC shape: a genuine Intel-signed quote from a CVM whose TLS
      // terminates at Phala's gateway. DCAP passing must not make it prompt-safe.
      const result = verifyGatewayAttestation(
        evidence({ binding: binding({ transport: "gateway-tls", tls_spki_sha256: null }) }),
        expectations({
          policy: policy({ requireHardwareVerified: true, requireInTeeTls: false }),
          chainVerifier: passingChain
        })
      );
      expect(result.status).toBe("ok");
      expect(result.verificationLevel).toBe("hardware-verified");
      // The transport check is separate and still reports the truth.
      expect(failedCheck(result, "transport_terminates_in_tee").passed).toBe(false);
      expect(result.binding?.transport).toBe("gateway-tls");
    });

    it("still rejects gateway-tls when in-TEE TLS is required, even with DCAP passing", () => {
      const result = verifyGatewayAttestation(
        evidence({ binding: binding({ transport: "gateway-tls", tls_spki_sha256: null }) }),
        expectations({
          policy: policy({ requireHardwareVerified: true, requireInTeeTls: true }),
          chainVerifier: passingChain
        })
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("transport_terminates_in_tee");
    });

    it("does not let in-TEE TLS substitute for hardware verification either", () => {
      // The converse: a TD that terminates its own TLS is still only
      // provider-attested until the quote is chained to Intel.
      const spki = "cd".repeat(32);
      const result = verifyGatewayAttestation(
        evidence({ binding: binding({ transport: "in-tee-tls", tls_spki_sha256: spki }) }),
        expectations({
          policy: policy({ requireInTeeTls: true }),
          observedTlsSpkiSha256: spki
        })
      );
      expect(result.status).toBe("ok");
      expect(result.verificationLevel).toBe("provider-attested");
    });
  });

  it("rejects report_data that does not commit to the binding", () => {
    const result = verifyGatewayAttestation(
      evidence({ quoteReportData: "0".repeat(128) }),
      expectations()
    );
    expect(result.status).toBe("failed");
    expect(result.reason).toBe("report_data_binds_binding");
  });

  it("rejects a replayed quote issued for a different nonce", () => {
    // A genuine document from an earlier session, presented to a new caller.
    const replayed = evidence({ binding: binding({ nonce: "1".repeat(64) }) });
    const result = verifyGatewayAttestation(replayed, expectations());
    expect(result.status).toBe("failed");
    expect(result.reason).toBe("nonce_matches_request");
  });

  it("rejects a quote bound to a different origin than the one connected to", () => {
    const other = evidence({ binding: binding({ origin: "https://tee.evil.example" }) });
    const result = verifyGatewayAttestation(other, expectations());
    expect(result.status).toBe("failed");
    expect(result.reason).toBe("origin_matches_connection");
  });

  it("rejects an event log that does not replay to the quote registers", () => {
    const result = verifyGatewayAttestation(evidence({ breakRtmr3: true }), expectations());
    expect(result.status).toBe("failed");
    expect(failedCheck(result, "event_log_replays_rtmrs").passed).toBe(false);
  });

  it("rejects a rewritten compose-hash payload", () => {
    // A real guest agent ships RTMR3 entries with NO digest and expects the
    // verifier to derive one, so the replay itself is computed over
    // (event_type, event, event_payload). Rewriting the payload therefore
    // changes the derived digest and breaks the replay: there is nothing left
    // to rewrite that reproduces the hardware register.
    const result = verifyGatewayAttestation(evidence({ tamperComposeEventPayload: true }), expectations());
    expect(result.status).toBe("failed");
    expect(failedCheck(result, "event_log_replays_rtmrs").passed).toBe(false);
  });

  it("rejects an entry whose supplied digest disagrees with its own fields", () => {
    // Entries MAY carry a digest. When they do it must agree with the derived
    // value, so a log cannot supply one that replays while displaying a
    // different payload next to it.
    const log = buildSyntheticEventLog({ appId: APP_ID, composeHash: compose.hash, instanceId: INSTANCE_ID });
    const events = log.events.map((event) =>
      event.event === "compose-hash" ? { ...event, digest: "e".repeat(96) } : event);
    const value = binding();
    const result = verifyGatewayAttestation(
      {
        binding: value,
        quote: buildSyntheticTdxQuote({
          reportDataHex: gatewayBindingHash(value),
          rtmr0: log.rtmr0,
          rtmr1: log.rtmr1,
          rtmr2: log.rtmr2,
          rtmr3: log.rtmr3
        }),
        event_log: JSON.stringify(events),
        app_compose: compose.manifest,
        issued_at_ms: NOW
      },
      expectations()
    );
    expect(result.status).toBe("failed");
    expect(failedCheck(result, "event_digests_commit_to_payloads").passed).toBe(false);
  });

  it("rejects a manifest that is not the measured one", () => {
    const other = buildAppCompose({ name: "someone-elses-app" });
    const result = verifyGatewayAttestation(evidence({ manifest: other.manifest }), expectations());
    expect(result.status).toBe("failed");
    expect(failedCheck(result, "app_compose_matches_measurement").passed).toBe(false);
  });

  it("rejects a build whose measured configuration publishes logs", () => {
    const loud = buildAppCompose({ public_logs: true });
    const log = buildSyntheticEventLog({ appId: APP_ID, composeHash: loud.hash, instanceId: INSTANCE_ID });
    const value = binding({ compose_hash: loud.hash });
    const result = verifyGatewayAttestation(
      {
        binding: value,
        quote: buildSyntheticTdxQuote({
          reportDataHex: gatewayBindingHash(value),
          rtmr0: log.rtmr0,
          rtmr1: log.rtmr1,
          rtmr2: log.rtmr2,
          rtmr3: log.rtmr3
        }),
        event_log: JSON.stringify(log.events),
        app_compose: loud.manifest,
        issued_at_ms: NOW
      },
      expectations({ policy: policy({ composeHashes: [loud.hash] }) })
    );
    expect(result.status).toBe("failed");
    expect(failedCheck(result, "compose_public_logs_disabled").passed).toBe(false);
  });

  it("rejects a build whose images are pinned only by mutable tag", () => {
    const mutable = buildAppCompose({
      docker_compose_file: "services:\n  relay:\n    image: ghcr.io/example/anonrouter:latest\n"
    });
    const log = buildSyntheticEventLog({ appId: APP_ID, composeHash: mutable.hash, instanceId: INSTANCE_ID });
    const value = binding({ compose_hash: mutable.hash });
    const result = verifyGatewayAttestation(
      {
        binding: value,
        quote: buildSyntheticTdxQuote({
          reportDataHex: gatewayBindingHash(value),
          rtmr0: log.rtmr0,
          rtmr1: log.rtmr1,
          rtmr2: log.rtmr2,
          rtmr3: log.rtmr3
        }),
        event_log: JSON.stringify(log.events),
        app_compose: mutable.manifest,
        issued_at_ms: NOW
      },
      expectations({ policy: policy({ composeHashes: [mutable.hash] }) })
    );
    expect(result.status).toBe("failed");
    expect(failedCheck(result, "compose_images_digest_pinned").passed).toBe(false);
  });

  it("rejects an unknown build even when every cryptographic check passes", () => {
    const unknown = buildAppCompose({ name: "unreviewed-build" });
    const log = buildSyntheticEventLog({ appId: APP_ID, composeHash: unknown.hash, instanceId: INSTANCE_ID });
    const value = binding({ compose_hash: unknown.hash });
    const result = verifyGatewayAttestation(
      {
        binding: value,
        quote: buildSyntheticTdxQuote({
          reportDataHex: gatewayBindingHash(value),
          rtmr0: log.rtmr0,
          rtmr1: log.rtmr1,
          rtmr2: log.rtmr2,
          rtmr3: log.rtmr3
        }),
        event_log: JSON.stringify(log.events),
        app_compose: unknown.manifest,
        issued_at_ms: NOW
      },
      expectations()
    );
    expect(result.status).toBe("failed");
    expect(failedCheck(result, "compose_hash_pinned").passed).toBe(false);
  });

  it("rejects an unpinned app id and an unpinned release", () => {
    const wrongApp = verifyGatewayAttestation(
      evidence({ binding: binding({ app_id: "dead".repeat(10) }) }),
      expectations()
    );
    expect(failedCheck(wrongApp, "app_id_pinned").passed).toBe(false);

    const wrongRelease = verifyGatewayAttestation(
      evidence({ binding: binding({ release_id: "anonrouter-tee@deadbee" }) }),
      expectations()
    );
    expect(failedCheck(wrongRelease, "release_pinned").passed).toBe(false);
  });

  it("rejects a debug TD and a non-TDX quote", () => {
    const debug = verifyGatewayAttestation(evidence({ debug: true }), expectations());
    expect(debug.status).toBe("failed");
    expect(failedCheck(debug, "quote_not_debug").passed).toBe(false);

    const notTdx = verifyGatewayAttestation(evidence({ teeType: 0 }), expectations());
    expect(notTdx.status).toBe("failed");
    expect(failedCheck(notTdx, "quote_is_tdx").passed).toBe(false);
  });

  it("fails closed when in-TEE TLS is required but the platform terminates TLS", () => {
    const result = verifyGatewayAttestation(
      evidence(),
      expectations({ policy: policy({ requireInTeeTls: true }) })
    );
    expect(result.status).toBe("failed");
    expect(failedCheck(result, "transport_terminates_in_tee").passed).toBe(false);
  });

  it("binds the caller's own TLS certificate when in-TEE TLS is in use", () => {
    const spki = createHash("sha256").update("served-certificate-spki").digest("hex");
    const teeBinding = binding({ transport: "in-tee-tls", tls_spki_sha256: spki });
    const strict = policy({ requireInTeeTls: true });

    const matching = verifyGatewayAttestation(
      evidence({ binding: teeBinding }),
      expectations({ policy: strict, observedTlsSpkiSha256: spki })
    );
    expect(matching.status).toBe("ok");

    const mismatched = verifyGatewayAttestation(
      evidence({ binding: teeBinding }),
      expectations({ policy: strict, observedTlsSpkiSha256: "0".repeat(64) })
    );
    expect(mismatched.status).toBe("failed");
    expect(failedCheck(mismatched, "tls_certificate_bound_to_quote").passed).toBe(false);
  });

  it("never throws on hostile or truncated input", () => {
    for (const bad of [
      { ...evidence(), quote: "not-a-quote" },
      { ...evidence(), quote: "" },
      { ...evidence(), binding: null },
      { ...evidence(), binding: { v: 1 } },
      { ...evidence(), event_log: "{" },
      { ...evidence(), event_log: 42 },
      { ...evidence(), app_compose: null },
      { ...evidence(), app_compose: "not json" }
    ] as GatewayAttestationEvidence[]) {
      const result = verifyGatewayAttestation(bad, expectations());
      expect(result.status).toBe("failed");
      expect(result.verificationLevel).toBe("unverified");
      expect(typeof result.reason).toBe("string");
    }
  });

  it("rejects a duplicated compose-hash event", () => {
    const result = verifyGatewayAttestation(
      evidence({ extraRtmr3: [rtmr3Event("compose-hash", "d".repeat(64))] }),
      expectations()
    );
    expect(result.status).toBe("failed");
    expect(failedCheck(result, "compose_hash_measured_in_rtmr3").passed).toBe(false);
  });

  // MRCONFIGID and the measured OS image are the platform half of the claim:
  // the compose hash says WHAT was deployed, these say what it was deployed ON.
  // Confirmed populated on Phala prod5 (dstack-dev-0.5.9), which is why they are
  // pinnable at all rather than being 48 zero bytes.
  describe("platform pinning", () => {
    it("accepts a document whose platform stack matches the pin", () => {
      const result = verifyGatewayAttestation(evidence(), expectations({ policy: platformPolicy() }));
      expect(result.reason).toBeNull();
      expect(failedCheck(result, "platform_measurements_pinned").passed).toBe(true);
      expect(failedCheck(result, "os_image_pinned").passed).toBe(true);
      expect(result.measurements?.mrConfigId).toBe(SYNTHETIC_MR_CONFIG_ID);
    });

    it("rejects a TD built with a different MRCONFIGID", () => {
      // Same app, same compose, same OS image, different CPU-measured config.
      const result = verifyGatewayAttestation(
        evidence({ mrConfigId: "03" + "cd".repeat(32) + "00".repeat(15) }),
        expectations({ policy: platformPolicy() })
      );
      expect(result.status).toBe("failed");
      expect(failedCheck(result, "platform_measurements_pinned").passed).toBe(false);
    });

    it("rejects an unpinned dstack OS image", () => {
      const other = "ba".repeat(32);
      const result = verifyGatewayAttestation(
        evidence({ measuredOsImageHash: other }),
        expectations({ policy: platformPolicy() })
      );
      expect(result.status).toBe("failed");
      expect(failedCheck(result, "os_image_pinned").passed).toBe(false);
    });

    it("refuses a partial platform pin rather than silently skipping a field", () => {
      // Consistent with the rest of the policy: no permissive defaults, so a
      // hand-edited policy cannot quietly stop checking MRCONFIGID or the OS
      // image while still looking like it pins the platform.
      const full = {
        mrTd: ["aa".repeat(48)],
        mrConfigId: [SYNTHETIC_MR_CONFIG_ID],
        rtmr0: ["b0".repeat(48)],
        rtmr1: ["b1".repeat(48)],
        rtmr2: ["b2".repeat(48)],
        osImageHash: [SYNTHETIC_OS_IMAGE_HASH]
      };
      const base = {
        source: "t", version: "1", origins: [ORIGIN], appIds: [APP_ID],
        composeHashes: [compose.hash], releaseIds: [RELEASE_ID],
        requireInTeeTls: false, requirePrivateLogs: true,
        requireDigestPinnedImages: true,
        requireHardwareVerified: false, maxEvidenceAgeMs: 300_000
      };
      expect(() => loadGatewayPolicy({ ...base, platform: full })).not.toThrow();
      for (const omitted of Object.keys(full)) {
        const partial = { ...full } as Record<string, unknown>;
        delete partial[omitted];
        expect(() => loadGatewayPolicy({ ...base, platform: partial }), omitted).toThrow(/platform/);
      }
    });

    it("does not pin the platform when the policy omits it", () => {
      const result = verifyGatewayAttestation(evidence({ mrConfigId: "11".repeat(48) }), expectations());
      expect(result.status).toBe("ok");
      expect(result.checks.some((c) => c.name === "platform_measurements_pinned")).toBe(false);
      expect(result.checks.some((c) => c.name === "os_image_pinned")).toBe(false);
    });
  });

  describe("vm_config cross-check", () => {
    it("accepts a vm_config that names the measured OS image", () => {
      const result = verifyGatewayAttestation(evidence(), expectations());
      expect(failedCheck(result, "vm_config_matches_measured_os_image").passed).toBe(true);
      expect(failedCheck(result, "vm_config_matches_measured_os_image").required).toBe(true);
    });

    it("rejects a vm_config that names a different OS image than the one measured", () => {
      // Serving this vm_config would send an auditor to recompute MRTD/RTMR0-2
      // for the wrong image, and conclude the genuine quote was forged.
      const result = verifyGatewayAttestation(
        evidence({ vmConfig: buildVmConfig("ab".repeat(32)) }),
        expectations()
      );
      expect(result.status).toBe("failed");
      expect(result.reason).toBe("vm_config_matches_measured_os_image");
    });

    it("records an omitted vm_config as a visible gap rather than agreement", () => {
      const result = verifyGatewayAttestation(evidence({ vmConfig: null }), expectations());
      const entry = failedCheck(result, "vm_config_matches_measured_os_image");
      expect(entry.passed).toBe(false);
      expect(entry.required).toBe(false);
      expect(entry.detail).toContain("unanchored");
      // Advisory, so it must not by itself sink an otherwise sound document.
      expect(result.status).toBe("ok");
    });

    it("ignores a vm_config that is not usable JSON instead of throwing", () => {
      for (const bad of ["", "{", "[]", JSON.stringify({ os_image_hash: 7 }), "x".repeat(70_000)]) {
        const result = verifyGatewayAttestation(evidence({ vmConfig: bad }), expectations());
        expect(failedCheck(result, "vm_config_matches_measured_os_image").required).toBe(false);
        expect(result.status).toBe("ok");
      }
    });
  });

  it("treats a stale evidence document as advisory, not fatal", () => {
    const result = verifyGatewayAttestation(evidence(), expectations({ now: NOW + 3_600_000 }));
    // The nonce is the real freshness proof; age is reported but never fatal.
    expect(failedCheck(result, "evidence_recent").passed).toBe(false);
    expect(failedCheck(result, "evidence_recent").required).toBe(false);
    expect(result.status).toBe("ok");
  });
});
