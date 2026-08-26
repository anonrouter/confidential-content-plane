// Provider-neutral TEE attestation + signature verification contracts.
//
// This subsystem generalizes what was previously a Venice-only attestation path
// (VeniceProviderAdapter.fetchAttestation + the e2ee relay flow) into a
// provider-neutral interface so Chutes, Tinfoil, NEAR AI, and Venice can each
// declare and verify their own TEE evidence, per-request signatures, and
// client-opaque E2EE capability without three more hardcoded branches.
//
// Design invariants (see docs/TEE_VERIFICATION.md):
//   - Verification FAILS CLOSED: a missing/expired/mismatched required check
//     yields status "failed"; a route is never upgraded to a stronger privacy
//     class on unverified evidence.
//   - We never treat an upstream `verified: true` field, a `-TEE` id suffix, or a
//     `confidential_compute` flag as cryptographic proof. Those are routing hints.
//   - verifyAttestation / verifySignature are PURE over their inputs (no network,
//     no clock except an injectable `now`) so every check is deterministically
//     testable with synthetic and sanitized recorded fixtures.
//   - Nothing here logs or returns raw prompts, responses, API keys, decrypted
//     E2EE content, or unsafe upstream bodies. Only sanitized, structured facts.

/**
 * Honest description of HOW strongly a route's TEE claim was actually checked by
 * this implementation. Distinguishing these is a hard requirement: we must never
 * label a route `hardware-verified` unless the implementation performed and
 * passed the cryptographic verification that level requires.
 */
export type VerificationLevel =
  /** Full cryptographic verification of the hardware quote / certificate chain to
   *  the silicon vendor's roots (Intel PCS/QVL, NVIDIA NRAS, AMD KDS). */
  | "hardware-verified"
  /** Verified via the provider's official attestation SDK / verifier library
   *  (e.g. Tinfoil's `Verifier`), which performs the vendor-root checks for us. */
  | "sdk-verified"
  /** Structurally valid, freshness/binding/measurement checks passed, but the raw
   *  quote signature was not cryptographically chained to vendor roots in-process
   *  (no vetted DCAP/NRAS verifier wired). NOT proof of hardware; a strong hint. */
  | "provider-attested"
  /** Evidence present but one or more REQUIRED checks failed, or verification was
   *  not attempted. Treat as untrusted. */
  | "unverified"
  /** The provider/route does not expose this capability at all. */
  | "unsupported";

export type HardwareType =
  | "intel-tdx"
  | "amd-sev-snp"
  | "nvidia-cc"
  | "intel-tdx+nvidia-cc"
  | "amd-sev-snp+nvidia-cc"
  | "unknown";

/** The two verified-execution privacy modalities. `tee`: enclave-verified but the
 *  gateway may see plaintext. `e2ee`: client ciphertext stays opaque to the
 *  gateway and terminates inside the verified enclave. */
export type PrivacyModality = "tee" | "e2ee";

/** A single fail-closed verification step outcome. `detail` is always safe and
 *  content-free (never echoes prompts, keys, or raw bodies). */
export interface AttestationCheck {
  name: string;
  passed: boolean;
  /** A required check that fails forces the overall status to "failed". */
  required: boolean;
  detail?: string;
}

/** Per-provider accepted-measurement policy the verifier binds evidence against.
 *  Opaque `accepted` payload is interpreted by the provider verifier only. */
export interface MeasurementPolicy {
  /** Where the allowlist came from, e.g. "chutes:/servers/tee/measurements". */
  source: string;
  /** Policy/allowlist version so a cache entry can be invalidated on change. */
  version: string;
  /** Provider-specific accepted measurement identities. */
  accepted: unknown;
}

/** What the verifier binds the evidence to. A mismatch on any of these is a
 *  fail-closed rejection (prevents cross-provider / cross-route substitution). */
export interface AttestationExpectations {
  provider: string;
  canonicalModel: string;
  /** Provider-native (upstream) model id. */
  upstreamModel: string;
  /** Public route id / slug the caller selected (unambiguous route binding). */
  routeId: string;
  /** Endpoint identity the evidence must be bound to (host / enclave url). */
  endpointIdentity: string;
  /** Fresh caller-provided nonce/challenge (hex). Bound into the quote. */
  nonce: string;
  privacyModality: PrivacyModality;
  measurementPolicy?: MeasurementPolicy;
  /** Injectable clock (ms) for deterministic freshness/expiry tests. */
  now?: number;
  /** Max age of the evidence before it is considered stale. Default 5 min. */
  maxEvidenceAgeMs?: number;
  /** How long a successful verification result may be cached. Default 5 min. */
  cacheTtlMs?: number;
}

/** The normalized, safe attestation result. Contains only sanitized structured
 *  facts an advanced client can use to independently re-verify, never secrets,
 *  raw evidence bodies, prompts, or responses. */
export interface NormalizedAttestationResult {
  provider: string;
  canonicalModel: string;
  upstreamModel: string;
  routeId: string;
  endpointIdentity: string;
  hardwareType: HardwareType;
  verificationLevel: VerificationLevel;
  privacyModality: PrivacyModality;
  /** Measurement identities keyed by name (mrtd, rtmr0..rtmr3, mrenclave, …),
   *  lowercase hex. Empty when the provider exposes none. */
  measurementIdentities: Record<string, string>;
  /** Attested model/weight identity (e.g. mr_config_id-derived, HF revision). */
  modelWeightIdentity: string | null;
  /** Attested TLS SubjectPublicKeyInfo hash (SPKI), hex, when bound. */
  attestedTlsSpki: string | null;
  /** Attested client-opaque encryption key (HPKE / X25519 pubkey), hex. */
  attestedEncryptionKey: string | null;
  /** Attested per-request signing identity (address / pubkey), hex. */
  attestedSigningKey: string | null;
  /** The caller nonce the quote was bound to, echoed back. */
  nonce: string | null;
  /** ISO instant the verification was performed. */
  verifiedAt: string;
  /** ISO instant after which this result must not be trusted / recomputed. */
  expiresAt: string;
  /** Measurement policy/allowlist source that gated the decision. */
  policySource: string | null;
  /** Verifier implementation identifier + version (e.g. "chutes-tdx/1"). */
  verifierVersion: string;
  /** Whether the route supports client-opaque E2EE (ciphertext body). */
  supportsClientOpaqueE2ee: boolean;
  status: "ok" | "failed";
  /** Safe machine-readable reason when status === "failed" (never content). */
  reason: string | null;
  checks: AttestationCheck[];
}

/**
 * The envelope the credential-isolated worker adapter wraps raw provider evidence
 * in before handing it to a (pure) verifier. It adds the fetch instant (the
 * freshness anchor for providers whose quotes carry no timestamp) and the endpoint
 * the evidence was fetched from. `payload` is the raw provider evidence, returned
 * verbatim to advanced clients for independent re-verification.
 */
export interface AttestationEnvelope {
  fetchedAtMs: number;
  endpointIdentity: string;
  payload: unknown;
}

export type SignatureKind = "provider_tee" | "gateway" | "unsupported";

/** Inputs to per-request signature verification. AnonRouter supplies the request
 *  and response hashes it computed (content-free digests), and the provider's raw
 *  signature payload. The verifier binds the two and checks the signature. */
export interface SignatureVerificationInput {
  provider: string;
  routeId: string;
  upstreamModel: string;
  canonicalModel: string;
  /** Provider request/completion id the signature is keyed to. */
  providerRequestId: string;
  /** sha-256 hex of the exact request body AnonRouter forwarded. */
  requestHash: string;
  /** sha-256 hex of the exact response payload AnonRouter returned. */
  responseHash: string;
  /** The attested signing identity from a prior attestation, if known, so the
   *  signature can be bound to the same enclave key. */
  attestedSigningIdentity?: string | null;
  /** Raw provider signature payload (opaque; interpreted by the verifier). */
  evidence: unknown;
  now?: number;
}

export interface SignatureVerificationResult {
  supported: boolean;
  verified: boolean;
  verificationLevel: VerificationLevel;
  signatureKind: SignatureKind;
  /** Recovered / declared signer identity (address or pubkey), sanitized. */
  signingIdentity: string | null;
  /** The request/response hashes the signature actually bound, echoed back so a
   *  caller can confirm they equal the hashes it expected. */
  boundRequestHash: string | null;
  boundResponseHash: string | null;
  /** Safe machine-readable reason (e.g. tee_signature_not_supported,
   *  signature_mismatch, request_hash_mismatch, wrong_signer). */
  reason: string | null;
  checks: AttestationCheck[];
}

/**
 * The provider-neutral verifier a provider registers. Implementations are PURE
 * over their inputs. Network fetches (getting the quote / signature bytes) belong
 * on the credential-isolated worker adapter (ProviderAdapter.fetchAttestation /
 * fetchSignature); the verifier only interprets and validates what was fetched.
 */
export interface TeeVerifier {
  readonly provider: string;
  readonly verifierVersion: string;
  /** Whether the provider exposes a verifiable per-request signature at all. */
  readonly supportsSignatures: boolean;
  /** Whether a given route supports client-opaque E2EE (ciphertext body). */
  supportsClientOpaqueE2ee(routeId: string): boolean;
  /** Verify raw provider evidence against the expectations. Fails closed. */
  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult;
  /** Verify a per-request signature; returns supported:false / unsupported when
   *  the provider does not expose one (never fabricates a gateway signature). */
  verifySignature(input: SignatureVerificationInput): SignatureVerificationResult;
}
