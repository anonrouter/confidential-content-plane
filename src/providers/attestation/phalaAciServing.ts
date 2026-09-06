// Phala ACI SERVING-enclave verifier.
//
// WHAT THIS VERIFIES, AND WHAT IT DELIBERATELY DOES NOT
// =====================================================
// It reads the evidence of the enclave that RUNS THE MODEL, retrieved from
// `GET /v1/aci/sessions/{session_id}` (the single-session form, whose
// `evidence.data` carries the full upstream blob; the cheap list form publishes
// only `evidence.digest` and is not sufficient input here).
//
// It ESTABLISHES, by re-derivation rather than by trusting a provider verdict:
//   - the published evidence digest is a commitment to the bytes we decoded;
//   - the blob carries an Intel TDX v4 quote that parses, with TD debug OFF;
//   - report_data re-derives as sha256(signing_address || tls_spki) || nonce;
//   - mr_config_id re-derives as 0x01 || compose_hash;
//   - the TD's own vm_config declares at least one GPU, and the NVIDIA evidence
//     count equals that declared GPU count and carries the exact nonce the TD
//     quote committed to (so the GPU evidence belongs to THIS TD, not a relayed
//     one from another machine);
//   - the attested TLS SPKI equals the leaf AnonRouter observed on its own
//     independent handshake to the serving endpoint.
//
// It DOES NOT ESTABLISH, and no caller may imply that it does:
//   - WHICH MODEL WEIGHTS were loaded. Phala types `model_weights_provenance`
//     as `unknown` on every route measured. Nothing here checks weights.
//   - WHICH SERVING BINARY is running. `serving_software_known_good` is likewise
//     `unknown`, and `source_provenance.image_digest` is null, so the repo and
//     commit the provider names are bound to nothing. `mr_config_id` binds the
//     compose document, not the image that compose names.
//   - That mr_td / rtmr* measure known-good software. No published allowlist
//     exists to diff against, so "the quote is genuine" is checkable here but
//     "it measures the right software" is not.
//   - The Intel DCAP signature chain or the NVIDIA NRAS certificate chain.
//     Parsing is structural, which is why the honest ceiling stays
//     `provider-attested`, exactly as for Venice, Chutes and NEAR.
//   - THAT ANY PARTICULAR REQUEST WAS SERVED BY THIS ENCLAVE. This is the
//     structural gap, and it is the important one. The serving TD's quote binds
//     PHALA'S SESSION NONCE, established up to an hour before the request; it
//     does not bind a caller nonce. The only thing linking a completion to a
//     session is `upstream.verified.session_id` in a gateway-signed receipt,
//     which is a signed ASSERTION, not a hardware binding. A gateway that lied
//     about session_id would produce a receipt that verifies perfectly. The
//     permanently-failing advisory `caller_nonce_bound` check below carries that
//     limit into every result this verifier produces, so it cannot be lost.
//
// Because of that last point this verifier answers "this enclave exists, is
// genuine, has GPUs, and serves the endpoint we handshook with". It does not
// answer "your prompt went into it".

import { assembleResult, check, freshnessCheck, hexEqual, readEnvelope } from "./checks.js";
import { sha256Hex } from "./crypto.js";
import { dstackDeclaredGpuCount, parseTdxQuote, tdxHardwareTypeFor } from "./tdxQuote.js";
import type {
  AttestationCheck,
  AttestationExpectations,
  NormalizedAttestationResult,
  SignatureVerificationInput,
  SignatureVerificationResult,
  TeeVerifier
} from "./types.js";

const TDX_TEE_TYPE = 0x00000081;
/** dstack tags MRCONFIGID with a one-byte scheme prefix, then the compose hash,
 *  then zero padding out to the 48-byte register. */
const COMPOSE_HASH_PREFIX = "01";
const MR_CONFIG_ID_HEX_LEN = 96;
const DATA_URI_PREFIX = "data:application/json;base64,";

/** The single-session ACI record. Everything is `unknown` until proven: this
 *  document is provider-authored and every field is validated before use. */
interface AciSessionRecord {
  api_version?: unknown;
  channel_binding?: unknown;
  claims?: { extra?: Record<string, unknown> };
  endpoint?: unknown;
  established_at?: unknown;
  evidence?: { data?: unknown; digest?: unknown };
  expires_at?: unknown;
  identity?: { signing_address?: unknown };
  upstream_name?: unknown;
  verifier_id?: unknown;
}

/** The decoded `evidence.data` blob: the serving enclave's own attestation. */
interface ServingEvidenceBlob {
  info?: { compose_hash?: unknown; os_image_hash?: unknown };
  intel_quote?: unknown;
  nvidia_payload?: unknown;
  request_nonce?: unknown;
  signing_address?: unknown;
  signing_algo?: unknown;
  signing_public_key?: unknown;
  tls_cert_fingerprint?: unknown;
  vm_config?: unknown;
}

interface NvidiaPayload {
  arch?: unknown;
  nonce?: unknown;
  evidence_list?: unknown;
}

export interface PhalaAciServingVerifierOptions {
  verifierVersion?: string;
}

export class PhalaAciServingVerifier implements TeeVerifier {
  readonly provider = "phala-ai";
  readonly verifierVersion: string;
  /** The receipt that binds request bytes is signed by the GATEWAY keyset and
   *  points at a session by assertion. Claiming per-request signature support
   *  here would imply a binding to the SERVING enclave that does not exist. */
  readonly supportsSignatures = false;

  constructor(opts: PhalaAciServingVerifierOptions = {}) {
    this.verifierVersion = opts.verifierVersion ?? "phala-aci-serving/1";
  }

  /** Phala's gateway decrypts and re-encrypts at its frontend, so client
   *  ciphertext is never opaque to it. This is never an E2EE route. */
  supportsClientOpaqueE2ee(): boolean {
    return false;
  }

  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult {
    const envelope = readEnvelope(evidence, expectations);
    const session = asRecord(envelope.payload) as AciSessionRecord | null;
    const checks: AttestationCheck[] = [];

    // -- 1. the session envelope, and the digest as a commitment ------------
    const digest = typeof session?.evidence?.digest === "string" ? session.evidence.digest : null;
    const dataUri = typeof session?.evidence?.data === "string" ? session.evidence.data : null;
    const decoded = decodeEvidenceData(dataUri);
    checks.push(check("evidence_present", Boolean(digest && decoded), true,
      decoded ? undefined : "session published no retrievable serving evidence"));

    const recomputed = decoded ? `sha256:${sha256Hex(decoded)}` : null;
    checks.push(check("evidence_digest_reproduces", Boolean(recomputed && digest && recomputed === digest), true,
      recomputed && digest ? undefined : "no digest to reproduce"));

    const blob = decoded ? parseJson<ServingEvidenceBlob>(decoded.toString("utf8")) : null;
    checks.push(check("evidence_parsed", blob !== null, true,
      blob ? undefined : "serving evidence did not decode to JSON"));

    // -- 2. the serving TD quote -------------------------------------------
    const quoteRaw = typeof blob?.intel_quote === "string" ? blob.intel_quote : null;
    const parsed = quoteRaw ? parseTdxQuote(quoteRaw) : null;
    checks.push(check("quote_parsed", parsed !== null, true, parsed ? undefined : "TDX quote did not parse"));
    checks.push(check("expected_tee_type", parsed?.teeType === TDX_TEE_TYPE, true,
      parsed?.teeType === TDX_TEE_TYPE ? undefined : "not an Intel TDX quote"));
    checks.push(check("debug_disabled", parsed !== null && !parsed.debugEnabled, true,
      parsed?.debugEnabled ? "TD debug mode enabled" : undefined));

    // -- 3. report_data, re-derived rather than read ------------------------
    // sha256( signing_address(20 raw bytes) || tls_cert_fingerprint(32 raw bytes) )
    // occupies the first half; the provider session nonce occupies the second.
    const signingAddress = typeof blob?.signing_address === "string" ? blob.signing_address.toLowerCase() : null;
    const tlsFingerprint = typeof blob?.tls_cert_fingerprint === "string" ? blob.tls_cert_fingerprint.toLowerCase() : null;
    const addressBytes = signingAddress && /^0x[0-9a-f]{40}$/.test(signingAddress)
      ? Buffer.from(signingAddress.slice(2), "hex") : null;
    const fingerprintBytes = tlsFingerprint && /^[0-9a-f]{64}$/.test(tlsFingerprint)
      ? Buffer.from(tlsFingerprint, "hex") : null;
    const derivedPrefix = addressBytes && fingerprintBytes
      ? sha256Hex(Buffer.concat([addressBytes, fingerprintBytes])) : null;
    checks.push(check("report_data_key_binding",
      Boolean(parsed && derivedPrefix && hexEqual(derivedPrefix, parsed.reportData.slice(0, 64))), true,
      derivedPrefix ? undefined : "signing address or TLS fingerprint was absent or malformed"));

    // The nonce inside the quote is the anchor every other nonce is compared to.
    const quoteNonce = parsed ? parsed.reportData.slice(64, 128) : null;
    const requestNonce = typeof blob?.request_nonce === "string" ? blob.request_nonce.toLowerCase() : null;
    checks.push(check("report_data_nonce_binding", Boolean(quoteNonce && hexEqual(quoteNonce, requestNonce)), true,
      requestNonce ? undefined : "serving evidence declared no session nonce"));

    // -- 4. mr_config_id, re-derived from the compose hash ------------------
    const composeHash = typeof blob?.info?.compose_hash === "string" ? blob.info.compose_hash.toLowerCase() : null;
    const derivedMrConfigId = composeHash && /^[0-9a-f]{64}$/.test(composeHash)
      ? (COMPOSE_HASH_PREFIX + composeHash).padEnd(MR_CONFIG_ID_HEX_LEN, "0") : null;
    checks.push(check("compose_binding",
      Boolean(parsed && derivedMrConfigId && hexEqual(derivedMrConfigId, parsed.mrConfigId)), true,
      derivedMrConfigId ? undefined : "no compose hash to re-derive mr_config_id from"));

    // -- 5. the GPU, and its binding to THIS TD ----------------------------
    // This is the check the gateway document fails. A GPU-less aggregator can
    // relay perfectly genuine GPU evidence belonging to another machine, so
    // presence of `nvidia_payload` proves nothing on its own. The TD's own
    // vm_config must declare GPUs, and the evidence must match that count and
    // carry the exact nonce this TD's quote committed to.
    const numGpus = dstackDeclaredGpuCount(blob?.vm_config);
    checks.push(check("vm_config_parsed", numGpus !== null, true,
      numGpus === null ? "vm_config absent, unparseable, or declared no integer GPU count" : undefined));
    checks.push(check("serving_td_has_gpus", numGpus !== null && numGpus > 0, true,
      numGpus === 0 ? "attested TD declares zero GPUs: this is an aggregator/router, not a serving enclave" : undefined));

    const nvidia = parseMaybeJson<NvidiaPayload>(blob?.nvidia_payload);
    const entries = Array.isArray(nvidia?.evidence_list) ? nvidia.evidence_list : null;
    const nvidiaNonce = typeof nvidia?.nonce === "string" ? nvidia.nonce.toLowerCase() : null;
    checks.push(check("gpu_evidence_parsed", entries !== null && entries.length > 0, true,
      entries === null ? "nvidia_payload absent or did not decode to an evidence list" : undefined));
    checks.push(check("gpu_evidence_count_matches_vm_config",
      Boolean(entries && numGpus !== null && numGpus > 0 && entries.length === numGpus), true,
      entries && numGpus !== null && entries.length !== numGpus
        ? "GPU evidence count does not equal the GPU count the attested TD declares"
        : undefined));
    checks.push(check("gpu_evidence_nonce_bound_to_quote",
      Boolean(nvidiaNonce && quoteNonce && hexEqual(nvidiaNonce, quoteNonce)), true,
      nvidiaNonce
        ? "GPU evidence carries a different nonce than the TD quote: it belongs to another document"
        : "GPU evidence carried no nonce"));
    const arch = typeof nvidia?.arch === "string" && nvidia.arch.length > 0 ? nvidia.arch : null;
    const archConsistent = Boolean(arch && entries && entries.every((entry) =>
      asRecord(entry)?.arch === arch));
    checks.push(check("gpu_arch_consistent", archConsistent, true,
      arch ? undefined : "GPU evidence declared no architecture"));

    // -- 6. the channel, against OUR OWN handshake -------------------------
    // The provider authors `tls_cert_fingerprint` and it authors the session's
    // channel_binding, so those agreeing with each other proves nothing. The
    // independent side is the SPKI AnonRouter observed itself.
    const endpoint = typeof session?.endpoint === "string" ? session.endpoint : null;
    const channelSpki = readChannelSpki(session?.channel_binding, endpoint);
    const observedSpki = typeof expectations.observedTlsSpkiSha256 === "string"
      ? expectations.observedTlsSpkiSha256.toLowerCase() : null;
    checks.push(check("channel_binding_matches_report_data",
      Boolean(channelSpki && tlsFingerprint && hexEqual(channelSpki, tlsFingerprint)), true,
      channelSpki ? undefined : "session published no TLS SPKI channel binding for its endpoint"));
    checks.push(check("attested_spki_matches_our_handshake",
      Boolean(observedSpki && tlsFingerprint && hexEqual(observedSpki, tlsFingerprint)), true,
      observedSpki
        ? "attested TLS SPKI did not equal the leaf we observed on our own handshake"
        : "no independently observed TLS SPKI was supplied; the attested channel has no second side"));
    checks.push(check("endpoint_binding", Boolean(endpoint && hostOf(endpoint) === expectations.endpointIdentity), true,
      endpoint ? undefined : "session named no endpoint"));

    // -- 7. route + scope + liveness ---------------------------------------
    const extra = session?.claims?.extra ?? {};
    checks.push(check("model_binding", extra.canonical_model_id === expectations.upstreamModel, true,
      typeof extra.canonical_model_id === "string" ? undefined : "session named no canonical model"));
    // A scope assertion can only ever NARROW what we accept, so relying on the
    // provider's own label here adds a refusal and never an upgrade. A resold
    // route (verifier_id .../chutes/v1) publishes an EMPTY evidence object and
    // is already refused above; this keeps it refused for a legible reason.
    checks.push(check("serving_scope_is_model_instance", extra.evidence_scope === "model_instance", true,
      extra.evidence_scope === "model_instance" ? undefined : "session evidence is not scoped to a model instance"));
    checks.push(check("direct_serving_verifier",
      typeof session?.verifier_id === "string" && session.verifier_id.startsWith("private-ai-verifier/phala-direct/"), true,
      "session was not produced by Phala's direct serving verifier (a resold route publishes no serving evidence)"));

    const now = expectations.now ?? Date.now();
    const expiresAt = typeof session?.expires_at === "number" ? session.expires_at * 1000 : null;
    checks.push(check("session_not_expired", expiresAt !== null && expiresAt > now, true,
      expiresAt === null
        ? "session published no expiry"
        : "session has expired; its evidence stops resolving within minutes of this point"));
    checks.push(freshnessCheck(envelope.fetchedAtMs, expectations));

    // -- 8. the honesty marker ---------------------------------------------
    // Advisory and PERMANENTLY FAILING, by design. It is not a defect to fix:
    // it is the structural limit, restated in every result so that no consumer
    // can read a passing verification as proof that a given request ran here.
    checks.push(check("caller_nonce_bound", false, false,
      "the serving TD quote binds the provider's session nonce, not the caller's; "
      + "which session served a given request is a signed gateway assertion, not a hardware binding"));

    const measurements: Record<string, string> = parsed ? {
      mrtd: parsed.mrTd,
      mr_config_id: parsed.mrConfigId,
      rtmr0: parsed.rtmr0,
      rtmr1: parsed.rtmr1,
      rtmr2: parsed.rtmr2,
      rtmr3: parsed.rtmr3
    } : {};

    return assembleResult({
      expectations,
      // Derived, never defaulted. The required GPU checks above mean a passing
      // result always lands on `intel-tdx+nvidia-cc`; on a FAILING one this
      // reports what the TD actually attested rather than repeating a hardware
      // claim the evidence contradicts.
      hardwareType: tdxHardwareTypeFor(numGpus),
      requestedLevel: "provider-attested",
      privacyModality: expectations.privacyModality,
      measurementIdentities: measurements,
      // Deliberately null: nothing here attests which weights were loaded.
      modelWeightIdentity: null,
      attestedTlsSpki: tlsFingerprint,
      // The gateway decrypts at its frontend, so there is no client-opaque key.
      attestedEncryptionKey: null,
      attestedSigningKey: signingAddress,
      // The PROVIDER's session nonce, never the caller's. See caller_nonce_bound.
      boundNonce: requestNonce,
      verifierVersion: this.verifierVersion,
      supportsClientOpaqueE2ee: false,
      checks
    });
  }

  verifySignature(_input: SignatureVerificationInput): SignatureVerificationResult {
    return {
      supported: false,
      verified: false,
      verificationLevel: "unsupported",
      signatureKind: "unsupported",
      signingIdentity: null,
      boundRequestHash: null,
      boundResponseHash: null,
      reason: "serving_enclave_exposes_no_per_request_signature",
      checks: [check("signature_supported", false, true,
        "Phala's receipt is signed by the gateway keyset and points at a session by assertion; "
        + "the serving enclave itself signs nothing per request")]
    };
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function parseJson<T>(text: string): T | null {
  try {
    const parsed: unknown = JSON.parse(text);
    return asRecord(parsed) ? parsed as T : null;
  } catch {
    return null;
  }
}

/** `vm_config` and `nvidia_payload` arrive as JSON STRINGS on the wire. Accept a
 *  already-decoded object too, and fail closed on anything else. */
function parseMaybeJson<T>(value: unknown): T | null {
  if (typeof value === "string") return parseJson<T>(value);
  return asRecord(value) ? value as T : null;
}

/** Decode `data:application/json;base64,…`. Anything else is a refusal, and a
 *  payload that does not round-trip through base64 is treated as absent. */
function decodeEvidenceData(dataUri: string | null): Buffer | null {
  if (!dataUri || !dataUri.startsWith(DATA_URI_PREFIX)) return null;
  const b64 = dataUri.slice(DATA_URI_PREFIX.length);
  if (b64.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return null;
  try {
    const buf = Buffer.from(b64, "base64");
    if (buf.length === 0 || buf.toString("base64").replace(/=+$/, "") !== b64.replace(/=+$/, "")) return null;
    return buf;
  } catch {
    return null;
  }
}

/** The SPKI the session publishes for its OWN endpoint. A binding entry naming a
 *  different origin is ignored rather than accepted. */
function readChannelSpki(bindings: unknown, endpoint: string | null): string | null {
  if (!Array.isArray(bindings) || !endpoint) return null;
  for (const raw of bindings) {
    const entry = asRecord(raw);
    if (!entry || entry.type !== "tls_spki_sha256") continue;
    if (typeof entry.origin !== "string" || hostOf(entry.origin) !== hostOf(endpoint)) continue;
    if (typeof entry.spki_sha256 === "string") return entry.spki_sha256.toLowerCase();
  }
  return null;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return null;
  }
}
