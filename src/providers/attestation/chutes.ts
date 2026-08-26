// Chutes TEE evidence verifier. This validates every instance returned by the
// provider and the protocol-level bindings documented by Chutes. Full Intel
// DCAP + NVIDIA NRAS chain verification remains a separate fail-closed port.

import { constants, X509Certificate, verify as nodeVerify } from "node:crypto";
import { assembleResult, check, freshnessCheck, hexEqual, readEnvelope } from "./checks.js";
import { sha256Hex } from "./crypto.js";
import { matchMeasurementAllowlist, parseTdxQuote, type TdxChainVerifier, type TdxMeasurementEntry } from "./tdxQuote.js";
import type {
  AttestationCheck,
  AttestationExpectations,
  NormalizedAttestationResult,
  SignatureVerificationInput,
  SignatureVerificationResult,
  TeeVerifier
} from "./types.js";

const TDX_TEE_TYPE = 0x00000081;

interface ChutesInstanceEvidence {
  quote?: unknown;
  gpu_evidence?: unknown;
  instance_id?: unknown;
  certificate?: unknown;
  signature?: unknown;
  attested_body?: unknown;
}

interface ChutesEvidencePayload {
  evidence?: ChutesInstanceEvidence[];
  failed_instance_ids?: unknown;
  e2e_pubkeys?: Record<string, unknown>;
}

interface ChutesAttestedBody {
  nonce?: unknown;
  evidence?: { tdx_quote?: unknown; nvtrust_evidence?: unknown };
}

export interface ChutesVerifierOptions {
  chainVerifier?: TdxChainVerifier;
  verifierVersion?: string;
}

export class ChutesTeeVerifier implements TeeVerifier {
  readonly provider = "chutes";
  readonly verifierVersion: string;
  readonly supportsSignatures = false;
  private readonly chainVerifier?: TdxChainVerifier;

  constructor(opts: ChutesVerifierOptions = {}) {
    this.chainVerifier = opts.chainVerifier;
    this.verifierVersion = opts.verifierVersion ?? "chutes-tdx/2";
  }

  supportsClientOpaqueE2ee(): boolean {
    return true;
  }

  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult {
    const envelope = readEnvelope(evidence, expectations);
    const payload = envelope.payload as ChutesEvidencePayload | undefined;
    const instances = Array.isArray(payload?.evidence) ? payload.evidence : [];
    const checks: AttestationCheck[] = [];
    const failedIds = Array.isArray(payload?.failed_instance_ids) ? payload.failed_instance_ids : [];
    const pubkeys = payload?.e2e_pubkeys && typeof payload.e2e_pubkeys === "object" ? payload.e2e_pubkeys : {};

    checks.push(check("evidence_present", instances.length > 0, true, instances.length > 0 ? undefined : "no instance evidence"));
    checks.push(check("all_instances_returned", failedIds.length === 0, true,
      failedIds.length === 0 ? undefined : "evidence retrieval failed for one or more instances"));

    const allowlist = (expectations.measurementPolicy?.accepted as TdxMeasurementEntry[] | undefined) ?? [];
    checks.push(check("measurement_policy_pinned", allowlist.length > 0, true,
      allowlist.length > 0 ? undefined : "no accepted-measurement policy pinned"));

    let firstMeasurements: Record<string, string> = {};
    let everyChainVerified = Boolean(this.chainVerifier) && instances.length > 0;
    let firstTcbStatus: string | undefined;
    let firstBoundNonce: string | null = null;
    let everyEncryptionKeyBound = instances.length > 0;

    for (let index = 0; index < instances.length; index += 1) {
      const instance = instances[index];
      const label = `instance_${index}`;
      const instanceId = typeof instance.instance_id === "string" ? instance.instance_id : null;
      const quoteRaw = typeof instance.quote === "string" ? instance.quote : null;
      const parsed = quoteRaw ? parseTdxQuote(quoteRaw) : null;
      checks.push(check(`${label}_identity`, Boolean(instanceId), true, instanceId ? undefined : "instance id missing"));
      checks.push(check(`${label}_quote_parsed`, parsed !== null, true, parsed ? undefined : "TDX quote did not parse"));
      if (!parsed || !quoteRaw) continue;

      const measurements = {
        mrtd: parsed.mrTd,
        rtmr0: parsed.rtmr0,
        rtmr1: parsed.rtmr1,
        rtmr2: parsed.rtmr2,
        rtmr3: parsed.rtmr3
      };
      if (index === 0) firstMeasurements = measurements;
      checks.push(check(`${label}_expected_tee_type`, parsed.teeType === TDX_TEE_TYPE, true,
        parsed.teeType === TDX_TEE_TYPE ? undefined : "not an Intel TDX quote"));
      checks.push(check(`${label}_debug_disabled`, !parsed.debugEnabled, true,
        parsed.debugEnabled ? "TD debug mode enabled" : undefined));
      checks.push(check(`${label}_measurement_allowlist`, matchMeasurementAllowlist(parsed, allowlist) !== null, true,
        "measurements not in accepted allowlist"));

      const e2ePubkey = instanceId && typeof pubkeys[instanceId] === "string" ? pubkeys[instanceId] as string : null;
      const expectedNonceKey = e2ePubkey ? sha256Hex(expectations.nonce + e2ePubkey) : null;
      const reportNonceKey = parsed.reportData.slice(0, 64);
      checks.push(check(`${label}_nonce_key_binding`, hexEqual(reportNonceKey, expectedNonceKey), true,
        e2ePubkey ? undefined : "no discovered ML-KEM public key for instance"));
      everyEncryptionKeyBound &&= hexEqual(reportNonceKey, expectedNonceKey);
      if (index === 0 && expectedNonceKey && hexEqual(reportNonceKey, expectedNonceKey)) firstBoundNonce = expectations.nonce;

      const certificate = decodeBase64(instance.certificate);
      const attestedBody = decodeBase64(instance.attested_body);
      const signature = decodeBase64(instance.signature);
      let certificateSpkiHash: string | null = null;
      let possessionVerified = false;
      let certificateFresh = false;
      if (certificate && attestedBody && signature) {
        try {
          const cert = new X509Certificate(certificate);
          const spki = cert.publicKey.export({ format: "der", type: "spki" });
          certificateSpkiHash = sha256Hex(spki);
          possessionVerified = nodeVerify("sha256", attestedBody, {
            key: cert.publicKey,
            padding: constants.RSA_PKCS1_PADDING
          }, signature);
          const at = expectations.now ?? Date.now();
          certificateFresh = Date.parse(cert.validFrom) <= at && at <= Date.parse(cert.validTo);
        } catch {
          // Malformed cert/key/signature fails the required checks below.
        }
      }
      checks.push(check(`${label}_certificate_spki_binding`, hexEqual(parsed.reportData.slice(64, 128), certificateSpkiHash), true,
        certificateSpkiHash ? undefined : "certificate could not be parsed"));
      checks.push(check(`${label}_certificate_freshness`, certificateFresh, true,
        certificateFresh ? undefined : "instance certificate is outside its validity window"));
      checks.push(check(`${label}_key_possession`, possessionVerified, true,
        possessionVerified ? undefined : "RSA signature over attested_body did not verify"));

      const body = parseAttestedBody(attestedBody);
      const gpu = Array.isArray(instance.gpu_evidence) ? instance.gpu_evidence : [];
      const innerGpu = parseJson(body?.evidence?.nvtrust_evidence);
      checks.push(check(`${label}_attested_nonce`, body?.nonce === expectations.nonce, true,
        body?.nonce === expectations.nonce ? undefined : "signed body nonce mismatch"));
      checks.push(check(`${label}_attested_quote`, body?.evidence?.tdx_quote === quoteRaw, true,
        body?.evidence?.tdx_quote === quoteRaw ? undefined : "signed body quote mismatch"));
      checks.push(check(`${label}_attested_gpu_evidence`, Array.isArray(innerGpu) && jsonEqual(innerGpu, gpu), true,
        "signed body GPU evidence mismatch"));
      const gpuShapeOk = gpu.length > 0 && gpu.every((item) => item !== null && typeof item === "object"
        && typeof (item as Record<string, unknown>).certificate === "string"
        && typeof (item as Record<string, unknown>).evidence === "string");
      checks.push(check(`${label}_gpu_evidence_present`, gpuShapeOk, true,
        gpuShapeOk ? undefined : "no complete NVIDIA GPU evidence"));

      if (this.chainVerifier) {
        const chain = this.chainVerifier.verifyChain(quoteRaw, gpu);
        const acceptableTcb = chain.verified && chain.tcbStatus === "UpToDate";
        everyChainVerified &&= acceptableTcb;
        firstTcbStatus ??= chain.tcbStatus;
        checks.push(check(`${label}_dcap_nras_chain`, acceptableTcb, true,
          acceptableTcb ? "tcb:UpToDate" : "Intel/NVIDIA chain did not verify with an UpToDate TCB"));
      }
    }

    checks.push(freshnessCheck(envelope.fetchedAtMs, expectations));
    const requestedLevel: NormalizedAttestationResult["verificationLevel"] = everyChainVerified
      ? "hardware-verified"
      : "provider-attested";
    return assembleResult({
      expectations,
      hardwareType: "intel-tdx+nvidia-cc",
      requestedLevel,
      privacyModality: expectations.privacyModality,
      measurementIdentities: firstMeasurements,
      modelWeightIdentity: null,
      attestedTlsSpki: null,
      attestedEncryptionKey: Object.keys(pubkeys).length === 1
        ? String(pubkeys[Object.keys(pubkeys)[0]])
        : null,
      attestedSigningKey: null,
      boundNonce: firstBoundNonce,
      verifierVersion: `${this.verifierVersion}${firstTcbStatus ? `:${firstTcbStatus}` : ""}`,
      supportsClientOpaqueE2ee: expectations.privacyModality === "e2ee" && everyEncryptionKeyBound,
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
      reason: "tee_signature_not_supported",
      checks: [check("signature_supported", false, true, "provider exposes no per-request signature")]
    };
  }
}

function decodeBase64(value: unknown): Buffer | null {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    const decoded = Buffer.from(value, "base64");
    return decoded.length > 0 ? decoded : null;
  } catch {
    return null;
  }
}

function parseJson(value: unknown): unknown {
  if (typeof value !== "string") return null;
  try { return JSON.parse(value); } catch { return null; }
}

function parseAttestedBody(value: Buffer | null): ChutesAttestedBody | null {
  if (!value) return null;
  try { return JSON.parse(value.toString("utf8")) as ChutesAttestedBody; } catch { return null; }
}

function jsonEqual(a: unknown, b: unknown): boolean {
  try { return JSON.stringify(a) === JSON.stringify(b); } catch { return false; }
}
