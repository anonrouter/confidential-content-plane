// NEAR AI verifier. NEAR runs inference in Intel-TDX Confidential VMs and, for a
// direct route ({slug}.completions.near.ai), terminates TLS INSIDE the enclave and
// exposes a per-request signature. We verify (all fail-closed):
//   - the caller nonce is bound in report_data[32:64];
//   - the attested TLS SPKI is bound in report_data[0:32] == sha256(signing_addr ‖
//     tls_cert_fingerprint)  (this is what proves TLS terminates in the TEE);
//   - the attested model_name equals the route's upstream model;
//   - mr_config_id binds the pinned app_compose document
//     (== "01" + sha256(app_compose));
//   - boot measurements match NEAR's allowlist;
//   - TD debug is disabled.
// The raw TDX/NRAS chains are only cryptographically verified when a vetted chain
// verifier is wired; otherwise the honest level is `provider-attested`.
//
// Per-request signatures ARE supported. For the ed25519 signing_algo we verify the
// signature in-process with the Node stdlib (real crypto). For the ecdsa (eth
// personal_sign) algo we recover the signer via a pluggable recoverer; absent one
// we keep the (real) request/response-hash binding checks and report honestly.

import { sha256Hex, fromHex, verifyEd25519, unavailableEthRecoverer, type EthMessageRecoverer } from "./crypto.js";
import {
  assembleResult,
  check,
  freshnessCheck,
  hexEqual,
  nonceBindingCheck,
  readEnvelope
} from "./checks.js";
import { matchMeasurementAllowlist, parseTdxQuote, type TdxChainVerifier, type TdxMeasurementEntry } from "./tdxQuote.js";
import type {
  AttestationCheck,
  AttestationExpectations,
  NormalizedAttestationResult,
  SignatureKind,
  SignatureVerificationInput,
  SignatureVerificationResult,
  TeeVerifier
} from "./types.js";

const TDX_TEE_TYPE = 0x00000081;
const ALL_ZERO_MR_CONFIG = "00".repeat(48);

interface NearAttestationPayload {
  intel_quote?: unknown;
  nvidia_payload?: unknown;
  tls_cert_fingerprint?: unknown;
  model_name?: unknown;
  signing_address?: unknown;
  signing_algo?: unknown;
  signing_public_key?: unknown;
  app_compose?: unknown;
  compose_hash?: unknown;
  info?: { tcb_info?: { app_compose?: { docker_compose_file?: unknown } } };
}

interface NearSignaturePayload {
  text?: unknown;
  signature?: unknown;
  signing_address?: unknown;
  signing_algo?: unknown;
  signing_public_key?: unknown;
  signature_kind?: unknown;
}

export interface NearVerifierOptions {
  chainVerifier?: TdxChainVerifier;
  ethRecoverer?: EthMessageRecoverer;
  verifierVersion?: string;
}

export class NearTeeVerifier implements TeeVerifier {
  readonly provider = "near-ai";
  readonly verifierVersion: string;
  readonly supportsSignatures = true;
  private readonly chainVerifier?: TdxChainVerifier;
  private readonly ethRecoverer: EthMessageRecoverer;

  constructor(opts: NearVerifierOptions = {}) {
    this.chainVerifier = opts.chainVerifier;
    this.ethRecoverer = opts.ethRecoverer ?? unavailableEthRecoverer;
    this.verifierVersion = opts.verifierVersion ?? "near-tdx/1";
  }

  // NEAR direct routes support a client-opaque E2EE (Curve25519) chat modality.
  supportsClientOpaqueE2ee(): boolean {
    return true;
  }

  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult {
    const envelope = readEnvelope(evidence, expectations);
    const payload = envelope.payload as NearAttestationPayload | undefined;
    const checks: AttestationCheck[] = [];

    const quoteRaw = payload?.intel_quote;
    const hasQuote = typeof quoteRaw === "string" && quoteRaw.length > 0;
    checks.push(check("evidence_present", hasQuote, true, hasQuote ? undefined : "no intel_quote in report"));
    const parsed = hasQuote ? parseTdxQuote(quoteRaw) : null;
    checks.push(check("quote_parsed", parsed !== null, true, parsed ? undefined : "TDX quote did not parse"));

    const measurements: Record<string, string> = {};
    const tlsFingerprint = typeof payload?.tls_cert_fingerprint === "string" ? payload.tls_cert_fingerprint : null;
    const signingAddress = typeof payload?.signing_address === "string" ? payload.signing_address : null;
    const modelName = typeof payload?.model_name === "string" ? payload.model_name : null;
    const appCompose = typeof payload?.app_compose === "string"
      ? payload.app_compose
      : typeof payload?.info?.tcb_info?.app_compose?.docker_compose_file === "string"
        ? (payload.info!.tcb_info!.app_compose!.docker_compose_file as string)
        : null;
    let matchedPolicy = false;

    if (parsed) {
      measurements.mrtd = parsed.mrTd;
      measurements.rtmr0 = parsed.rtmr0;
      measurements.rtmr1 = parsed.rtmr1;
      measurements.rtmr2 = parsed.rtmr2;
      measurements.rtmr3 = parsed.rtmr3;
      measurements.mr_config_id = parsed.mrConfigId;

      checks.push(check("expected_tee_type", parsed.teeType === TDX_TEE_TYPE, true, parsed.teeType === TDX_TEE_TYPE ? undefined : "not an Intel TDX quote"));
      checks.push(check("debug_disabled", !parsed.debugEnabled, true, parsed.debugEnabled ? "TD debug mode enabled" : undefined));

      // report_data layout: [0:32] = sha256(signing_address ‖ tls_fingerprint) when
      // include_tls_fingerprint; [32:64] = nonce.
      const reportFirst = parsed.reportData.slice(0, 64); // first 32 bytes hex
      const reportSecond = parsed.reportData.slice(64, 128); // next 32 bytes hex
      checks.push(nonceBindingCheck(expectations.nonce, reportSecond));

      if (tlsFingerprint && signingAddress) {
        let expectedFirst: string | null = null;
        try {
          expectedFirst = sha256Hex(Buffer.concat([fromHex(signingAddress), fromHex(tlsFingerprint)]));
        } catch {
          expectedFirst = null;
        }
        checks.push(check("tls_spki_binding", hexEqual(reportFirst, expectedFirst), true, expectedFirst ? undefined : "malformed signing_address/tls fingerprint"));
      } else {
        checks.push(check("tls_spki_binding", false, true, "attestation did not bind a TLS SPKI"));
      }

      // mr_config_id binds the exact app_compose document. It does not, by
      // itself, prove a separate model-weight digest, so we expose the register
      // as a measurement and leave modelWeightIdentity unset below.
      const composeSha256 = appCompose ? sha256Hex(appCompose) : null;
      if (composeSha256 && parsed.mrConfigId !== ALL_ZERO_MR_CONFIG) {
        const expectedConfig = ("01" + composeSha256).padEnd(96, "0");
        const reportedComposeHash = typeof payload?.compose_hash === "string" ? payload.compose_hash : null;
        checks.push(check("compose_binding", hexEqual(parsed.mrConfigId, expectedConfig), true, undefined));
        checks.push(check("reported_compose_hash", hexEqual(reportedComposeHash, composeSha256), true,
          reportedComposeHash ? undefined : "report did not include compose hash"));
      } else if (parsed.mrConfigId === ALL_ZERO_MR_CONFIG) {
        checks.push(check("compose_binding", false, true, "mr_config_id is all-zero and does not bind the compose"));
      } else {
        checks.push(check("compose_binding", false, true, "no app_compose provided to bind"));
      }

      const allowlist = (expectations.measurementPolicy?.accepted as TdxMeasurementEntry[] | undefined) ?? [];
      if (allowlist.length > 0) {
        const matchedName = matchMeasurementAllowlist(parsed, allowlist);
        const matchedEntry = matchedName ? allowlist.find((entry) => entry.name === matchedName) as (TdxMeasurementEntry & { composeSha256?: string }) | undefined : undefined;
        matchedPolicy = Boolean(matchedEntry)
          && typeof matchedEntry?.composeSha256 === "string"
          && hexEqual(matchedEntry.composeSha256, composeSha256);
        checks.push(check("measurement_allowlist", matchedPolicy, true, matchedPolicy ? undefined : "measurements not in accepted allowlist"));
      } else {
        checks.push(check("measurement_allowlist", false, true, "no accepted-measurement policy pinned"));
      }
    }

    // The attested model_name must equal the route's upstream model (prevents a
    // quote from another model being replayed for this route).
    checks.push(check("model_binding", modelName === expectations.upstreamModel, true, modelName ? undefined : "attestation did not name a model"));

    // NVIDIA GPU evidence must be present for a confidential GPU claim.
    const gpuOk = typeof payload?.nvidia_payload === "string" && (payload.nvidia_payload as string).length > 0;
    checks.push(check("gpu_evidence_present", gpuOk, true, gpuOk ? undefined : "no NVIDIA GPU evidence"));

    checks.push(freshnessCheck(envelope.fetchedAtMs, expectations));

    let level: NormalizedAttestationResult["verificationLevel"] = "provider-attested";
    if (this.chainVerifier && parsed && hasQuote) {
      const chain = this.chainVerifier.verifyChain(quoteRaw as string, payload?.nvidia_payload);
      const acceptableTcb = chain.verified && chain.tcbStatus === "UpToDate";
      checks.push(check("dcap_chain", acceptableTcb, true, acceptableTcb
        ? "tcb:UpToDate"
        : "quote/GPU chain did not verify with an UpToDate TCB"));
      level = acceptableTcb && matchedPolicy ? "hardware-verified" : "provider-attested";
    }

    const boundNonce = parsed ? parsed.reportData.slice(64, 128) : null;
    return assembleResult({
      expectations,
      hardwareType: "intel-tdx+nvidia-cc",
      requestedLevel: level,
      privacyModality: expectations.privacyModality,
      measurementIdentities: measurements,
      modelWeightIdentity: null,
      attestedTlsSpki: tlsFingerprint,
      attestedEncryptionKey: typeof payload?.signing_public_key === "string" ? payload.signing_public_key : null,
      attestedSigningKey: signingAddress,
      boundNonce: parsed && hexEqual(expectations.nonce, boundNonce) ? expectations.nonce : boundNonce,
      verifierVersion: this.verifierVersion,
      supportsClientOpaqueE2ee: true,
      checks
    });
  }

  verifySignature(input: SignatureVerificationInput): SignatureVerificationResult {
    const payload = input.evidence as NearSignaturePayload | undefined;
    const text = typeof payload?.text === "string" ? payload.text : null;
    const signature = typeof payload?.signature === "string" ? payload.signature : null;
    const signer = typeof payload?.signing_address === "string" ? payload.signing_address : null;
    const algo = typeof payload?.signing_algo === "string" ? payload.signing_algo.toLowerCase() : "ecdsa";
    const checks: AttestationCheck[] = [];

    checks.push(check("signature_present", Boolean(text && signature), true, text && signature ? undefined : "missing text/signature"));
    if (!text || !signature) {
      return unverifiedSignature(checks, "malformed_signature_payload");
    }

    const inputHashesValid = /^[0-9a-f]{64}$/i.test(input.requestHash) && /^[0-9a-f]{64}$/i.test(input.responseHash);
    checks.push(check("gateway_hashes_present", inputHashesValid, true, inputHashesValid ? undefined : "gateway did not supply persisted exact-byte hashes"));

    // text = "{model}:{sha256(request)}:{sha256(response)}" (provider_tee) or
    //        "{sha256(request)}:{sha256(response)}" (gateway). Reject extra
    // fields rather than ambiguously selecting a subset.
    const parts = text.split(":");
    const kind: SignatureKind = parts.length === 3 ? "provider_tee" : parts.length === 2 ? "gateway" : "unsupported";
    const boundReqHash = kind === "provider_tee" ? parts[1] : parts[0];
    const boundRespHash = kind === "provider_tee" ? parts[2] : parts[1];

    checks.push(check("signed_text_format", kind !== "unsupported" && /^[0-9a-f]{64}$/i.test(boundReqHash ?? "")
      && /^[0-9a-f]{64}$/i.test(boundRespHash ?? ""), true, "signed text is not canonical"));

    checks.push(check("request_hash_binding", hexEqual(boundReqHash, input.requestHash), true, undefined));
    checks.push(check("response_hash_binding", hexEqual(boundRespHash, input.responseHash), true, undefined));
    if (kind === "provider_tee") {
      checks.push(check("model_binding", parts[0] === input.upstreamModel, true, undefined));
    }
    const hasAttestedSigner = typeof input.attestedSigningIdentity === "string" && input.attestedSigningIdentity.length > 0;
    checks.push(check("attested_signer_present", hasAttestedSigner, true, hasAttestedSigner ? undefined : "no prior attested signing identity"));
    checks.push(check("declared_signer_matches_attestation", hasAttestedSigner && hexEqual(signer, input.attestedSigningIdentity), true, undefined));

    // Cryptographic signature check. ed25519 is verifiable in-process; the eth
    // (secp256k1 personal_sign) path uses the pluggable recoverer.
    let cryptoVerified = false;
    if (algo === "ed25519" && typeof payload?.signing_public_key === "string") {
      try {
        cryptoVerified = verifyEd25519(Buffer.from(text, "utf8"), fromHex(signature), fromHex(payload.signing_public_key));
      } catch {
        cryptoVerified = false;
      }
      checks.push(check("signature_crypto", cryptoVerified, true, cryptoVerified ? undefined : "ed25519 signature did not verify"));
    } else if (algo === "ecdsa") {
      const recovered = this.ethRecoverer.recoverAddress(text, signature);
      cryptoVerified = recovered !== null && hasAttestedSigner
        && hexEqual(recovered, signer) && hexEqual(recovered, input.attestedSigningIdentity);
      checks.push(check("signature_crypto", cryptoVerified, true,
        recovered === null ? "eth signer recovery failed" : cryptoVerified ? undefined : "recovered signer does not match attested signer"));
    } else {
      checks.push(check("signature_crypto", false, true, "unsupported signing algorithm"));
    }

    const requiredPassed = checks.every((c) => !c.required || c.passed);
    return {
      supported: true,
      verified: requiredPassed && cryptoVerified,
      verificationLevel: requiredPassed && cryptoVerified ? "provider-attested" : "unverified",
      signatureKind: kind,
      signingIdentity: signer,
      boundRequestHash: boundReqHash ?? null,
      boundResponseHash: boundRespHash ?? null,
      reason: requiredPassed && cryptoVerified ? null : (checks.find((c) => c.required && !c.passed)?.name ?? "signature_unverified"),
      checks
    };
  }
}

function unverifiedSignature(checks: AttestationCheck[], reason: string): SignatureVerificationResult {
  return {
    supported: true,
    verified: false,
    verificationLevel: "unverified",
    signatureKind: "unsupported",
    signingIdentity: null,
    boundRequestHash: null,
    boundResponseHash: null,
    reason,
    checks
  };
}
