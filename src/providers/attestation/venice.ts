// Venice TEE/E2EE verifier. Venice returns an Intel TDX quote, NVIDIA evidence,
// a nonce, and a secp256k1 signing/encryption key. We validate the structural
// quote bindings and per-response EIP-191 signature locally. Full Intel/NVIDIA
// vendor-root verification is deliberately not inferred from Venice's own
// `verified` booleans, so the honest maximum remains `provider-attested`.

import { assembleResult, check, freshnessCheck, hexEqual, readEnvelope } from "./checks.js";
import {
  secp256k1AddressFromPublicKey,
  unavailableEthRecoverer,
  type EthMessageRecoverer
} from "./crypto.js";
import { parseTdxQuote } from "./tdxQuote.js";
import type {
  AttestationCheck,
  AttestationExpectations,
  NormalizedAttestationResult,
  SignatureVerificationInput,
  SignatureVerificationResult,
  TeeVerifier
} from "./types.js";

const TDX_TEE_TYPE = 0x00000081;

interface VeniceAttestationPayload {
  intel_quote?: unknown;
  nvidia_payload?: unknown;
  nonce?: unknown;
  model?: unknown;
  signing_address?: unknown;
  signing_public_key?: unknown;
  signing_key?: unknown;
  signing_algo?: unknown;
  attestation?: {
    report_data?: unknown;
    workload_keyset?: {
      e2ee_public_keys?: Array<{ algo?: unknown; public_key?: unknown }>;
    };
    evidence?: { quote_report_data?: unknown };
  };
}

interface VeniceReceiptEvent {
  type?: unknown;
  body_hash?: unknown;
}

interface VeniceSignaturePayload {
  text?: unknown;
  signature?: unknown;
  signing_address?: unknown;
  signing_algo?: unknown;
  model?: unknown;
  requested_request_id?: unknown;
  receipt?: {
    chat_id?: unknown;
    endpoint?: unknown;
    method?: unknown;
    event_log?: VeniceReceiptEvent[];
  };
}

export interface VeniceVerifierOptions {
  ethRecoverer?: EthMessageRecoverer;
  verifierVersion?: string;
}

export class VeniceTeeVerifier implements TeeVerifier {
  readonly provider = "venice";
  readonly verifierVersion: string;
  readonly supportsSignatures = true;
  private readonly ethRecoverer: EthMessageRecoverer;

  constructor(opts: VeniceVerifierOptions = {}) {
    this.ethRecoverer = opts.ethRecoverer ?? unavailableEthRecoverer;
    this.verifierVersion = opts.verifierVersion ?? "venice-tdx-receipt/2";
  }

  supportsClientOpaqueE2ee(): boolean {
    return true;
  }

  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult {
    const envelope = readEnvelope(evidence, expectations);
    const payload = envelope.payload as VeniceAttestationPayload | undefined;
    const checks: AttestationCheck[] = [];
    const quoteRaw = typeof payload?.intel_quote === "string" ? payload.intel_quote : null;
    const parsed = quoteRaw ? parseTdxQuote(quoteRaw) : null;
    const nonce = typeof payload?.nonce === "string" ? payload.nonce : null;
    const model = typeof payload?.model === "string" ? payload.model : null;
    const signingAddress = typeof payload?.signing_address === "string" ? payload.signing_address.toLowerCase() : null;
    const signingPublicKey = typeof payload?.signing_public_key === "string"
      ? payload.signing_public_key
      : typeof payload?.signing_key === "string" ? payload.signing_key : null;
    const derivedAddress = signingPublicKey ? secp256k1AddressFromPublicKey(signingPublicKey) : null;

    checks.push(check("evidence_present", Boolean(payload && quoteRaw), true, quoteRaw ? undefined : "no Intel quote"));
    checks.push(check("quote_parsed", parsed !== null, true, parsed ? undefined : "TDX quote did not parse"));
    checks.push(check("expected_tee_type", parsed?.teeType === TDX_TEE_TYPE, true,
      parsed?.teeType === TDX_TEE_TYPE ? undefined : "not an Intel TDX quote"));
    checks.push(check("debug_disabled", parsed !== null && !parsed.debugEnabled, true,
      parsed?.debugEnabled ? "TD debug mode enabled" : undefined));
    checks.push(check("nonce_binding", Boolean(parsed && nonce && hexEqual(nonce, expectations.nonce)
      && hexEqual(parsed.reportData.slice(64, 128), expectations.nonce)), true,
    nonce ? undefined : "attestation did not carry the caller nonce"));
    checks.push(check("model_binding", model === expectations.upstreamModel, true,
      model ? undefined : "attestation did not name the route model"));
    checks.push(check("signing_algorithm", payload?.signing_algo === "ecdsa", true,
      payload?.signing_algo === "ecdsa" ? undefined : "unsupported attested signing algorithm"));
    checks.push(check("signing_key_address", Boolean(derivedAddress && signingAddress && hexEqual(derivedAddress, signingAddress)), true,
      derivedAddress ? undefined : "attested secp256k1 key was missing or malformed"));

    const addressReportPrefix = signingAddress && /^0x[0-9a-f]{40}$/.test(signingAddress)
      ? signingAddress.slice(2).padEnd(64, "0")
      : null;
    checks.push(check("signing_address_quote_binding", Boolean(parsed && addressReportPrefix
      && hexEqual(parsed.reportData.slice(0, 64), addressReportPrefix)), true,
    addressReportPrefix ? undefined : "attested signing address was malformed"));
    const reportedReportData = typeof payload?.attestation?.report_data === "string"
      ? payload.attestation.report_data : null;
    const evidenceReportData = typeof payload?.attestation?.evidence?.quote_report_data === "string"
      ? payload.attestation.evidence.quote_report_data : null;
    checks.push(check("reported_quote_binding", Boolean(parsed
      && hexEqual(reportedReportData, parsed.reportData)
      && hexEqual(evidenceReportData, parsed.reportData)), true,
    "nested attestation report_data did not match the quote"));

    const keysetKeys = payload?.attestation?.workload_keyset?.e2ee_public_keys;
    const keyInWorkload = Array.isArray(keysetKeys) && keysetKeys.some((entry) =>
      entry?.algo === "secp256k1-aes-256-gcm-hkdf-sha256"
      && typeof entry.public_key === "string"
      && signingPublicKey !== null
      && hexEqual(entry.public_key, signingPublicKey)
    );
    checks.push(check("workload_keyset_binding", keyInWorkload, true,
      keyInWorkload ? undefined : "signing key was not in the attested workload keyset"));
    const gpuPresent = typeof payload?.nvidia_payload === "string" && payload.nvidia_payload.length > 0;
    checks.push(check("gpu_evidence_present", gpuPresent, true, gpuPresent ? undefined : "no NVIDIA GPU evidence"));
    checks.push(freshnessCheck(envelope.fetchedAtMs, expectations));

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
      hardwareType: "intel-tdx+nvidia-cc",
      requestedLevel: "provider-attested",
      privacyModality: expectations.privacyModality,
      measurementIdentities: measurements,
      modelWeightIdentity: null,
      attestedTlsSpki: null,
      attestedEncryptionKey: signingPublicKey,
      attestedSigningKey: signingAddress,
      boundNonce: parsed && nonce && hexEqual(nonce, expectations.nonce) ? expectations.nonce : nonce,
      verifierVersion: this.verifierVersion,
      supportsClientOpaqueE2ee: true,
      checks
    });
  }

  verifySignature(input: SignatureVerificationInput): SignatureVerificationResult {
    const payload = input.evidence as VeniceSignaturePayload | undefined;
    const text = typeof payload?.text === "string" ? payload.text : null;
    const signature = typeof payload?.signature === "string" ? payload.signature : null;
    const signer = typeof payload?.signing_address === "string" ? payload.signing_address.toLowerCase() : null;
    const checks: AttestationCheck[] = [];
    checks.push(check("signature_present", Boolean(text && signature), true,
      text && signature ? undefined : "missing text/signature"));
    if (!text || !signature) return unverifiedVeniceSignature(checks, "malformed_signature_payload");

    const parts = text.split(":");
    const signedRequestHash = parts[0] ?? null;
    const signedResponseHash = parts[1] ?? null;
    const signedTextCanonical = parts.length === 2
      && /^[0-9a-f]{64}$/.test(signedRequestHash)
      && /^[0-9a-f]{64}$/.test(signedResponseHash);
    checks.push(check("signed_text_format", signedTextCanonical, true,
      signedTextCanonical ? undefined : "signed text is not request_hash:response_hash"));
    checks.push(check("signing_algorithm", payload?.signing_algo === "ecdsa", true,
      payload?.signing_algo === "ecdsa" ? undefined : "unsupported signing algorithm"));
    checks.push(check("model_binding", payload?.model === input.upstreamModel, true,
      payload?.model === input.upstreamModel ? undefined : "signature model did not match route"));
    checks.push(check("request_id_binding", payload?.requested_request_id === input.providerRequestId
      && payload?.receipt?.chat_id === input.providerRequestId, true,
    "signature receipt did not match the requested completion id"));
    checks.push(check("receipt_endpoint_binding", payload?.receipt?.endpoint === "/v1/chat/completions"
      && payload?.receipt?.method === "POST", true,
    "receipt did not describe a chat completion POST"));

    const events = Array.isArray(payload?.receipt?.event_log) ? payload.receipt.event_log : [];
    const requestEventHash = receiptHash(events, "request.received");
    const responseEventHash = receiptHash(events, "response.returned");
    checks.push(check("receipt_request_hash", hexEqual(requestEventHash, signedRequestHash), true,
      "receipt request hash did not match signed text"));
    checks.push(check("receipt_response_hash", hexEqual(responseEventHash, signedResponseHash), true,
      "receipt response hash did not match signed text"));

    const hasAttestedSigner = typeof input.attestedSigningIdentity === "string"
      && /^0x[0-9a-f]{40}$/i.test(input.attestedSigningIdentity);
    checks.push(check("attested_signer_present", hasAttestedSigner, true,
      hasAttestedSigner ? undefined : "no prior attested signing identity"));
    checks.push(check("declared_signer_matches_attestation", Boolean(signer && hasAttestedSigner
      && hexEqual(signer, input.attestedSigningIdentity)), true,
    "declared signer did not match fresh attestation"));
    const recovered = this.ethRecoverer.recoverAddress(text, signature);
    const cryptoVerified = Boolean(recovered && signer && hasAttestedSigner
      && hexEqual(recovered, signer) && hexEqual(recovered, input.attestedSigningIdentity));
    checks.push(check("signature_crypto", cryptoVerified, true,
      recovered ? "recovered signer did not match attestation" : "EIP-191 signer recovery failed"));

    // Venice signs hashes observed inside its attested gateway. Live responses
    // demonstrate that those are not the exact public API wire hashes retained
    // by AnonRouter. Keep the distinction explicit instead of claiming an exact
    // byte binding that the provider receipt does not prove.
    const gatewayHashesMatch = hexEqual(signedRequestHash, input.requestHash)
      && hexEqual(signedResponseHash, input.responseHash);
    checks.push(check("gateway_exact_hash_binding", gatewayHashesMatch, false,
      gatewayHashesMatch ? undefined : "Venice receipt hashes the enclave ingress/egress representation, not AnonRouter's API wire bytes"));

    const requiredPassed = checks.every((item) => !item.required || item.passed);
    return {
      supported: true,
      verified: requiredPassed && cryptoVerified,
      verificationLevel: requiredPassed && cryptoVerified ? "provider-attested" : "unverified",
      signatureKind: "provider_tee",
      signingIdentity: signer,
      boundRequestHash: signedRequestHash,
      boundResponseHash: signedResponseHash,
      reason: requiredPassed && cryptoVerified ? null : (checks.find((item) => item.required && !item.passed)?.name ?? "signature_unverified"),
      checks
    };
  }
}

function receiptHash(events: VeniceReceiptEvent[], type: string): string | null {
  const value = events.find((event) => event?.type === type)?.body_hash;
  if (typeof value !== "string") return null;
  return value.startsWith("sha256:") ? value.slice(7) : value;
}

function unverifiedVeniceSignature(checks: AttestationCheck[], reason: string): SignatureVerificationResult {
  return {
    supported: true,
    verified: false,
    verificationLevel: "unverified",
    signatureKind: "provider_tee",
    signingIdentity: null,
    boundRequestHash: null,
    boundResponseHash: null,
    reason,
    checks
  };
}
