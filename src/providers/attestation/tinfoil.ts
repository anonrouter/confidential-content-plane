// Tinfoil verifier. Tinfoil's own SDK (`tinfoil` on npm) performs the hard
// cryptographic work: AMD SEV-SNP + NVIDIA confidential-compute hardware
// attestation, a Sigstore-transparency-log code measurement, and TLS key binding,
// refusing to send data if any check fails. Re-implementing that in a weaker
// homegrown check would be strictly worse, so the credential-isolated worker
// adapter runs the SDK's Verifier and
// hands us its verification DOCUMENT; this verifier binds that document to the
// route and reports `sdk-verified` when the SDK confirmed security.
//
// This gateway currently wires only the SDK-verified TLS transport. Tinfoil's
// separate EHBP/HPKE transport is deliberately not advertised until the relay
// can preserve its raw body and headers byte-for-byte.

import { assembleResult, check, freshnessCheck, hexEqual, readEnvelope } from "./checks.js";
import type {
  AttestationCheck,
  AttestationExpectations,
  NormalizedAttestationResult,
  SignatureVerificationInput,
  SignatureVerificationResult,
  TeeVerifier
} from "./types.js";

/** The sanitized verification document the worker obtains from the Tinfoil SDK's
 *  `Verifier.verify()` / `getVerificationDocument()`. No raw quotes/keys beyond
 *  the attested public fingerprints, which are safe to surface. */
export interface TinfoilVerificationDocument {
  schemaVersion?: number;
  securityVerified?: boolean;
  enclaveHost?: string;
  configRepo?: string;
  releaseTag?: string;
  releaseDigest?: string;
  codeMeasurement?: { type?: string; registers?: string[] };
  enclaveMeasurement?: {
    tlsPublicKeyFingerprint?: string;
    hpkePublicKey?: string;
    measurement?: { type?: string; registers?: string[] };
  };
  codeFingerprint?: string;
  enclaveFingerprint?: string;
  selectedRouterEndpoint?: string;
  tlsPublicKey?: string;
  /** Attested HPKE public key (ehbp transport / e2ee). */
  hpkePublicKey?: string;
  verifier?: { name?: string; version?: string };
  steps?: Record<string, { status?: string; error?: string }>;
}

interface TinfoilProviderAuthorityPolicy {
  authority?: string;
  configRepo?: string;
  releaseSelection?: string;
  requireTaggedRelease?: boolean;
}

export interface TinfoilVerifierOptions {
  verifierVersion?: string;
}

export class TinfoilTeeVerifier implements TeeVerifier {
  readonly provider = "tinfoil";
  readonly verifierVersion: string;
  readonly supportsSignatures = false;

  constructor(opts: TinfoilVerifierOptions = {}) {
    this.verifierVersion = opts.verifierVersion ?? "tinfoil-sdk/1";
  }

  // Provider capability is not gateway capability. EHBP is not wired here.
  supportsClientOpaqueE2ee(): boolean {
    return false;
  }

  verifyAttestation(evidence: unknown, expectations: AttestationExpectations): NormalizedAttestationResult {
    const envelope = readEnvelope(evidence, expectations);
    const doc = envelope.payload as TinfoilVerificationDocument | undefined;
    const checks: AttestationCheck[] = [];

    const present = Boolean(doc && typeof doc === "object");
    checks.push(check("evidence_present", present, true, present ? undefined : "no SDK verification document"));

    // The SDK is the crypto root of trust: it verified hardware + signed release
    // provenance + code/enclave equality + key binding, or refused. We require
    // its explicit securityVerified === true.
    const securityVerified = doc?.securityVerified === true;
    checks.push(check("sdk_security_verified", securityVerified, true, securityVerified ? undefined : "Tinfoil SDK did not confirm enclave security"));

    // Bind the document to the official verifier implementation rather than a
    // provider-shaped object that merely carries `securityVerified: true`.
    const verifierIdentityOk = doc?.schemaVersion === 1
      && doc?.verifier?.name === "@tinfoilsh/verifier"
      && typeof doc.verifier.version === "string"
      && doc.verifier.version.length > 0;
    checks.push(check(
      "official_verifier_identity",
      verifierIdentityOk,
      true,
      verifierIdentityOk ? undefined : "verification document is not from the official Tinfoil verifier"
    ));

    // The SDK selects an enclave behind the stable router URL. Bind the route to
    // that router URL exactly; its verified certificate separately binds the
    // selected enclaveHost and TLS/HPKE keys.
    const selectedRouterHost = hostFromUrl(doc?.selectedRouterEndpoint);
    const hostOk = selectedRouterHost === expectations.endpointIdentity;
    checks.push(check("enclave_host_binding", hostOk, true, hostOk ? undefined : "attested enclave host does not match route endpoint"));

    const requiredSteps = ["fetchDigest", "verifyCode", "verifyEnclave", "compareMeasurements", "verifyCertificate"];
    const stepsOk = requiredSteps.every((name) => doc?.steps?.[name]?.status === "success");
    checks.push(check("sdk_verification_steps", stepsOk, true, stepsOk ? undefined : "one or more SDK cryptographic steps did not succeed"));

    // Tinfoil rotates its measured release frequently. Requiring AnonRouter to
    // copy each new fingerprint into a second static allowlist added no
    // independent cryptographic proof: the official verifier had already
    // verified the DSSE signature, Fulcio identity, Rekor inclusion, exact
    // GitHub repository, signed tag, AMD chain, and equality with the live
    // enclave. It only made valid routes fail between our releases.
    //
    // Keep the trust decision explicit and fixed instead: accept releases
    // authorized by Tinfoil's official tagged-release workflow for the exact
    // repository AnonRouter supports. A different repository still fails closed.
    const authority = expectations.measurementPolicy?.accepted as TinfoilProviderAuthorityPolicy | undefined;
    const authorityOk = authority?.authority === "github-actions-sigstore"
      && authority.configRepo === "tinfoilsh/confidential-model-router"
      && authority.releaseSelection === "latest"
      && authority.requireTaggedRelease === true
      && doc?.configRepo === authority.configRepo;
    checks.push(check(
      "provider_release_authority",
      authorityOk,
      true,
      authorityOk ? undefined : "release is not bound to the supported Tinfoil GitHub authority"
    ));

    // `verifyCode: success` proves the digest belongs to the signed in-toto
    // statement and that the certificate's workflow ref names this selected tag.
    // Require the safe document to carry those identities so a blank/partial
    // document never inherits the SDK's aggregate boolean.
    const releaseIdentityOk = typeof doc?.releaseTag === "string"
      && doc.releaseTag.length > 0
      && typeof doc.releaseDigest === "string"
      && /^[0-9a-f]{64}$/i.test(doc.releaseDigest)
      && typeof doc.codeFingerprint === "string"
      && /^[0-9a-f]{64,192}$/i.test(doc.codeFingerprint)
      && typeof doc.enclaveFingerprint === "string"
      && /^[0-9a-f]{64,192}$/i.test(doc.enclaveFingerprint);
    checks.push(check(
      "signed_release_identity",
      releaseIdentityOk,
      true,
      releaseIdentityOk ? undefined : "signed release identity is missing or malformed"
    ));

    const measurementOk = hexEqual(doc?.codeFingerprint, doc?.enclaveFingerprint);
    checks.push(check(
      "code_matches_live_enclave",
      measurementOk,
      true,
      measurementOk ? undefined : "signed release measurement does not match the live enclave"
    ));

    const servingModalitySupported = expectations.privacyModality === "tee";
    checks.push(check(
      "serving_modality_supported",
      servingModalitySupported,
      true,
      servingModalitySupported ? undefined : "AnonRouter does not implement Tinfoil EHBP forwarding"
    ));

    // The wired TLS modality must bind the serving certificate. The SDK may also
    // report an HPKE key, but its presence does not make EHBP routable here.
    const e2ee = expectations.privacyModality === "e2ee";
    const hpkePublicKey = doc?.enclaveMeasurement?.hpkePublicKey ?? doc?.hpkePublicKey;
    const tlsPublicKeyFingerprint = doc?.enclaveMeasurement?.tlsPublicKeyFingerprint;
    const keyOk = e2ee ? typeof hpkePublicKey === "string" && hpkePublicKey.length > 0
      : /^[0-9a-f]{64}$/i.test(tlsPublicKeyFingerprint ?? "")
        && hexEqual(tlsPublicKeyFingerprint, doc?.tlsPublicKey);
    checks.push(check("attested_key_binding", keyOk, true, keyOk ? undefined : "no attested key for the serving modality"));

    // Tinfoil attestation is connection-bound (SDK handshake), not caller-nonce
    // bound; record the caller's freshness intent as advisory, not required.
    checks.push(check("nonce_binding", false, false, "Tinfoil attestation is connection-bound, not nonce-bound"));
    checks.push(freshnessCheck(envelope.fetchedAtMs, expectations));

    return assembleResult({
      expectations,
      hardwareType: "amd-sev-snp+nvidia-cc",
      requestedLevel: "sdk-verified",
      privacyModality: expectations.privacyModality,
      measurementIdentities: {
        ...(typeof doc?.codeFingerprint === "string" ? { code: doc.codeFingerprint } : {}),
        ...(typeof doc?.enclaveFingerprint === "string" ? { enclave: doc.enclaveFingerprint } : {})
      },
      // The SDK document currently proves the release/code measurement and
      // enclave keys. It does not expose a model-weight digest, so never invent
      // one from the requested model id.
      modelWeightIdentity: null,
      attestedTlsSpki: typeof tlsPublicKeyFingerprint === "string" ? tlsPublicKeyFingerprint : null,
      // EHBP is not a gateway capability yet. Do not surface its public key as
      // the key for the currently exposed TLS/plaintext-to-worker modality.
      attestedEncryptionKey: null,
      attestedSigningKey: null,
      boundNonce: null,
      verifierVersion: this.verifierVersion,
      supportsClientOpaqueE2ee: false,
      checks
    });
  }

  verifySignature(_input: SignatureVerificationInput): SignatureVerificationResult {
    // Tinfoil provides connection-level integrity (attested key binding + AEAD),
    // but no offline-verifiable per-request signature. Never fabricate one.
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

function hostFromUrl(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    return new URL(value).host;
  } catch {
    return value;
  }
}
