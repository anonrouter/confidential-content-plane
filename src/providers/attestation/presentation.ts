// Shared, DB-free presentation helpers for attestation responses. Both the public
// GET /v1/tee/attestation route (src/routes/tee.ts, which additionally persists an
// audit row) and the ticketed POST /v1/tee/attestation relay route
// (src/routes/chat.ts, which must run on a split relay with no database) use these
// so the two responses cannot drift and the relay never duplicates the verifier
// presentation logic.

import { pinnedEndpointIdentityFor, pinnedMeasurementPolicyFor } from "./policies.js";
import type { AttestationExpectations, NormalizedAttestationResult, PrivacyModality } from "./types.js";

/** Minimal shape of the provider base URLs the endpoint identity falls back to.
 *  Typed structurally so this module does not depend on the full ContentPlaneConfig. */
export interface ProviderEndpointConfig {
  providers: {
    chutesBaseUrl: string;
    tinfoilBaseUrl: string;
    nearBaseUrl: string;
    veniceBaseUrl: string;
  };
}

/** The wire protocol identifier for a provider's client-opaque E2EE route. */
export function e2eeProtocolFor(provider: string): "near-v2" | "venice-legacy" | "chutes-mlkem-v1" | null {
  if (provider === "near-ai") return "near-v2";
  if (provider === "venice") return "venice-legacy";
  if (provider === "chutes") return "chutes-mlkem-v1";
  return null;
}

/** Resolve the endpoint identity for a route: the operator-pinned direct domain
 *  when one exists, otherwise the configured provider base URL host. */
export function endpointIdentityFor(config: ProviderEndpointConfig, provider: string, upstreamModel: string): string {
  const pinned = pinnedEndpointIdentityFor(provider, upstreamModel);
  if (pinned) return pinned;
  const hostOf = (url: string) => {
    try { return new URL(url).host; } catch { return url; }
  };
  switch (provider) {
    case "chutes": return hostOf(config.providers.chutesBaseUrl);
    case "tinfoil": return hostOf(config.providers.tinfoilBaseUrl);
    case "near-ai": return hostOf(config.providers.nearBaseUrl);
    case "venice": return hostOf(config.providers.veniceBaseUrl);
    default: return provider;
  }
}

/** Build the verifier expectations for a route. `canonicalModel`/`routeId` default
 *  to upstream-derived values for the relay, which has no catalog; callers with a
 *  DB (the GET route) pass the exact catalog identifiers. */
export function buildAttestationExpectations(input: {
  provider: string;
  upstreamModel: string;
  canonicalModel?: string;
  routeId?: string;
  endpointIdentity: string;
  nonce: string;
  privacyModality: PrivacyModality;
  now: number;
}): AttestationExpectations {
  return {
    provider: input.provider,
    canonicalModel: input.canonicalModel ?? input.upstreamModel,
    upstreamModel: input.upstreamModel,
    routeId: input.routeId ?? `${input.provider}/${input.upstreamModel}`,
    endpointIdentity: input.endpointIdentity,
    nonce: input.nonce,
    privacyModality: input.privacyModality,
    now: input.now,
    measurementPolicy: pinnedMeasurementPolicyFor(input.provider, input.upstreamModel)
  } as AttestationExpectations;
}

/** The public projection of a verification result: safe, structured, no secrets
 *  or raw upstream bodies beyond the evidence the client re-verifies. */
export function attestationView(result: NormalizedAttestationResult) {
  return {
    status: result.status,
    verification_level: result.verificationLevel,
    privacy_modality: result.privacyModality,
    hardware_type: result.hardwareType,
    measurement_identities: result.measurementIdentities,
    model_weight_identity: result.modelWeightIdentity,
    attested_tls_spki: result.attestedTlsSpki,
    attested_encryption_key: result.attestedEncryptionKey,
    attested_signing_key: result.attestedSigningKey,
    nonce: result.nonce,
    verified_at: result.verifiedAt,
    expires_at: result.expiresAt,
    policy_source: result.policySource,
    verifier_version: result.verifierVersion,
    supports_client_opaque_e2ee: result.supportsClientOpaqueE2ee,
    reason: result.reason,
    checks: result.checks
  };
}
