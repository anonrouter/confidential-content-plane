// Provider-neutral TEE attestation + signature verification subsystem.
//
// See docs/TEE_VERIFICATION.md. The public TEE API (src/routes/tee.ts), admin
// on-demand verification, and catalog privacy classification all consume this.

export * from "./types.js";
export {
  ATTESTABLE_PROVIDERS,
  providerExposesAttestation,
  VerifierRegistry,
  type VerifierRegistryOptions
} from "./registry.js";
export { attestableRoutes, resolveExactAttestableRoute } from "./routeSelection.js";
export { ChutesTeeVerifier, type ChutesVerifierOptions } from "./chutes.js";
export { TinfoilTeeVerifier, type TinfoilVerificationDocument, type TinfoilVerifierOptions } from "./tinfoil.js";
export { NearTeeVerifier, type NearVerifierOptions } from "./near.js";
export { VeniceTeeVerifier } from "./venice.js";
// Exported for tests and for an owner decision that has NOT been taken. It is
// deliberately absent from VERIFIER_FACTORIES, so `phala-ai` stays out of
// ATTESTABLE_PROVIDERS and the attestation-ticket mint keeps refusing it.
// Building the verifier and switching the product onto it are separate calls.
export { PhalaAciServingVerifier, type PhalaAciServingVerifierOptions } from "./phalaAciServing.js";
export { parseTdxQuote, matchMeasurementAllowlist, dstackDeclaredGpuCount, tdxHardwareTypeFor, type ParsedTdxQuote, type TdxChainVerifier, type TdxMeasurementEntry } from "./tdxQuote.js";
export { sha256Hex, fromHex, verifyEd25519, verifyEcdsa, ethersEthMessageRecoverer, secp256k1AddressFromPublicKey, type EthMessageRecoverer, unavailableEthRecoverer } from "./crypto.js";
export { pinnedMeasurementPolicyFor, pinnedEndpointIdentityFor } from "./policies.js";
export { readEnvelope } from "./checks.js";
export {
  attestationNoteFor,
  attestationView,
  buildAttestationExpectations,
  e2eeProtocolFor,
  endpointIdentityFor,
  type ProviderEndpointConfig
} from "./presentation.js";
