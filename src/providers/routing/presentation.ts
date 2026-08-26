// Public privacy presentation. The internal ladder has four classes
// (anonymous < private < tee < e2ee, plus `unknown`), and the product surfaces
// all four as distinct public tiers:
//
//   Anonymous · Private · TEE · E2EE
//
// TEE is its own tier, not folded under Private: a confidential-compute (TEE)
// route runs inside an attested hardware enclave but does not require the client
// to encrypt the request end to end. E2EE (client-attested ciphertext to an
// enclave) is TEE plus client-side encryption, and stays the strongest tier.
// `unknown` and anything unrecognized present as the weakest tier.

export type PublicPrivacyTier = "anonymous" | "private" | "tee" | "e2ee";

export function publicPrivacyTier(privacyClass: string): PublicPrivacyTier {
  switch (privacyClass) {
    case "e2ee":
      return "e2ee";
    case "tee":
      return "tee";
    case "private":
      return "private";
    default:
      // anonymous / unknown / anything unrecognized presents as the weakest tier.
      return "anonymous";
  }
}

export function publicPrivacyTierLabel(tier: PublicPrivacyTier): string {
  switch (tier) {
    case "e2ee":
      return "E2EE";
    case "tee":
      return "TEE";
    case "private":
      return "Private";
    default:
      return "Anonymous";
  }
}

/** Whether a privacy class is bound to a specific enclave and cannot transparently fail over. */
export function isProviderBoundPrivacyClass(privacyClass: string): boolean {
  // E2EE ciphertext and attestation are bound to one enclave/provider; automatic
  // provider fallback would break the client's attestation contract.
  return privacyClass === "e2ee";
}
