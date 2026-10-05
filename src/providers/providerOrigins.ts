// Where a provider credential is allowed to go, by deployment profile.
//
// WHAT THIS IS. src/providers/transport.ts binds each provider's key to the
// origins of that provider's CONFIGURED base URLs. That is only as good as the
// configuration: a worker booted with a base URL pointing somewhere else would
// send its key there, faithfully. This file is the list the configuration is
// checked against. src/config.ts does the checking at boot, for each production
// provider worker and only for the provider that worker serves.
//
// CREDENTIAL-BEARING ORIGINS ONLY. These are the origins that may RECEIVE a key,
// not every host a worker reaches. Keyless hosts are absent on purpose:
// Tinfoil's GitHub and KDS proxies, NEAR's endpoint discovery, and the GitHub
// and Base release-authority collateral. NEAR's direct enclave hosts are absent
// too, because they are not configuration: the transport takes them from the
// reviewed route table. Bedrock has no bearer and no base URL override.
//
// NO IMPORTS from the rest of the app. src/config.ts imports this file, and
// nearly everything else imports src/config.ts.

/**
 * `production` pins each provider to its real origins. `synthetic` is for
 * manifests whose providers are fixtures: the fixture origins REPLACE the real
 * ones instead of joining them, so a synthetic deployment cannot send a key to
 * a real provider. The value is a literal in the measured
 * compose file. No profile skips the check.
 */
export const PROVIDER_TRANSPORT_PROFILES = ["production", "synthetic"] as const;

export type ProviderTransportProfile = (typeof PROVIDER_TRANSPORT_PROFILES)[number];

/** The in-CVM mock of the preproduction compose. Plain http, reachable only inside the CVM. */
export const SYNTHETIC_CREDENTIAL_ORIGIN = "http://mock-provider:3000";

/**
 * The TLS fixture of deploy/verify-prod-isolation.sh. That rehearsal exercises
 * the SNI egress gateway, so it cannot use the plain-http mock. `.invalid` is
 * a reserved name that never resolves on the public Internet, so admitting it
 * keeps the property that matters: no real provider is reachable with a key.
 */
export const REHEARSAL_CREDENTIAL_ORIGIN = "https://synthetic-provider.rehearsal.invalid";

/** Every origin the synthetic profile admits. None is a real provider. */
export const SYNTHETIC_CREDENTIAL_ORIGINS: readonly string[] = [
  SYNTHETIC_CREDENTIAL_ORIGIN,
  REHEARSAL_CREDENTIAL_ORIGIN
];

interface CredentialOriginPin {
  /** Environment variables holding a base URL this provider's key is sent to. */
  readonly baseUrlVariables: readonly string[];
  /** The exact origins those base URLs must be on under the production profile. */
  readonly origins: readonly string[];
}

// Keyed by canonical provider name. `baseUrlVariables` must name every base URL
// the provider's transport binds (transport.ts), or a key could be bound to an
// origin nothing checked; tests/unit/provider-origin-config.test.ts holds the
// two together.
export const PROVIDER_CREDENTIAL_ORIGINS = {
  venice: { baseUrlVariables: ["VENICE_BASE_URL"], origins: ["https://api.venice.ai"] },
  fireworks: { baseUrlVariables: ["FIREWORKS_BASE_URL"], origins: ["https://api.fireworks.ai"] },
  deepinfra: { baseUrlVariables: ["DEEPINFRA_BASE_URL"], origins: ["https://api.deepinfra.com"] },
  tinfoil: { baseUrlVariables: ["TINFOIL_BASE_URL"], origins: ["https://inference.tinfoil.sh"] },
  "near-ai": { baseUrlVariables: ["NEAR_BASE_URL"], origins: ["https://cloud-api.near.ai"] },
  "phala-ai": { baseUrlVariables: ["PHALA_AI_BASE_URL"], origins: ["https://inference.phala.com"] },
  // Inference on one host; the E2EE invoke and instance discovery on the other.
  chutes: {
    baseUrlVariables: ["CHUTES_BASE_URL", "CHUTES_ATTESTATION_BASE_URL"],
    origins: ["https://llm.chutes.ai", "https://api.chutes.ai"]
  }
} as const satisfies Record<string, CredentialOriginPin>;

export type CredentialOriginProvider = keyof typeof PROVIDER_CREDENTIAL_ORIGINS;

export function isCredentialOriginProvider(provider: string | null): provider is CredentialOriginProvider {
  return provider !== null && Object.hasOwn(PROVIDER_CREDENTIAL_ORIGINS, provider);
}

/** The origins a provider's credential-bearing base URLs must be on under a profile. */
export function credentialOrigins(
  provider: CredentialOriginProvider,
  profile: ProviderTransportProfile
): readonly string[] {
  return profile === "synthetic" ? SYNTHETIC_CREDENTIAL_ORIGINS : PROVIDER_CREDENTIAL_ORIGINS[provider].origins;
}

/**
 * Whether a configured base URL may carry the provider's credential under a
 * profile. Compared as an exact origin (scheme, host and port), which is how
 * the transport compares a request, so plain http, another port and a host that
 * merely starts with the pinned one all fail. Userinfo fails as well: the
 * transport refuses it on every request, and a base URL that can never be used
 * is better caught at boot.
 */
export function credentialBaseUrlPermitted(
  provider: CredentialOriginProvider,
  profile: ProviderTransportProfile,
  baseUrl: string
): boolean {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    return false;
  }
  if (parsed.username || parsed.password) return false;
  return credentialOrigins(provider, profile).includes(parsed.origin);
}
