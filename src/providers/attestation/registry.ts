// Provider-neutral verifier registry. Maps a provider name to its TeeVerifier so
// the public TEE API, admin on-demand verification, and catalog classification can
// all resolve "the verifier for provider X" without another hardcoded branch.

import { ChutesTeeVerifier } from "./chutes.js";
import { NearTeeVerifier } from "./near.js";
import { TinfoilTeeVerifier } from "./tinfoil.js";
import { VeniceTeeVerifier } from "./venice.js";
import { ethersEthMessageRecoverer, type EthMessageRecoverer } from "./crypto.js";
import type { TdxChainVerifier } from "./tdxQuote.js";
import type { TeeVerifier } from "./types.js";

export interface VerifierRegistryOptions {
  /** Optional vetted TDX/NRAS chain verifier (Chutes + NEAR). When absent those
   *  verifiers report `provider-attested` rather than `hardware-verified`. */
  tdxChainVerifier?: TdxChainVerifier;
  /** Optional eth (secp256k1 personal_sign) recoverer for provider signatures. */
  ethRecoverer?: EthMessageRecoverer;
}

/**
 * The single source of truth for "which providers can be attested at all".
 *
 * A construction map rather than a hand-kept list, because the control plane
 * needs the ANSWER without building the verifiers. Issuing an attestation ticket
 * is a control-plane decision, and control holds no provider credential and has
 * no reason to instantiate four verifier objects to ask one boolean. Deriving
 * both from the same map is what keeps "control will mint a ticket for this
 * provider" and "the content plane has a verifier for it" from drifting apart —
 * a drift that would mint tickets the content plane can only fail on.
 */
const VERIFIER_FACTORIES: Readonly<Record<string, (opts: VerifierRegistryOptions) => TeeVerifier>> =
  Object.freeze({
    venice: (opts) => new VeniceTeeVerifier({ ethRecoverer: opts.ethRecoverer ?? ethersEthMessageRecoverer }),
    chutes: (opts) => new ChutesTeeVerifier({ chainVerifier: opts.tdxChainVerifier }),
    tinfoil: () => new TinfoilTeeVerifier(),
    "near-ai": (opts) => new NearTeeVerifier({
      chainVerifier: opts.tdxChainVerifier,
      ethRecoverer: opts.ethRecoverer ?? ethersEthMessageRecoverer
    })
  });

/** Provider names with a registered verifier. Read-only, and derived, never listed. */
export const ATTESTABLE_PROVIDERS: ReadonlySet<string> = Object.freeze(
  new Set(Object.keys(VERIFIER_FACTORIES))
) as ReadonlySet<string>;

/**
 * Whether a provider exposes verifiable enclave evidence at all.
 *
 * A catalog row may carry `privacy_class = 'tee'` for a provider that publishes
 * no evidence — the class describes where execution happens, not whether anyone
 * can check it. Only a registered verifier makes a route genuinely attestable,
 * so this is the predicate the ticket mint uses, not the privacy class alone.
 */
export function providerExposesAttestation(provider: string): boolean {
  return ATTESTABLE_PROVIDERS.has(provider);
}

export class VerifierRegistry {
  private readonly verifiers: Map<string, TeeVerifier>;

  constructor(opts: VerifierRegistryOptions = {}) {
    this.verifiers = new Map<string, TeeVerifier>(
      Object.entries(VERIFIER_FACTORIES).map(([provider, create]) => [provider, create(opts)])
    );
  }

  /** Resolve a verifier, or null when the provider exposes no TEE verification. */
  forProvider(provider: string): TeeVerifier | null {
    return this.verifiers.get(provider) ?? null;
  }

  has(provider: string): boolean {
    return this.verifiers.has(provider);
  }
}
