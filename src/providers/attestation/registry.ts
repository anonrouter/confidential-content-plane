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

export class VerifierRegistry {
  private readonly verifiers: Map<string, TeeVerifier>;

  constructor(opts: VerifierRegistryOptions = {}) {
    this.verifiers = new Map<string, TeeVerifier>([
      ["venice", new VeniceTeeVerifier({ ethRecoverer: opts.ethRecoverer ?? ethersEthMessageRecoverer })],
      ["chutes", new ChutesTeeVerifier({ chainVerifier: opts.tdxChainVerifier })],
      ["tinfoil", new TinfoilTeeVerifier()],
      ["near-ai", new NearTeeVerifier({
        chainVerifier: opts.tdxChainVerifier,
        ethRecoverer: opts.ethRecoverer ?? ethersEthMessageRecoverer
      })]
    ]);
  }

  /** Resolve a verifier, or null when the provider exposes no TEE verification. */
  forProvider(provider: string): TeeVerifier | null {
    return this.verifiers.get(provider) ?? null;
  }

  has(provider: string): boolean {
    return this.verifiers.has(provider);
  }
}
