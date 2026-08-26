import { CAPABILITY_ACTIONS, type CapabilityAction } from "../providers/credentials/capability.js";

/**
 * The content plane's configuration side of provider-credential capabilities.
 *
 * THE PROTOCOL ITSELF IS NOT DEFINED HERE. It lives in
 * `src/providers/credentials/capability.ts`, which is a byte-identical copy of
 * the control plane's implementation at `gcp-us-west-control-implementation@34a6c7a`.
 * Both planes must agree on the signed bytes, and the only reliable way to agree
 * byte for byte is to run the same code rather than two readings of one
 * specification. The integration pass collapses the duplicate to a single file.
 *
 * WHY THAT PROTOCOL AND NOT THE ONE THIS BRANCH HAD
 *
 * This branch previously carried `arcap1`: a JSON payload with a `.`-separated
 * envelope. It worked and it was tested. It lost anyway, for reasons that are
 * about the surrounding machinery rather than the format:
 *
 *   - the control plane's version is the one with a canonical CBOR codec whose
 *     decoder RE-ENCODES and compares, so a non-canonical encoding is rejected
 *     instead of silently accepted. `arcap1` compared JSON text, which has no
 *     canonical form and would have needed one inventing;
 *   - it ships a published negative-case fixture set and a harness both planes
 *     can run, so agreement is demonstrated rather than asserted;
 *   - it is already bound into that plane's key hierarchy and issuance store.
 *
 * Two protocols is strictly worse than either one, so this branch adopts it.
 * See docs/architecture/confidential-backend/CAPABILITY_PROTOCOL_DECISION.md
 * for what was given up and what was proposed for a v2.
 */

/** A pinned capability signer: `<keyId>:<hex raw Ed25519 public key>`. */
export interface CapabilitySignerSet {
  /** keyId -> hex-encoded raw 32-byte Ed25519 public key. */
  publicKeys: Record<string, string>;
}

const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{2,63}$/;

/**
 * Parse the pinned signer set from configuration.
 *
 * The value is measured with the rest of the workload's configuration, so
 * changing which key may authorize a credential installation changes the
 * deployment's measurements. That is the intended cost: the signer set cannot be
 * swapped by anyone who merely reaches the control plane.
 *
 * Accepts hex or base64 for the key, because the control plane's own verifier
 * takes hex and an operator copying a key out of a base64 field should get a
 * clear error rather than a signature failure at the worst possible moment.
 */
export function parseCapabilitySigners(raw: string): CapabilitySignerSet {
  const publicKeys: Record<string, string> = {};
  for (const entry of raw.split(",").map((value) => value.trim()).filter(Boolean)) {
    const separator = entry.indexOf(":");
    if (separator <= 0) {
      throw new Error(`capability signer "${entry.slice(0, 16)}" is not <keyId>:<key>`);
    }
    const keyId = entry.slice(0, separator);
    if (!KEY_ID_PATTERN.test(keyId)) throw new Error("capability signer key id is malformed");
    if (publicKeys[keyId]) throw new Error(`capability signer key id ${keyId} is listed twice`);

    const value = entry.slice(separator + 1);
    const bytes = /^[0-9a-f]{64}$/i.test(value) ? Buffer.from(value, "hex") : Buffer.from(value, "base64");
    if (bytes.length !== 32) {
      throw new Error(`capability signer ${keyId} is not a 32-byte Ed25519 public key`);
    }
    publicKeys[keyId] = bytes.toString("hex");
  }
  return { publicKeys };
}

/** Actions this endpoint performs, as the control plane names them. */
export const INSTALL_ACTIONS: readonly CapabilityAction[] = ["register", "rotate"];
export const REVOKE_ACTIONS: readonly CapabilityAction[] = ["revoke"];

export { CAPABILITY_ACTIONS };
export type { CapabilityAction };
