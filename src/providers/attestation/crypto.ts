// Cryptographic primitives for signature/key verification. Node handles SHA-256,
// Ed25519, and direct ECDSA verification; the pinned ethers dependency handles
// EIP-191/Keccak-256/secp256k1 public-key recovery for provider signatures.
//
// What this deliberately does NOT do: verify a raw Intel TDX / NVIDIA DCAP quote
// signature chain to silicon-vendor roots (that needs a vetted DCAP/NRAS verifier
// library and collateral fetch). Those chains are surfaced as a pluggable port in
// the provider verifiers and, absent a real verifier, are reported honestly as
// `provider-attested` rather than fabricated `hardware-verified`.

import { createHash, createPublicKey, verify as nodeVerify, type KeyObject } from "node:crypto";
import { computeAddress, getAddress, verifyMessage } from "ethers";

export function sha256Hex(input: Uint8Array | string): string {
  return createHash("sha256").update(typeof input === "string" ? Buffer.from(input, "utf8") : input).digest("hex");
}

export function fromHex(hex: string): Buffer {
  const clean = hex.toLowerCase().replace(/^0x/, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/.test(clean)) {
    throw new Error("invalid_hex");
  }
  return Buffer.from(clean, "hex");
}

// SPKI DER prefixes that wrap a raw public key so Node's createPublicKey accepts
// it. These are the fixed AlgorithmIdentifier + BIT STRING headers per RFC 5280.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const P256_SPKI_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");
const SECP256K1_SPKI_PREFIX = Buffer.from("3056301006072a8648ce3d020106052b8104000a034200", "hex");

/** Build a Node public KeyObject from a raw Ed25519 public key (32 bytes). */
export function ed25519KeyFromRaw(raw: Uint8Array): KeyObject {
  const key = Buffer.from(raw);
  if (key.length !== 32) throw new Error("ed25519_key_length");
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, key]), format: "der", type: "spki" });
}

/** Build a Node public KeyObject from a raw uncompressed EC point (65 bytes,
 *  leading 0x04) on the named curve. */
export function ecKeyFromRaw(raw: Uint8Array, curve: "p256" | "secp256k1"): KeyObject {
  const point = Buffer.from(raw);
  if (point.length !== 65 || point[0] !== 0x04) throw new Error("ec_point_format");
  const prefix = curve === "p256" ? P256_SPKI_PREFIX : SECP256K1_SPKI_PREFIX;
  return createPublicKey({ key: Buffer.concat([prefix, point]), format: "der", type: "spki" });
}

/** Verify an Ed25519 signature (64 bytes) over `message` with a raw 32-byte key.
 *  Returns false on any malformed input rather than throwing. */
export function verifyEd25519(message: Uint8Array, signature: Uint8Array, rawPublicKey: Uint8Array): boolean {
  try {
    const key = ed25519KeyFromRaw(rawPublicKey);
    return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}

/** Verify an ECDSA signature over `message` (hashed with `hash`) against a raw
 *  uncompressed EC public key. `sigEncoding` selects DER vs raw r||s (ieee-p1363). */
export function verifyEcdsa(
  message: Uint8Array,
  signature: Uint8Array,
  rawPublicKey: Uint8Array,
  opts: { curve: "p256" | "secp256k1"; hash?: string; sigEncoding?: "der" | "ieee-p1363" } = { curve: "p256" }
): boolean {
  try {
    const key = ecKeyFromRaw(rawPublicKey, opts.curve);
    return nodeVerify(opts.hash ?? "sha256", Buffer.from(message), { key, dsaEncoding: opts.sigEncoding ?? "der" }, Buffer.from(signature));
  } catch {
    return false;
  }
}

/**
 * Pluggable port for Ethereum-style `personal_sign` recovery (Keccak-256 plus
 * secp256k1 public-key recovery), which NEAR AI and Venice use for receipts.
 * Tests may inject a recoverer; the production registry defaults to ethers.
 */
export interface EthMessageRecoverer {
  /** Recover the lowercase 0x-prefixed signer address from an eth personal_sign
   *  signature over `message`, or null if recovery fails / is unavailable. */
  recoverAddress(message: string, signature: string): string | null;
}

/** Explicit fail-closed recoverer for tests or installations that intentionally
 * disable EIP-191 recovery. It never claims a verified signer. */
export const unavailableEthRecoverer: EthMessageRecoverer = {
  recoverAddress: () => null
};

/** Production Ethereum `personal_sign` recoverer. Ethers implements the EIP-191
 * message prefix, Keccak-256 digest and secp256k1 public-key recovery used by
 * Provider direct-enclave signature endpoints. Malformed/non-canonical inputs
 * fail closed rather than escaping into the route handler. */
export const ethersEthMessageRecoverer: EthMessageRecoverer = {
  recoverAddress(message, signature) {
    try {
      if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) return null;
      return getAddress(verifyMessage(message, signature)).toLowerCase();
    } catch {
      return null;
    }
  }
};

/** Derive the checksummed Ethereum address from a secp256k1 public key and
 * return it lowercase. Accepts compressed or uncompressed hex; malformed keys
 * fail closed. This binds a provider-declared address to the public key carried
 * in the same attestation without trusting the declared address by itself. */
export function secp256k1AddressFromPublicKey(publicKey: string): string | null {
  try {
    const normalized = publicKey.startsWith("0x") ? publicKey : `0x${publicKey}`;
    if (!/^0x(?:[0-9a-fA-F]{66}|[0-9a-fA-F]{130})$/.test(normalized)) return null;
    return getAddress(computeAddress(normalized)).toLowerCase();
  } catch {
    return null;
  }
}
