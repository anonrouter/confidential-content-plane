/**
 * Cross-plane opaque settlement receipts.
 *
 * Why this exists
 * ---------------
 * Settlement used to carry `teeSignatureBinding.requestHash` and
 * `.responseHash` — exact SHA-256 commitments over the wire request and
 * response — from the content plane into the control plane. Once the control
 * plane runs in GCP that is a guessable content oracle: anyone holding a
 * candidate prompt can hash it and test the guess against a stored value, so
 * "we only store a hash" would silently become "we store a verifiable claim
 * about the prompt".
 *
 * `docs/architecture/confidential-backend/CONTROL_RPC_CONTRACT.md` therefore
 * replaces the whole commitment with a receipt identifier that is:
 *
 *   - freshly random per settlement, so it is not derived from content at all;
 *   - at least 128 bits, so it cannot be enumerated;
 *   - single-purpose, joining exactly one content-plane record to exactly one
 *     control settlement; and
 *   - unlinkable across requests.
 *
 * The exact hashes stay in the attested content plane, in the receipt store in
 * ./contentReceipts.ts. The control plane learns only that a receipt exists.
 *
 * Encoding
 * --------
 * `arcpt_` + 52 characters of lowercase Crockford base32 over 32 random bytes.
 * The fixed 58-character length is itself a control: a 64-character hex digest
 * can never satisfy it, which is what lets migration 096 express "this column
 * cannot hold a hash" as a CHECK constraint rather than as a code review
 * comment. See `tests/unit/opaque-receipt.test.ts` and
 * `tests/integration/control-boundary-hash-impossibility.test.ts`.
 */

import { randomBytes } from "node:crypto";

/** Crockford base32 without i, l, o, u. */
const ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";

export const OPAQUE_RECEIPT_PREFIX = "arcpt_";
/** 32 bytes = 256 bits, comfortably above the 128-bit contract minimum. */
export const OPAQUE_RECEIPT_ENTROPY_BYTES = 32;
/** ceil(256 / 5) = 52 base32 characters. */
export const OPAQUE_RECEIPT_BODY_LENGTH = 52;
export const OPAQUE_RECEIPT_LENGTH = OPAQUE_RECEIPT_PREFIX.length + OPAQUE_RECEIPT_BODY_LENGTH;

/**
 * The single source of truth for the receipt shape. The identical expression is
 * pinned into the migration 096 CHECK constraint and asserted equal by the
 * schema test, so the database and the application cannot drift apart.
 */
export const OPAQUE_RECEIPT_SQL_PATTERN = `^arcpt_[${ALPHABET}]{${OPAQUE_RECEIPT_BODY_LENGTH}}$`;

const OPAQUE_RECEIPT_PATTERN = new RegExp(OPAQUE_RECEIPT_SQL_PATTERN);

/** Mint a fresh receipt id. Never derived from, or seeded with, content. */
export function mintOpaqueReceiptId(): string {
  const raw = randomBytes(OPAQUE_RECEIPT_ENTROPY_BYTES);
  let acc = 0n;
  for (const byte of raw) acc = (acc << 8n) | BigInt(byte);
  // Left-align the 256 bits in 260 bits (52 * 5) so every character is used.
  acc <<= 4n;
  let body = "";
  for (let i = 0; i < OPAQUE_RECEIPT_BODY_LENGTH; i += 1) {
    const shift = BigInt((OPAQUE_RECEIPT_BODY_LENGTH - 1 - i) * 5);
    body += ALPHABET[Number((acc >> shift) & 31n)];
  }
  return OPAQUE_RECEIPT_PREFIX + body;
}

export function isOpaqueReceiptId(value: unknown): value is string {
  return typeof value === "string" && OPAQUE_RECEIPT_PATTERN.test(value);
}

/** A 64-character lowercase hex digest — the shape that must never cross. */
export function looksLikeExactContentHash(value: unknown): boolean {
  return typeof value === "string" && /^[0-9a-f]{64}$/i.test(value);
}

// The STORE that holds those bindings lives in ./contentReceipts.ts, and is the
// only one: this module used to carry a second implementation
// (`InMemoryContentPlaneReceiptStore`) built independently on the other branch.
// Two stores of the same thing is how the two planes ended up disagreeing about
// a receipt in the first place. What stays here is the ENCODING, which both
// planes and migration 096's CHECK constraint must agree on exactly.
