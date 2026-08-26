// The canonical binding object for AnonRouter GATEWAY attestation.
//
// This is deliberately separate from the provider attestation subsystem in
// src/providers/attestation/*. Those verifiers answer "did the UPSTREAM model
// provider run my request in an enclave?". This module answers a different
// question: "is the AnonRouter data plane I am talking to right now the exact
// reviewed build running inside an Intel TDX confidential VM, and is the key
// protecting this connection the one that TD holds?".
//
// The binding is the single object whose SHA-512 digest is placed in the TDX
// quote's 64-byte report_data field. Because the TD cannot forge report_data,
// a caller that recomputes this digest from the returned fields and finds it
// equal to the quote's report_data has proven that the attesting TD asserted
// every field at quote time: the caller's fresh nonce, the app/instance
// identity, the compose measurement, the release identity, the public origin,
// and the application public key.
//
// Invariants:
//   - PURE. No I/O, no clock, no dstack dependency. Both the in-TEE producer
//     and the out-of-TEE verifier import this exact file, so the two can never
//     drift into computing different digests.
//   - Deterministic serialization. Keys are emitted in a FIXED order defined
//     here, not in object-literal or insertion order, so a re-serialization in
//     another language or runtime produces byte-identical output.
//   - Fail closed. Every field is validated on both sides; a malformed field
//     throws rather than producing a digest over partially-checked input.

import { createHash } from "node:crypto";

/** Binding format version. Bump on ANY change to fields or serialization. */
export const GATEWAY_BINDING_VERSION = 1 as const;

/** Report data is exactly 64 bytes in an Intel TDX quote; SHA-512 fills it. */
export const GATEWAY_BINDING_DIGEST_ALGORITHM = "sha512" as const;
export const GATEWAY_BINDING_DIGEST_HEX_LENGTH = 128;

/** Caller nonce: exactly 32 bytes, lowercase hex. */
export const GATEWAY_NONCE_BYTES = 32;
export const GATEWAY_NONCE_HEX_LENGTH = GATEWAY_NONCE_BYTES * 2;

export type GatewayKeyAlgorithm = "x25519" | "ed25519" | "secp256k1";

const KEY_ALGORITHMS: readonly GatewayKeyAlgorithm[] = ["x25519", "ed25519", "secp256k1"];

/**
 * Where the TLS session the client is using actually terminates.
 *
 *   in-tee-tls   The private key for the served certificate was generated
 *                inside this TD and never left it. `tls_spki_sha256` names that
 *                certificate, so a client can pin its own connection to the
 *                attested TD end to end.
 *   gateway-tls  TLS terminates in front of the TD (a platform reverse proxy).
 *                The TD still attests its own code and its application key, but
 *                the transport itself is NOT proof of who you are talking to.
 *                Clients that require transport binding must fail closed here
 *                and use the application key for an inner encrypted channel.
 *
 * This field is REQUIRED and has no default. Making the weaker mode explicit is
 * the point: a client can never mistake a proxied connection for a direct one.
 */
export type GatewayTransportBinding = "in-tee-tls" | "gateway-tls";

const TRANSPORT_BINDINGS: readonly GatewayTransportBinding[] = ["in-tee-tls", "gateway-tls"];

/**
 * The exact object hashed into report_data. Field names are part of the wire
 * contract and are snake_case to match the rest of the public API surface.
 */
export interface GatewayAttestationBinding {
  /** Binding format version (GATEWAY_BINDING_VERSION). */
  v: number;
  /** Fresh caller-supplied challenge, 64 lowercase hex characters. */
  nonce: string;
  /** dstack application identity (stable across instances of one app). */
  app_id: string;
  /** dstack instance identity (this specific CVM). */
  instance_id: string;
  /** SHA-256 of the deterministic app-compose manifest, 64 lowercase hex. */
  compose_hash: string;
  /**
   * AnonRouter release identity for this build. Opaque to the TD but pinned by
   * the verifier, so a client can require an exact reviewed release rather than
   * "any build that happens to attest".
   */
  release_id: string;
  /** The public origin a client must have connected to, e.g. https://tee.anonrouter.ai */
  origin: string;
  /** Algorithm of the application key below. */
  key_alg: GatewayKeyAlgorithm;
  /** Application transport/encryption public key, lowercase hex. */
  public_key: string;
  /** Where the client's TLS session terminates. See GatewayTransportBinding. */
  transport: GatewayTransportBinding;
  /**
   * SHA-256 of the DER SubjectPublicKeyInfo of the certificate this TD serves,
   * lowercase hex — or null when `transport` is "gateway-tls" and the TD does
   * not own the served certificate. Never omitted; null is an assertion, not an
   * absence.
   */
  tls_spki_sha256: string | null;
}

/**
 * Fixed serialization order. This array — not the object literal, not
 * Object.keys, not a sort — defines the canonical form. Adding a field means
 * bumping GATEWAY_BINDING_VERSION and appending here.
 */
const CANONICAL_FIELD_ORDER = [
  "v",
  "nonce",
  "app_id",
  "instance_id",
  "compose_hash",
  "release_id",
  "origin",
  "key_alg",
  "public_key",
  "transport",
  "tls_spki_sha256"
] as const satisfies readonly (keyof GatewayAttestationBinding)[];

export class GatewayBindingError extends Error {
  readonly field: string;

  constructor(field: string, message: string) {
    super(message);
    this.name = "GatewayBindingError";
    this.field = field;
  }
}

function requireLowercaseHex(field: string, value: unknown, exactChars?: number): string {
  if (typeof value !== "string") throw new GatewayBindingError(field, `${field} must be a string`);
  if (!/^[0-9a-f]+$/.test(value)) {
    throw new GatewayBindingError(field, `${field} must be lowercase hex`);
  }
  if (exactChars !== undefined && value.length !== exactChars) {
    throw new GatewayBindingError(field, `${field} must be exactly ${exactChars} hex characters`);
  }
  if (exactChars === undefined && (value.length === 0 || value.length > 512)) {
    throw new GatewayBindingError(field, `${field} must be 1..512 hex characters`);
  }
  return value;
}

/**
 * Origins are compared byte-for-byte by the verifier, so accept only the
 * canonical scheme://host[:port] form with no trailing slash, path, query,
 * credentials, or fragment. This prevents an "equivalent" origin from silently
 * passing an equality check that a different client would fail.
 */
export function canonicalGatewayOrigin(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 253 + 16) {
    throw new GatewayBindingError("origin", "origin must be a non-empty string");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new GatewayBindingError("origin", "origin must be an absolute URL");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new GatewayBindingError("origin", "origin must be http(s)");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/") {
    throw new GatewayBindingError("origin", "origin must contain only scheme, host, and optional port");
  }
  if (parsed.origin !== value.replace(/\/$/, "")) {
    throw new GatewayBindingError("origin", "origin must already be in canonical scheme://host[:port] form");
  }
  return parsed.origin;
}

/** Validate a caller nonce. Rejects anything that is not exactly 32 bytes hex. */
export function assertGatewayNonce(nonce: unknown): string {
  if (typeof nonce !== "string") throw new GatewayBindingError("nonce", "nonce must be a string");
  const lower = nonce.toLowerCase();
  return requireLowercaseHex("nonce", lower, GATEWAY_NONCE_HEX_LENGTH);
}

/**
 * Validate and normalize an untrusted binding into the canonical shape. Used by
 * the producer (before hashing) and by the verifier (before recomputing), so a
 * field the verifier cannot validate can never contribute to a digest it
 * accepts.
 */
export function normalizeGatewayBinding(input: unknown): GatewayAttestationBinding {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new GatewayBindingError("binding", "binding must be a JSON object");
  }
  const raw = input as Record<string, unknown>;

  // Reject unknown fields: a verifier that silently ignores an extra field would
  // accept a digest computed over data it never inspected.
  for (const key of Object.keys(raw)) {
    if (!(CANONICAL_FIELD_ORDER as readonly string[]).includes(key)) {
      throw new GatewayBindingError(key, `binding carries unknown field ${key}`);
    }
  }

  if (raw.v !== GATEWAY_BINDING_VERSION) {
    throw new GatewayBindingError("v", `binding version must be ${GATEWAY_BINDING_VERSION}`);
  }
  if (typeof raw.key_alg !== "string" || !KEY_ALGORITHMS.includes(raw.key_alg as GatewayKeyAlgorithm)) {
    throw new GatewayBindingError("key_alg", `key_alg must be one of ${KEY_ALGORITHMS.join(", ")}`);
  }
  if (typeof raw.release_id !== "string" || !/^[A-Za-z0-9._:@+-]{1,128}$/.test(raw.release_id)) {
    throw new GatewayBindingError("release_id", "release_id must be 1..128 chars of [A-Za-z0-9._:@+-]");
  }
  if (typeof raw.transport !== "string" || !TRANSPORT_BINDINGS.includes(raw.transport as GatewayTransportBinding)) {
    throw new GatewayBindingError("transport", `transport must be one of ${TRANSPORT_BINDINGS.join(", ")}`);
  }
  // `undefined` would serialize away entirely; require an explicit null so the
  // absence of a TD-owned certificate is a signed assertion, not an omission.
  if (!("tls_spki_sha256" in raw)) {
    throw new GatewayBindingError("tls_spki_sha256", "tls_spki_sha256 must be present (hex or null)");
  }
  const tlsSpki = raw.tls_spki_sha256 === null
    ? null
    : requireLowercaseHex(
      "tls_spki_sha256",
      typeof raw.tls_spki_sha256 === "string" ? raw.tls_spki_sha256.toLowerCase() : raw.tls_spki_sha256,
      64
    );
  // A TD that claims to own the transport must name the certificate it owns.
  if (raw.transport === "in-tee-tls" && tlsSpki === null) {
    throw new GatewayBindingError("tls_spki_sha256", "in-tee-tls requires a certificate SPKI digest");
  }
  if (raw.transport === "gateway-tls" && tlsSpki !== null) {
    throw new GatewayBindingError("tls_spki_sha256", "gateway-tls must not claim a TD-owned certificate");
  }

  return {
    v: GATEWAY_BINDING_VERSION,
    nonce: assertGatewayNonce(raw.nonce),
    app_id: requireLowercaseHex("app_id", typeof raw.app_id === "string" ? raw.app_id.toLowerCase().replace(/^0x/, "") : raw.app_id),
    instance_id: requireLowercaseHex(
      "instance_id",
      typeof raw.instance_id === "string" ? raw.instance_id.toLowerCase().replace(/^0x/, "") : raw.instance_id
    ),
    compose_hash: requireLowercaseHex(
      "compose_hash",
      typeof raw.compose_hash === "string" ? raw.compose_hash.toLowerCase().replace(/^0x/, "") : raw.compose_hash,
      64
    ),
    release_id: raw.release_id,
    origin: canonicalGatewayOrigin(raw.origin),
    key_alg: raw.key_alg as GatewayKeyAlgorithm,
    public_key: requireLowercaseHex(
      "public_key",
      typeof raw.public_key === "string" ? raw.public_key.toLowerCase().replace(/^0x/, "") : raw.public_key
    ),
    transport: raw.transport as GatewayTransportBinding,
    tls_spki_sha256: tlsSpki
  };
}

/**
 * The canonical byte string hashed into report_data. Emitted with an explicit
 * field order and JSON.stringify's standard string escaping, so any language
 * that can produce the same ordered JSON reproduces the same bytes.
 */
export function canonicalGatewayBindingJson(binding: GatewayAttestationBinding): string {
  const normalized = normalizeGatewayBinding(binding);
  const parts = CANONICAL_FIELD_ORDER.map(
    (field) => `${JSON.stringify(field)}:${JSON.stringify(normalized[field])}`
  );
  return `{${parts.join(",")}}`;
}

/** The 64-byte digest placed in the TDX quote's report_data field. */
export function gatewayBindingDigest(binding: GatewayAttestationBinding): Buffer {
  return createHash(GATEWAY_BINDING_DIGEST_ALGORITHM)
    .update(canonicalGatewayBindingJson(binding), "utf8")
    .digest();
}

/** Lowercase hex form of gatewayBindingDigest (128 characters). */
export function gatewayBindingHash(binding: GatewayAttestationBinding): string {
  return gatewayBindingDigest(binding).toString("hex");
}
