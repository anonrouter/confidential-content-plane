/**
 * Provider-credential administration capabilities.
 *
 * The problem (O15/D31)
 * ---------------------
 * Today `POST /v1/admin/venice-keys` takes the raw provider secret in its body,
 * on the control plane, and forwards it to the credential worker. Once control
 * runs in GCP that means every provider credential the operator ever registers
 * transits GCP memory, its request path and anything that observes either. The
 * launch boundary says provider credentials terminate in the attested Phala
 * workload and never traverse GCP.
 *
 * The replacement
 * ---------------
 * GCP issues a CAPABILITY: a short-lived, single-use, signed, content-free
 * authorization to perform one credential operation against one exact Phala
 * deployment. The operator's client verifies fresh Phala evidence and that its
 * TLS terminates inside that attested workload, and only then sends the raw
 * secret directly to Phala together with the capability. Phala validates the
 * capability, stores the secret in its measured secret mechanism, and reports
 * back only opaque metadata.
 *
 * What a capability may contain is therefore the whole design. It carries the
 * capability id and version, who authorized it, the provider, the OPAQUE
 * credential id, the action, the exact target deployment, its validity window
 * and a replay nonce. It carries no secret and nothing derived from one: the
 * fingerprint is computed by Phala AFTER the secret arrives there and comes back
 * as metadata, never the other way round.
 */

import { createHash, randomBytes, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey, timingSafeEqual } from "node:crypto";
import { encodeCbor, decodeCanonicalCbor, CborError, type CborValue } from "../../gcp/control/cbor.js";

export const CAPABILITY_PROTOCOL = "anonrouter-provider-credential-capability-v1";
/**
 * Deliberately short. A capability is used within one operator interaction; a
 * long window is only useful to someone who stole it.
 */
export const CAPABILITY_DEFAULT_TTL_SECONDS = 300;
export const CAPABILITY_MAX_TTL_SECONDS = 900;

export type CapabilityAction = "register" | "rotate" | "revoke";
export const CAPABILITY_ACTIONS: readonly CapabilityAction[] = ["register", "rotate", "revoke"];

const FIELDS = [
  "protocol",
  "capabilityId",
  "operatorId",
  "provider",
  "credentialId",
  "action",
  "deploymentId",
  "issuedAt",
  "expiresAt",
  "nonce"
] as const;

const ID_PATTERN = /^[a-z0-9][a-z0-9._-]{2,63}$/;
const CREDENTIAL_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export class CapabilityError extends Error {}

export interface CredentialCapability {
  capabilityId: string;
  /** Which operator authorized this. An identifier, never a session token. */
  operatorId: string;
  provider: string;
  /** Opaque credential identifier. Never derived from the secret. */
  credentialId: string;
  action: CapabilityAction;
  /** The exact Phala deployment this capability is valid against. */
  deploymentId: string;
  /** Unix seconds. */
  issuedAt: number;
  expiresAt: number;
  /** 16 random bytes; the replay identifier Phala echoes back. */
  nonce: Buffer;
}

function requireId(name: string, value: string, pattern = ID_PATTERN): string {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new CapabilityError(`${name} must match ${pattern}`);
  }
  return value;
}

/** Canonical bytes. What is signed, and what Phala re-encodes to verify. */
export function encodeCapability(capability: CredentialCapability): Buffer {
  if (!CAPABILITY_ACTIONS.includes(capability.action)) {
    throw new CapabilityError(`unknown action: ${capability.action}`);
  }
  if (!Buffer.isBuffer(capability.nonce) || capability.nonce.length !== 16) {
    throw new CapabilityError("nonce must be 16 bytes");
  }
  if (capability.expiresAt <= capability.issuedAt) {
    throw new CapabilityError("expiresAt must be after issuedAt");
  }
  if (capability.expiresAt - capability.issuedAt > CAPABILITY_MAX_TTL_SECONDS) {
    throw new CapabilityError(`capability lifetime exceeds ${CAPABILITY_MAX_TTL_SECONDS}s`);
  }
  const map = new Map<string, CborValue>([
    ["protocol", CAPABILITY_PROTOCOL],
    ["capabilityId", requireId("capabilityId", capability.capabilityId)],
    ["operatorId", requireId("operatorId", capability.operatorId)],
    ["provider", requireId("provider", capability.provider)],
    ["credentialId", requireId("credentialId", capability.credentialId, CREDENTIAL_ID_PATTERN)],
    ["action", capability.action],
    ["deploymentId", requireId("deploymentId", capability.deploymentId, CREDENTIAL_ID_PATTERN)],
    ["issuedAt", capability.issuedAt],
    ["expiresAt", capability.expiresAt],
    ["nonce", new Uint8Array(capability.nonce)]
  ]);
  return Buffer.from(encodeCbor(map));
}

/** Parse canonical bytes. Unknown fields are a rejection, not an extension. */
export function decodeCapability(encoded: Buffer): CredentialCapability {
  let decoded: CborValue;
  try {
    decoded = decodeCanonicalCbor(new Uint8Array(encoded));
  } catch (error) {
    throw new CapabilityError(
      error instanceof CborError ? `capability is not canonical CBOR: ${error.message}` : "capability is not canonical CBOR"
    );
  }
  if (!(decoded instanceof Map)) throw new CapabilityError("capability must be a CBOR map");
  const unknown = [...decoded.keys()].filter((key) => !(FIELDS as readonly string[]).includes(key));
  if (unknown.length > 0) throw new CapabilityError(`unknown capability field: ${unknown.sort().join(", ")}`);
  for (const field of FIELDS) {
    if (!decoded.has(field)) throw new CapabilityError(`missing capability field: ${field}`);
  }
  if (decoded.get("protocol") !== CAPABILITY_PROTOCOL) throw new CapabilityError("unexpected capability protocol");

  const text = (key: string): string => {
    const value = decoded.get(key);
    if (typeof value !== "string") throw new CapabilityError(`${key} must be a string`);
    return value;
  };
  const uint = (key: string): number => {
    const value = decoded.get(key);
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
      throw new CapabilityError(`${key} must be a non-negative integer`);
    }
    return value;
  };
  const action = text("action");
  if (!CAPABILITY_ACTIONS.includes(action as CapabilityAction)) throw new CapabilityError(`unknown action: ${action}`);
  const nonce = decoded.get("nonce");
  if (!(nonce instanceof Uint8Array) || nonce.length !== 16) throw new CapabilityError("nonce must be 16 bytes");

  return {
    capabilityId: requireId("capabilityId", text("capabilityId")),
    operatorId: requireId("operatorId", text("operatorId")),
    provider: requireId("provider", text("provider")),
    credentialId: requireId("credentialId", text("credentialId"), CREDENTIAL_ID_PATTERN),
    action: action as CapabilityAction,
    deploymentId: requireId("deploymentId", text("deploymentId"), CREDENTIAL_ID_PATTERN),
    issuedAt: uint("issuedAt"),
    expiresAt: uint("expiresAt"),
    nonce: Buffer.from(nonce)
  };
}

function ed25519Private(rawHex: string) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(rawHex, "hex")]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function ed25519Public(rawHex: string) {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(rawHex, "hex")]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

export interface SignedCapability {
  /** Base64url canonical bytes, for transport in a header or JSON field. */
  capability: string;
  /** Base64url detached Ed25519 signature. */
  signature: string;
  /** Which signing key produced it, so rotation is possible. */
  keyId: string;
}

/**
 * Sign a capability.
 *
 * The signing key belongs to the admitted guest: it is generated inside the TDX
 * guest after admission and persisted under the application envelope hierarchy,
 * not shipped in the bootstrap bundle. Losing it invalidates outstanding
 * capabilities, which is the correct blast radius for a five-minute credential.
 */
export function signCapability(capability: CredentialCapability, privateKeyHex: string, keyId: string): SignedCapability {
  const encoded = encodeCapability(capability);
  return {
    capability: encoded.toString("base64url"),
    signature: edSign(null, encoded, ed25519Private(privateKeyHex)).toString("base64url"),
    keyId
  };
}

export interface CapabilityVerificationInput {
  signed: SignedCapability;
  /** Public keys by key id, as the content plane holds them. */
  publicKeys: Record<string, string>;
  /** The deployment doing the verifying. A capability for another one fails. */
  deploymentId: string;
  /** The action being attempted. A register capability cannot revoke. */
  action: CapabilityAction;
  provider: string;
  credentialId: string;
  /** Unix seconds. */
  now: number;
  /** Returns true when this capability id has already been used. */
  isConsumed: (capabilityId: string) => boolean;
}

/**
 * Content-plane verification. Exported from the control-plane repository on
 * purpose: both sides must agree byte for byte, and the fixtures in
 * `tests/fixtures/control-boundary/` are generated from this code.
 */
export function verifyCapability(input: CapabilityVerificationInput): CredentialCapability {
  const encoded = Buffer.from(input.signed.capability, "base64url");
  const publicKeyHex = input.publicKeys[input.signed.keyId];
  if (!publicKeyHex) throw new CapabilityError(`unknown capability signing key id: ${input.signed.keyId}`);

  const signature = Buffer.from(input.signed.signature, "base64url");
  if (signature.length !== 64) throw new CapabilityError("malformed capability signature");
  if (!edVerify(null, encoded, ed25519Public(publicKeyHex), signature)) {
    throw new CapabilityError("invalid capability signature");
  }

  const capability = decodeCapability(encoded);
  if (capability.deploymentId !== input.deploymentId) {
    throw new CapabilityError("capability is bound to a different deployment");
  }
  if (capability.action !== input.action) throw new CapabilityError("capability does not authorize this action");
  if (capability.provider !== input.provider) throw new CapabilityError("capability is bound to a different provider");
  if (capability.credentialId !== input.credentialId) {
    throw new CapabilityError("capability is bound to a different credential id");
  }
  if (input.now < capability.issuedAt) throw new CapabilityError("capability is not yet valid");
  if (input.now >= capability.expiresAt) throw new CapabilityError("capability has expired");
  if (input.isConsumed(capability.capabilityId)) throw new CapabilityError("capability has already been used");
  return capability;
}

/** Mint a fresh capability. `nonce` and `capabilityId` are always random. */
export function mintCapability(params: {
  operatorId: string;
  provider: string;
  credentialId: string;
  action: CapabilityAction;
  deploymentId: string;
  now: number;
  ttlSeconds?: number;
}): CredentialCapability {
  const ttl = Math.min(params.ttlSeconds ?? CAPABILITY_DEFAULT_TTL_SECONDS, CAPABILITY_MAX_TTL_SECONDS);
  return {
    capabilityId: `cap-${randomBytes(12).toString("hex")}`,
    operatorId: params.operatorId,
    provider: params.provider,
    credentialId: params.credentialId,
    action: params.action,
    deploymentId: params.deploymentId,
    issuedAt: params.now,
    expiresAt: params.now + ttl,
    nonce: randomBytes(16)
  };
}

/**
 * Guard for the one thing that must never happen: a provider secret arriving at
 * the control plane.
 *
 * Applied to every field of a credential-administration request body. It is
 * deliberately shape-based rather than a list of known key formats, because the
 * next provider's key format is not knowable in advance and "we did not have a
 * pattern for it" is not an acceptable reason for a secret to be persisted.
 */
export function assertNoProviderSecretShape(value: unknown, where: string): void {
  const inspect = (node: unknown, path: string): void => {
    if (typeof node === "string") {
      // A short opaque id or a truncated fingerprint is fine. A long
      // high-entropy string in a credential-administration body is not.
      if (node.length >= 20 && /^[A-Za-z0-9_\-+/=.]+$/.test(node) && !/^[0-9a-f]{8,64}$/.test(node)) {
        throw new CapabilityError(
          `${where}: ${path} looks like a provider secret. Raw provider credentials go directly to the `
            + "attested content plane and never through the control plane (D31)."
        );
      }
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, index) => inspect(item, `${path}[${index}]`));
      return;
    }
    if (node && typeof node === "object") {
      for (const [key, item] of Object.entries(node)) {
        if (/secret|apikey|api_key|token|password|credential$/i.test(key)) {
          throw new CapabilityError(
            `${where}: field "${key}" may not exist on this boundary. Raw provider credentials go directly `
              + "to the attested content plane (D31)."
          );
        }
        inspect(item, path ? `${path}.${key}` : key);
      }
    }
  };
  inspect(value, "");
}

/** Stable, content-free digest of a capability, for the audit record. */
export function capabilityDigest(signed: SignedCapability): string {
  return createHash("sha256").update(Buffer.from(signed.capability, "base64url")).digest("hex");
}

/** Constant-time comparison for the replay nonce Phala echoes back. */
export function nonceMatches(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}
