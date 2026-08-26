import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CAPABILITY_MAX_TTL_SECONDS,
  CAPABILITY_PROTOCOL,
  CapabilityError,
  decodeCapability,
  encodeCapability,
  mintCapability,
  signCapability,
  verifyCapability,
  type CapabilityAction,
  type CredentialCapability
} from "../../src/providers/credentials/capability.js";
import { parseCapabilitySigners } from "../../src/credentials/capabilityConfig.js";
import { ConsumedCapabilityLog } from "../../src/credentials/consumedCapabilities.js";

// The provider-credential capability, verified from the CONTENT plane's side.
//
// The implementation under test is a byte-identical copy of the control plane's
// at gcp-us-west-control-implementation@34a6c7a. That is the point: both planes
// must agree on the signed bytes, and running the same code is the only way to
// agree byte for byte rather than agree on a reading of a specification. This
// branch's own `arcap1` format was retired for it; see
// docs/architecture/confidential-backend/CAPABILITY_PROTOCOL_DECISION.md.
//
// These are the content-plane negatives. They overlap the peer's published set
// deliberately: a shared protocol whose two implementations are only tested on
// one side is a protocol with one implementation and one hope.

const DEPLOYMENT_ID = "us-west-1-prod5";
const PROVIDER = "venice";
const CREDENTIAL_ID = "vk-prod5-01";
const KEY_ID = "gcp-cap-2026";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const rawPublic = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
const rawPrivate = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex");
const SIGNERS = parseCapabilitySigners(`${KEY_ID}:${rawPublic}`);

const now = () => Math.floor(Date.now() / 1000);

function capability(overrides: Partial<CredentialCapability> = {}): CredentialCapability {
  return {
    ...mintCapability({
      operatorId: "opa-test-000001",
      provider: PROVIDER,
      credentialId: CREDENTIAL_ID,
      action: "register",
      deploymentId: DEPLOYMENT_ID,
      now: now()
    }),
    ...overrides
  };
}

function verifyContext(overrides: Partial<Parameters<typeof verifyCapability>[0]> = {}) {
  return {
    publicKeys: SIGNERS.publicKeys,
    deploymentId: DEPLOYMENT_ID,
    action: "register" as CapabilityAction,
    provider: PROVIDER,
    credentialId: CREDENTIAL_ID,
    now: now(),
    isConsumed: () => false,
    ...overrides
  };
}

function expectRefusal(
  signed: ReturnType<typeof signCapability>,
  match: RegExp,
  overrides: Partial<Parameters<typeof verifyCapability>[0]> = {}
) {
  expect(() => verifyCapability({ signed, ...verifyContext(overrides) } as never)).toThrow(match);
}

describe("a valid capability", () => {
  it("verifies against the deployment, provider, credential and action it names", () => {
    const value = capability();
    const verified = verifyCapability({ signed: signCapability(value, rawPrivate, KEY_ID), ...verifyContext() } as never);
    expect(verified.capabilityId).toBe(value.capabilityId);
    expect(verified.credentialId).toBe(CREDENTIAL_ID);
    expect(verified.action).toBe("register");
  });

  it("carries no secret and no secret-derived value", () => {
    // Checked structurally rather than by reading the type: the payload's own
    // field set is the whole disclosure.
    const decoded = decodeCapability(encodeCapability(capability()));
    expect(Object.keys(decoded).sort()).toEqual([
      "action", "capabilityId", "credentialId", "deploymentId",
      "expiresAt", "issuedAt", "nonce", "operatorId", "provider"
    ]);
    for (const forbidden of ["secret", "key", "token", "password", "apiKey", "fingerprint"]) {
      expect(Object.keys(decoded)).not.toContain(forbidden);
    }
  });

  it("names the protocol in the signed bytes, so a v2 cannot be replayed as a v1", () => {
    const encoded = encodeCapability(capability());
    expect(encoded.toString("latin1")).toContain(CAPABILITY_PROTOCOL);
  });
});

describe("a capability that is wrong in any way is refused", () => {
  it("refuses a signature from a key that is not pinned", () => {
    const other = generateKeyPairSync("ed25519");
    const otherPrivate = other.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex");
    expectRefusal(signCapability(capability(), otherPrivate, KEY_ID), /invalid capability signature/);
  });

  it("refuses an unknown signer key id", () => {
    expectRefusal(signCapability(capability(), rawPrivate, "some-other-key"), /unknown capability signing key id/);
  });

  it("refuses a modified payload", () => {
    const signed = signCapability(capability(), rawPrivate, KEY_ID);
    const tampered = Buffer.from(signed.capability, "base64url");
    // Flip a byte in the middle of the canonical bytes.
    tampered[Math.floor(tampered.length / 2)] ^= 0xff;
    expectRefusal({ ...signed, capability: tampered.toString("base64url") }, /invalid capability signature/);
  });

  it("refuses a capability for a different deployment", () => {
    const signed = signCapability(capability({ deploymentId: "eu-ams-1" }), rawPrivate, KEY_ID);
    expectRefusal(signed, /different deployment/);
  });

  it("refuses a capability for a different provider", () => {
    // The capability names fireworks; this workload IS venice. The verifying
    // context is local truth and is deliberately not overridden here — a caller
    // who could choose what the capability is compared against could satisfy
    // any comparison.
    const signed = signCapability(capability({ provider: "fireworks" }), rawPrivate, KEY_ID);
    expectRefusal(signed, /different provider/);
  });

  it("refuses a capability for a different credential id", () => {
    const signed = signCapability(capability({ credentialId: "vk-someone-else" }), rawPrivate, KEY_ID);
    expectRefusal(signed, /different credential id/);
  });

  it("refuses a register capability used to revoke", () => {
    // One capability authorizes exactly one action.
    const signed = signCapability(capability({ action: "register" }), rawPrivate, KEY_ID);
    expectRefusal(signed, /does not authorize this action/, { action: "revoke" as CapabilityAction });
  });

  it("refuses an expired capability", () => {
    const issued = now() - 900;
    const signed = signCapability(capability({ issuedAt: issued, expiresAt: issued + 300 }), rawPrivate, KEY_ID);
    expectRefusal(signed, /expired/);
  });

  it("refuses a capability from the future", () => {
    const issued = now() + 600;
    const signed = signCapability(capability({ issuedAt: issued, expiresAt: issued + 300 }), rawPrivate, KEY_ID);
    expectRefusal(signed, /not yet valid/);
  });

  it("refuses one minted with too long a lifetime, at encode time", () => {
    // The ceiling is enforced where the bytes are produced, so an over-long
    // capability cannot be signed at all rather than being caught later.
    const issued = now();
    expect(() =>
      encodeCapability(capability({ issuedAt: issued, expiresAt: issued + CAPABILITY_MAX_TTL_SECONDS + 1 }))
    ).toThrow(/lifetime exceeds/);
  });

  it("refuses a replayed capability", () => {
    const signed = signCapability(capability(), rawPrivate, KEY_ID);
    expectRefusal(signed, /already been used/, { isConsumed: () => true });
  });

  it("refuses non-canonical CBOR and an unknown field", () => {
    // The decoder re-encodes and compares, so a differently-ordered or
    // longer-than-necessary encoding is rejected rather than silently accepted,
    // and an added field is a rejection rather than an extension.
    expect(() => decodeCapability(Buffer.from("a1616101", "hex"))).toThrow(CapabilityError);
    expect(() => decodeCapability(Buffer.from([0xff]))).toThrow(CapabilityError);
  });

  it("refuses a malformed envelope", () => {
    for (const bad of ["", "not-base64url-!!!", "AAAA"]) {
      expect(() =>
        verifyCapability({ signed: { capability: bad, signature: "AAAA", keyId: KEY_ID }, ...verifyContext() } as never)
      ).toThrow();
    }
  });

  it("refuses a signature of the wrong length before verifying it", () => {
    const signed = signCapability(capability(), rawPrivate, KEY_ID);
    expectRefusal({ ...signed, signature: Buffer.alloc(32).toString("base64url") }, /malformed capability signature/);
  });
});

describe("one-time use survives a restart", () => {
  let directory = "";
  let path = "";

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "anonrouter-cap-"));
    path = join(directory, "consumed.json");
  });
  afterEach(() => rmSync(directory, { recursive: true, force: true }));

  it("accepts a capability once and refuses the replay", () => {
    const log = new ConsumedCapabilityLog(path);
    const id = "cap-abc123def456";
    const expiry = now() + 300;
    expect(log.consume(id, expiry).firstUse).toBe(true);
    expect(log.consume(id, expiry).firstUse).toBe(false);
  });

  it("still refuses the replay through a FRESH instance, as a restarted container would be", () => {
    // The point of persisting at all. An in-memory nonce set would forget this,
    // and restarting a container is not a hard thing to arrange.
    const id = "cap-restart-000001";
    const expiry = now() + 300;
    expect(new ConsumedCapabilityLog(path).consume(id, expiry).firstUse).toBe(true);
    expect(new ConsumedCapabilityLog(path).consume(id, expiry).firstUse).toBe(false);
  });

  it("stores capability ids and timestamps, and nothing else", () => {
    new ConsumedCapabilityLog(path).consume("cap-inspect-000001", now() + 300);
    const stored = JSON.parse(readFileSync(path, "utf8"));
    expect(stored).toHaveLength(1);
    expect(Object.keys(stored[0]).sort()).toEqual(["capabilityId", "consumedAtMs", "expiresAtMs"]);
  });

  it("refuses to operate on an unreadable log rather than treating it as empty", () => {
    // Fail closed. An empty list is indistinguishable from "nothing was ever
    // consumed", which is exactly the answer a replay wants.
    writeFileSync(path, "{ this is not json");
    expect(() => new ConsumedCapabilityLog(path).consume("cap-corrupt-000001", 1)).toThrow(/unreadable/);
  });

  it("accepts the id format the peer mints", () => {
    // mintCapability produces `cap-` plus 24 hex characters. A log that refused
    // it would fail closed in the most confusing possible way: only in
    // production, only on a real capability.
    const minted = mintCapability({
      operatorId: "opa-1", provider: PROVIDER, credentialId: CREDENTIAL_ID,
      action: "register", deploymentId: DEPLOYMENT_ID, now: now()
    });
    expect(new ConsumedCapabilityLog(path).consume(minted.capabilityId, minted.expiresAt).firstUse).toBe(true);
    expect(new ConsumedCapabilityLog(path).wasConsumed(minted.capabilityId)).toBe(true);
  });
});

describe("the pinned signer set", () => {
  it("parses a hex key", () => {
    expect(SIGNERS.publicKeys[KEY_ID]).toBe(rawPublic);
  });

  it("also parses a base64 key, so a copy from the wrong field is not a signature failure", () => {
    const base64 = Buffer.from(rawPublic, "hex").toString("base64");
    expect(parseCapabilitySigners(`${KEY_ID}:${base64}`).publicKeys[KEY_ID]).toBe(rawPublic);
  });

  it("refuses a malformed, duplicated or wrong-length entry", () => {
    expect(() => parseCapabilitySigners("no-separator")).toThrow();
    expect(() => parseCapabilitySigners(`${KEY_ID}:${Buffer.alloc(16).toString("base64")}`)).toThrow(/32-byte/);
    expect(() => parseCapabilitySigners(`${KEY_ID}:${rawPublic},${KEY_ID}:${rawPublic}`)).toThrow(/twice/);
  });

  it("is empty for an empty setting, so capability mode cannot boot unpinned", () => {
    expect(Object.keys(parseCapabilitySigners("").publicKeys)).toHaveLength(0);
  });
});
