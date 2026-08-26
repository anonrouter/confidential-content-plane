import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  assertGatewayNonce,
  canonicalGatewayBindingJson,
  canonicalGatewayOrigin,
  gatewayBindingHash,
  GatewayBindingError,
  GATEWAY_BINDING_DIGEST_HEX_LENGTH,
  GATEWAY_BINDING_VERSION,
  normalizeGatewayBinding,
  type GatewayAttestationBinding
} from "../../src/gateway/binding.js";

// The binding is the ONLY thing a TDX quote's report_data commits to, so its
// serialization is a security contract, not an implementation detail. These
// tests pin the exact bytes and prove every field participates in the digest.

const NONCE = "a".repeat(64);

function binding(overrides: Partial<GatewayAttestationBinding> = {}): GatewayAttestationBinding {
  return {
    v: GATEWAY_BINDING_VERSION,
    nonce: NONCE,
    app_id: "1f2e3d4c5b6a7988",
    instance_id: "00112233445566778899aabbccddeeff",
    compose_hash: "b".repeat(64),
    release_id: "anonrouter-tee@c7b32e0",
    origin: "https://tee.anonrouter.ai",
    key_alg: "x25519",
    public_key: "c".repeat(64),
    transport: "gateway-tls",
    tls_spki_sha256: null,
    ...overrides
  };
}

describe("gateway attestation binding", () => {
  it("serializes fields in the fixed canonical order regardless of insertion order", () => {
    const forward = binding();
    // Rebuild with keys inserted in reverse to prove ordering is not incidental.
    const reversed = Object.fromEntries(
      Object.entries(forward).reverse()
    ) as unknown as GatewayAttestationBinding;

    expect(canonicalGatewayBindingJson(reversed)).toBe(canonicalGatewayBindingJson(forward));
    expect(canonicalGatewayBindingJson(forward)).toBe(
      `{"v":1,"nonce":"${NONCE}","app_id":"1f2e3d4c5b6a7988",`
      + `"instance_id":"00112233445566778899aabbccddeeff","compose_hash":"${"b".repeat(64)}",`
      + `"release_id":"anonrouter-tee@c7b32e0","origin":"https://tee.anonrouter.ai",`
      + `"key_alg":"x25519","public_key":"${"c".repeat(64)}",`
      + `"transport":"gateway-tls","tls_spki_sha256":null}`
    );
  });

  it("produces a 64-byte digest that equals sha512 of the canonical JSON", () => {
    const value = binding();
    const expected = createHash("sha512").update(canonicalGatewayBindingJson(value), "utf8").digest("hex");
    expect(gatewayBindingHash(value)).toBe(expected);
    expect(gatewayBindingHash(value)).toHaveLength(GATEWAY_BINDING_DIGEST_HEX_LENGTH);
  });

  it("changes the digest when ANY field changes", () => {
    const base = gatewayBindingHash(binding());
    const mutations: Array<Partial<GatewayAttestationBinding>> = [
      { nonce: "b".repeat(64) },
      { app_id: "1f2e3d4c5b6a7989" },
      { instance_id: "00112233445566778899aabbccddee00" },
      { compose_hash: "c".repeat(64) },
      { release_id: "anonrouter-tee@deadbee" },
      { origin: "https://tee-2.anonrouter.ai" },
      { key_alg: "ed25519" },
      { public_key: "d".repeat(64) },
      { transport: "in-tee-tls", tls_spki_sha256: "e".repeat(64) }
    ];
    for (const mutation of mutations) {
      expect(gatewayBindingHash(binding(mutation)), JSON.stringify(mutation)).not.toBe(base);
    }
  });

  it("rejects unknown fields rather than hashing over uninspected data", () => {
    const withExtra = { ...binding(), evil: "payload" };
    expect(() => normalizeGatewayBinding(withExtra)).toThrow(GatewayBindingError);
    expect(() => normalizeGatewayBinding(withExtra)).toThrow(/unknown field evil/);
  });

  it("requires an exactly 32-byte lowercase hex nonce", () => {
    expect(assertGatewayNonce(NONCE)).toBe(NONCE);
    expect(assertGatewayNonce("A".repeat(64))).toBe("a".repeat(64));
    expect(() => assertGatewayNonce("a".repeat(63))).toThrow(/exactly 64 hex/);
    expect(() => assertGatewayNonce("a".repeat(66))).toThrow(/exactly 64 hex/);
    expect(() => assertGatewayNonce("z".repeat(64))).toThrow(/lowercase hex/);
    expect(() => assertGatewayNonce(randomBytes(32))).toThrow(/must be a string/);
  });

  it("accepts only canonical origins", () => {
    expect(canonicalGatewayOrigin("https://tee.anonrouter.ai")).toBe("https://tee.anonrouter.ai");
    expect(canonicalGatewayOrigin("http://127.0.0.1:3000")).toBe("http://127.0.0.1:3000");
    // A bare trailing slash is the same URL; it normalizes away, and the
    // NORMALIZED form is what gets hashed, so there is no ambiguity to exploit.
    expect(canonicalGatewayOrigin("https://tee.anonrouter.ai/")).toBe("https://tee.anonrouter.ai");
    for (const bad of [
      "https://tee.anonrouter.ai/v1",
      "https://tee.anonrouter.ai?x=1",
      "https://tee.anonrouter.ai#f",
      "https://u:p@tee.anonrouter.ai",
      "ftp://tee.anonrouter.ai",
      "tee.anonrouter.ai"
    ]) {
      expect(() => canonicalGatewayOrigin(bad), bad).toThrow(GatewayBindingError);
    }
  });

  it("forces an honest, explicit transport claim", () => {
    // in-tee-tls must name the certificate it owns.
    expect(() => normalizeGatewayBinding(binding({ transport: "in-tee-tls", tls_spki_sha256: null })))
      .toThrow(/in-tee-tls requires a certificate SPKI digest/);
    // gateway-tls must not pretend to own one.
    expect(() => normalizeGatewayBinding(binding({ transport: "gateway-tls", tls_spki_sha256: "e".repeat(64) })))
      .toThrow(/must not claim a TD-owned certificate/);
    // The field can never be simply omitted.
    const { tls_spki_sha256: _omitted, ...withoutTls } = binding();
    expect(() => normalizeGatewayBinding(withoutTls)).toThrow(/must be present/);
    // The valid in-TEE form round-trips.
    const inTee = normalizeGatewayBinding(binding({ transport: "in-tee-tls", tls_spki_sha256: "e".repeat(64) }));
    expect(inTee.transport).toBe("in-tee-tls");
    expect(inTee.tls_spki_sha256).toBe("e".repeat(64));
  });

  it("rejects a binding whose version does not match this build", () => {
    expect(() => normalizeGatewayBinding({ ...binding(), v: 2 })).toThrow(/binding version must be 1/);
  });

  it("normalizes 0x prefixes and uppercase identity hex before hashing", () => {
    const canonical = gatewayBindingHash(binding());
    const messy = gatewayBindingHash({
      ...binding(),
      app_id: "0x1F2E3D4C5B6A7988",
      instance_id: "0x00112233445566778899AABBCCDDEEFF",
      compose_hash: `0x${"B".repeat(64)}`,
      public_key: `0x${"C".repeat(64)}`
    } as GatewayAttestationBinding);
    expect(messy).toBe(canonical);
  });
});
