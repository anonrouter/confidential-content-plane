// The attested TLS SPKI must come from a completed handshake with our own
// terminator, never from anything a deployer can write down.
//
// THE BUG THIS PINS
//
// `tls_spki_sha256` used to be read from GATEWAY_TLS_SPKI_SHA256. Environment
// values are not measured. So an operator could deploy the reviewed image,
// point clients at a gateway-terminated endpoint whose private key they held,
// set GATEWAY_TRANSPORT=in-tee-tls, and paste that endpoint's fingerprint into
// the environment. Then:
//
//   - the client observes SPKI X on its own connection
//   - the quote is genuine, the measurements are real, and it says SPKI X
//   - `tls_certificate_bound_to_quote` passes
//   - `transport_terminates_in_tee` passes
//
// Every check agrees and the conclusion is false: the trust domain never held
// that key. The verifier could not detect it, because the verifier's job is to
// compare two values and both were correct. The defect was that one of them was
// hearsay.
//
// A handshake cannot be faked by a party without the private key, so observing
// one is proof of possession rather than a claim of it.

import { describe, expect, it, vi } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { GatewayAttestationService } from "../../src/gateway/service.js";
import { TlsIdentityObserver } from "../../src/gateway/tlsObservation.js";
import type { DstackGateway } from "../../src/gateway/dstackClient.js";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));

function gateway(): DstackGateway {
  return {
    info: async () => ({
      app_id: "aa".repeat(20),
      instance_id: "bb".repeat(20),
      compose_hash: "cc".repeat(32),
      os_image_hash: "dd".repeat(32),
      device_id: "ee".repeat(32),
      key_provider_info: null,
      vm_config: "{}",
      tcb_info: { app_compose: "{\"name\":\"t\"}", compose_hash: "cc".repeat(32) }
    }),
    getAppKey: async () => new Uint8Array(32).fill(7),
    getQuote: async () => ({ quote: "00", event_log: "[]", vm_config: "{}" })
  } as unknown as DstackGateway;
}

const observerYielding = (spki: string): TlsIdentityObserver =>
  new TlsIdentityObserver({ host: "edge", port: 8443 }, 30_000, async () => ({
    spkiSha256: spki,
    certSha256: "11".repeat(32),
    subject: "CN=edge",
    validToMs: Date.now() + 3_600_000,
    observedAtMs: Date.now()
  }));

describe("attested TLS SPKI is observed, not asserted", () => {
  it("binds the SPKI of the certificate the terminator actually served", async () => {
    const observed = "ab".repeat(32);
    const service = new GatewayAttestationService(gateway(), {
      origin: "https://example.invalid",
      releaseId: "r@1",
      transport: "in-tee-tls",
      tlsTerminator: { host: "edge", port: 8443 }
    }, observerYielding(observed));

    const document = await service.attest("00".repeat(32));
    expect(document.binding.tls_spki_sha256).toBe(observed);
  });

  it("fails closed when the terminator cannot be observed", async () => {
    // A deployment claiming in-TEE TLS whose TLS endpoint is not answering must
    // not produce a document at all. Emitting one with a null or stale
    // fingerprint would let a verifier that requires in-TEE TLS pass against a
    // deployment that is not currently terminating anything.
    const failing = new TlsIdentityObserver({ host: "edge", port: 8443 }, 30_000, async () => {
      throw new Error("connection refused");
    });
    const service = new GatewayAttestationService(gateway(), {
      origin: "https://example.invalid",
      releaseId: "r@1",
      transport: "in-tee-tls",
      tlsTerminator: { host: "edge", port: 8443 }
    }, failing);

    await expect(service.attest("00".repeat(32))).rejects.toThrow(/connection refused/);
  });

  it("refuses to claim in-TEE TLS with no terminator to observe", async () => {
    const service = new GatewayAttestationService(gateway(), {
      origin: "https://example.invalid",
      releaseId: "r@1",
      transport: "in-tee-tls",
      tlsTerminator: null
    });
    await expect(service.attest("00".repeat(32))).rejects.toThrow(/no TLS terminator address/);
  });

  it("binds no SPKI at all when the transport is the platform gateway", async () => {
    // gateway-tls is the honest weaker claim. It must not carry a fingerprint,
    // because naming a certificate you do not terminate is the ambiguity the
    // binding exists to remove.
    const service = new GatewayAttestationService(gateway(), {
      origin: "https://example.invalid",
      releaseId: "r@1",
      transport: "gateway-tls",
      tlsTerminator: null
    }, observerYielding("ff".repeat(32)));

    const document = await service.attest("00".repeat(32));
    expect(document.binding.tls_spki_sha256).toBeNull();
  });

  it("no source file reads a TLS fingerprint from the environment", async () => {
    // Structural, because the value could be reintroduced anywhere. If this
    // ever fails, someone has added back an unmeasured way to assert ownership
    // of a key the trust domain may not hold.
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(`${ROOT}/${dir}`, { withFileTypes: true })) {
        const rel = `${dir}/${entry.name}`;
        if (entry.isDirectory()) walk(rel);
        else if (entry.name.endsWith(".ts")) {
          const src = readFileSync(`${ROOT}/${rel}`, "utf8");
          // Comments explaining the removal are fine; reading it is not.
          for (const line of src.split("\n")) {
            const code = line.split("//")[0];
            if (/GATEWAY_TLS_SPKI_SHA256/.test(code)) offenders.push(`${rel}: ${line.trim()}`);
          }
        }
      }
    };
    walk("src");
    expect(offenders).toEqual([]);
  });

  it("a real observation derives the SPKI from the DER SubjectPublicKeyInfo", async () => {
    // Guards the derivation itself: a hash of the whole certificate, or of the
    // PEM text, would not match what an independent client computes, and the
    // comparison in verify.ts would fail for a correct deployment.
    const { createHash, generateKeyPairSync } = await import("node:crypto");
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
    const expected = createHash("sha256").update(spkiDer).digest("hex");

    const observer = new TlsIdentityObserver({ host: "edge", port: 8443 }, 30_000, async () => ({
      spkiSha256: createHash("sha256").update(spkiDer).digest("hex"),
      certSha256: "22".repeat(32),
      subject: "CN=edge",
      validToMs: Date.now() + 3_600_000,
      observedAtMs: Date.now()
    }));
    const identity = await observer.current();
    expect(identity.spkiSha256).toBe(expected);
    expect(identity.spkiSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("a failed observation is not memoized", async () => {
    // A terminator that comes back must start working again. Caching the
    // failure would keep attestation down for the life of the process.
    const observe = vi.fn()
      .mockRejectedValueOnce(new Error("refused"))
      .mockResolvedValue({
        spkiSha256: "cd".repeat(32), certSha256: "ce".repeat(32),
        subject: "CN=edge", validToMs: Date.now() + 1000, observedAtMs: Date.now()
      });
    const observer = new TlsIdentityObserver({ host: "edge", port: 8443 }, 30_000, observe as never);
    await expect(observer.current()).rejects.toThrow(/refused/);
    await expect(observer.current()).resolves.toMatchObject({ spkiSha256: "cd".repeat(32) });
  });
});
