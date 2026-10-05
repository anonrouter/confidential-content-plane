// Release-authority collateral comes ONLY from AnonRouter's fetch layer.
//
// `anonrouter_release_collateral` is the key the verifiers (server and
// browser) read publication data from: the provider's published measurement
// list, release tags, on-chain answers. If a provider could put that key in
// its own evidence and have it survive, it would be supplying the reference
// its evidence is checked against. Chutes' adapter used to return the raw
// evidence untouched whenever our own collateral fetch failed, so a
// Chutes-supplied key reached the verifiers exactly then.
//
// Each case below sends a MALICIOUS evidence document that carries a
// collateral record which, on its own, makes the authority checks pass (the
// control proves that), and asserts the adapter's output never carries it.

import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChutesProviderAdapter } from "../../src/providers/chutes.js";
import { NearProviderAdapter } from "../../src/providers/near.js";
import { VeniceProviderAdapter } from "../../src/providers/venice.js";
import { ChutesTeeVerifier } from "../../src/providers/attestation/index.js";
import { pinnedMeasurementPolicyFor } from "../../src/providers/attestation/policies.js";
import {
  RELEASE_COLLATERAL_FIELD,
  replaceReleaseCollateral,
  withoutReleaseCollateral,
  withReleaseCollateral,
  type NearReleaseCollateralSource
} from "../../src/providers/attestation/authority/collateral.js";
import type { ChutesPublicationFetcher } from "../../src/providers/attestation/authority/chutesFetcher.js";
import type { AppConfig } from "../../src/config.js";
import type { NormalizedAttestationResult } from "../../src/providers/attestation/types.js";

const fixture = (path: string) => JSON.parse(readFileSync(new URL(`../fixtures/hw-evidence/${path}`, import.meta.url), "utf8"));

const NONCE = "ab".repeat(32);
const CHUTE_ID = "chute-under-test";
const MODEL = "Qwen/Qwen3-32B-TEE";

const chutesConfig = {
  providers: { chutesBaseUrl: "https://llm.chutes.ai/v1", chutesAttestationBaseUrl: "https://api.chutes.ai", chutesApiKey: "cpk_test_secret" }
} as unknown as AppConfig;

afterEach(() => {
  vi.unstubAllGlobals();
});

/** The real Chutes evidence with a collateral record that would pass, planted by "Chutes". */
function maliciousChutesEvidence() {
  const evidence = fixture("chutes/qwen3-32b.evidence.json");
  const planted = fixture("chutes/release-collateral.json");
  return { evidence, planted, malicious: { ...evidence, [RELEASE_COLLATERAL_FIELD]: planted } };
}

/** Serve Chutes' catalog, the (malicious) evidence and the e2e key discovery. */
function stubChutes(body: unknown) {
  const instanceIds = ((body as { evidence?: Array<{ instance_id?: string }> }).evidence ?? [])
    .map((item) => item.instance_id)
    .filter((id): id is string => typeof id === "string");
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    const target = String(url);
    const json = (value: unknown) => new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
    if (target === "https://llm.chutes.ai/v1/models") {
      return json({ data: [{ id: MODEL, chute_id: CHUTE_ID, confidential_compute: true }] });
    }
    if (target.startsWith(`https://api.chutes.ai/chutes/${CHUTE_ID}/evidence?`)) return json(body);
    if (target === `https://api.chutes.ai/e2e/instances/${CHUTE_ID}`) {
      return json({ instances: instanceIds.map((id) => ({ instance_id: id, e2e_pubkey: "pk-" + id, nonces: [] })) });
    }
    throw new Error(`unexpected fetch ${target}`);
  }));
}

function verifyChutes(payload: unknown, now: number): NormalizedAttestationResult {
  return new ChutesTeeVerifier().verifyAttestation({ fetchedAtMs: now - 30_000, endpointIdentity: "api.chutes.ai", payload }, {
    provider: "chutes", canonicalModel: "qwen/qwen3-32b", upstreamModel: MODEL, routeId: "chutes/qwen3-32b",
    endpointIdentity: "api.chutes.ai", nonce: NONCE, privacyModality: "e2ee", now,
    measurementPolicy: pinnedMeasurementPolicyFor("chutes", MODEL)
  });
}

const authorityChecks = (result: NormalizedAttestationResult) => result.checks.filter((c) => c.name.endsWith("_release_authority"));

describe("Chutes: provider-supplied collateral never reaches a verifier", () => {
  it("CONTROL: the planted record would pass the authority checks if it reached the verifier", () => {
    // Without this, the cases below could pass because the planted record was
    // useless anyway, and they would prove nothing.
    const { malicious, planted } = maliciousChutesEvidence();
    const checks = authorityChecks(verifyChutes(malicious, planted.chutes.fetchedAtMs + 60_000));
    expect(checks.length).toBeGreaterThan(0);
    for (const c of checks) expect(c.passed, c.detail).toBe(true);
  });

  it("strips it when our own fetch fails, and the verifier then fails closed", async () => {
    const { malicious, planted } = maliciousChutesEvidence();
    stubChutes(malicious);
    const failing = { collect: vi.fn(async () => { throw new Error("github_unavailable"); }) } as unknown as ChutesPublicationFetcher;
    const document = await new ChutesProviderAdapter(chutesConfig, failing).fetchAttestation(MODEL, NONCE) as Record<string, unknown>;
    expect(failing.collect).toHaveBeenCalledTimes(1);
    expect(Object.hasOwn(document, RELEASE_COLLATERAL_FIELD)).toBe(false);
    expect(JSON.stringify(document)).not.toContain(planted.chutes.bodySha256);
    // The provider's own evidence is otherwise intact.
    expect(document.evidence).toEqual(malicious.evidence);

    const result = verifyChutes(document, planted.chutes.fetchedAtMs + 60_000);
    expect(result.status).toBe("failed");
    const checks = authorityChecks(result);
    expect(checks.length).toBeGreaterThan(0);
    for (const c of checks) {
      expect(c.passed).toBe(false);
      expect(c.detail).toMatch(/no snapshot of Chutes' published measurements was supplied/);
    }
  });

  it("replaces it with ours when our fetch succeeds", async () => {
    const { malicious, planted } = maliciousChutesEvidence();
    const ours = { ...planted.chutes, bodySha256: "f".repeat(64) };
    stubChutes(malicious);
    const working = { collect: vi.fn(async () => ours) } as unknown as ChutesPublicationFetcher;
    const document = await new ChutesProviderAdapter(chutesConfig, working).fetchAttestation(MODEL, NONCE) as Record<string, unknown>;
    expect(document[RELEASE_COLLATERAL_FIELD]).toEqual({ chutes: ours });
  });

  it("drops a planted record of any shape, including one that is not an object", async () => {
    for (const planted of [null, "x", 1, [], { chutes: null }, { github: [] }]) {
      const { evidence } = maliciousChutesEvidence();
      stubChutes({ ...evidence, [RELEASE_COLLATERAL_FIELD]: planted });
      const failing = { collect: async () => { throw new Error("down"); } } as unknown as ChutesPublicationFetcher;
      const document = await new ChutesProviderAdapter(chutesConfig, failing).fetchAttestation(MODEL, NONCE) as Record<string, unknown>;
      expect(Object.hasOwn(document, RELEASE_COLLATERAL_FIELD), JSON.stringify(planted)).toBe(false);
    }
  });
});

describe("Venice and NEAR: the key is ours on every path", () => {
  const veniceConfig = {
    env: "test",
    providers: { veniceBaseUrl: "https://api.venice.ai/api/v1", veniceInferenceKey: "venice_test_secret", veniceKeys: [] }
  } as unknown as AppConfig;

  function stubVenice(body: unknown) {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } })));
  }

  it("Venice standard format: a planted key is removed (no collateral is fetched for it)", async () => {
    const doc = fixture("venice/e2ee-gemma-4-26b-a4b-uncensored-p.json");
    stubVenice({ ...doc, [RELEASE_COLLATERAL_FIELD]: { github: [{ repository: "attacker/x" }] } });
    const source = { collect: vi.fn(async () => ({})) } as unknown as NearReleaseCollateralSource;
    const adapter = new VeniceProviderAdapter(veniceConfig, undefined, undefined, source);
    const document = await adapter.fetchAttestation("e2ee-gemma-4-26b-a4b-uncensored-p", NONCE) as Record<string, unknown>;
    expect(Object.hasOwn(document, RELEASE_COLLATERAL_FIELD)).toBe(false);
    expect(document.intel_quote).toBe(doc.intel_quote);
  });

  it("Venice serving-TD format: a planted key is overwritten by our fetch layer's answer, even an empty one", async () => {
    const doc = fixture("venice/e2ee-glm-5-3-flash.json");
    stubVenice({ ...doc, [RELEASE_COLLATERAL_FIELD]: fixture("venice/e2ee-glm-5-3-flash.release-collateral.json") });
    const source = { collect: vi.fn(async () => ({})) } as unknown as NearReleaseCollateralSource;
    const adapter = new VeniceProviderAdapter(veniceConfig, undefined, undefined, source);
    const document = await adapter.fetchAttestation("e2ee-glm-5-3-flash", NONCE) as Record<string, unknown>;
    expect(document[RELEASE_COLLATERAL_FIELD]).toEqual({});
  });
});

describe("collateral helpers", () => {
  it("withoutReleaseCollateral removes only the key and does not mutate its input", () => {
    const input = { a: 1, [RELEASE_COLLATERAL_FIELD]: { github: [] } };
    const out = withoutReleaseCollateral(input);
    expect(out).toEqual({ a: 1 });
    expect(Object.hasOwn(input, RELEASE_COLLATERAL_FIELD)).toBe(true);
  });

  it("replaceReleaseCollateral attaches ours or leaves the key absent", () => {
    const input = { a: 1, [RELEASE_COLLATERAL_FIELD]: { github: ["theirs"] } };
    expect(replaceReleaseCollateral(input, undefined)).toEqual({ a: 1 });
    expect(replaceReleaseCollateral(input, { onchain: [] })).toEqual({ a: 1, [RELEASE_COLLATERAL_FIELD]: { onchain: [] } });
    expect(withReleaseCollateral(input, {})[RELEASE_COLLATERAL_FIELD]).toEqual({});
  });

  it("NEAR always overwrites (regression guard for the adapter that already did)", async () => {
    const host = "glm-5-3-flash.completions.near.ai";
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      const target = String(url);
      const json = (value: unknown) => new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
      if (target.endsWith("/endpoints")) return json({ endpoints: [{ domain: host, models: ["z-ai/glm-5.3-flash"] }] });
      if (target.startsWith(`https://${host}/v1/attestation/report?`)) {
        return json({ signing_address: "0x00", [RELEASE_COLLATERAL_FIELD]: { github: [{ repository: "attacker/x" }] } });
      }
      throw new Error(`unexpected fetch ${target}`);
    }));
    const source = { collect: vi.fn(async () => ({})) } as unknown as NearReleaseCollateralSource;
    const adapter = new NearProviderAdapter({ providers: { nearBaseUrl: "https://n.invalid/v1", nearEndpointsUrl: "https://n.invalid/endpoints", nearApiKey: "k" } } as unknown as AppConfig, source);
    const document = await adapter.fetchAttestation("z-ai/glm-5.3-flash", NONCE) as Record<string, unknown>;
    expect(document[RELEASE_COLLATERAL_FIELD]).toEqual({});
  });
});
