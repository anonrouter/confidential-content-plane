// Artifact-only pool invariants. No generators or git history are needed in
// the public export; generator equality remains a private-monorepo gate.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { pairKey, readCompose, sharedNetworks } from "../helpers/composeYaml.js";
const read = (path: string) => readFileSync(new URL(`../../deploy/phala/${path}`, import.meta.url), "utf8");
const compose = readCompose(read("docker-compose.prod5-pool.yml"));
const edge = read("images/edge-pool/Caddyfile");
describe("portable measured pool artifacts", () => {
  it("keeps key and prompt holders off the Internet", () => {
    for (const name of ["relay", "compat", "attest", "pool-worker", "bedrock-worker", "release-collateral"]) {
      expect(compose.services[name], name).toBeDefined();
      expect(compose.services[name].networks, name).not.toContain("cvm-internet");
    }
    expect((sharedNetworks(compose)[pairKey("pool-worker", "bedrock-worker")] ?? [])).toEqual([]);
    expect((sharedNetworks(compose)[pairKey("pool-worker", "compat")] ?? [])).toEqual([]);
  });
  it("binds every pooled credential route to its literal provider namespace", () => {
    for (const [slug, provider] of [["venice", "venice"], ["fireworks", "fireworks"], ["deepinfra", "deepinfra"], ["tinfoil", "tinfoil"], ["near", "near-ai"], ["phala-ai", "phala-ai"]]) {
      for (const leaf of ["identity", "secret", "revoke"]) {
        expect(edge).toContain(`path /v1/credentials/${slug}/${leaf}`);
        expect(edge).toContain(`rewrite * /internal/credentials/${provider}/${leaf}`);
      }
    }
    expect(edge).not.toContain("/v1/credentials/chutes/");
  });
  it("addresses every network explicitly, so none draws on Docker's default address pools", () => {
    const subnets = Object.values(compose.networks).map((options) =>
      ((options.ipam as { config?: Array<{ subnet?: string }> } | undefined)?.config ?? []).map((entry) => entry.subnet));
    expect(subnets.length).toBeGreaterThan(0);
    for (const list of subnets) expect(list).toEqual([expect.stringMatching(/^10\.231\.\d{1,3}\.0\/24$/)]);
    expect(new Set(subnets.flat()).size).toBe(subnets.length);
  });
  it("keeps the release evidence proxy keyless and unreachable from compat", () => {
    const collateral = compose.services["release-collateral"];
    expect(collateral.environment.RUNTIME_ROLE).toBe("release-collateral");
    expect(Object.keys(collateral.environment).some((key) => key.endsWith("KEY_B64"))).toBe(false);
    expect((sharedNetworks(compose)[pairKey("compat", "release-collateral")] ?? [])).toEqual([]);
  });
});
