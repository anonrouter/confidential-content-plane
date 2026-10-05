// The release-collateral client gives the verifier what the fetchers would have
// (PROVIDER_POOL_PLAN.md, W3; review finding S1).
//
// A pooled worker gets its release-authority collateral through the
// release-collateral role instead of fetching it. That is only acceptable if
// the verifier cannot tell: the same records, with the same fetch times and
// source attribution, and so the same verdict. This suite puts the two side by
// side:
//
//   local   the fetchers, called in-process, as every single-provider worker
//           still does;
//   rpc     the same fetchers inside a real release-collateral server, reached through
//           the client's implementation of the same source interface.
//
// It also pins where they deliberately differ (always toward failing), and
// that the client fails closed on every way the role can fail to answer.
//
// No test waits on a duration. The client's deadline and the role's are
// injected signals: they never fire unless a test fires them, and a test that
// needs calls to be in flight waits for them to arrive.

import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { FastifyInstance } from "fastify";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../../src/config.js";
import { NearTeeVerifier, VeniceTeeVerifier } from "../../src/providers/attestation/index.js";
import {
  NearReleaseCollateralSource,
  withReleaseCollateral,
  type NearReleaseSources,
  type ReleaseCollateral
} from "../../src/providers/attestation/authority/collateral.js";
import { DSTACK_IMAGE_MEASUREMENTS } from "../../src/providers/attestation/authority/dstackImages.generated.js";
import { DstackOnchainFetcher, type DstackOnchainAuthorization } from "../../src/providers/attestation/authority/dstackOnchain.js";
import { RequestBudget } from "../../src/providers/attestation/authority/fetchLayer.js";
import type { GithubPublication, PublicationClaim } from "../../src/providers/attestation/authority/github.js";
import { GithubPublicationFetcher } from "../../src/providers/attestation/authority/githubFetcher.js";
import { GithubReleasesFetcher, type GithubReleaseImages } from "../../src/providers/attestation/authority/githubReleases.js";
import { NEAR_DSTACK_KMS } from "../../src/providers/attestation/authority/near.js";
import { pinnedMeasurementPolicyFor } from "../../src/providers/attestation/policies.js";
import type { NormalizedAttestationResult } from "../../src/providers/attestation/types.js";
import {
  releaseCollateralClientFor,
  ReleaseCollateralRpcClient,
  ReleaseCollateralRpcError,
  nearReleaseCollateralSourceFor,
  rpcNearReleaseSources
} from "../../src/releaseCollateral/client.js";
import { releaseCollateralPath, MAX_PUBLICATION_CLAIMS, type ReleaseCollateralOperation } from "../../src/releaseCollateral/contract.js";
import { ReleaseCollateralAdmission, releaseCollateralSources, type ReleaseCollateralSources } from "../../src/releaseCollateral/server.js";
import { buildReleaseCollateralServer } from "../../src/roles.js";
import { FakeUpstream, FILES_REPOSITORY, RELEASES_REPOSITORY } from "../helpers/releaseCollateralUpstream.js";

const T0 = Date.parse("2026-10-03T12:00:00Z");
const distinct = (seed: string) => `prod-${seed}-${"x".repeat(40)}`.slice(0, 48);
const TOKEN = distinct("release-collateral-token");
const RELEASE_COLLATERAL_URL = "http://release-collateral.parity.invalid:3000";

const HEAD = "a".repeat(40);
const TAGGED = "b".repeat(40);
const ANCESTOR = "c".repeat(40);
const FORK = "d".repeat(40);
const APP = "2c".repeat(20);
const OTHER_APP = "3d".repeat(20);
const COMPOSE = "c8".repeat(32);
const IMAGE = DSTACK_IMAGE_MEASUREMENTS[0]!.osImageHash;
const OTHER_IMAGE = DSTACK_IMAGE_MEASUREMENTS[1]!.osImageHash;

const fixture = (path: string) => JSON.parse(readFileSync(new URL(`../fixtures/hw-evidence/${path}`, import.meta.url), "utf8"));

/** A deadline that never arrives: no timer is armed at all. */
const NEVER = () => new AbortController().signal;
/** What a deadline aborts with when it does arrive. */
const timedOut = () => new DOMException("The operation was aborted due to timeout", "TimeoutError");

let snapshot: NodeJS.ProcessEnv;
let config: AppConfig;
const servers: FastifyInstance[] = [];
const sockets: Server[] = [];

beforeAll(() => {
  snapshot = { ...process.env };
  for (const key of Object.keys(process.env)) {
    if (/^(RUNTIME_ROLE|POOL_PROVIDERS|RELEASE_COLLATERAL_|LOG_LEVEL|RELAY_RPC|WORKER_RPC|METADATA_RPC|COMPAT_RPC|VENICE_|FIREWORKS_|DEEPINFRA_|CHUTES_|TINFOIL_|NEAR_|PHALA_AI_|BEDROCK_|AWS_|APP_SECRET|EMAIL_|COOKIE_SECRET|BETTER_AUTH_SECRET|ADMIN_|SMTP_|DATABASE_URL|MIGRATION_DATABASE_URL|APP_DB|GATEWAY_|DSTACK_|REDIS_URL|STRIPE_|CONSUMED_CAPABILITY|CREDENTIAL_|CONTENT_TLS|PROVIDER_CAPABILITY|PROVIDER_CREDENTIAL|TRUST_PROXY_HOPS)/.test(key)) {
      delete process.env[key];
    }
  }
  process.env.NODE_ENV = "production";
  process.env.RUNTIME_ROLE = "release-collateral";
  process.env.RELEASE_COLLATERAL_RPC_TOKEN = TOKEN;
  process.env.LOG_LEVEL = "silent";
  config = loadConfig();
});

afterAll(() => {
  process.env = snapshot;
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
  await Promise.all(sockets.splice(0).map((server) => new Promise<void>((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  })));
});

interface Seen {
  url: string;
  authorization: string | null;
  redirect: RequestInit["redirect"];
  body: unknown;
}

/** The client's `fetch`, delivered to a release-collateral server in this process. */
function deliverTo(server: FastifyInstance, seen: Seen[] = []): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    seen.push({
      url: String(input),
      authorization: headers.get("authorization"),
      redirect: init?.redirect,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : null
    });
    const sent: Record<string, string> = {};
    headers.forEach((value, name) => {
      sent[name] = value;
    });
    const response = await server.inject({
      method: "POST",
      url: `${url.pathname}${url.search}`,
      headers: sent,
      payload: init?.body as string
    });
    return new Response(response.body, {
      status: response.statusCode,
      headers: { "content-type": String(response.headers["content-type"] ?? "application/json") }
    });
  }) as typeof fetch;
}

function standardUpstream(): FakeUpstream {
  const upstream = new FakeUpstream();
  upstream.head = HEAD;
  upstream.tags = { "v0.0.461": TAGGED, "release/2026": TAGGED };
  upstream.ancestors = new Set([ANCESTOR]);
  upstream.files.set(`${TAGGED}/prod/x.yaml`, "services: {}\n");
  upstream.files.set(`${ANCESTOR}/prod/y.yaml`, "services: { y: 1 }\n");
  upstream.files.set(`${ANCESTOR}/root.yml`, "services: { root: 1 }\n");
  upstream.files.set(`${TAGGED}/deep/er/z.yaml`, "services: { deep: 1 }\n");
  upstream.registeredApps.add(`0x${APP}`);
  upstream.allowedCompose.set(`0x${APP}`, new Set([COMPOSE]));
  upstream.allowedCompose.set(`0x${OTHER_APP}`, new Set([COMPOSE]));
  upstream.allowedImages.add(IMAGE);
  return upstream;
}

const roomy = () => new RequestBudget({}, () => T0, { burst: 100_000, perHour: 100_000 });

/** The fetchers called in-process: what `defaultNearReleaseSources` builds, on a stub and a fixed clock. */
function localSources(upstream: FakeUpstream): NearReleaseSources {
  const shared = { fetch: upstream.fetch, now: () => T0, budget: roomy() };
  return {
    composeRepository: new GithubPublicationFetcher({ repository: FILES_REPOSITORY, ...shared }),
    composeManagerReleases: new GithubReleasesFetcher(RELEASES_REPOSITORY, shared),
    onchain: new DstackOnchainFetcher({ kms: NEAR_DSTACK_KMS, rpcUrls: ["https://mainnet.base.org", "https://base-rpc.publicnode.com"], ...shared })
  };
}

async function releaseCollateralServer(sources: ReleaseCollateralSources): Promise<FastifyInstance> {
  const server = await buildReleaseCollateralServer(config, { sources, admission: new ReleaseCollateralAdmission({}, () => T0, NEVER) });
  await server.ready();
  servers.push(server);
  return server;
}

/** The same fetchers behind a real release-collateral server, reached through the client. */
async function rpcSources(upstream: FakeUpstream, seen: Seen[] = []) {
  const server = await releaseCollateralServer(releaseCollateralSources({ fetch: upstream.fetch, now: () => T0, budget: roomy() }));
  const client = new ReleaseCollateralRpcClient({ baseUrl: RELEASE_COLLATERAL_URL, token: TOKEN, timeoutMs: 5_000, deadline: NEVER, fetch: deliverTo(server, seen) });
  return { sources: rpcNearReleaseSources(client), client, server };
}

// --- each operation, against stubbed upstreams ---------------------------------------

describe("each operation returns what the fetcher returns for the same inputs", () => {
  const claimSets: Array<[string, PublicationClaim[]]> = [
    ["a tagged release", [{ commit: TAGGED, path: "prod/x.yaml", tag: "v0.0.461" }]],
    ["a commit on the default branch, no tag", [{ commit: ANCESTOR, path: "prod/y.yaml", tag: null }]],
    ["a commit named by a tag that does not peel to it", [{ commit: ANCESTOR, path: "prod/y.yaml", tag: "v0.0.461" }]],
    ["a fork commit", [{ commit: FORK, path: "prod/x.yaml", tag: "v9" }]],
    ["a file the repository does not have", [{ commit: TAGGED, path: "prod/missing.yaml", tag: "v0.0.461" }]],
    ["a root-level .yml file", [{ commit: ANCESTOR, path: "root.yml" }]],
    ["a tag with a slash", [{ commit: TAGGED, path: "prod/x.yaml", tag: "release/2026" }]],
    ["a commit in upper case", [{ commit: TAGGED.toUpperCase(), path: "prod/x.yaml", tag: "v0.0.461" }]],
    ["an unsafe tag", [{ commit: ANCESTOR, path: "prod/y.yaml", tag: "not a ref name" }]],
    ["an empty commit and an empty path", [{ commit: "", path: "prod/x.yaml" }, { commit: TAGGED, path: "" }]],
    ["a log's worth, repeated and out of order", [
      { commit: FORK, path: "prod/x.yaml", tag: "v9" },
      { commit: ANCESTOR, path: "root.yml", tag: null },
      { commit: TAGGED, path: "prod/x.yaml", tag: "v0.0.461" },
      { commit: ANCESTOR, path: "prod/y.yaml" },
      { commit: TAGGED, path: "prod/x.yaml", tag: "v0.0.461" },
      { commit: TAGGED, path: "prod/missing.yaml", tag: "release/2026" },
      { commit: "not-a-commit", path: "prod/x.yaml" }
    ]]
  ];

  it.each(claimSets)("github-publication: %s", async (_label, claims) => {
    const local = await localSources(standardUpstream()).composeRepository.collect(claims);
    const { sources } = await rpcSources(standardUpstream());
    expect(await sources.composeRepository.collect(claims)).toEqual(local);
    expect(local.fetchedAtMs).toBe(T0);
  });

  it("github-release-images", async () => {
    const local = await localSources(standardUpstream()).composeManagerReleases.collect();
    const { sources } = await rpcSources(standardUpstream());
    expect(await sources.composeManagerReleases.collect()).toEqual(local);
    expect(local.images).toHaveLength(2);
  });

  it.each<[string, { appId: string; composeHash: string; osImageHash: string }, Partial<DstackOnchainAuthorization>]>([
    ["registered, compose and image allowed", { appId: APP, composeHash: COMPOSE, osImageHash: IMAGE }, { appRegistered: true, composeHashAllowed: true, osImageAllowed: true }],
    ["a compose the app does not allow", { appId: APP, composeHash: "ee".repeat(32), osImageHash: IMAGE }, { appRegistered: true, composeHashAllowed: false, osImageAllowed: true }],
    ["an image the KMS does not allow", { appId: APP, composeHash: COMPOSE, osImageHash: OTHER_IMAGE }, { appRegistered: true, composeHashAllowed: true, osImageAllowed: false }],
    ["the subject as evidence spells it: 0x and upper case", { appId: `0x${APP.toUpperCase()}`, composeHash: COMPOSE.toUpperCase(), osImageHash: IMAGE.toUpperCase() }, { appRegistered: true, composeHashAllowed: true }]
  ])("dstack-onchain-authorization: %s", async (_label, subject, expected) => {
    const local = await localSources(standardUpstream()).onchain.authorize(subject);
    const { sources } = await rpcSources(standardUpstream());
    expect(await sources.onchain.authorize(subject)).toEqual(local);
    expect(local).toMatchObject({ chainId: 8453, rpc: "https://mainnet.base.org", blockNumber: 0x1f4a, fetchedAtMs: T0, ...expected });
  });

  it("the same malformed subject is the same error", async () => {
    const subject = { appId: "nope", composeHash: COMPOSE, osImageHash: IMAGE };
    await expect(localSources(standardUpstream()).onchain.authorize(subject)).rejects.toThrow("onchain_subject_malformed");
    const upstream = standardUpstream();
    const seen: Seen[] = [];
    const { sources } = await rpcSources(upstream, seen);
    await expect(sources.onchain.authorize(subject)).rejects.toThrow("onchain_subject_malformed");
    // Not sent, so not refused: the role was never asked.
    expect(seen).toEqual([]);
  });

  it("an answer served from the role's cache keeps its original fetch time", async () => {
    // The freshness the verifier checks is the fetch's, not the relay's.
    let now = T0;
    const upstream = standardUpstream();
    const server = await releaseCollateralServer(releaseCollateralSources({ fetch: upstream.fetch, now: () => now, budget: roomy() }));
    const client = new ReleaseCollateralRpcClient({ baseUrl: RELEASE_COLLATERAL_URL, token: TOKEN, timeoutMs: 5_000, deadline: NEVER, fetch: deliverTo(server) });
    const first = await client.onchainAuthorization("near-base-mainnet", { appId: APP, composeHash: COMPOSE, osImageHash: IMAGE });
    now = T0 + 9 * 60_000;
    const again = await client.onchainAuthorization("near-base-mainnet", { appId: APP, composeHash: COMPOSE, osImageHash: IMAGE });
    expect(again).toEqual(first);
    expect(again.fetchedAtMs).toBe(T0);
    expect(upstream.requests).toHaveLength(5);
  });
});

describe("where the role deliberately answers less than a worker's own lookup", () => {
  it("an app the KMS does not register: its contract is not asked, and the check fails either way", async () => {
    const subject = { appId: OTHER_APP, composeHash: COMPOSE, osImageHash: IMAGE };
    // A worker asks the unregistered address anyway, and here it says yes.
    const local = await localSources(standardUpstream()).onchain.authorize(subject);
    expect(local).toMatchObject({ appRegistered: false, composeHashAllowed: true });
    const upstream = standardUpstream();
    const { sources } = await rpcSources(upstream);
    const remote = await sources.onchain.authorize(subject);
    expect(remote).toEqual({ ...local, composeHashAllowed: false });
    expect(upstream.wire()).not.toContain(`"to":"0x${OTHER_APP}"`);
  });

  it("an OS image dstack has not published: no record, where a worker would have one", async () => {
    const subject = { appId: APP, composeHash: COMPOSE, osImageHash: "f0".repeat(32) };
    await expect(localSources(standardUpstream()).onchain.authorize(subject)).resolves.toMatchObject({ osImageAllowed: false });
    const upstream = standardUpstream();
    const { sources } = await rpcSources(upstream);
    await expect(sources.onchain.authorize(subject)).rejects.toMatchObject({ code: "release_collateral_os_image_unknown" });
    expect(upstream.requests).toEqual([]);
  });

  it("a compose path outside the contract's shapes: not looked up, so not published", async () => {
    const claims = [{ commit: TAGGED, path: "deep/er/z.yaml", tag: "v0.0.461" }];
    const local = await localSources(standardUpstream()).composeRepository.collect(claims);
    expect(local.files).toHaveLength(1);
    const upstream = standardUpstream();
    const { sources } = await rpcSources(upstream);
    const remote = await sources.composeRepository.collect(claims);
    expect(remote).toEqual({ ...local, files: [], tags: {} });
    expect(upstream.wire()).not.toContain("deep/er");
  });
});

// --- the verifier, on live evidence ----------------------------------------------------

/**
 * Sources that answer from a captured collateral record, and only what they
 * are asked: a claim that is not sent is a file that is not returned, so a
 * client that dropped or mangled part of a log would change the verdict.
 */
function recordedSources(recorded: ReleaseCollateral): { sources: NearReleaseSources; server: ReleaseCollateralSources } {
  const publication = recorded.github![0]!;
  const releases = recorded.githubReleases![0]!;
  const onchain = recorded.onchain![0]!;
  const composeRepository = {
    collect: async (claims: PublicationClaim[]): Promise<GithubPublication> => {
      const asked = new Set(claims.map((claim) => `${claim.commit.toLowerCase()}:${claim.path}`));
      const commits = new Set(claims.map((claim) => claim.commit.toLowerCase()));
      const tags = new Set(claims.map((claim) => claim.tag).filter((tag): tag is string => typeof tag === "string"));
      return {
        ...publication,
        tags: Object.fromEntries(Object.entries(publication.tags).filter(([tag]) => tags.has(tag))),
        defaultBranchAncestors: publication.defaultBranchAncestors.filter((commit) => commits.has(commit)),
        files: publication.files.filter((file) => asked.has(`${file.commit}:${file.path}`))
      };
    }
  };
  const composeManagerReleases = { collect: async (): Promise<GithubReleaseImages> => releases };
  const authorize = {
    authorize: async (subject: { appId: string; composeHash: string; osImageHash: string }) => {
      const asked = `0x${subject.appId.toLowerCase().replace(/^0x/, "")}:${subject.composeHash.toLowerCase()}:${subject.osImageHash.toLowerCase()}`;
      if (asked !== `${onchain.appId}:${onchain.composeHash}:${onchain.osImageHash}`) throw new Error("no recorded answer for this subject");
      return onchain;
    }
  };
  return {
    sources: { composeRepository, composeManagerReleases, onchain: authorize },
    server: {
      publication: { [FILES_REPOSITORY]: composeRepository },
      releaseImages: { [RELEASES_REPOSITORY]: composeManagerReleases },
      onchain: { "near-base-mainnet": authorize },
      osImages: new Set(DSTACK_IMAGE_MEASUREMENTS.map((image) => image.osImageHash))
    } as ReleaseCollateralSources
  };
}

function verifyNear(slug: string, collateral: ReleaseCollateral, nowMs: number): NormalizedAttestationResult {
  const doc = fixture(`near-ai/${slug}.json`);
  const meta = fixture(`near-ai/${slug}.meta.json`);
  const tcb = doc.info.tcb_info;
  return new NearTeeVerifier().verifyAttestation({
    fetchedAtMs: nowMs - 30_000,
    endpointIdentity: meta.endpoint,
    payload: withReleaseCollateral({ ...doc, app_compose: tcb.app_compose, compose_hash: tcb.compose_hash }, collateral)
  }, {
    provider: "near-ai", canonicalModel: doc.model_name, upstreamModel: doc.model_name, routeId: `near-ai/${slug}`,
    endpointIdentity: meta.endpoint, nonce: meta.nonce, privacyModality: "tee", now: nowMs,
    measurementPolicy: pinnedMeasurementPolicyFor("near-ai", doc.model_name)
  });
}

function verifyVenice(route: string, collateral: ReleaseCollateral, nowMs: number): NormalizedAttestationResult {
  const doc = fixture(`venice/${route}.json`);
  const meta = fixture(`venice/${route}.meta.json`);
  return new VeniceTeeVerifier().verifyAttestation({
    fetchedAtMs: nowMs - 30_000, endpointIdentity: "api.venice.ai", payload: withReleaseCollateral(doc, collateral)
  }, {
    provider: "venice", canonicalModel: route, upstreamModel: route, routeId: route, endpointIdentity: "api.venice.ai",
    nonce: meta.nonce, privacyModality: "e2ee", now: nowMs, measurementPolicy: pinnedMeasurementPolicyFor("venice", route)
  });
}

const verdict = (result: NormalizedAttestationResult) => ({
  status: result.status,
  checks: result.checks.map((check) => ({ name: check.name, passed: check.passed, required: check.required, detail: check.detail }))
});

describe("the verifier reaches the same verdict from either source (live NEAR and Venice evidence)", () => {
  const cases: Array<["near-ai" | "venice", string, "ok" | "failed"]> = [
    ["near-ai", "glm-5-3-flash", "ok"],
    ["near-ai", "glm-5-3-flash-long", "ok"],
    ["near-ai", "qwen3-30b", "failed"],
    ["venice", "e2ee-glm-5-3-flash", "ok"],
    ["venice", "e2ee-qwen3-8-27b", "failed"]
  ];

  it.each(cases)("%s %s: %s", async (provider, name, expected) => {
    const document = fixture(`${provider}/${name}.json`);
    const recorded = fixture(`${provider}/${name}.release-collateral.json`) as ReleaseCollateral;
    const nowMs = recorded.github![0]!.fetchedAtMs + 60_000;
    const { sources, server: serverSources } = recordedSources(recorded);

    const local = await new NearReleaseCollateralSource(sources).collect(document);
    const seen: Seen[] = [];
    const server = await releaseCollateralServer(serverSources);
    const client = new ReleaseCollateralRpcClient({ baseUrl: RELEASE_COLLATERAL_URL, token: TOKEN, timeoutMs: 5_000, deadline: NEVER, fetch: deliverTo(server, seen) });
    const remote = await new NearReleaseCollateralSource(rpcNearReleaseSources(client)).collect(document);

    // The collateral the pool attaches is the collateral a worker attaches.
    expect(remote).toEqual(local);
    expect(Object.keys(remote).sort()).toEqual(["dstackImages", "github", "githubReleases", "onchain"]);
    expect(seen.map((call) => new URL(call.url).pathname).sort()).toEqual([
      releaseCollateralPath("dstack-onchain-authorization"), releaseCollateralPath("github-publication"), releaseCollateralPath("github-release-images")
    ]);

    const verify = provider === "near-ai" ? verifyNear : verifyVenice;
    const fromLocal = verify(name, local, nowMs);
    const fromRemote = verify(name, remote, nowMs);
    expect(verdict(fromRemote)).toEqual(verdict(fromLocal));
    expect(fromRemote.status).toBe(expected);
    if (expected === "ok") {
      for (const check of ["authority_boot_onchain_authorized", "authority_runtime_composes_published", "authority_compose_manager_released", "authority_publication_fresh"]) {
        expect(fromRemote.checks.find((entry) => entry.name === check)?.passed, check).toBe(true);
      }
    }
  });

  it("is a comparison that can fail: a claim the client did not send changes the verdict", async () => {
    // The recorded sources answer only what they are asked, so the parity above
    // is not two copies of one fixture. Withhold the claims and the files go.
    const document = fixture("near-ai/glm-5-3-flash.json");
    const recorded = fixture("near-ai/glm-5-3-flash.release-collateral.json") as ReleaseCollateral;
    const { sources } = recordedSources(recorded);
    const withheld: NearReleaseSources = {
      ...sources,
      composeRepository: { collect: (claims, signal) => sources.composeRepository.collect(claims.slice(0, 1), signal) }
    };
    const collateral = await new NearReleaseCollateralSource(withheld).collect(document);
    const result = verifyNear("glm-5-3-flash", collateral, recorded.github![0]!.fetchedAtMs + 60_000);
    expect(result.status).toBe("failed");
    expect(result.checks.find((check) => check.name === "authority_runtime_composes_published")?.passed).toBe(false);
  });
});

// --- the client fails closed ---------------------------------------------------------------

describe("an unavailable release-collateral role fails the authority check; it is never skipped", () => {
  const document = fixture("near-ai/glm-5-3-flash.json");
  const recorded = fixture("near-ai/glm-5-3-flash.release-collateral.json") as ReleaseCollateral;
  const nowMs = recorded.github![0]!.fetchedAtMs + 60_000;
  const AUTHORITY_CHECKS = ["authority_boot_onchain_authorized", "authority_runtime_composes_published", "authority_compose_manager_released", "authority_publication_fresh"];

  async function collectThrough(fetchImpl: typeof fetch, deadline: (ms: number) => AbortSignal = NEVER) {
    const failures: Array<[ReleaseCollateralOperation, string]> = [];
    const client = new ReleaseCollateralRpcClient({ baseUrl: RELEASE_COLLATERAL_URL, token: TOKEN, timeoutMs: 5_000, deadline, fetch: fetchImpl });
    client.observeFailures((operation, code) => failures.push([operation, code]));
    const collateral = await new NearReleaseCollateralSource(rpcNearReleaseSources(client)).collect(document);
    return { collateral, failures: failures.sort(([a], [b]) => a.localeCompare(b)) };
  }

  function expectFailedClosed(collateral: ReleaseCollateral) {
    // Only the image registers, which are this process's own data, remain.
    expect(Object.keys(collateral)).toEqual(["dstackImages"]);
    const result = verifyNear("glm-5-3-flash", collateral, nowMs);
    expect(result.status).toBe("failed");
    for (const name of AUTHORITY_CHECKS) {
      const check = result.checks.find((entry) => entry.name === name);
      expect(check?.required, name).toBe(true);
      expect(check?.passed, name).toBe(false);
    }
  }

  const everyOperation = (code: string): Array<[ReleaseCollateralOperation, string]> => [
    ["dstack-onchain-authorization", code], ["github-publication", code], ["github-release-images", code]
  ];

  it("the control: with the role answering, the same evidence passes", async () => {
    const server = await releaseCollateralServer(recordedSources(recorded).server);
    const { collateral, failures } = await collectThrough(deliverTo(server));
    expect(failures).toEqual([]);
    expect(verifyNear("glm-5-3-flash", collateral, nowMs).status).toBe("ok");
  });

  it("the role is unreachable", async () => {
    const { collateral, failures } = await collectThrough((async () => {
      throw new TypeError("fetch failed");
    }) as typeof fetch);
    expect(failures).toEqual(everyOperation("release_collateral_unreachable"));
    expectFailedClosed(collateral);
  });

  it("the role does not answer within the deadline", async () => {
    // The deadline is the client's injected signal. The test fires it once all
    // three calls are waiting on a role that never answers: no timer, and no
    // assertion about how long anything took.
    const deadline = new AbortController();
    const armedFor: number[] = [];
    let waiting = 0;
    let allWaiting!: () => void;
    const everyCallWaiting = new Promise<void>((resolve) => { allWaiting = resolve; });
    const pending = collectThrough(((_input: unknown, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal!.reason), { once: true });
      waiting += 1;
      if (waiting === 3) allWaiting();
    })) as typeof fetch, (ms) => {
      armedFor.push(ms);
      return deadline.signal;
    });
    await everyCallWaiting;
    // Each call armed the configured deadline, and none has given up yet.
    expect(armedFor).toEqual([5_000, 5_000, 5_000]);

    deadline.abort(timedOut());
    const { collateral, failures } = await pending;
    expect(failures).toEqual(everyOperation("release_collateral_timeout"));
    expectFailedClosed(collateral);
  });

  it.each<[string, number, unknown, string]>([
    ["refuses the token", 401, { error: { type: "service_unauthorized" } }, "service_unauthorized"],
    ["is rate limiting", 429, { error: { type: "release_collateral_rate_limited" } }, "release_collateral_rate_limited"],
    ["is at capacity", 429, { error: { type: "release_collateral_busy" } }, "release_collateral_busy"],
    ["could not complete the lookup", 503, { error: { type: "release_collateral_unavailable", reason: "budget_exhausted" } }, "release_collateral_unavailable"],
    ["answers an error it does not define", 500, { error: { type: "sk-DEVDUMMY-not-a-code" } }, "release_collateral_http_error"],
    ["answers an error that is not JSON", 502, "<html>bad gateway</html>", "release_collateral_http_error"]
  ])("the role %s", async (_label, status, body, code) => {
    const { collateral, failures } = await collectThrough((async () => new Response(
      typeof body === "string" ? body : JSON.stringify(body), { status }
    )) as typeof fetch);
    expect(failures).toEqual(everyOperation(code));
    expectFailedClosed(collateral);
  });

  it.each<[string, (operation: string) => unknown]>([
    ["an empty object", () => ({})],
    ["a list", () => []],
    ["not JSON", () => "not json"],
    ["a record for another repository", (operation) => operation === "github-publication"
      ? { publication: { ...recorded.github![0], repository: "evil/cvm-compose-files" } }
      : operation === "github-release-images"
        ? { releases: { ...recorded.githubReleases![0], repository: "evil/compose-manager" } }
        : { authorization: { ...recorded.onchain![0], appId: `0x${"11".repeat(20)}` } }],
    ["a record for another subject", (operation) => operation === "github-publication"
      ? { publication: { ...recorded.github![0], defaultBranchHead: "not-a-commit" } }
      : operation === "github-release-images"
        ? { releases: { ...recorded.githubReleases![0], images: [{ release: "prod-1", component: "compose-manager", digest: "sha256:short" }] } }
        : { authorization: { ...recorded.onchain![0], composeHash: "00".repeat(32) } }],
    ["a record under the wrong key", () => ({ record: recorded.github![0] })]
  ])("a 200 that is %s is not an answer", async (_label, body) => {
    const { collateral, failures } = await collectThrough((async (input: string | URL | Request) => {
      const answer = body(new URL(String(input)).pathname.split("/").at(-1)!);
      return new Response(typeof answer === "string" ? answer : JSON.stringify(answer), { status: 200 });
    }) as typeof fetch);
    expect(failures).toEqual(everyOperation("release_collateral_response_invalid"));
    expectFailedClosed(collateral);
  });

  it("an answer larger than any real record is not read to the end", async () => {
    const { failures } = await collectThrough((async () => new Response(
      JSON.stringify({ pad: "x".repeat(3 * 1024 * 1024) }), { status: 200 }
    )) as typeof fetch);
    expect(failures).toEqual(everyOperation("release_collateral_response_invalid"));
  });

  it("a redirect is refused, and the token does not follow it", async () => {
    // Real sockets on loopback: the first answers every request with a redirect
    // to the second, which records what reaches it.
    const reached: Array<string | undefined> = [];
    const listen = (handler: Parameters<typeof createServer>[1]) => new Promise<number>((resolve) => {
      const server = createServer(handler);
      sockets.push(server);
      server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port));
    });
    const targetPort = await listen((request, response) => {
      reached.push(request.headers.authorization);
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ releases: recorded.githubReleases![0] }));
    });
    const redirectingPort = await listen((request, response) => {
      response.writeHead(307, { location: `http://127.0.0.1:${targetPort}${request.url}` }).end();
    });
    const failures: string[] = [];
    const client = new ReleaseCollateralRpcClient({ baseUrl: `http://127.0.0.1:${redirectingPort}`, token: TOKEN, timeoutMs: 5_000, deadline: NEVER });
    client.observeFailures((_operation, code) => failures.push(code));
    await expect(client.releaseImages(RELEASES_REPOSITORY)).rejects.toBeInstanceOf(ReleaseCollateralRpcError);
    expect(failures).toEqual(["release_collateral_unreachable"]);
    expect(reached).toEqual([]);
    // The same target, asked directly, does answer: the refusal was the redirect.
    const direct = new ReleaseCollateralRpcClient({ baseUrl: `http://127.0.0.1:${targetPort}`, token: TOKEN, timeoutMs: 5_000, deadline: NEVER });
    await expect(direct.releaseImages(RELEASES_REPOSITORY)).resolves.toMatchObject({ repository: RELEASES_REPOSITORY });
    expect(reached).toEqual([`Bearer ${TOKEN}`]);
  });

  it("a log naming more files than the contract carries is not sent in part", async () => {
    const seen: Seen[] = [];
    const server = await releaseCollateralServer(recordedSources(recorded).server);
    const failures: string[] = [];
    const client = new ReleaseCollateralRpcClient({ baseUrl: RELEASE_COLLATERAL_URL, token: TOKEN, timeoutMs: 5_000, deadline: NEVER, fetch: deliverTo(server, seen) });
    client.observeFailures((_operation, code) => failures.push(code));
    const claims = Array.from({ length: MAX_PUBLICATION_CLAIMS + 1 }, (_, index) => ({ commit: TAGGED, path: `prod/f${index}.yaml` }));
    await expect(client.publication(FILES_REPOSITORY, claims)).rejects.toMatchObject({ code: "release_collateral_claims_exceeded" });
    expect(seen).toEqual([]);
    expect(failures).toEqual(["release_collateral_claims_exceeded"]);
    // Exactly at the limit it is sent, whole.
    await client.publication(FILES_REPOSITORY, claims.slice(1));
    expect((seen[0]!.body as { claims: unknown[] }).claims).toHaveLength(MAX_PUBLICATION_CLAIMS);
  });

  it("a caller that gives up is not reported as a failure of the role", async () => {
    const failures: string[] = [];
    const client = new ReleaseCollateralRpcClient({
      baseUrl: RELEASE_COLLATERAL_URL, token: TOKEN, timeoutMs: 5_000, deadline: NEVER,
      fetch: ((_input: unknown, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal!.reason), { once: true });
      })) as typeof fetch
    });
    client.observeFailures((_operation, code) => failures.push(code));
    const controller = new AbortController();
    const pending = client.releaseImages(RELEASES_REPOSITORY, controller.signal);
    controller.abort(new DOMException("Client disconnected", "AbortError"));
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(failures).toEqual([]);
  });
});

describe("how the client calls the role", () => {
  it("sends the token, refuses redirects, and puts nothing but the contract's fields on the wire", async () => {
    const seen: Seen[] = [];
    const { sources } = await rpcSources(standardUpstream(), seen);
    await sources.composeRepository.collect([{ commit: TAGGED.toUpperCase(), path: "prod/x.yaml", tag: "v0.0.461" }, { commit: "", path: "x" }]);
    await sources.composeManagerReleases.collect();
    await sources.onchain.authorize({ appId: `0x${APP}`, composeHash: COMPOSE, osImageHash: IMAGE });
    expect(seen).toEqual([
      {
        url: `${RELEASE_COLLATERAL_URL}${releaseCollateralPath("github-publication")}`, authorization: `Bearer ${TOKEN}`, redirect: "error",
        body: { repository: FILES_REPOSITORY, claims: [{ commit: TAGGED, path: "prod/x.yaml", tag: "v0.0.461" }] }
      },
      {
        url: `${RELEASE_COLLATERAL_URL}${releaseCollateralPath("github-release-images")}`, authorization: `Bearer ${TOKEN}`, redirect: "error",
        body: { repository: RELEASES_REPOSITORY }
      },
      {
        url: `${RELEASE_COLLATERAL_URL}${releaseCollateralPath("dstack-onchain-authorization")}`, authorization: `Bearer ${TOKEN}`, redirect: "error",
        body: { registry: "near-base-mainnet", appId: APP, composeHash: COMPOSE, osImageHash: IMAGE }
      }
    ]);
  });

  it("holds its own calls to a bound, so an honest pool is never the caller the role refuses", async () => {
    // The stub role answers a call only when the test tells it to, so how many
    // are in flight at each step is decided here and not by a sleep.
    const answers: Array<() => void> = [];
    const arrivals: Array<{ count: number; resolve: () => void }> = [];
    const whenArrived = (count: number) => answers.length >= count
      ? Promise.resolve()
      : new Promise<void>((resolve) => { arrivals.push({ count, resolve }); });
    let inFlight = 0;
    let most = 0;
    const client = new ReleaseCollateralRpcClient({
      baseUrl: RELEASE_COLLATERAL_URL, token: TOKEN, timeoutMs: 5_000, deadline: NEVER, maxConcurrent: 3,
      fetch: (() => new Promise<Response>((resolve) => {
        inFlight += 1;
        most = Math.max(most, inFlight);
        answers.push(() => {
          inFlight -= 1;
          resolve(new Response(JSON.stringify({ releases: { v: 1, repository: RELEASES_REPOSITORY, fetchedAtMs: T0, images: [] } }), { status: 200 }));
        });
        for (const waiter of arrivals.splice(0)) {
          if (answers.length >= waiter.count) waiter.resolve();
          else arrivals.push(waiter);
        }
      })) as typeof fetch
    });
    const calls = Array.from({ length: 20 }, () => client.releaseImages(RELEASES_REPOSITORY));
    // Twenty asked for in one turn: three reached the role, seventeen wait.
    expect(answers).toHaveLength(3);
    expect(inFlight).toBe(3);
    // Answer them in order. Each answer lets exactly one waiting call through.
    for (let answered = 0; answered < 20; answered += 1) {
      await whenArrived(answered + 1);
      expect(inFlight).toBeLessThanOrEqual(3);
      answers[answered]!();
    }
    await Promise.all(calls);
    expect(answers).toHaveLength(20);
    expect(inFlight).toBe(0);
    expect(most).toBe(3);
  });

  it("is used only where a release-collateral URL is configured, and is one client per configuration", () => {
    const direct = { ...config, internal: { ...config.internal, releaseCollateralRpcUrl: "" } };
    expect(releaseCollateralClientFor(direct)).toBeNull();
    // Hand-built partial configs in other suites carry no `internal` at all.
    expect(releaseCollateralClientFor({ providers: {} } as never)).toBeNull();
    expect(nearReleaseCollateralSourceFor({ providers: {} } as never)).toBeInstanceOf(NearReleaseCollateralSource);

    const delegated = { ...config, internal: { ...config.internal, releaseCollateralRpcUrl: RELEASE_COLLATERAL_URL } };
    const client = releaseCollateralClientFor(delegated);
    expect(client).toBeInstanceOf(ReleaseCollateralRpcClient);
    expect(releaseCollateralClientFor(delegated)).toBe(client);
    expect(releaseCollateralClientFor({ ...config, internal: { ...delegated.internal } })).not.toBe(client);
  });
});
