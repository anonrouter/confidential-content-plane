// A pooled worker's release-authority lookups leave through the
// release-collateral role, and through nothing else (PROVIDER_POOL_PLAN.md, W3).
//
// Every test builds the REAL worker server from a PRODUCTION configuration and
// drives it through its worker RPC, with live NEAR and Venice evidence served
// by a stub of each provider. A REAL release-collateral server listens on
// loopback.
//
// THE ONE ASSERTION THIS FILE EXISTS FOR. The worker process sends requests by
// calling global `fetch`, which is replaced by a recorder. The
// release-collateral server's own fetchers are handed their upstream directly
// and never touch the global. So any request the recorder sees for a GitHub or
// Base host was made by the worker, and the recorder both logs it and fails it.
// With a release-collateral role configured there must be none. The control at
// the end runs the same evidence through a single-provider worker and shows
// the recorder does see those requests when a worker makes them.
//
// TIME. Nothing here asserts on a duration. The release-collateral role's deadline is
// an injected signal that never fires and its allowances run on a fixed clock.
// The pool's own client is built from configuration, which has no such seam, so
// its deadline is set to the schema maximum (60 s): longer than this suite's
// per-test timeout, so it cannot be what ends a test. "Down" is a listener the
// test owns that drops every connection, not a port that was free a moment ago.

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { createServer as createTcpServer, type AddressInfo, type Server as TcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../../src/config.js";
import { NearTeeVerifier, VeniceTeeVerifier } from "../../src/providers/attestation/index.js";
import {
  RELEASE_COLLATERAL_FIELD,
  type ReleaseCollateral
} from "../../src/providers/attestation/authority/collateral.js";
import { DSTACK_IMAGE_MEASUREMENTS } from "../../src/providers/attestation/authority/dstackImages.generated.js";
import { RequestBudget } from "../../src/providers/attestation/authority/fetchLayer.js";
import type { PublicationClaim } from "../../src/providers/attestation/authority/github.js";
import { pinnedMeasurementPolicyFor } from "../../src/providers/attestation/policies.js";
import type { NormalizedAttestationResult } from "../../src/providers/attestation/types.js";
import { releaseCollateralPath } from "../../src/releaseCollateral/contract.js";
import { ReleaseCollateralAdmission, releaseCollateralSources, type ReleaseCollateralSources } from "../../src/releaseCollateral/server.js";
import { buildReleaseCollateralServer, buildWorkerServer } from "../../src/roles.js";
import {
  BASE_RPC_HOSTS,
  FakeUpstream,
  FILES_REPOSITORY,
  GITHUB_HOSTS,
  RELEASES_REPOSITORY
} from "../helpers/releaseCollateralUpstream.js";

const fixture = (path: string) => JSON.parse(readFileSync(new URL(`../fixtures/hw-evidence/${path}`, import.meta.url), "utf8"));

const T0 = Date.parse("2026-10-03T12:00:00Z");
/** A lookup deadline that never arrives: no timer is armed at all. */
const NEVER = () => new AbortController().signal;
const roomy = () => new RequestBudget({}, () => T0, { burst: 100_000, perHour: 100_000 });

const CONTROL_URL = "http://control.pool.invalid:8444";
const MOCK_ORIGIN = "http://mock-provider:3000";
const DISCOVERY_URL = "http://127.0.0.1:9/endpoints";
const NEAR_MODEL = "z-ai/glm-5.3-flash";
const NEAR_ENCLAVE = "glm-5-3-flash.completions.near.ai";
const VENICE_MODEL = "e2ee-glm-5-3-flash";
const AUTHORITY_HOSTS: readonly string[] = [...GITHUB_HOSTS, ...BASE_RPC_HOSTS];
const AUTHORITY_CHECKS = [
  "authority_boot_onchain_authorized", "authority_runtime_composes_published",
  "authority_compose_manager_released", "authority_publication_fresh"
];

const distinct = (seed: string) => `prod-${seed}-${"x".repeat(40)}`.slice(0, 48);
const WORKER_RPC_TOKEN = distinct("workertoken");
const RELEASE_COLLATERAL_TOKEN = distinct("release-collateral-token");
const WORKER_AUTH = { authorization: `Bearer ${WORKER_RPC_TOKEN}` };
// Development-only dummy secrets, recognisable so a leak search can find them.
const providerKey = (provider: string) => `sk-DEVDUMMY-pool-${provider}-key`;

const nearDocument = fixture("near-ai/glm-5-3-flash.json");
const nearMeta = fixture("near-ai/glm-5-3-flash.meta.json");
const nearRecorded = fixture("near-ai/glm-5-3-flash.release-collateral.json") as ReleaseCollateral;
const veniceDocument = fixture(`venice/${VENICE_MODEL}.json`);
const veniceMeta = fixture(`venice/${VENICE_MODEL}.meta.json`);
const veniceRecorded = fixture(`venice/${VENICE_MODEL}.release-collateral.json`) as ReleaseCollateral;

const { publicKey } = generateKeyPairSync("ed25519");
const rawPublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");

// --- the recorder: everything the WORKER process sends -------------------------------

interface Call {
  url: string;
  host: string;
  method: string;
  authorization: string | null;
  body: string | null;
}

const recorder = {
  /** Every request the worker made, in order. */
  calls: [] as Call[],
  /** The origin of the release-collateral role this worker was configured with. */
  releaseCollateralOrigin: "",
  attestation: "allow" as "allow" | "deny"
};

const realFetch = globalThis.fetch;
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });

function installRecorder() {
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const parsed = new URL(url);
    const call: Call = {
      url,
      host: parsed.host,
      method: init?.method ?? "GET",
      authorization: new Headers(init?.headers).get("authorization"),
      body: typeof init?.body === "string" ? init.body : null
    };
    recorder.calls.push(call);
    // The release-collateral role: a real request to a real loopback socket.
    if (recorder.releaseCollateralOrigin && parsed.origin === recorder.releaseCollateralOrigin) return realFetch(input, init);
    if (url.startsWith(`${CONTROL_URL}/`)) {
      return recorder.attestation === "allow" ? json({}) : json({ error: "denied" }, 403);
    }
    if (url.startsWith(DISCOVERY_URL)) return json({ endpoints: [{ domain: NEAR_ENCLAVE, models: [NEAR_MODEL] }] });
    if (parsed.origin === `https://${NEAR_ENCLAVE}` && parsed.pathname === "/v1/attestation/report") return json(nearDocument);
    if (parsed.origin === MOCK_ORIGIN && parsed.pathname.endsWith("/tee/attestation")) return json(veniceDocument);
    // A GitHub or Base host, or anything else: the worker has no business here.
    throw new Error("a request tried to leave the worker for an unexpected destination");
  }));
}

const callsTo = (...hosts: readonly string[]) => recorder.calls.filter((call) => hosts.includes(call.host));
const directAuthorityCalls = () => callsTo(...AUTHORITY_HOSTS);
const releaseCollateralCalls = () => recorder.calls.filter((call) => recorder.releaseCollateralOrigin !== "" && call.url.startsWith(recorder.releaseCollateralOrigin));

// --- configuration -------------------------------------------------------------------

let envSnapshot: NodeJS.ProcessEnv;
let secretsDir = "";
const stateDirs: string[] = [];
const servers: FastifyInstance[] = [];
const listeners: TcpServer[] = [];

function clearRelevant() {
  for (const key of Object.keys(process.env)) {
    if (/^(RUNTIME_ROLE|POOL_PROVIDERS|RELEASE_COLLATERAL_|PROVIDER_TRANSPORT_PROFILE|LOG_LEVEL|RELAY_RPC|WORKER_RPC|METADATA_RPC|METADATA_PUSH|CONTROL_RPC|CONTROL_METADATA|COMPAT_RPC|VENICE_|FIREWORKS_|DEEPINFRA_|CHUTES_|TINFOIL_|NEAR_|PHALA_AI_|BEDROCK_|AWS_|MOCK_PROVIDER_|DEFAULT_PROVIDER|ALLOW_INLINE_TICKET|ALLOW_COMPAT_MODE|APP_SECRET|EMAIL_HASH_SECRET|EMAIL_ENCRYPTION_KEY|COOKIE_SECRET|BETTER_AUTH_SECRET|ADMIN_|CORS_ORIGIN|SMTP_|DATABASE_URL|MIGRATION_DATABASE_URL|APP_DB|GATEWAY_|DSTACK_|REDIS_URL|STRIPE_|PAYMENTS_MODE|CONSUMED_CAPABILITY|CREDENTIAL_|CONTENT_TLS|CONFIDENTIAL_DEPLOYMENT|PROVIDER_CAPABILITY|PROVIDER_CREDENTIAL|CATALOG_SYNC|TRUST_PROXY_HOPS)/.test(key)) {
      delete process.env[key];
    }
  }
}

function newStateDir(): string {
  const directory = mkdtempSync(join(tmpdir(), "anonrouter-pool-release-collateral-"));
  stateDirs.push(directory);
  return directory;
}

function workerEnvironment() {
  const stateDir = newStateDir();
  clearRelevant();
  process.env.NODE_ENV = "production";
  process.env.LOG_LEVEL = "silent";
  process.env.WORKER_RPC_TOKEN = WORKER_RPC_TOKEN;
  process.env.CONTROL_METADATA_URL = CONTROL_URL;
  process.env.CONFIDENTIAL_DEPLOYMENT_ID = "unit-pool";
  process.env.CREDENTIAL_ADMIN_MODE = "capability";
  process.env.CREDENTIAL_CAPABILITY_SIGNERS = `unit-cap-signer:${rawPublicKey}`;
  process.env.CONTENT_TLS_SPKI_SHA256 = "7c".repeat(32);
  process.env.VENICE_KEYSET_OVERLAY_FILE = join(stateDir, "venice-keyset-overlay.json");
  process.env.CATALOG_SYNC_ENABLED = "false";
  // The preproduction profile: the only credential-bearing origin is the mock.
  process.env.PROVIDER_TRANSPORT_PROFILE = "synthetic";
  process.env.NEAR_ENDPOINTS_URL = DISCOVERY_URL;
  process.env.VENICE_BASE_URL = `${MOCK_ORIGIN}/venice/api/v1`;
  process.env.NEAR_BASE_URL = `${MOCK_ORIGIN}/near-ai/v1`;
  return stateDir;
}

/** A production pool for Venice and NEAR, pointed at a release-collateral role. */
function poolEnvironment(releaseCollateralUrl: string, token = RELEASE_COLLATERAL_TOKEN) {
  const stateDir = workerEnvironment();
  process.env.RUNTIME_ROLE = "pool-worker";
  process.env.POOL_PROVIDERS = "venice,near-ai";
  process.env.CONSUMED_CAPABILITY_DIR = stateDir;
  process.env.METADATA_RPC_TOKEN_VENICE = distinct("metadata-venice");
  process.env.METADATA_RPC_TOKEN_NEAR = distinct("metadata-near-ai");
  process.env.VENICE_INFERENCE_KEY_FILE = join(secretsDir, "venice.key");
  process.env.NEAR_API_KEY_FILE = join(secretsDir, "near-ai.key");
  process.env.RELEASE_COLLATERAL_RPC_URL = releaseCollateralUrl;
  process.env.RELEASE_COLLATERAL_RPC_TOKEN = token;
  // The schema maximum, and longer than a test may run: see TIME above.
  process.env.RELEASE_COLLATERAL_RPC_TIMEOUT_MS = "60000";
  recorder.releaseCollateralOrigin = new URL(releaseCollateralUrl).origin;
}

/** Today's single-provider worker: no release-collateral role, its own lookups. */
function singleEnvironment(role: "near-worker" | "venice-worker") {
  const stateDir = workerEnvironment();
  process.env.RUNTIME_ROLE = role;
  process.env.CONSUMED_CAPABILITY_FILE = join(stateDir, "consumed.json");
  process.env.METADATA_RPC_TOKEN = distinct("metadatatoken");
  if (role === "near-worker") process.env.NEAR_API_KEY_FILE = join(secretsDir, "near-ai.key");
  else process.env.VENICE_INFERENCE_KEY_FILE = join(secretsDir, "venice.key");
  recorder.releaseCollateralOrigin = "";
}

async function buildWorker(): Promise<FastifyInstance> {
  const server = await buildWorkerServer(loadConfig());
  servers.push(server);
  await server.ready();
  return server;
}

/**
 * A real release-collateral server on a loopback socket, built from its own production
 * configuration. Its fetchers get `sources` directly; they never use global
 * fetch, so nothing they send appears in the recorder.
 */
async function listenReleaseCollateral(sources: ReleaseCollateralSources, token = RELEASE_COLLATERAL_TOKEN): Promise<{ url: string; server: FastifyInstance }> {
  const saved = { ...process.env };
  clearRelevant();
  process.env.NODE_ENV = "production";
  process.env.RUNTIME_ROLE = "release-collateral";
  process.env.RELEASE_COLLATERAL_RPC_TOKEN = token;
  process.env.LOG_LEVEL = "silent";
  const config = loadConfig();
  process.env = saved;
  const server = await buildReleaseCollateralServer(config, { sources, admission: new ReleaseCollateralAdmission({}, () => T0, NEVER) });
  servers.push(server);
  await server.listen({ host: "127.0.0.1", port: 0 });
  return { url: `http://127.0.0.1:${(server.server.address() as AddressInfo).port}`, server };
}

/**
 * A release-collateral role that is down: a loopback listener this test owns for its
 * whole life, which drops every connection the moment it is accepted. A port
 * that was merely free a moment ago could be handed to another process before
 * the pool connects; this one cannot.
 */
async function downReleaseCollateral(): Promise<string> {
  const listener = createTcpServer((socket) => socket.destroy());
  listeners.push(listener);
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(listener.address() as AddressInfo).port}`;
}

/** Sources that answer from a captured record, and only what they are asked. */
function recordedSources(recorded: ReleaseCollateral): ReleaseCollateralSources {
  const publication = recorded.github![0]!;
  const onchain = recorded.onchain![0]!;
  return {
    publication: {
      [FILES_REPOSITORY]: {
        collect: async (claims: PublicationClaim[]) => {
          const asked = new Set(claims.map((claim) => `${claim.commit}:${claim.path}`));
          const commits = new Set(claims.map((claim) => claim.commit));
          const tags = new Set(claims.map((claim) => claim.tag));
          return {
            ...publication,
            tags: Object.fromEntries(Object.entries(publication.tags).filter(([tag]) => tags.has(tag))),
            defaultBranchAncestors: publication.defaultBranchAncestors.filter((commit) => commits.has(commit)),
            files: publication.files.filter((file) => asked.has(`${file.commit}:${file.path}`))
          };
        }
      }
    },
    releaseImages: { [RELEASES_REPOSITORY]: { collect: async () => recorded.githubReleases![0]! } },
    onchain: {
      "near-base-mainnet": {
        authorize: async (subject: { appId: string; composeHash: string; osImageHash: string }) => {
          if (`0x${subject.appId}:${subject.composeHash}:${subject.osImageHash}` !== `${onchain.appId}:${onchain.composeHash}:${onchain.osImageHash}`) {
            throw new Error("no recorded answer for this subject");
          }
          return onchain;
        }
      }
    },
    osImages: new Set(DSTACK_IMAGE_MEASUREMENTS.map((image) => image.osImageHash))
  } as ReleaseCollateralSources;
}

// --- driving the worker ------------------------------------------------------------------

async function evidenceFrom(server: FastifyInstance, path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = await server.inject({ method: "POST", url: path, headers: WORKER_AUTH, payload: body });
  expect(response.statusCode, response.body.slice(0, 300)).toBe(200);
  return (response.json() as { evidence: Record<string, unknown> }).evidence;
}

const nearEvidence = (server: FastifyInstance) => evidenceFrom(server, "/internal/near-ai/tee-attestation", {
  providerName: "near-ai", externalModelId: NEAR_MODEL, nonce: nearMeta.nonce
});
/** The registry's Venice adapter. */
const veniceEvidence = (server: FastifyInstance) => evidenceFrom(server, "/internal/venice/tee-attestation", {
  providerName: "venice", externalModelId: VENICE_MODEL, nonce: veniceMeta.nonce
});
/** The worker client's own Venice adapter, behind the attestation fence. */
const veniceFencedEvidence = (server: FastifyInstance) => evidenceFrom(server, "/internal/venice/attestation", {
  providerName: "venice", externalModelId: VENICE_MODEL, dispatchToken: "atd_test", nonce: veniceMeta.nonce
});

const collateralOf = (evidence: Record<string, unknown>) => evidence[RELEASE_COLLATERAL_FIELD] as ReleaseCollateral;

function verifyNear(evidence: Record<string, unknown>, recorded: ReleaseCollateral): NormalizedAttestationResult {
  const now = recorded.github![0]!.fetchedAtMs + 60_000;
  return new NearTeeVerifier().verifyAttestation({ fetchedAtMs: now - 30_000, endpointIdentity: nearMeta.endpoint, payload: evidence }, {
    provider: "near-ai", canonicalModel: NEAR_MODEL, upstreamModel: NEAR_MODEL, routeId: "near-ai/glm-5-3-flash",
    endpointIdentity: nearMeta.endpoint, nonce: nearMeta.nonce, privacyModality: "tee", now,
    measurementPolicy: pinnedMeasurementPolicyFor("near-ai", NEAR_MODEL)
  });
}

function verifyVenice(evidence: Record<string, unknown>, recorded: ReleaseCollateral): NormalizedAttestationResult {
  const now = recorded.github![0]!.fetchedAtMs + 60_000;
  return new VeniceTeeVerifier().verifyAttestation({ fetchedAtMs: now - 30_000, endpointIdentity: "api.venice.ai", payload: evidence }, {
    provider: "venice", canonicalModel: VENICE_MODEL, upstreamModel: VENICE_MODEL, routeId: VENICE_MODEL, endpointIdentity: "api.venice.ai",
    nonce: veniceMeta.nonce, privacyModality: "e2ee", now, measurementPolicy: pinnedMeasurementPolicyFor("venice", VENICE_MODEL)
  });
}

const failedChecks = (result: NormalizedAttestationResult) =>
  result.checks.filter((check) => check.required && !check.passed).map((check) => check.name);

beforeAll(() => {
  envSnapshot = { ...process.env };
  secretsDir = mkdtempSync(join(tmpdir(), "anonrouter-pool-release-collateral-secrets-"));
  for (const provider of ["venice", "near-ai"]) writeFileSync(join(secretsDir, `${provider}.key`), providerKey(provider));
});

afterAll(() => {
  rmSync(secretsDir, { recursive: true, force: true });
  for (const directory of stateDirs.splice(0)) rmSync(directory, { recursive: true, force: true });
  process.env = envSnapshot;
});

beforeEach(() => {
  recorder.calls = [];
  recorder.releaseCollateralOrigin = "";
  recorder.attestation = "allow";
  installRecorder();
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
  await Promise.all(listeners.splice(0).map((listener) => new Promise<void>((resolve) => listener.close(() => resolve()))));
  vi.unstubAllGlobals();
});

// --- the pool ----------------------------------------------------------------------------

describe("a production pool with a release-collateral role", () => {
  it("NEAR: the verifier passes on collateral the pool never fetched itself", async () => {
    const role = await listenReleaseCollateral(recordedSources(nearRecorded));
    poolEnvironment(role.url);
    const pool = await buildWorker();

    const evidence = await nearEvidence(pool);
    expect(Object.keys(collateralOf(evidence)).sort()).toEqual(["dstackImages", "github", "githubReleases", "onchain"]);
    const result = verifyNear(evidence, nearRecorded);
    expect(failedChecks(result)).toEqual([]);
    expect(result.status).toBe("ok");

    // No GitHub or Base host, from this process, at all.
    expect(directAuthorityCalls()).toEqual([]);
    // Everything it sent: NEAR's keyless discovery and enclave report, and the
    // three release-collateral operations.
    expect(recorder.calls.map((call) => `${call.method} ${new URL(call.url).origin}${new URL(call.url).pathname}`).sort()).toEqual([
      "GET http://127.0.0.1:9/endpoints",
      `GET https://${NEAR_ENCLAVE}/v1/attestation/report`,
      `POST ${role.url}${releaseCollateralPath("dstack-onchain-authorization")}`,
      `POST ${role.url}${releaseCollateralPath("github-publication")}`,
      `POST ${role.url}${releaseCollateralPath("github-release-images")}`
    ].sort());
  });

  it("Venice's NEAR-format routes: both Venice adapters go through the release-collateral role too", async () => {
    const role = await listenReleaseCollateral(recordedSources(veniceRecorded));
    poolEnvironment(role.url);
    const pool = await buildWorker();

    for (const fetchEvidence of [veniceEvidence, veniceFencedEvidence]) {
      recorder.calls = [];
      const evidence = await fetchEvidence(pool);
      const result = verifyVenice(evidence, veniceRecorded);
      expect(failedChecks(result)).toEqual([]);
      expect(result.status).toBe("ok");
      expect(directAuthorityCalls()).toEqual([]);
      expect(releaseCollateralCalls()).toHaveLength(3);
    }
  });

  it("what reaches the release-collateral role is the contract's fields and its own token, never a provider key", async () => {
    const role = await listenReleaseCollateral(recordedSources(nearRecorded));
    poolEnvironment(role.url);
    const pool = await buildWorker();
    await nearEvidence(pool);

    const calls = releaseCollateralCalls();
    expect(calls).toHaveLength(3);
    for (const call of calls) {
      expect(call.method).toBe("POST");
      expect(call.authorization).toBe(`Bearer ${RELEASE_COLLATERAL_TOKEN}`);
      // Not the worker's RPC token, a metadata token or a provider key.
      for (const secret of [WORKER_RPC_TOKEN, distinct("metadata-near-ai"), distinct("metadata-venice"), providerKey("near-ai"), providerKey("venice")]) {
        expect(`${call.authorization} ${call.body}`).not.toContain(secret);
      }
    }
    const bodies = Object.fromEntries(calls.map((call) => [new URL(call.url).pathname, JSON.parse(call.body!) as Record<string, unknown>]));
    expect(Object.keys(bodies[releaseCollateralPath("github-publication")]!).sort()).toEqual(["claims", "repository"]);
    expect(bodies[releaseCollateralPath("github-release-images")]).toEqual({ repository: RELEASES_REPOSITORY });
    const recorded = nearRecorded.onchain![0]!;
    expect(bodies[releaseCollateralPath("dstack-onchain-authorization")]).toEqual({
      registry: "near-base-mainnet",
      appId: recorded.appId.slice(2),
      composeHash: recorded.composeHash,
      osImageHash: recorded.osImageHash
    });
    // The NEAR and Venice provider requests still carry no key to the release-collateral host either.
    for (const call of recorder.calls.filter((entry) => !entry.url.startsWith(role.url))) {
      expect(call.authorization ?? "").not.toContain(RELEASE_COLLATERAL_TOKEN);
    }
  });

  it("with the role's real fetchers: the upstream is reached by the release-collateral role, and only by it", async () => {
    const upstream = new FakeUpstream();
    const recorded = nearRecorded.onchain![0]!;
    upstream.registeredApps.add(recorded.appId);
    upstream.allowedCompose.set(recorded.appId, new Set([recorded.composeHash]));
    upstream.allowedImages.add(recorded.osImageHash);
    const role = await listenReleaseCollateral(releaseCollateralSources({ fetch: upstream.fetch, budget: roomy(), now: () => T0 }));
    poolEnvironment(role.url);
    const pool = await buildWorker();

    const attached = collateralOf(await nearEvidence(pool));
    expect(attached.onchain![0]).toMatchObject({
      appId: recorded.appId, composeHash: recorded.composeHash, osImageHash: recorded.osImageHash,
      appRegistered: true, composeHashAllowed: true, osImageAllowed: true, chainId: 8453, rpc: "https://mainnet.base.org"
    });
    expect(attached.github![0]).toMatchObject({ repository: FILES_REPOSITORY, defaultBranchHead: upstream.head });
    expect(attached.githubReleases![0]).toMatchObject({ repository: RELEASES_REPOSITORY });

    // The lookups happened: the stub upstream saw GitHub and Base requests ...
    expect(upstream.to(...GITHUB_HOSTS).length).toBeGreaterThan(2);
    expect(upstream.to(...BASE_RPC_HOSTS)).toHaveLength(5);
    // ... and none of them came from the worker.
    expect(directAuthorityCalls()).toEqual([]);
  });

  it("a bare `?` on the wire is still a query string the role refuses", async () => {
    // The in-process tests cannot send this: their injector drops an empty query.
    const role = await listenReleaseCollateral(recordedSources(nearRecorded));
    const post = (path: string) => new Promise<number>((resolve, reject) => {
      // `path` is given as written: a URL object would drop the empty query.
      const outgoing = httpRequest({
        host: "127.0.0.1",
        port: new URL(role.url).port,
        path,
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${RELEASE_COLLATERAL_TOKEN}` }
      }, (response) => {
        response.resume();
        resolve(response.statusCode ?? 0);
      });
      outgoing.on("error", reject);
      outgoing.end(JSON.stringify({ repository: RELEASES_REPOSITORY }));
    });
    expect(await post(releaseCollateralPath("github-release-images"))).toBe(200);
    expect(await post(`${releaseCollateralPath("github-release-images")}?`)).toBe(400);
  });
});

describe("the release-collateral role is unavailable", () => {
  async function expectFailedClosed(pool: FastifyInstance, code: string) {
    const warned = vi.spyOn(pool.log, "warn");
    const evidence = await nearEvidence(pool);
    // The evidence still comes back: only the collateral is missing.
    expect(Object.keys(collateralOf(evidence))).toEqual(["dstackImages"]);
    const result = verifyNear(evidence, nearRecorded);
    expect(result.status).toBe("failed");
    expect(failedChecks(result)).toEqual(expect.arrayContaining(AUTHORITY_CHECKS));
    for (const name of AUTHORITY_CHECKS) {
      expect(result.checks.find((check) => check.name === name)?.passed, name).toBe(false);
    }
    // It did not go and fetch the collateral itself instead.
    expect(directAuthorityCalls()).toEqual([]);
    expect(releaseCollateralCalls()).toHaveLength(3);
    // One line per failed call: the operation and a fixed code, nothing asked.
    const lines = warned.mock.calls.filter(([, message]) => message === "release_collateral_rpc_failed").map(([fields]) => fields);
    expect(lines.sort((a, b) => String((a as { operation: string }).operation).localeCompare((b as { operation: string }).operation))).toEqual([
      { operation: "dstack-onchain-authorization", error_type: code },
      { operation: "github-publication", error_type: code },
      { operation: "github-release-images", error_type: code }
    ]);
  }

  it("down: the authority checks fail, and the pool does not fall back to GitHub or Base", async () => {
    poolEnvironment(await downReleaseCollateral());
    await expectFailedClosed(await buildWorker(), "release_collateral_unreachable");
  });

  it("refusing the pool's token: the same", async () => {
    const role = await listenReleaseCollateral(recordedSources(nearRecorded), distinct("another-release-collateral-token"));
    poolEnvironment(role.url);
    await expectFailedClosed(await buildWorker(), "service_unauthorized");
  });

  it("answering but unable to complete a lookup: the same", async () => {
    const upstream = new FakeUpstream();
    upstream.failing = new Set(AUTHORITY_HOSTS);
    const role = await listenReleaseCollateral(releaseCollateralSources({ fetch: upstream.fetch, budget: roomy(), now: () => T0 }));
    poolEnvironment(role.url);
    await expectFailedClosed(await buildWorker(), "release_collateral_unavailable");
  });

  it("Venice's NEAR-format routes fail closed the same way, on both adapters", async () => {
    poolEnvironment(await downReleaseCollateral());
    const pool = await buildWorker();
    for (const fetchEvidence of [veniceEvidence, veniceFencedEvidence]) {
      const evidence = await fetchEvidence(pool);
      expect(Object.keys(collateralOf(evidence))).toEqual(["dstackImages"]);
      const result = verifyVenice(evidence, veniceRecorded);
      expect(result.status).toBe("failed");
      expect(failedChecks(result)).toEqual(expect.arrayContaining(AUTHORITY_CHECKS));
    }
    expect(directAuthorityCalls()).toEqual([]);
  });
});

describe("the control: a single-provider worker still makes these lookups itself", () => {
  // Without this, "the pool made no GitHub or Base request" could be true of a
  // recorder that cannot see one. Same evidence, same recorder, no
  // release-collateral role: the requests appear, to the hosts and paths the
  // fetchers always used.
  it.each<["near-worker" | "venice-worker", (server: FastifyInstance) => Promise<Record<string, unknown>>]>([
    ["near-worker", nearEvidence],
    ["venice-worker", veniceEvidence]
  ])("%s", async (role, fetchEvidence) => {
    singleEnvironment(role);
    const worker = await buildWorker();
    const evidence = await fetchEvidence(worker);
    // The recorder fails them, so no collateral was gathered ...
    expect(Object.keys(collateralOf(evidence))).toEqual(["dstackImages"]);
    // ... but they were attempted, directly, by this process.
    const attempted = directAuthorityCalls().map((call) => `${call.method} ${call.url}`);
    expect(attempted).toEqual(expect.arrayContaining([
      `GET https://github.com/${FILES_REPOSITORY}.git/info/refs?service=git-upload-pack`,
      `GET https://api.github.com/repos/${RELEASES_REPOSITORY}/releases?per_page=100`,
      "POST https://mainnet.base.org",
      "POST https://base-rpc.publicnode.com"
    ]));
    for (const call of directAuthorityCalls()) expect(call.authorization).toBeNull();
    expect(recorder.calls.some((call) => call.url.includes("/internal/release-collateral/"))).toBe(false);
  });

  it("the pool, given the same evidence, attempts none of them", async () => {
    const role = await listenReleaseCollateral(recordedSources(nearRecorded));
    poolEnvironment(role.url);
    const pool = await buildWorker();
    await nearEvidence(pool);
    await veniceEvidence(pool).catch(() => undefined);
    expect(directAuthorityCalls()).toEqual([]);
    expect(releaseCollateralCalls().length).toBeGreaterThanOrEqual(3);
  });
});
