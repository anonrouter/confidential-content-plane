// The release-collateral role's contract, enforced by the SERVER (PROVIDER_POOL_PLAN.md,
// W3; review findings C2 and S1).
//
// The role makes release-authority lookups for a caller it does not trust: a
// compromised pool holds every pooled key and prompt, and a deputy that
// forwards what it is handed discloses those to GitHub or an RPC node even on a
// 404. So these tests are written from the caller's side. Each one sends the
// real release-collateral server (built by the role's own builder, from a production
// configuration) a request with a canary encoded where a field allows the
// caller to vary something, and reads the result off ONE list: every request
// the role's fetchers sent upstream. A refused request must leave that list
// empty.
//
// The upstream is tests/helpers/releaseCollateralUpstream.ts. Nothing opens a
// socket.
//
// NOTHING HERE WAITS ON A DURATION OR READS THE WALL CLOCK. The role's two
// readings of time (the clock its allowances refill on, and the signal that
// ends a lookup at its deadline) are injected, and a test that needs a lookup
// to be in flight waits for the upstream request to ARRIVE. And nothing is
// compared against a response body as text: every response carries a random
// request id, so "the body does not contain X" is only true most of the time.

import { createHash } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../../src/config.js";
import { LOGGED_FIELD_ALLOWLIST, LOGGED_MESSAGE_ALLOWLIST } from "../../src/logger.js";
import { DSTACK_IMAGE_MEASUREMENTS } from "../../src/providers/attestation/authority/dstackImages.generated.js";
import { DEFAULT_HOST_BUDGETS, RequestBudget } from "../../src/providers/attestation/authority/fetchLayer.js";
import {
  RELEASE_COLLATERAL_BODY_LIMIT_BYTES,
  RELEASE_COLLATERAL_OPERATIONS,
  canonicalClaims,
  releaseCollateralPath,
  contractClaims,
  contractOnchainSubject,
  isComposeFilePath,
  MAX_PUBLICATION_CLAIMS,
  ONCHAIN_REGISTRIES,
  PUBLICATION_REPOSITORIES,
  RELEASE_REPOSITORIES,
  type ReleaseCollateralOperation
} from "../../src/releaseCollateral/contract.js";
import {
  RELEASE_COLLATERAL_HOST_BUDGETS,
  RELEASE_COLLATERAL_LIMITS,
  ReleaseCollateralAdmission,
  releaseCollateralErrorHandler,
  releaseCollateralSources,
  type ReleaseCollateralLimits
} from "../../src/releaseCollateral/server.js";
import { buildReleaseCollateralServer } from "../../src/roles.js";
import {
  BASE_RPC_HOSTS,
  FakeUpstream,
  FILES_REPOSITORY,
  KMS_ADDRESS,
  RELEASES_REPOSITORY,
  UPSTREAM_ERROR_WORDS
} from "../helpers/releaseCollateralUpstream.js";

const T0 = Date.parse("2026-10-03T12:00:00Z");
const distinct = (seed: string) => `prod-${seed}-${"x".repeat(40)}`.slice(0, 48);
const TOKEN = distinct("release-collateral-token");
const AUTH = { authorization: `Bearer ${TOKEN}` };

// A development-only dummy secret, recognisable so a leak search can find it.
const CANARY = "sk-DEVDUMMY-release-authority-canary-7Qx9";
const CANARY_HEX = Buffer.from(CANARY).toString("hex");
const CANARY_B64 = Buffer.from(CANARY).toString("base64url");
const CANARY_FORMS = [CANARY, CANARY_HEX, CANARY_HEX.toUpperCase(), CANARY_B64, CANARY_HEX.slice(0, 38)];

const HEAD = "a".repeat(40);
const TAGGED = "b".repeat(40);
const ANCESTOR = "c".repeat(40);
const FORK = "d".repeat(40);
const APP = "2c".repeat(20);
const COMPOSE = "c8".repeat(32);
const IMAGE = DSTACK_IMAGE_MEASUREMENTS[0]!.osImageHash;
const REGISTRY = "near-base-mainnet";

const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");

function standardUpstream(): FakeUpstream {
  const upstream = new FakeUpstream();
  upstream.head = HEAD;
  upstream.tags = { "v0.0.461": TAGGED };
  upstream.ancestors = new Set([ANCESTOR]);
  upstream.files.set(`${TAGGED}/prod/x.yaml`, "services: {}\n");
  upstream.files.set(`${ANCESTOR}/prod/y.yaml`, "services: { y: 1 }\n");
  upstream.registeredApps.add(`0x${APP}`);
  upstream.allowedCompose.set(`0x${APP}`, new Set([COMPOSE]));
  upstream.allowedImages.add(IMAGE);
  return upstream;
}

const PUBLICATION = { repository: FILES_REPOSITORY, claims: [{ commit: TAGGED, path: "prod/x.yaml", tag: "v0.0.461" }] };
const RELEASES = { repository: RELEASES_REPOSITORY };
const ONCHAIN = { registry: REGISTRY, appId: APP, composeHash: COMPOSE, osImageHash: IMAGE };
const VALID: Record<ReleaseCollateralOperation, Record<string, unknown>> = {
  "github-publication": PUBLICATION,
  "github-release-images": RELEASES,
  "dstack-onchain-authorization": ONCHAIN
};

interface LogCall {
  level: string;
  fields: Record<string, unknown>;
  message: unknown;
}

interface Harness {
  server: FastifyInstance;
  upstream: FakeUpstream;
  admission: ReleaseCollateralAdmission;
  logs: LogCall[];
  clock: { now: () => number; advance: (ms: number) => void };
}

let snapshot: NodeJS.ProcessEnv;
let config: AppConfig;
const servers: FastifyInstance[] = [];

beforeAll(() => {
  snapshot = { ...process.env };
  for (const key of Object.keys(process.env)) {
    if (/^(RUNTIME_ROLE|POOL_PROVIDERS|RELEASE_COLLATERAL_|LOG_LEVEL|RELAY_RPC|WORKER_RPC|METADATA_RPC|COMPAT_RPC|VENICE_|FIREWORKS_|DEEPINFRA_|CHUTES_|TINFOIL_|NEAR_|PHALA_AI_|BEDROCK_|AWS_|APP_SECRET|EMAIL_|COOKIE_SECRET|BETTER_AUTH_SECRET|ADMIN_|SMTP_|DATABASE_URL|MIGRATION_DATABASE_URL|APP_DB|GATEWAY_|DSTACK_|REDIS_URL|STRIPE_|CONSUMED_CAPABILITY|CREDENTIAL_|CONTENT_TLS|PROVIDER_CAPABILITY|PROVIDER_CREDENTIAL|TRUST_PROXY_HOPS)/.test(key)) {
      delete process.env[key];
    }
  }
  // The role as production runs it: its one secret and nothing else.
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
});

function makeClock() {
  let at = T0;
  return { now: () => at, advance: (ms: number) => { at += ms; } };
}

/** A lookup deadline that never arrives: no timer is armed at all. */
const NEVER = () => new AbortController().signal;

/** The request id every response carries: random, so matched by shape and never by content. */
const REQUEST_ID = /^req_[0-9a-z]{26}$/;

async function harness(options: {
  limits?: Partial<ReleaseCollateralLimits>;
  upstream?: FakeUpstream;
  /** The fetchers' per-host budget. Roomy unless a test is about it; "role" is the role's own. */
  budget?: "role";
  /** The signal that ends a lookup at its deadline. One that never fires unless a test is about it. */
  deadline?: (ms: number) => AbortSignal;
} = {}): Promise<Harness> {
  const upstream = options.upstream ?? standardUpstream();
  const clock = makeClock();
  const admission = new ReleaseCollateralAdmission(options.limits, clock.now, options.deadline ?? NEVER);
  const logs: LogCall[] = [];
  // "role": no budget is handed in, so the role builds its own, on this clock.
  const budget = options.budget === "role" ? undefined : new RequestBudget({}, clock.now, { burst: 100_000, perHour: 100_000 });
  const server = await buildReleaseCollateralServer(config, {
    sources: releaseCollateralSources({ fetch: upstream.fetch, budget, now: clock.now, limits: options.limits }),
    admission,
    // Every log call the role makes, as written, before the logger's own
    // allowlist touches it.
    observe: (instance) => {
      instance.addHook("onRequest", async (request: FastifyRequest) => {
        const log = request.log as unknown as Record<string, (...args: unknown[]) => void>;
        for (const level of ["info", "warn", "error"]) {
          const original = log[level]!.bind(request.log);
          log[level] = (...args: unknown[]) => {
            logs.push({ level, fields: (args[0] ?? {}) as Record<string, unknown>, message: args[1] });
            original(...args);
          };
        }
      });
    }
  });
  await server.ready();
  servers.push(server);
  return { server, upstream, admission, logs, clock };
}

interface Sent {
  status: number;
  body: string;
  type: string | undefined;
  reason: string | undefined;
  json: Record<string, unknown>;
  retryAfter: string | undefined;
}

async function send(
  h: Harness,
  target: ReleaseCollateralOperation | { path: string; method?: "POST" | "GET" | "PUT" },
  payload: unknown,
  headers: Record<string, string> = AUTH
): Promise<Sent> {
  const path = typeof target === "string" ? releaseCollateralPath(target) : target.path;
  const method = typeof target === "string" ? "POST" : target.method ?? "POST";
  const response = await h.server.inject({
    method,
    url: path,
    headers: { "content-type": "application/json", ...headers },
    payload: typeof payload === "string" ? payload : JSON.stringify(payload)
  });
  let json: Record<string, unknown> = {};
  try {
    json = response.json() as Record<string, unknown>;
  } catch {
    // A non-JSON body is asserted on by status.
  }
  const error = json.error as { type?: string; reason?: string } | undefined;
  return {
    status: response.statusCode,
    body: response.body,
    type: error?.type,
    reason: error?.reason,
    json,
    retryAfter: response.headers["retry-after"] as string | undefined
  };
}

/** No log line carries anything but reviewed names, and none carries caller data. */
function expectContentFreeLogs(h: Harness, ...forbidden: string[]) {
  for (const call of h.logs) {
    expect(LOGGED_MESSAGE_ALLOWLIST.has(String(call.message)), `message ${String(call.message)}`).toBe(true);
    for (const key of Object.keys(call.fields)) expect(LOGGED_FIELD_ALLOWLIST.has(key), `field ${key}`).toBe(true);
    // The request id is random: checked by shape, and left out of the text the
    // forbidden values are searched for in.
    const { request_id: requestId, ...fields } = call.fields;
    expect(String(requestId)).toMatch(REQUEST_ID);
    const line = JSON.stringify({ level: call.level, fields, message: call.message });
    for (const value of [...CANARY_FORMS, ...forbidden]) expect(line).not.toContain(value);
  }
}

/** Refused, with a fixed answer, having sent nothing anywhere. */
function expectRefused(h: Harness, sent: Sent, status = 400, type = "release_collateral_request_refused") {
  expect(sent.status, sent.body).toBe(status);
  // The WHOLE body, field for field: a fixed message, a fixed code and the
  // request id. There is no fourth field for anything the caller sent to be
  // repeated in, which is a stronger statement than "the canary is not in it"
  // and does not depend on what the random id happens to spell.
  expect(sent.json).toEqual({
    error: { message: "Release-collateral request refused", type, request_id: expect.stringMatching(REQUEST_ID) }
  });
  expect(h.upstream.requests, "a refused request reached an upstream").toEqual([]);
  expectContentFreeLogs(h);
  const refusal = h.logs.filter((call) => call.message === "release_collateral_request_refused");
  expect(refusal.length).toBeGreaterThan(0);
}

// --- the contract's own lists ----------------------------------------------------

describe("what a request may pick from", () => {
  it("is exactly the repositories and the registry the fetchers already name", () => {
    expect([...RELEASE_COLLATERAL_OPERATIONS]).toEqual(["github-publication", "github-release-images", "dstack-onchain-authorization"]);
    expect([...PUBLICATION_REPOSITORIES]).toEqual(["nearai/cvm-compose-files"]);
    expect([...RELEASE_REPOSITORIES]).toEqual(["nearai/compose-manager"]);
    expect(ONCHAIN_REGISTRIES).toEqual({
      "near-base-mainnet": { chainId: 8453, kms: "0x8fa1593fac104c1aa0c59eaa3553f7e3e162d637" }
    });
  });

  it("admits every compose path in the captured NEAR and Venice evidence", () => {
    // Every path the live logs name (tests/fixtures/hw-evidence), written out.
    for (const path of [
      "prod/GLM-5.3-Flash-SGL-TP4.yaml", "prod/GLM-5.3-Flash-SGL-TP4-Canary.yaml",
      "prod/GLM-5.3-Flash-SGL-TP4-LongContext.yaml", "prod/GLM-5.3-Flash-SGL-TP4-W4AFP8-Canary.yaml",
      "prod/GLM-5.3-Flash-SGL-TP4-W4AFP8-LongContext.yaml", "prod/rotate-compose-manager-token.yaml",
      "prod/GLM-5.3-Flash-SGL-TP4-W4AFP8.yaml", "dsv4-qwen36-gemma4.yaml", "glm51_otel_test.yaml",
      "deepseek-v4-gemma4-int4-autoround-test.yaml", "GLM-5.1-SGL-AWQ-TP4.yaml", "prod/GLM-5.1-SGL-AWQ-TP4.yaml",
      "cleanup-hf-model.yaml", "prod/small-models.yaml", "prod/migration-gpu-preflight.yaml",
      "prod/gpu13-qwen-handover.yaml", "experiments/GLM-5.3-gpu23-local-engine-bench.yaml",
      "prod/GLM-5.3-Flash-SGL-TP4-HiCache.yaml"
    ]) expect(isComposeFilePath(path), path).toBe(true);
    // The longest shapes it admits, and one past each.
    expect(isComposeFilePath(`${"d".repeat(24)}/${"n".repeat(64)}.yaml`)).toBe(true);
    expect(isComposeFilePath(`${"d".repeat(25)}/n.yaml`)).toBe(false);
    expect(isComposeFilePath(`${"n".repeat(65)}.yaml`)).toBe(false);
    expect(isComposeFilePath("a/b/c.yaml")).toBe(false);
  });

  it("puts claims in one order whatever order they arrived in, and drops repeats", () => {
    const a = { commit: TAGGED, path: "prod/x.yaml", tag: "v1" };
    const b = { commit: ANCESTOR, path: "prod/y.yaml" };
    const c = { commit: TAGGED, path: "a.yaml" };
    expect(canonicalClaims([a, b, c, a])).toEqual(canonicalClaims([c, a, b]));
    expect(canonicalClaims([a, b, c, a])).toHaveLength(3);
  });

  it("prepares a log's claims for the wire the way the fetcher reads them", () => {
    expect(contractClaims([
      { commit: TAGGED.toUpperCase(), path: "prod/x.yaml", tag: "v1" },
      // Unusable to the fetcher too: dropped.
      { commit: "", path: "prod/x.yaml", tag: null },
      { commit: TAGGED, path: "", tag: "v1" },
      // An unsafe tag is ignored, the claim is kept.
      { commit: ANCESTOR, path: "prod/y.yaml", tag: "bad tag" },
      // The contract's own narrowing: a path outside its shapes is not sent.
      { commit: ANCESTOR, path: "deep/er/z.yaml", tag: null }
    ])).toEqual([
      { commit: TAGGED, path: "prod/x.yaml", tag: "v1" },
      { commit: ANCESTOR, path: "prod/y.yaml" }
    ]);
    expect(contractOnchainSubject({ appId: `0x${APP.toUpperCase()}`, composeHash: COMPOSE.toUpperCase(), osImageHash: IMAGE }))
      .toEqual({ appId: APP, composeHash: COMPOSE, osImageHash: IMAGE });
    expect(contractOnchainSubject({ appId: "nope", composeHash: COMPOSE, osImageHash: IMAGE })).toBeNull();
  });
});

// --- authentication ---------------------------------------------------------------

describe("a caller without the release-collateral token", () => {
  const callers: Array<[string, Record<string, string>]> = [
    ["no authorization header", {}],
    ["a wrong token", { authorization: `Bearer ${distinct("some-other-token")}` }],
    ["the token without the scheme", { authorization: TOKEN }],
    ["another scheme", { authorization: `Basic ${Buffer.from(`pool:${TOKEN}`).toString("base64")}` }],
    ["a prefix of the token", { authorization: `Bearer ${TOKEN.slice(0, -1)}` }],
    ["the token with a suffix", { authorization: `Bearer ${TOKEN}x` }]
  ];

  it.each(callers)("is refused on every operation, before any work: %s", async (_label, headers) => {
    const h = await harness();
    for (const operation of RELEASE_COLLATERAL_OPERATIONS) {
      const sent = await send(h, operation, VALID[operation], headers);
      expect(sent.status, operation).toBe(401);
      expect(sent.type).toBe("service_unauthorized");
    }
    expect(h.upstream.requests).toEqual([]);
    expect(h.admission.stats()).toEqual({ inFlight: 0, publicationSubjects: 0, onchainSubjects: 0 });
    expectContentFreeLogs(h);
  });

  it("is refused before the body is read: a malformed or oversized body is still a 401", async () => {
    const h = await harness();
    for (const operation of RELEASE_COLLATERAL_OPERATIONS) {
      expect((await send(h, operation, "{ not json", {})).status, operation).toBe(401);
      expect((await send(h, operation, { pad: "x".repeat(RELEASE_COLLATERAL_BODY_LIMIT_BYTES[operation] + 1) }, {})).status, operation).toBe(401);
    }
    expect((await send(h, { path: "/internal/release-collateral/v1/anything" }, {}, {})).status).toBe(401);
    expect(h.upstream.requests).toEqual([]);
  });

  it("spends none of the request allowance", async () => {
    // One request is all the allowance there is. Ten refused callers later it
    // must still be there for the pool.
    const h = await harness({ limits: { requestBurst: 1, requestsPerMinute: 1 } });
    for (let i = 0; i < 10; i += 1) expect((await send(h, "github-release-images", RELEASES, {})).status).toBe(401);
    expect((await send(h, "github-release-images", RELEASES)).status).toBe(200);
  });

  it("an empty configured token admits no one, not everyone", async () => {
    const upstream = standardUpstream();
    const server = await buildReleaseCollateralServer(
      { ...config, internal: { ...config.internal, releaseCollateralRpcToken: "" } },
      { sources: releaseCollateralSources({ fetch: upstream.fetch, now: () => T0 }), admission: new ReleaseCollateralAdmission({}, () => T0, NEVER) }
    );
    servers.push(server);
    for (const headers of [{}, { authorization: "Bearer " }, { authorization: "Bearer" }]) {
      const response = await server.inject({ method: "POST", url: releaseCollateralPath("github-release-images"), headers: { "content-type": "application/json", ...headers }, payload: JSON.stringify(RELEASES) });
      expect(response.statusCode).toBe(401);
    }
    expect(upstream.requests).toEqual([]);
  });
});

// --- refusals: a canary in every variable field ---------------------------------

describe("github-publication refuses, with zero upstream requests", () => {
  const claim = (overrides: Record<string, unknown>) => ({
    repository: FILES_REPOSITORY,
    claims: [{ commit: TAGGED, path: "prod/x.yaml", tag: "v0.0.461", ...overrides }]
  });
  const without = (field: string) => {
    const entry: Record<string, unknown> = { commit: TAGGED, path: "prod/x.yaml", tag: "v0.0.461" };
    delete entry[field];
    return { repository: FILES_REPOSITORY, claims: [entry] };
  };

  it.each<[string, unknown]>([
    // repository: only by picking the one entry, spelled exactly.
    ["an unknown repository", { ...PUBLICATION, repository: "evil/cvm-compose-files" }],
    ["a repository allowed for another operation", { ...PUBLICATION, repository: RELEASES_REPOSITORY }],
    ["the repository as a URL", { ...PUBLICATION, repository: `https://github.com/${FILES_REPOSITORY}` }],
    ["the repository in another case", { ...PUBLICATION, repository: "NearAI/cvm-compose-files" }],
    ["the repository with .git", { ...PUBLICATION, repository: `${FILES_REPOSITORY}.git` }],
    ["the repository with a trailing slash", { ...PUBLICATION, repository: `${FILES_REPOSITORY}/` }],
    ["a canary after the repository", { ...PUBLICATION, repository: `${FILES_REPOSITORY}/${CANARY_HEX}` }],
    ["a repository that is a path traversal", { ...PUBLICATION, repository: `${FILES_REPOSITORY}/../../${CANARY_B64}` }],
    ["no repository", { claims: PUBLICATION.claims }],
    ["a repository list", { ...PUBLICATION, repository: [FILES_REPOSITORY] }],

    // commit: exactly 40 lowercase hex.
    ["a canary commit one character too long", claim({ commit: CANARY_HEX.slice(0, 41) })],
    ["a canary commit one character too short", claim({ commit: CANARY_HEX.slice(0, 39) })],
    ["a canary commit in upper case", claim({ commit: CANARY_HEX.slice(0, 40).toUpperCase() })],
    ["a canary commit with 0x", claim({ commit: `0x${CANARY_HEX.slice(0, 38)}` })],
    ["a canary commit that is not hex", claim({ commit: CANARY_B64.padEnd(40, "A").slice(0, 40) })],
    ["a 64-hex hash where a commit goes", claim({ commit: CANARY_HEX.slice(0, 64) })],
    ["a commit with a path in it", claim({ commit: `${TAGGED.slice(0, 20)}/../${CANARY_HEX.slice(0, 16)}` })],
    ["a commit that is a ref name", claim({ commit: "main" })],
    ["a commit that is a number", claim({ commit: 12345 })],
    ["a commit that is a list", claim({ commit: [TAGGED] })],
    ["no commit", without("commit")],

    // path: <name>.yaml, at the root or under one directory.
    ["the fetcher's old 512-character path", claim({ path: `${CANARY_HEX.repeat(8).slice(0, 507)}.yaml` })],
    ["a path one directory character too long", claim({ path: `${"d".repeat(25)}/x.yaml` })],
    ["a path one name character too long", claim({ path: `prod/${CANARY_HEX.slice(0, 65)}.yaml` })],
    ["a path two directories deep", claim({ path: `prod/${CANARY_HEX.slice(0, 20)}/x.yaml` })],
    ["a path three directories deep", claim({ path: "a/b/c/x.yaml" })],
    ["a parent traversal", claim({ path: "../x.yaml" })],
    ["a traversal under a directory", claim({ path: "prod/../x.yaml" })],
    ["an absolute path", claim({ path: "/prod/x.yaml" })],
    ["an empty directory", claim({ path: "prod//x.yaml" })],
    ["a query string", claim({ path: `prod/x.yaml?k=${CANARY_HEX}` })],
    ["a fragment", claim({ path: `prod/x.yaml#${CANARY_HEX}` })],
    ["percent-encoding", claim({ path: "prod/%2e%2e/x.yaml" })],
    ["characters the fetcher allowed and this does not (+)", claim({ path: `prod/${CANARY_B64}+x.yaml` })],
    ["characters the fetcher allowed and this does not (@)", claim({ path: `prod/x@${CANARY_HEX.slice(0, 20)}.yaml` })],
    ["a space", claim({ path: "prod/x y.yaml" })],
    ["a trailing newline", claim({ path: "prod/x.yaml\n" })],
    ["a NUL", claim({ path: "prod/x\u0000.yaml" })],
    ["a non-ASCII name", claim({ path: "prod/é.yaml" })],
    ["a backslash", claim({ path: "prod\\x.yaml" })],
    ["another extension", claim({ path: `prod/${CANARY_HEX.slice(0, 30)}.json` })],
    ["no extension", claim({ path: `prod/${CANARY_HEX.slice(0, 30)}` })],
    ["an upper-case extension", claim({ path: "prod/x.YAML" })],
    ["a hidden file", claim({ path: "prod/.x.yaml" })],
    ["a hidden directory", claim({ path: ".github/x.yaml" })],
    ["a name starting with a dash", claim({ path: "-x.yaml" })],
    ["an empty path", claim({ path: "" })],
    ["a path that is a list", claim({ path: ["prod/x.yaml"] })],
    ["a URL", claim({ path: `https://attacker.example/${CANARY_HEX}.yaml` })],
    ["no path", without("path")],

    // tag: the fetcher's ref-name shape.
    ["a canary tag over 200 characters", claim({ tag: CANARY_HEX.repeat(3).slice(0, 201) })],
    ["a tag with a space", claim({ tag: `v1 ${CANARY}` })],
    ["a tag with ..", claim({ tag: `v1..${CANARY_HEX}` })],
    ["a tag ending .lock", claim({ tag: `${CANARY_HEX}.lock` })],
    ["a tag with @{", claim({ tag: `v1@{${CANARY_HEX}}` })],
    ["a tag starting with a slash", claim({ tag: `/${CANARY_HEX}` })],
    ["a tag ending with a slash", claim({ tag: `${CANARY_HEX}/` })],
    ["a tag with a control character", claim({ tag: `v1\n${CANARY_HEX}` })],
    ["a tag with a colon", claim({ tag: `refs:${CANARY_HEX}` })],
    ["a null tag", claim({ tag: null })],
    ["a tag that is a number", claim({ tag: 461 })],
    ["an empty tag", claim({ tag: "" })],

    // No field for anything else.
    ["an extra top-level field", { ...PUBLICATION, url: `https://attacker.example/${CANARY_HEX}` }],
    ["a head for the compare", { ...PUBLICATION, head: CANARY_HEX.slice(0, 40) }],
    ["headers", { ...PUBLICATION, headers: { "x-canary": CANARY } }],
    ["a query", { ...PUBLICATION, query: { per_page: CANARY_HEX } }],
    ["an extra field on a claim", claim({ sha256: CANARY_HEX.slice(0, 64) })],
    ["a ref on a claim", claim({ ref: `refs/heads/${CANARY_HEX}` })],
    ["a nested repository on a claim", claim({ repository: "evil/repo" })],

    // Shape of the whole.
    ["claims that are not a list", { repository: FILES_REPOSITORY, claims: { 0: PUBLICATION.claims[0] } }],
    ["a claim that is a string", { repository: FILES_REPOSITORY, claims: [`${TAGGED}:prod/x.yaml`] }],
    ["no claims field", { repository: FILES_REPOSITORY }],
    ["one claim too many", {
      repository: FILES_REPOSITORY,
      claims: Array.from({ length: MAX_PUBLICATION_CLAIMS + 1 }, (_, index) => ({ commit: TAGGED, path: `prod/f${index}.yaml` }))
    }],
    ["a batch of two valid requests", [PUBLICATION, PUBLICATION]],
    ["a batch of one", [PUBLICATION]],
    ["a JSON string", JSON.stringify(JSON.stringify(PUBLICATION))],
    ["null", "null"],
    ["a body that is not JSON", `repository=${FILES_REPOSITORY}&commit=${CANARY_HEX}`]
  ])("%s", async (_label, payload) => {
    const h = await harness();
    expectRefused(h, await send(h, "github-publication", payload));
    expect(h.admission.stats().publicationSubjects).toBe(0);
  });

  it("a body over the size limit, whatever it says", async () => {
    const h = await harness();
    const oversized = { ...PUBLICATION, pad: CANARY_HEX.repeat(Math.ceil(RELEASE_COLLATERAL_BODY_LIMIT_BYTES["github-publication"] / CANARY_HEX.length) + 1) };
    expectRefused(h, await send(h, "github-publication", oversized), 413);
  });

  it("one bad claim among good ones refuses them all", async () => {
    const h = await harness();
    expectRefused(h, await send(h, "github-publication", {
      repository: FILES_REPOSITORY,
      claims: [...PUBLICATION.claims, { commit: ANCESTOR, path: "prod/y.yaml" }, { commit: ANCESTOR, path: `prod/${CANARY_HEX}/z.yaml` }]
    }));
  });
});

describe("github-release-images refuses, with zero upstream requests", () => {
  it.each<[string, unknown]>([
    ["an unknown repository", { repository: "evil/compose-manager" }],
    ["a repository allowed for another operation", { repository: FILES_REPOSITORY }],
    ["the repository as a URL", { repository: `https://api.github.com/repos/${RELEASES_REPOSITORY}/releases` }],
    ["the repository in another case", { repository: "nearai/Compose-Manager" }],
    ["a canary after the repository", { repository: `${RELEASES_REPOSITORY}/releases/tags/${CANARY_HEX}` }],
    ["no repository", {}],
    ["a tag", { ...RELEASES, tag: `prod-${CANARY_HEX}` }],
    ["a page", { ...RELEASES, page: 2 }],
    ["a page size", { ...RELEASES, per_page: 100 }],
    ["an etag", { ...RELEASES, etag: `"${CANARY_HEX}"` }],
    ["a url", { ...RELEASES, url: `https://attacker.example/${CANARY_HEX}` }],
    ["a batch", [RELEASES, RELEASES]],
    ["null", "null"]
  ])("%s", async (_label, payload) => {
    const h = await harness();
    expectRefused(h, await send(h, "github-release-images", payload));
  });

  it("a body over the size limit", async () => {
    const h = await harness();
    expectRefused(h, await send(h, "github-release-images", { ...RELEASES, pad: CANARY_HEX.repeat(8) }), 413);
  });
});

describe("dstack-onchain-authorization refuses, with zero upstream requests", () => {
  const subject = (overrides: Record<string, unknown>) => ({ ...ONCHAIN, ...overrides });
  const without = (field: string) => {
    const body: Record<string, unknown> = { ...ONCHAIN };
    delete body[field];
    return body;
  };

  it.each<[string, unknown]>([
    // registry: only by name.
    ["an unknown registry", subject({ registry: "near-ethereum-mainnet" })],
    ["the registry as its address", subject({ registry: KMS_ADDRESS })],
    ["the registry as an RPC URL", subject({ registry: `https://attacker.example/${CANARY_HEX}` })],
    ["a canary registry", subject({ registry: CANARY_HEX.slice(0, 40) })],
    ["no registry", without("registry")],

    // appId: exactly 40 lowercase hex, no 0x.
    ["an app id with 0x", subject({ appId: `0x${APP}` })],
    ["a canary app id in upper case", subject({ appId: CANARY_HEX.slice(0, 40).toUpperCase() })],
    ["a canary app id one character too long", subject({ appId: CANARY_HEX.slice(0, 41) })],
    ["a canary app id one character too short", subject({ appId: CANARY_HEX.slice(0, 39) })],
    ["a 32-byte value where the address goes", subject({ appId: CANARY_HEX.slice(0, 64) })],
    ["an app id that is not hex", subject({ appId: CANARY_B64.padEnd(40, "A").slice(0, 40) })],
    ["an app id that is a number", subject({ appId: 44 })],
    ["no app id", without("appId")],

    // composeHash: exactly 64 lowercase hex.
    ["a canary compose hash one character too long", subject({ composeHash: CANARY_HEX.slice(0, 65) })],
    ["a canary compose hash one character too short", subject({ composeHash: CANARY_HEX.slice(0, 63) })],
    ["a canary compose hash in upper case", subject({ composeHash: CANARY_HEX.slice(0, 64).toUpperCase() })],
    ["a compose hash with 0x", subject({ composeHash: `0x${COMPOSE}` })],
    ["a compose hash that is not hex", subject({ composeHash: "z".repeat(64) })],
    ["calldata where the compose hash goes", subject({ composeHash: `2f6622e5${COMPOSE}` })],
    ["no compose hash", without("composeHash")],

    // osImageHash: 64 lowercase hex AND a published image.
    ["an image hash one character too long", subject({ osImageHash: `${IMAGE}0` })],
    ["an image hash one character too short", subject({ osImageHash: IMAGE.slice(1) })],
    ["an image hash in upper case", subject({ osImageHash: IMAGE.toUpperCase() })],
    ["an image hash with 0x", subject({ osImageHash: `0x${IMAGE}` })],
    ["no image hash", without("osImageHash")],

    // No field for anything the server builds.
    ["a block number", subject({ blockNumber: "0x1" })],
    ["a block tag", subject({ block: "latest" })],
    ["a callee", subject({ to: `0x${CANARY_HEX.slice(0, 40)}` })],
    ["calldata", subject({ data: `0x${CANARY_HEX}` })],
    ["a selector", subject({ selector: "0x2f6622e5" })],
    ["a JSON-RPC id", subject({ id: CANARY })],
    ["a JSON-RPC method", subject({ method: "eth_getLogs" })],
    ["JSON-RPC params", subject({ params: [{ to: KMS_ADDRESS, data: `0x${CANARY_HEX}` }, "latest"] })],
    ["a state override", subject({ stateOverride: { [KMS_ADDRESS]: { code: `0x${CANARY_HEX}` } } })],
    ["call options", subject({ from: `0x${CANARY_HEX.slice(0, 40)}`, gas: "0xffff", value: "0x1" })],
    ["an RPC endpoint", subject({ rpc: `https://attacker.example/${CANARY_HEX}` })],
    ["a chain id", subject({ chainId: 1 })],
    ["a KMS address", subject({ kms: `0x${CANARY_HEX.slice(0, 40)}` })],
    ["a batch of two valid requests", [ONCHAIN, ONCHAIN]],
    ["a JSON-RPC batch", [{ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: KMS_ADDRESS, data: `0x${CANARY_HEX}` }, "latest"] }]],
    ["a raw JSON-RPC call", { jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: KMS_ADDRESS, data: `0x${CANARY_HEX}` }, "latest"] }],
    ["null", "null"]
  ])("%s", async (_label, payload) => {
    const h = await harness();
    expectRefused(h, await send(h, "dstack-onchain-authorization", payload));
    expect(h.admission.stats().onchainSubjects).toBe(0);
  });

  it("a well-formed image hash that is not an image dstack published", async () => {
    // 64 lowercase hex, so the shape passes: the server refuses it because it
    // is not in the list the server itself holds.
    const h = await harness();
    const canaryImage = sha256(CANARY);
    expectRefused(h, await send(h, "dstack-onchain-authorization", { ...ONCHAIN, osImageHash: canaryImage }), 400, "release_collateral_os_image_unknown");
    expect(h.admission.stats().onchainSubjects).toBe(0);
    // Every image the server holds is admitted.
    for (const image of DSTACK_IMAGE_MEASUREMENTS) {
      h.upstream.allowedImages.add(image.osImageHash);
      expect((await send(h, "dstack-onchain-authorization", { ...ONCHAIN, osImageHash: image.osImageHash })).status).toBe(200);
    }
    expect(h.upstream.wire()).not.toContain(canaryImage);
  });

  it("a body over the size limit", async () => {
    const h = await harness();
    expectRefused(h, await send(h, "dstack-onchain-authorization", { ...ONCHAIN, pad: CANARY_HEX.repeat(8) }), 413);
  });
});

describe("anything that is not one of the three operations", () => {
  it.each<[string, { path: string; method?: "POST" | "GET" | "PUT" }, unknown]>([
    ["a fetch operation", { path: "/internal/release-collateral/v1/fetch" }, { url: `https://raw.githubusercontent.com/${FILES_REPOSITORY}/${TAGGED}/${CANARY_HEX}` }],
    ["an eth_call operation", { path: "/internal/release-collateral/v1/eth-call" }, { to: KMS_ADDRESS, data: `0x${CANARY_HEX}` }],
    ["a compare operation", { path: "/internal/release-collateral/v1/github-compare" }, { repository: FILES_REPOSITORY, head: HEAD, commit: CANARY_HEX.slice(0, 40) }],
    ["a ref advertisement operation", { path: "/internal/release-collateral/v1/github-refs" }, { repository: FILES_REPOSITORY }],
    ["a path under an operation", { path: `/internal/release-collateral/v1/github-publication/${CANARY_HEX}` }, PUBLICATION],
    ["another version", { path: "/internal/release-collateral/v2/github-publication" }, PUBLICATION],
    ["an operation in another case", { path: "/internal/release-collateral/v1/GitHub-Publication" }, PUBLICATION],
    ["the prefix alone", { path: "/internal/release-collateral/v1" }, PUBLICATION],
    ["GET on an operation", { path: releaseCollateralPath("github-release-images"), method: "GET" }, ""],
    ["PUT on an operation", { path: releaseCollateralPath("github-release-images"), method: "PUT" }, RELEASES],
    ["a worker RPC path", { path: "/internal/near-ai/tee-attestation" }, { providerName: "near-ai", externalModelId: "m", nonce: "ab".repeat(32) }]
  ])("is a fixed 404 with zero upstream requests: %s", async (_label, target, payload) => {
    // The framework's default handler would repeat the requested path back.
    // expectRefused compares the whole body, so nothing of the path can be in
    // it. (This used to be `body not to contain <last path segment>`, which for
    // "the prefix alone" is the two characters "v1": about one random request
    // id in fifty contains them.)
    const h = await harness();
    expectRefused(h, await send(h, target, payload), 404);
  });

  it("a query string on a real operation is refused, whatever it carries", async () => {
    const h = await harness();
    for (const operation of RELEASE_COLLATERAL_OPERATIONS) {
      for (const query of [`?ref=${CANARY_HEX}`, "?x", `?repository=${FILES_REPOSITORY}`, "?block=latest"]) {
        expectRefused(h, await send(h, { path: `${releaseCollateralPath(operation)}${query}` }, VALID[operation]));
      }
    }
  });
});

// --- what the server builds itself ------------------------------------------------

describe("the upstream requests are the server's, not the caller's", () => {
  const FIXED_HEADERS = ["accept", "user-agent", "content-type", "if-none-match"];

  it("github-publication: fixed templates, the server's own head, no file at an unpublished commit", async () => {
    const h = await harness();
    const sent = await send(h, "github-publication", {
      repository: FILES_REPOSITORY,
      claims: [
        { commit: TAGGED, path: "prod/x.yaml", tag: "v0.0.461" },
        { commit: ANCESTOR, path: "prod/y.yaml" },
        { commit: FORK, path: "prod/x.yaml", tag: "v9" }
      ]
    });
    expect(sent.status, sent.body).toBe(200);
    expect(h.upstream.urls().sort()).toEqual([
      `https://api.github.com/repos/${FILES_REPOSITORY}/compare/${HEAD}...${ANCESTOR}?per_page=1`,
      `https://api.github.com/repos/${FILES_REPOSITORY}/compare/${HEAD}...${FORK}?per_page=1`,
      `https://github.com/${FILES_REPOSITORY}.git/info/refs?service=git-upload-pack`,
      `https://raw.githubusercontent.com/${FILES_REPOSITORY}/${ANCESTOR}/prod/y.yaml`,
      `https://raw.githubusercontent.com/${FILES_REPOSITORY}/${TAGGED}/prod/x.yaml`
    ].sort());
    for (const request of h.upstream.requests) {
      expect(request.method).toBe("GET");
      expect(request.body).toBeNull();
    }
    expect(sent.json.publication).toEqual({
      v: 1,
      repository: FILES_REPOSITORY,
      fetchedAtMs: T0,
      defaultBranch: "main",
      defaultBranchHead: HEAD,
      tags: { "v0.0.461": TAGGED },
      defaultBranchAncestors: [ANCESTOR],
      files: [
        { commit: TAGGED, path: "prod/x.yaml", sha256: sha256("services: {}\n") },
        { commit: ANCESTOR, path: "prod/y.yaml", sha256: sha256("services: { y: 1 }\n") }
      ]
    });
    expect(Object.keys(sent.json)).toEqual(["publication"]);
  });

  it("github-publication: a tag is looked up locally and never sent anywhere", async () => {
    // Well formed, so it is accepted. It is a ref name the repository does not
    // advertise, and no request carries it.
    const h = await harness();
    const tag = `hotfix-${CANARY_HEX}`;
    const sent = await send(h, "github-publication", {
      repository: FILES_REPOSITORY,
      claims: [{ commit: TAGGED, path: "prod/x.yaml", tag }]
    });
    expect(sent.status).toBe(200);
    expect(h.upstream.requests.length).toBeGreaterThan(0);
    expect(h.upstream.wire()).not.toContain(CANARY_HEX);
    expect((sent.json.publication as { tags: object }).tags).toEqual({});
  });

  it("github-publication: the order of a request does not show in the order of the upstream requests", async () => {
    const claims = Array.from({ length: 24 }, (_, index) => ({
      commit: index.toString(16).padStart(2, "0").repeat(20),
      path: `prod/f${index}.yaml`
    }));
    const sequence = async (ordered: typeof claims) => {
      const h = await harness();
      expect((await send(h, "github-publication", { repository: FILES_REPOSITORY, claims: ordered })).status).toBe(200);
      return h.upstream.urls();
    };
    const forwards = await sequence(claims);
    const backwards = await sequence([...claims].reverse());
    const shuffled = await sequence([...claims.slice(7), ...claims.slice(0, 7)]);
    expect(forwards.filter((url) => url.includes("/compare/"))).toHaveLength(24);
    expect(backwards).toEqual(forwards);
    expect(shuffled).toEqual(forwards);
  });

  it("github-publication: no claims is the bare record, from the one fixed request", async () => {
    const h = await harness();
    const sent = await send(h, "github-publication", { repository: FILES_REPOSITORY, claims: [] });
    expect(sent.status).toBe(200);
    expect(h.upstream.urls()).toEqual([`https://github.com/${FILES_REPOSITORY}.git/info/refs?service=git-upload-pack`]);
    expect(sent.json.publication).toMatchObject({ defaultBranchHead: HEAD, tags: {}, defaultBranchAncestors: [], files: [] });
  });

  it("github-release-images: one fixed request", async () => {
    const h = await harness();
    const sent = await send(h, "github-release-images", RELEASES);
    expect(sent.status).toBe(200);
    expect(h.upstream.urls()).toEqual([`https://api.github.com/repos/${RELEASES_REPOSITORY}/releases?per_page=100`]);
    expect(h.upstream.requests[0]!.method).toBe("GET");
    expect(sent.json).toEqual({
      releases: {
        v: 1,
        repository: RELEASES_REPOSITORY,
        fetchedAtMs: T0,
        images: [
          { release: "prod-20260702-8e07c35", component: "compose-manager", digest: `sha256:${"6e".repeat(32)}` },
          { release: "prod-20260702-8e07c35", component: "compose-manager-launcher", digest: `sha256:${"91".repeat(32)}` }
        ]
      }
    });
  });

  it("dstack-onchain-authorization: chain id, the server's block, fixed selectors, the KMS and the app contract", async () => {
    const h = await harness();
    const sent = await send(h, "dstack-onchain-authorization", ONCHAIN);
    expect(sent.status, sent.body).toBe(200);
    const calls = h.upstream.requests.map((request) => request.rpc!);
    // Every request: one endpoint, POST, the fixed id and version, nothing else.
    for (const request of h.upstream.requests) {
      expect(request.url).toBe("https://mainnet.base.org");
      expect(request.method).toBe("POST");
      expect(Object.keys(request.rpc!).sort()).toEqual(["id", "jsonrpc", "method", "params"]);
      expect(request.rpc!.id).toBe(1);
      expect(request.rpc!.jsonrpc).toBe("2.0");
    }
    expect(calls.map((call) => call.method)).toEqual(["eth_chainId", "eth_blockNumber", "eth_call", "eth_call", "eth_call"]);
    expect(calls[0]!.params).toEqual([]);
    expect(calls[1]!.params).toEqual([]);
    // The block is the one the server just read, on every call. Each call is a
    // callee and calldata and nothing more: no from, gas, value or override.
    const ethCalls = calls.slice(2).map((call) => call.params as [{ to: string; data: string }, string]);
    for (const params of ethCalls) {
      expect(params).toHaveLength(2);
      expect(params[1]).toBe(h.upstream.blockNumber);
      expect(Object.keys(params[0]).sort()).toEqual(["data", "to"]);
    }
    expect(ethCalls.map(([target]) => target)).toEqual([
      { to: KMS_ADDRESS, data: `0xa6c4cce9${"0".repeat(24)}${APP}` },
      { to: KMS_ADDRESS, data: `0x9a4e1d18${IMAGE}` },
      { to: `0x${APP}`, data: `0x2f6622e5${COMPOSE}` }
    ]);
    expect(sent.json).toEqual({
      authorization: {
        v: 1,
        chainId: 8453,
        kms: KMS_ADDRESS,
        rpc: "https://mainnet.base.org",
        blockNumber: Number.parseInt(h.upstream.blockNumber, 16),
        fetchedAtMs: T0,
        appId: `0x${APP}`,
        appRegistered: true,
        composeHash: COMPOSE,
        composeHashAllowed: true,
        osImageHash: IMAGE,
        osImageAllowed: true
      }
    });
  });

  it("dstack-onchain-authorization: an address the KMS does not register is never called, and gets no compose hash", async () => {
    const h = await harness();
    const stranger = CANARY_HEX.slice(0, 40);
    const secret = CANARY_HEX.slice(4, 68);
    const sent = await send(h, "dstack-onchain-authorization", { ...ONCHAIN, appId: stranger, composeHash: secret });
    expect(sent.status, sent.body).toBe(200);
    expect(sent.json.authorization).toMatchObject({ appId: `0x${stranger}`, appRegistered: false, composeHashAllowed: false, osImageAllowed: true });
    const callees = h.upstream.requests
      .filter((request) => request.rpc!.method === "eth_call")
      .map((request) => (request.rpc!.params as [{ to: string }])[0].to);
    expect(callees).toEqual([KMS_ADDRESS, KMS_ADDRESS]);
    expect(h.upstream.wire()).not.toContain(secret);
  });

  it("dstack-onchain-authorization: another chain's node is not asked anything about the subject", async () => {
    const upstream = standardUpstream();
    upstream.chainId = "0x1";
    const h = await harness({ upstream });
    const sent = await send(h, "dstack-onchain-authorization", ONCHAIN);
    expect(sent.status).toBe(503);
    expect(sent.type).toBe("release_collateral_unavailable");
    expect(sent.reason).toBe("onchain_wrong_chain");
    // Both endpoints were asked their chain id, and neither was asked more.
    expect(h.upstream.requests.map((request) => request.rpc!.method)).toEqual(["eth_chainId", "eth_chainId"]);
    expect(h.upstream.wire()).not.toContain(APP);
    expect(h.upstream.wire()).not.toContain(COMPOSE);
  });

  it("nothing a caller puts in its own request headers reaches an upstream", async () => {
    const h = await harness();
    const hostile = {
      ...AUTH,
      "x-upstream-url": `https://attacker.example/${CANARY_HEX}`,
      "x-forwarded-host": "attacker.example",
      "x-http-method-override": "DELETE",
      "if-none-match": `"${CANARY_HEX}"`,
      "user-agent": CANARY,
      accept: `application/${CANARY_B64}`,
      cookie: `session=${CANARY}`,
      "x-request-id": CANARY_HEX
    };
    for (const operation of RELEASE_COLLATERAL_OPERATIONS) {
      expect((await send(h, operation, VALID[operation], hostile)).status, operation).toBe(200);
    }
    expect(h.upstream.requests.length).toBeGreaterThan(5);
    for (const request of h.upstream.requests) {
      for (const name of Object.keys(request.headers)) expect(FIXED_HEADERS, name).toContain(name);
      expect(request.headers["user-agent"]).toBe("anonrouter-attestation/1");
      expect(request.headers.authorization).toBeUndefined();
    }
    for (const form of [...CANARY_FORMS, TOKEN, "attacker.example"]) expect(h.upstream.wire()).not.toContain(form);
    expectContentFreeLogs(h);
  });

  it("reaches only the hosts the fetchers always reached", async () => {
    const h = await harness();
    for (const operation of RELEASE_COLLATERAL_OPERATIONS) await send(h, operation, VALID[operation]);
    await send(h, "github-publication", { repository: FILES_REPOSITORY, claims: [{ commit: ANCESTOR, path: "prod/y.yaml" }] });
    expect([...new Set(h.upstream.requests.map((request) => request.host))].sort())
      .toEqual(["api.github.com", "github.com", "mainnet.base.org", "raw.githubusercontent.com"]);
    // The second Base endpoint is the fetcher's fallback, used when the first fails.
    h.upstream.failing.add("mainnet.base.org");
    h.upstream.allowedCompose.get(`0x${APP}`)!.add("ee".repeat(32));
    const sent = await send(h, "dstack-onchain-authorization", { ...ONCHAIN, composeHash: "ee".repeat(32) });
    expect((sent.json.authorization as { rpc: string }).rpc).toBe("https://base-rpc.publicnode.com");
    expect(h.upstream.to(...BASE_RPC_HOSTS).length).toBeGreaterThan(5);
  });
});

// --- the residual, pinned ------------------------------------------------------------

describe("the residual channel is exactly these values, and it is real", () => {
  // Not a defect to fix: the lookup cannot be made without them. These tests
  // exist so nobody later writes that the role forwards nothing a caller chose.
  it("a well-formed commit that no named tag peels to leaves in one compare request", async () => {
    const h = await harness();
    const commit = CANARY_HEX.slice(0, 40);
    expect((await send(h, "github-publication", { repository: FILES_REPOSITORY, claims: [{ commit, path: "prod/x.yaml" }] })).status).toBe(200);
    expect(h.upstream.urls().filter((url) => url.includes(commit))).toEqual([
      `https://api.github.com/repos/${FILES_REPOSITORY}/compare/${HEAD}...${commit}?per_page=1`
    ]);
  });

  it("a well-formed path at a PUBLISHED commit leaves in one raw request, 404 or not", async () => {
    const h = await harness();
    const path = `prod/${CANARY_HEX.slice(0, 60)}.yaml`;
    const sent = await send(h, "github-publication", { repository: FILES_REPOSITORY, claims: [{ commit: TAGGED, path, tag: "v0.0.461" }] });
    expect(sent.status).toBe(200);
    expect((sent.json.publication as { files: unknown[] }).files).toEqual([{ commit: TAGGED, path, sha256: null }]);
    expect(h.upstream.urls().filter((url) => url.includes(CANARY_HEX.slice(0, 60)))).toEqual([
      `https://raw.githubusercontent.com/${FILES_REPOSITORY}/${TAGGED}/${path}`
    ]);
  });

  it("a path at an unpublished commit does not leave at all", async () => {
    const h = await harness();
    const path = `prod/${CANARY_HEX.slice(0, 60)}.yaml`;
    expect((await send(h, "github-publication", { repository: FILES_REPOSITORY, claims: [{ commit: FORK, path }] })).status).toBe(200);
    expect(h.upstream.wire()).not.toContain(CANARY_HEX.slice(0, 60));
  });

  it("an app id leaves in one registry call; a compose hash only to an app the KMS registers", async () => {
    const h = await harness();
    const compose = CANARY_HEX.slice(0, 64);
    expect((await send(h, "dstack-onchain-authorization", { ...ONCHAIN, composeHash: compose })).status).toBe(200);
    const carrying = h.upstream.requests.filter((request) => request.body?.includes(compose));
    expect(carrying).toHaveLength(1);
    expect((carrying[0]!.rpc!.params as [{ to: string }])[0].to).toBe(`0x${APP}`);
  });
});

// --- bounds ---------------------------------------------------------------------------

describe("bounds, each enforced before any outbound request", () => {
  const subjectN = (n: number) => ({ ...ONCHAIN, composeHash: n.toString(16).padStart(2, "0").repeat(32) });

  it("the documented defaults", () => {
    expect(RELEASE_COLLATERAL_LIMITS).toEqual({
      maxConcurrent: 16,
      requestBurst: 240,
      requestsPerMinute: 480,
      lookupDeadlineMs: 15_000,
      publication: { maxSubjects: 8192, novelBurst: 512, novelPerHour: 60 },
      onchain: { maxSubjects: 256, novelBurst: 32, novelPerHour: 30 }
    });
    // One full-size request must always be admissible from a full allowance.
    expect(RELEASE_COLLATERAL_LIMITS.publication.novelBurst).toBeGreaterThanOrEqual(MAX_PUBLICATION_CLAIMS);
    // The fetchers' budgets, with the file host's sustained rate cut to this
    // role's own allowance. Every other host is exactly a worker's.
    expect(RELEASE_COLLATERAL_HOST_BUDGETS).toEqual({
      ...DEFAULT_HOST_BUDGETS,
      "raw.githubusercontent.com": { burst: 600, perHour: 300 }
    });
    expect(RELEASE_COLLATERAL_BODY_LIMIT_BYTES).toEqual({
      "github-publication": 262_144,
      "github-release-images": 256,
      "dstack-onchain-authorization": 512
    });
  });

  it("concurrency: a lookup past the limit is refused at once, and admitted again when a slot frees", async () => {
    const h = await harness({ limits: { maxConcurrent: 2 } });
    const release = h.upstream.holdResponses();
    const first = send(h, "dstack-onchain-authorization", subjectN(1));
    const second = send(h, "dstack-onchain-authorization", subjectN(2));
    // Each lookup's first upstream request has arrived and is being held, so
    // both hold a slot. Waited for as an event, not for a length of time.
    await h.upstream.whenRequests(2);
    expect(h.admission.stats().inFlight).toBe(2);
    expect(h.upstream.requests).toHaveLength(2);

    // A third subject, and an operation with no subject at all.
    for (const [operation, payload] of [["dstack-onchain-authorization", subjectN(3)], ["github-release-images", RELEASES]] as const) {
      const refused = await send(h, operation, payload);
      expect(refused.status).toBe(429);
      expect(refused.type).toBe("release_collateral_busy");
      expect(refused.retryAfter).toBe("1");
    }
    expect(h.upstream.requests).toHaveLength(2);
    expect(h.upstream.wire()).not.toContain(subjectN(3).composeHash);
    // Refused for being busy: the third subject was not admitted either.
    expect(h.admission.stats().onchainSubjects).toBe(2);

    release();
    expect((await first).status).toBe(200);
    expect((await second).status).toBe(200);
    expect(h.admission.stats().inFlight).toBe(0);
    expect((await send(h, "dstack-onchain-authorization", subjectN(3))).status).toBe(200);
    expectContentFreeLogs(h);
  });

  it("request rate: the request past the burst is refused, and admitted again as the allowance refills", async () => {
    const h = await harness({ limits: { requestBurst: 3, requestsPerMinute: 6 } });
    for (let i = 0; i < 3; i += 1) expect((await send(h, "github-release-images", RELEASES)).status).toBe(200);
    const sentBefore = h.upstream.requests.length;
    expect(sentBefore).toBe(1);

    for (const operation of RELEASE_COLLATERAL_OPERATIONS) {
      const refused = await send(h, operation, operation === "dstack-onchain-authorization" ? subjectN(9) : VALID[operation]);
      expect(refused.status, operation).toBe(429);
      expect(refused.type).toBe("release_collateral_rate_limited");
      expect(Number(refused.retryAfter)).toBeGreaterThan(0);
    }
    // A malformed request past the rate is not even parsed.
    expect((await send(h, "github-publication", "{ not json")).status).toBe(429);
    expect(h.upstream.requests).toHaveLength(sentBefore);
    expect(h.admission.stats().onchainSubjects).toBe(0);

    // Six a minute is one every ten seconds.
    h.clock.advance(9_999);
    expect((await send(h, "github-release-images", RELEASES)).status).toBe(429);
    h.clock.advance(1);
    expect((await send(h, "github-release-images", RELEASES)).status).toBe(200);
    expect((await send(h, "github-release-images", RELEASES)).status).toBe(429);
    expectContentFreeLogs(h);
  });

  it("new on-chain subjects: the one past the allowance is refused; one already admitted is not new", async () => {
    const h = await harness({ limits: { onchain: { maxSubjects: 100, novelBurst: 2, novelPerHour: 60 } } });
    for (const n of [1, 2]) h.upstream.allowedCompose.get(`0x${APP}`)!.add(subjectN(n).composeHash);
    expect((await send(h, "dstack-onchain-authorization", subjectN(1))).status).toBe(200);
    expect((await send(h, "dstack-onchain-authorization", subjectN(2))).status).toBe(200);
    const sentBefore = h.upstream.requests.length;

    const refused = await send(h, "dstack-onchain-authorization", subjectN(3));
    expect(refused.status).toBe(429);
    expect(refused.type).toBe("release_collateral_rate_limited");
    expect(Number(refused.retryAfter)).toBe(60);
    expect(h.upstream.requests).toHaveLength(sentBefore);
    expect(h.upstream.wire()).not.toContain(subjectN(3).composeHash);

    // Repeats of what was admitted cost nothing, and reach no upstream (cached).
    for (let i = 0; i < 20; i += 1) expect((await send(h, "dstack-onchain-authorization", subjectN(1))).status).toBe(200);
    expect(h.upstream.requests).toHaveLength(sentBefore);

    // Sixty an hour is one a minute.
    h.clock.advance(59_999);
    expect((await send(h, "dstack-onchain-authorization", subjectN(3))).status).toBe(429);
    h.clock.advance(1);
    expect((await send(h, "dstack-onchain-authorization", subjectN(3))).status).toBe(200);
    expect((await send(h, "dstack-onchain-authorization", subjectN(4))).status).toBe(429);
  });

  it("new publication claims: admitted all together or not at all", async () => {
    const h = await harness({ limits: { publication: { maxSubjects: 100, novelBurst: 3, novelPerHour: 60 } } });
    const claim = (n: number) => ({ commit: TAGGED, path: `prod/n${n}.yaml`, tag: "v0.0.461" });
    const ask = (...numbers: number[]) => send(h, "github-publication", { repository: FILES_REPOSITORY, claims: numbers.map(claim) });

    expect((await ask(1, 2)).status).toBe(200);
    const sentBefore = h.upstream.requests.length;
    // Two more new ones with one left in the allowance: neither leaves.
    const refused = await ask(1, 3, 4);
    expect(refused.status).toBe(429);
    expect(refused.type).toBe("release_collateral_rate_limited");
    expect(h.upstream.requests).toHaveLength(sentBefore);
    expect(h.admission.stats().publicationSubjects).toBe(2);
    // One new one beside two known ones fits.
    expect((await ask(1, 2, 3)).status).toBe(200);
    expect(h.upstream.urls().filter((url) => url.endsWith("/prod/n3.yaml"))).toHaveLength(1);
    expect(h.upstream.wire()).not.toContain("n4.yaml");
    // The same claim under another tag is the same (commit, path): not new.
    expect((await send(h, "github-publication", {
      repository: FILES_REPOSITORY, claims: [{ commit: TAGGED, path: "prod/n1.yaml", tag: "another-tag" }]
    })).status).toBe(200);
    expect((await ask(5)).status).toBe(429);
  });

  it("cache cardinality: no more subjects are remembered or cached than the cap", async () => {
    const h = await harness({ limits: { onchain: { maxSubjects: 2, novelBurst: 4, novelPerHour: 60 } } });
    const perLookup = 5;
    for (const n of [1, 2, 3]) expect((await send(h, "dstack-onchain-authorization", subjectN(n))).status).toBe(200);
    expect(h.upstream.requests).toHaveLength(3 * perLookup);
    expect(h.admission.stats().onchainSubjects).toBe(2);

    // The two most recent are held: asking again reaches no upstream.
    for (const n of [2, 3]) expect((await send(h, "dstack-onchain-authorization", subjectN(n))).status).toBe(200);
    expect(h.upstream.requests).toHaveLength(3 * perLookup);
    // The first was forgotten by the ledger AND by the fetcher's cache. Asking
    // for it again is a new subject: it spends the last of the allowance and
    // is looked up again.
    expect((await send(h, "dstack-onchain-authorization", subjectN(1))).status).toBe(200);
    expect(h.upstream.requests).toHaveLength(4 * perLookup);
    expect(h.admission.stats().onchainSubjects).toBe(2);
    expect((await send(h, "dstack-onchain-authorization", subjectN(4))).status).toBe(429);
  });

  it("cache cardinality: the publication ledger is capped the same way", async () => {
    const h = await harness({ limits: { publication: { maxSubjects: 3, novelBurst: 100, novelPerHour: 60 } } });
    const claims = Array.from({ length: 8 }, (_, n) => ({ commit: TAGGED, path: `prod/n${n}.yaml`, tag: "v0.0.461" }));
    expect((await send(h, "github-publication", { repository: FILES_REPOSITORY, claims })).status).toBe(200);
    expect(h.admission.stats().publicationSubjects).toBe(3);
  });

  it("a lookup that does not finish within the deadline is a failure, and frees its slot", async () => {
    // The deadline is the role's injected signal, fired by the test. No timer.
    const deadline = new AbortController();
    const armedFor: number[] = [];
    const h = await harness({
      deadline: (ms) => {
        armedFor.push(ms);
        return deadline.signal;
      }
    });
    const release = h.upstream.holdResponses();
    const pending = send(h, "github-release-images", RELEASES);
    await h.upstream.whenRequests(1);
    // In flight, holding a slot, and waiting on the configured deadline.
    expect(h.admission.stats().inFlight).toBe(1);
    expect(armedFor).toEqual([RELEASE_COLLATERAL_LIMITS.lookupDeadlineMs]);

    deadline.abort(new DOMException("The operation was aborted due to timeout", "TimeoutError"));
    const sent = await pending;
    expect(sent.status).toBe(503);
    expect(sent.type).toBe("release_collateral_unavailable");
    expect(sent.reason).toBe("deadline");
    expect(h.admission.stats().inFlight).toBe(0);
    release();
    expectContentFreeLogs(h);
    expect(h.logs.some((call) => call.message === "release_collateral_lookup_failed" && call.fields.error_code === "deadline")).toBe(true);
  });

  it("the fetchers' own per-host budget still applies inside the role", async () => {
    // With no budget handed in, as the role runs: its own budget table, here on
    // the injected clock. api.github.com: ten at once, as in every worker
    // today. Eleven commits that need the compare API cannot all be asked about.
    const h = await harness({ budget: "role" });
    const claims = Array.from({ length: 11 }, (_, n) => ({ commit: (n + 16).toString(16).repeat(20), path: "prod/x.yaml" }));
    const sent = await send(h, "github-publication", { repository: FILES_REPOSITORY, claims });
    expect(sent.status).toBe(503);
    expect(sent.reason).toBe("budget_exhausted");
    expect(h.upstream.to("api.github.com")).toHaveLength(10);
  });

  it("an upstream outage is a failure with a fixed reason, never the upstream's words", async () => {
    const h = await harness();
    h.upstream.failing = new Set(["github.com", "api.github.com", ...BASE_RPC_HOSTS]);
    for (const operation of RELEASE_COLLATERAL_OPERATIONS) {
      const sent = await send(h, operation, VALID[operation]);
      expect(sent.status, operation).toBe(503);
      expect(sent.type).toBe("release_collateral_unavailable");
      // The fetch layer's own code for a non-200 answer.
      expect(sent.reason).toBe("upstream_status");
      // The whole body: nothing of what the upstream said is in it.
      expect(sent.json).toEqual({
        error: {
          message: "Release-collateral lookup produced no answer",
          type: "release_collateral_unavailable",
          reason: "upstream_status",
          request_id: expect.stringMatching(REQUEST_ID)
        }
      });
    }
    expectContentFreeLogs(h, UPSTREAM_ERROR_WORDS, "github.com", "mainnet.base.org", TAGGED, APP, COMPOSE);
    expect(h.logs.filter((call) => call.message === "release_collateral_lookup_failed")).toHaveLength(3);
  });
});

// --- logging -----------------------------------------------------------------------------

describe("what the role logs", () => {
  it("names the operation from the route template, a status and a fixed code, and nothing a caller sent", async () => {
    const h = await harness();
    await send(h, "github-publication", { repository: FILES_REPOSITORY, claims: [{ commit: CANARY_HEX.slice(0, 41), path: "prod/x.yaml" }] });
    await send(h, "dstack-onchain-authorization", { ...ONCHAIN, osImageHash: sha256(CANARY) });
    await send(h, { path: `/internal/release-collateral/v1/${CANARY_HEX}` }, {});
    await send(h, "github-release-images", RELEASES, {});
    expect(h.logs.filter((call) => call.level === "warn").map((call) => [call.message, call.fields.operation, call.fields.error_type, call.fields.status_code])).toEqual([
      ["release_collateral_request_refused", "github-publication", "release_collateral_request_refused", 400],
      ["release_collateral_request_refused", "dstack-onchain-authorization", "release_collateral_os_image_unknown", 400],
      ["release_collateral_request_refused", "unknown", "release_collateral_request_refused", 404],
      ["release_collateral_request_refused", "github-release-images", "service_unauthorized", 401]
    ]);
    expectContentFreeLogs(h, sha256(CANARY), TOKEN);
    // The access line carries the route template, never the URL.
    for (const call of h.logs.filter((entry) => entry.message === "request_complete")) {
      expect(String(call.fields.route ?? "")).not.toContain(CANARY_HEX);
    }
  });

  it("a successful lookup logs only the access line", async () => {
    const h = await harness();
    for (const operation of RELEASE_COLLATERAL_OPERATIONS) expect((await send(h, operation, VALID[operation])).status).toBe(200);
    expect(h.logs.map((call) => call.message)).toEqual(["request_complete", "request_complete", "request_complete"]);
    expectContentFreeLogs(h, TAGGED, APP, COMPOSE, IMAGE, "prod/x.yaml", "v0.0.461", FILES_REPOSITORY);
  });

  it("the handler reduces an error it did not raise to a status and a type", () => {
    const warned: unknown[][] = [];
    const sent: unknown[] = [];
    const reply = { header: () => reply, status: () => ({ send: (body: unknown) => { sent.push(body); } }) };
    const request = { id: "req_1", routeOptions: { url: releaseCollateralPath("github-publication") }, log: { warn: (...args: unknown[]) => { warned.push(args); } } };
    releaseCollateralErrorHandler(new Error(`upstream said ${CANARY}`), request as never, reply as never);
    expect(warned).toEqual([[
      { request_id: "req_1", operation: "github-publication", error_type: "internal_error", status_code: 500 },
      "release_collateral_lookup_failed"
    ]]);
    expect(JSON.stringify(sent)).not.toContain(CANARY);
  });
});
