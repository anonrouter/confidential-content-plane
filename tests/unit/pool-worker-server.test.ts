// The pool-worker server: one process, several providers (PROVIDER_POOL_PLAN.md,
// W1b; review findings C3, C5, S3, S4, S6).
//
// Every test here builds the REAL worker server from a PRODUCTION configuration
// and drives it through its routes. Nothing leaves the process: global fetch is
// replaced by a recorder that plays control and every provider, so "which token
// went to control" and "no provider request was made" are read off the one
// place a request can leave from.
//
// Except where a test says otherwise the pool runs the synthetic transport
// profile, whose only credential-bearing origin is the in-CVM mock. That is the
// preproduction manifest's own configuration, and it means that even a request
// that slipped past the recorder could not reach a real provider.
//
// TINFOIL. Its adapter sends through an attested, SPKI-pinned TLS socket, not
// fetch, and refuses to open one unless its base URL is Tinfoil's real origin.
// Under the mock origin it therefore fails closed before any network, which is
// exactly what these tests need from it at dispatch. Its catalog FETCH is the
// one thing replaced (below), so that a Tinfoil catalog push can be observed;
// everything from the built payload onwards is the real code.

import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../../src/config.js";
import { CATALOG_SCHEMA_VERSION } from "../../src/providers/catalog/normalized.js";
import {
  decodeCapability,
  mintCapability,
  signCapability,
  type CapabilityAction
} from "../../src/providers/credentials/capability.js";
import { consumedCapabilityFileName, type PoolProviderName } from "../../src/providers/workerProviders.js";
import { buildWorkerServer } from "../../src/roles.js";
import { registerCredentialAdminRoutes } from "../../src/routes/internal/credentialAdmin.js";
import { registerWorkerRpcRoutes } from "../../src/routes/internal/worker.js";

const tinfoilCatalog = vi.hoisted(() => ({ payload: null as unknown }));
vi.mock("../../src/providers/catalog/tinfoilSync.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/providers/catalog/tinfoilSync.js")>()),
  buildTinfoilCatalogPayload: async () => tinfoilCatalog.payload
}));

type Planned = Exclude<PoolProviderName, "chutes">;

const PLANNED: readonly Planned[] = ["venice", "fireworks", "deepinfra", "tinfoil", "near-ai", "phala-ai"];

const CONTROL_URL = "http://control.pool.invalid:8444";
const RELEASE_COLLATERAL_URL = "http://release-collateral.pool.invalid:3000";
const MOCK_ORIGIN = "http://mock-provider:3000";
const DISCOVERY_URL = "http://127.0.0.1:9/endpoints";
const DEPLOYMENT_ID = "unit-pool";
const SIGNER_ID = "unit-cap-signer";
const SPKI = "7c".repeat(32);

const distinct = (seed: string) => `prod-${seed}-${"x".repeat(40)}`.slice(0, 48);
const WORKER_RPC_TOKEN = distinct("workertoken");
const AUTH = { authorization: `Bearer ${WORKER_RPC_TOKEN}` };
const metadataToken = (provider: string) => distinct(`metadata-${provider}`);
// Development-only dummy secrets, recognisable so a leak search can find them.
const providerKey = (provider: string) => `sk-DEVDUMMY-pool-${provider}-key`;

const VARIABLES: Record<Planned, { token: string; keyFile: string; baseUrl: string; mockBase: string }> = {
  venice: { token: "METADATA_RPC_TOKEN_VENICE", keyFile: "VENICE_INFERENCE_KEY_FILE", baseUrl: "VENICE_BASE_URL", mockBase: `${MOCK_ORIGIN}/venice/api/v1` },
  fireworks: { token: "METADATA_RPC_TOKEN_FIREWORKS", keyFile: "FIREWORKS_API_KEY_FILE", baseUrl: "FIREWORKS_BASE_URL", mockBase: `${MOCK_ORIGIN}/fireworks/inference/v1` },
  deepinfra: { token: "METADATA_RPC_TOKEN_DEEPINFRA", keyFile: "DEEPINFRA_API_KEY_FILE", baseUrl: "DEEPINFRA_BASE_URL", mockBase: `${MOCK_ORIGIN}/deepinfra/v1/openai` },
  tinfoil: { token: "METADATA_RPC_TOKEN_TINFOIL", keyFile: "TINFOIL_API_KEY_FILE", baseUrl: "TINFOIL_BASE_URL", mockBase: `${MOCK_ORIGIN}/tinfoil/v1` },
  "near-ai": { token: "METADATA_RPC_TOKEN_NEAR", keyFile: "NEAR_API_KEY_FILE", baseUrl: "NEAR_BASE_URL", mockBase: `${MOCK_ORIGIN}/near-ai/v1` },
  "phala-ai": { token: "METADATA_RPC_TOKEN_PHALA_AI", keyFile: "PHALA_AI_API_KEY_FILE", baseUrl: "PHALA_AI_BASE_URL", mockBase: `${MOCK_ORIGIN}/phala-ai/v1` }
};

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const rawPublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
const rawPrivateKey = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex");

// --- the recorder --------------------------------------------------------------

interface Call {
  url: string;
  to: "control" | "provider" | "discovery";
  /** control: catalog | health | dispatch-attempt | attestation-attempt | credential-outcome. provider: chat | catalog | other. */
  kind: string;
  authorization: string | null;
  /** The pooled provider whose metadata token or API key the request carried. */
  bearerOf: string | null;
  body: Record<string, unknown> | null;
  probeLeaseOptIn?: string | null;
}

type CatalogBehaviour = "ok" | "fail" | (() => Promise<Response>);

interface Recorder {
  calls: Call[];
  dispatch: "allow" | "deny";
  attestation: "allow" | "deny";
  healthTargets: Partial<Record<Planned, string[]>>;
  leaseMode: "valid" | "missing" | "malformed" | "expired";
  catalog: Partial<Record<Planned, CatalogBehaviour>>;
  /** How long a provider chat takes, so concurrency is observable. */
  chatDelayMs: number;
  inFlight: Record<string, number>;
  maxInFlight: Record<string, number>;
  maxInFlightTotal: number;
}

const recorder: Recorder = {
  calls: [], dispatch: "allow", attestation: "allow", healthTargets: {}, leaseMode: "valid", catalog: {},
  chatDelayMs: 0, inFlight: {}, maxInFlight: {}, maxInFlightTotal: 0
};

function resetRecorder() {
  recorder.calls = [];
  recorder.dispatch = "allow";
  recorder.attestation = "allow";
  recorder.healthTargets = {};
  recorder.leaseMode = "valid";
  recorder.catalog = {};
  recorder.chatDelayMs = 0;
  recorder.inFlight = {};
  recorder.maxInFlight = {};
  recorder.maxInFlightTotal = 0;
  tinfoilCatalog.payload = null;
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

function bearerOf(authorization: string | null): string | null {
  if (!authorization) return null;
  for (const provider of PLANNED) {
    if (authorization === `Bearer ${metadataToken(provider)}`) return provider;
    if (authorization === `Bearer ${providerKey(provider)}`) return provider;
  }
  return "unknown";
}

async function respond(call: Call): Promise<Response> {
  if (call.to === "discovery") return json({ endpoints: [] });
  if (call.to === "control") {
    if (call.kind === "catalog") {
      const provider = (call.body?.payload as { provider?: Planned } | undefined)?.provider;
      const targets = (provider ? recorder.healthTargets[provider] : undefined) ?? [];
      return json({ health_probe_targets: targets.map((externalModelId) => ({ externalModelId })),
        ...(recorder.leaseMode === "missing" ? {} : { health_probe_lease: {
          leaseId: recorder.leaseMode === "malformed" ? "invalid" : "11".repeat(16),
          ttlMs: recorder.leaseMode === "expired" ? 1 : 1_800_000
        } }) });
    }
    if (call.kind === "health") return json({ accepted: (call.body?.healthChecks as unknown[]).length });
    if (call.kind === "dispatch-attempt") return recorder.dispatch === "allow" ? json({}) : json({ error: "denied" }, 403);
    if (call.kind === "attestation-attempt") return recorder.attestation === "allow" ? json({}) : json({ error: "denied" }, 403);
    return json({ ok: true });
  }
  const provider = call.bearerOf ?? "keyless";
  if (call.kind === "chat") {
    recorder.inFlight[provider] = (recorder.inFlight[provider] ?? 0) + 1;
    const total = Object.values(recorder.inFlight).reduce((sum, count) => sum + count, 0);
    recorder.maxInFlight[provider] = Math.max(recorder.maxInFlight[provider] ?? 0, recorder.inFlight[provider]!);
    recorder.maxInFlightTotal = Math.max(recorder.maxInFlightTotal, total);
    if (recorder.chatDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, recorder.chatDelayMs));
    recorder.inFlight[provider]! -= 1;
    return json({ id: "chatcmpl-1", choices: [], usage: { prompt_tokens: 1, completion_tokens: 1 } });
  }
  if (call.kind === "catalog") {
    const behaviour = recorder.catalog[provider as Planned] ?? "ok";
    if (typeof behaviour === "function") return behaviour();
    // 400 is not retried, so a failing provider fails at once.
    if (behaviour === "fail") return json({ error: "nope" }, 400);
    return json({ data: [], models: [] });
  }
  return json({ data: { rateLimits: [] } });
}

function installRecorder() {
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const parsed = new URL(url);
    const authorization = new Headers(init?.headers).get("authorization");
    let body: Record<string, unknown> | null = null;
    if (typeof init?.body === "string") {
      try {
        body = JSON.parse(init.body) as Record<string, unknown>;
      } catch {
        body = null;
      }
    }
    let call: Call;
    if (url.startsWith(`${CONTROL_URL}/`)) {
      const kind = parsed.pathname === "/internal/control/catalog"
        ? (body && "healthChecks" in body ? "health" : "catalog")
        : parsed.pathname.replace("/internal/control/", "");
      call = { url, to: "control", kind, authorization, bearerOf: bearerOf(authorization), body, probeLeaseOptIn: new Headers(init?.headers).get("x-anonrouter-probe-lease") };
    } else if (url.startsWith(DISCOVERY_URL)) {
      call = { url, to: "discovery", kind: "near-endpoints", authorization, bearerOf: bearerOf(authorization), body };
    } else if (parsed.origin === MOCK_ORIGIN) {
      const kind = parsed.pathname.endsWith("/chat/completions") ? "chat"
        : parsed.pathname.endsWith("/models") || parsed.pathname.endsWith("/models/list") ? "catalog"
          : "other";
      call = { url, to: "provider", kind, authorization, bearerOf: bearerOf(authorization), body };
    } else {
      // Anything else would be a request to a real host. There must be none.
      recorder.calls.push({ url, to: "provider", kind: "ESCAPED", authorization, bearerOf: null, body });
      throw new Error("a request tried to leave for an unexpected destination");
    }
    recorder.calls.push(call);
    return respond(call);
  }));
}

const controlCalls = () => recorder.calls.filter((call) => call.to === "control");
const providerCalls = () => recorder.calls.filter((call) => call.to === "provider");

// --- configuration --------------------------------------------------------------

let envSnapshot: NodeJS.ProcessEnv;
let secretsDir = "";
const stateDirs: string[] = [];
const servers: FastifyInstance[] = [];

function clearRelevant() {
  for (const key of Object.keys(process.env)) {
    if (/^(RUNTIME_ROLE|POOL_PROVIDERS|RELEASE_COLLATERAL_|PROVIDER_TRANSPORT_PROFILE|LOG_LEVEL|RELAY_RPC|WORKER_RPC|METADATA_RPC|METADATA_PUSH|CONTROL_RPC|CONTROL_METADATA|COMPAT_RPC|VENICE_|FIREWORKS_|DEEPINFRA_|CHUTES_|TINFOIL_|NEAR_|PHALA_AI_|BEDROCK_|AWS_|MOCK_PROVIDER_|DEFAULT_PROVIDER|ALLOW_INLINE_TICKET|ALLOW_COMPAT_MODE|APP_SECRET|EMAIL_HASH_SECRET|EMAIL_ENCRYPTION_KEY|COOKIE_SECRET|BETTER_AUTH_SECRET|ADMIN_|CORS_ORIGIN|SMTP_|DATABASE_URL|MIGRATION_DATABASE_URL|APP_DB|GATEWAY_|DSTACK_|REDIS_URL|STRIPE_|PAYMENTS_MODE|CONSUMED_CAPABILITY|CREDENTIAL_|CONTENT_TLS|CONFIDENTIAL_DEPLOYMENT|PROVIDER_CAPABILITY|CATALOG_SYNC|TRUST_PROXY_HOPS)/.test(key)) {
      delete process.env[key];
    }
  }
}

function newStateDir(): string {
  const directory = mkdtempSync(join(tmpdir(), "anonrouter-pool-state-"));
  stateDirs.push(directory);
  return directory;
}

interface WorkerOptions {
  stateDir: string;
  /** Run the scheduled poller. Off unless a test is about boot. */
  sync?: boolean;
  intervalSeconds?: number;
  /** "production" leaves every base URL on its real, pinned default. */
  profile?: "synthetic" | "production";
}

function commonEnvironment(options: WorkerOptions) {
  clearRelevant();
  process.env.NODE_ENV = "production";
  process.env.LOG_LEVEL = "silent";
  process.env.WORKER_RPC_TOKEN = WORKER_RPC_TOKEN;
  process.env.CONTROL_METADATA_URL = CONTROL_URL;
  process.env.METADATA_PUSH_TIMEOUT_MS = "1000";
  process.env.CONFIDENTIAL_DEPLOYMENT_ID = DEPLOYMENT_ID;
  process.env.CREDENTIAL_ADMIN_MODE = "capability";
  process.env.CREDENTIAL_CAPABILITY_SIGNERS = `${SIGNER_ID}:${rawPublicKey}`;
  process.env.CONTENT_TLS_SPKI_SHA256 = SPKI;
  process.env.VENICE_KEYSET_OVERLAY_FILE = join(options.stateDir, "venice-keyset-overlay.json");
  process.env.CATALOG_SYNC_ENABLED = options.sync ? "true" : "false";
  if (options.intervalSeconds) process.env.CATALOG_SYNC_INTERVAL_SECONDS = String(options.intervalSeconds);
  if ((options.profile ?? "synthetic") === "synthetic") {
    process.env.PROVIDER_TRANSPORT_PROFILE = "synthetic";
    // Keyless, so not a pinned variable. Pointed at a closed port all the same.
    process.env.NEAR_ENDPOINTS_URL = DISCOVERY_URL;
  }
}

function provide(provider: Planned, options: WorkerOptions) {
  const variables = VARIABLES[provider];
  process.env[variables.token] = metadataToken(provider);
  process.env[variables.keyFile] = join(secretsDir, `${provider}.key`);
  if ((options.profile ?? "synthetic") === "synthetic") process.env[variables.baseUrl] = variables.mockBase;
}

/** A production pool-worker for `providers`, as the measured compose would configure it. */
function poolEnvironment(providers: readonly Planned[], options: WorkerOptions) {
  commonEnvironment(options);
  process.env.RUNTIME_ROLE = "pool-worker";
  process.env.POOL_PROVIDERS = providers.join(",");
  process.env.CONSUMED_CAPABILITY_DIR = options.stateDir;
  // A production pool must be told where the release-collateral role is (W3). Nothing
  // in this suite serves NEAR-format evidence, so nothing here calls it; a call
  // would land in the recorder as an unexpected destination and fail the test.
  process.env.RELEASE_COLLATERAL_RPC_URL = RELEASE_COLLATERAL_URL;
  process.env.RELEASE_COLLATERAL_RPC_TOKEN = distinct("release-collateral-token");
  for (const provider of providers) provide(provider, options);
}

/** Today's single-provider worker for `provider`, replay log named as its compose names it. */
function singleEnvironment(role: string, provider: Planned, options: WorkerOptions) {
  commonEnvironment(options);
  process.env.RUNTIME_ROLE = role;
  process.env.CONSUMED_CAPABILITY_FILE = join(options.stateDir, consumedCapabilityFileName(provider));
  provide(provider, options);
}

async function build(routes?: string[]): Promise<FastifyInstance> {
  const server = await buildWorkerServer(loadConfig(), routes ? {
    observe: (instance) => {
      instance.addHook("onRoute", (route) => {
        for (const method of [route.method].flat()) routes.push(`${method} ${route.url}`);
      });
    }
  } : {});
  servers.push(server);
  await server.ready();
  return server;
}

async function buildPool(providers: readonly Planned[], options: WorkerOptions, routes?: string[]) {
  poolEnvironment(providers, options);
  return build(routes);
}

function capability(provider: string, action: CapabilityAction, credentialId: string) {
  return signCapability(
    mintCapability({
      operatorId: "opa-unit-000001", provider, credentialId, action,
      deploymentId: DEPLOYMENT_ID, now: Math.floor(Date.now() / 1000)
    }),
    rawPrivateKey,
    SIGNER_ID
  );
}

const capabilityIdOf = (signed: { capability: string }) =>
  decodeCapability(Buffer.from(signed.capability, "base64url")).capabilityId;

const chatBody = (providerName: string) => ({
  dispatchToken: "dsp_test",
  requestId: "req_test",
  providerName,
  externalModelId: "test-model",
  reasoningKey: "default",
  body: { model: "test-model", messages: [{ role: "user", content: "hi" }], max_tokens: 8, max_completion_tokens: 8 }
});

const attestationBody = (providerName: string) => ({
  providerName, externalModelId: "test-model", dispatchToken: "atd_test", nonce: "ab".repeat(32)
});

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

beforeAll(() => {
  envSnapshot = { ...process.env };
  secretsDir = mkdtempSync(join(tmpdir(), "anonrouter-pool-secrets-"));
  for (const provider of PLANNED) writeFileSync(join(secretsDir, `${provider}.key`), providerKey(provider));
});

afterAll(() => {
  rmSync(secretsDir, { recursive: true, force: true });
  for (const directory of stateDirs.splice(0)) rmSync(directory, { recursive: true, force: true });
  process.env = envSnapshot;
});

beforeEach(() => {
  resetRecorder();
  installRecorder();
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
  vi.unstubAllGlobals();
});

// --- boot ----------------------------------------------------------------------

const PROVIDER_OPERATIONS = [
  "attestation", "tee-attestation", "tee-signature", "chat", "opaque-e2ee",
  "embeddings", "image", "speech", "catalog-sync", "probe", "stream"
];

describe("a production-configured pool-worker with the full provider list", () => {
  it("boots on the real pinned origins, makes no request, and registers exactly its routes", async () => {
    const routes: string[] = [];
    const server = await buildPool(PLANNED, { stateDir: newStateDir(), profile: "production" }, routes);

    expect(server.config.env).toBe("production");
    expect(server.config.internal.role).toBe("pool-worker");
    expect(server.config.providers.transportProfile).toBe("production");
    expect(server.config.providers.veniceBaseUrl).toBe("https://api.venice.ai/api/v1");
    // Booting sent nothing anywhere: not to control, not to a provider.
    expect(recorder.calls).toEqual([]);

    const expected = [
      // Each provider's RPC routes, once.
      ...PLANNED.flatMap((provider) => PROVIDER_OPERATIONS.map((operation) => `POST /internal/${provider}/${operation}`)),
      // The legacy Venice key routes, once.
      "POST /internal/venice/keys",
      "DELETE /internal/venice/keys/:id",
      // Each provider's namespaced credential routes, once. HEAD is Fastify's
      // own companion to the GET.
      ...PLANNED.flatMap((provider) => [
        `GET /internal/credentials/${provider}/identity`,
        `HEAD /internal/credentials/${provider}/identity`,
        `POST /internal/credentials/${provider}/secret`,
        `POST /internal/credentials/${provider}/revoke`
      ])
    ];
    const internal = routes.filter((route) => route.includes(" /internal/"));
    expect([...internal].sort()).toEqual([...expected].sort());
    // "Once" is not implied by the sorted comparison alone if both sides repeat.
    expect(new Set(internal).size).toBe(internal.length);
    expect(internal).toHaveLength(6 * 11 + 2 + 6 * 4);
    // Outside /internal/ there is only what the base server gives every lean
    // role: the health route and the CORS plugin's preflight catch-all.
    expect(routes.filter((route) => !route.includes(" /internal/")).sort()).toEqual(["GET /healthz", "HEAD /healthz", "OPTIONS *"]);
  });

  it("serves no route for a provider it does not list, and no un-namespaced credential route", async () => {
    const server = await buildPool(["venice", "fireworks"], { stateDir: newStateDir() });
    for (const url of [
      "/internal/deepinfra/chat", "/internal/chutes/chat", "/internal/aws-bedrock/chat", "/internal/mock/chat",
      "/internal/credentials/secret", "/internal/credentials/revoke",
      "/internal/credentials/deepinfra/secret", "/internal/credentials/near/secret"
    ]) {
      const response = await server.inject({ method: "POST", url, headers: AUTH, payload: chatBody("venice") });
      expect(response.statusCode, url).toBe(404);
    }
    expect((await server.inject({ method: "GET", url: "/internal/credentials/identity" })).statusCode).toBe(404);
    expect(recorder.calls).toEqual([]);
  });

  it("keeps one Venice keyset store for the process, and none without Venice", async () => {
    const withVenice = await buildPool(["fireworks", "venice"], { stateDir: newStateDir() });
    expect(withVenice.hasDecorator("veniceKeyStore")).toBe(true);
    expect(withVenice.veniceKeyStore.effectiveKeys().map((entry) => entry.key)).toEqual([providerKey("venice")]);

    const without = await buildPool(["fireworks", "deepinfra"], { stateDir: newStateDir() });
    expect(without.hasDecorator("veniceKeyStore")).toBe(false);
    // The legacy key routes are still there, refused as on any non-Venice worker.
    const refused = await without.inject({ method: "POST", url: "/internal/venice/keys", headers: AUTH, payload: { id: "pushed-01", key: "sk-DEVDUMMY-pushed" } });
    expect(refused.statusCode).toBe(410);
  });

  it("points an operator using the retired key push at the pool's namespaced route", async () => {
    const server = await buildPool(["venice", "fireworks"], { stateDir: newStateDir() });
    const push = await server.inject({ method: "POST", url: "/internal/venice/keys", headers: AUTH, payload: { id: "pushed-01", key: "sk-DEVDUMMY-pushed" } });
    expect(push.statusCode).toBe(410);
    expect(push.json().error).toMatchObject({ type: "credential_push_disabled" });
    expect(push.json().error.message).toContain("POST /internal/credentials/venice/secret");
    const remove = await server.inject({ method: "DELETE", url: "/internal/venice/keys/primary", headers: AUTH });
    expect(remove.statusCode).toBe(410);
    expect(remove.json().error.message).toContain("POST /internal/credentials/venice/revoke");
  });

  it("refuses to build without a metadata token for a listed provider, outside production too", async () => {
    // Production config refuses this at load. Outside production nothing does,
    // so the server build itself has to: there is no token to fall back to.
    poolEnvironment(["venice", "fireworks"], { stateDir: newStateDir() });
    process.env.NODE_ENV = "test";
    delete process.env.METADATA_RPC_TOKEN_FIREWORKS;
    process.env.METADATA_RPC_TOKEN = distinct("metadata-shared");
    process.env.METADATA_RPC_DEPLOYMENT_TOKEN = distinct("metadata-deployment");
    await expect(buildWorkerServer(loadConfig())).rejects.toThrow("pool-worker has no metadata token for provider fireworks");
  });
});

describe("the registrars cannot be used on the pool as if it served one provider", () => {
  async function bare(): Promise<{ server: FastifyInstance; routes: string[] }> {
    const server = Fastify({ logger: false });
    servers.push(server);
    const routes: string[] = [];
    server.addHook("onRoute", (route) => {
      for (const method of [route.method].flat()) routes.push(`${method} ${route.url}`);
    });
    server.decorate("config", loadConfig());
    return { server, routes };
  }

  it("the un-namespaced credential registrar refuses the pool role, named provider or not", async () => {
    poolEnvironment(["venice", "fireworks"], { stateDir: newStateDir() });
    const { server, routes } = await bare();
    // Its default used to be "the role's provider, else Venice". For the pool
    // that would have mounted Venice's routes at paths that name no provider.
    await expect(registerCredentialAdminRoutes(server)).rejects.toThrow("pool-worker registers credential administration per provider");
    await expect(registerCredentialAdminRoutes(server, "venice")).rejects.toThrow("pool-worker registers credential administration per provider");
    expect(routes).toEqual([]);
  });

  it("the worker RPC registrar takes the pool's configured list when none is passed, never Venice", async () => {
    poolEnvironment(["fireworks", "deepinfra"], { stateDir: newStateDir() });
    const { server, routes } = await bare();
    await registerWorkerRpcRoutes(server);
    expect(routes.filter((route) => route.endsWith("/chat")).sort()).toEqual(["POST /internal/deepinfra/chat", "POST /internal/fireworks/chat"]);
    expect(routes.some((route) => route.includes("/internal/venice/chat"))).toBe(false);
  });
});

// --- route fences ---------------------------------------------------------------

describe("a body naming provider B on provider A's path", () => {
  const dispatch = { dispatchToken: "dsp_test", requestId: "req_test", externalModelId: "test-model" };
  const bodies: Record<string, Record<string, unknown>> = {
    attestation: { externalModelId: "test-model", dispatchToken: "atd_test", nonce: "ab".repeat(32) },
    "tee-attestation": { externalModelId: "test-model", nonce: "ab".repeat(32) },
    "tee-signature": { externalModelId: "test-model", providerRequestId: "provider-request-1" },
    chat: { ...dispatch, reasoningKey: "default", body: { model: "test-model", messages: [{ role: "user", content: "hi" }] } },
    stream: { ...dispatch, reasoningKey: "default", body: { model: "test-model", messages: [{ role: "user", content: "hi" }] } },
    "opaque-e2ee": {
      ...dispatch, reasoningKey: "default", effectiveMaxOutputTokens: 16,
      protocol: "chutes-mlkem-v1", headers: {}, ciphertextBase64: "AAAA"
    },
    embeddings: { ...dispatch, body: { model: "test-model", input: "hi" } },
    image: { ...dispatch, width: 512, height: 512, responseFormat: "b64_json", prompt: "a prompt" },
    speech: { ...dispatch, responseFormat: "mp3", input: "say this" }
  };
  // Every ordered pair of the six pooled providers, plus the names a body
  // could carry that are not pooled at all.
  const crossings: Array<[Planned, string]> = PLANNED.flatMap((pathProvider) => [
    ...PLANNED.filter((bodyProvider) => bodyProvider !== pathProvider).map((bodyProvider): [Planned, string] => [pathProvider, bodyProvider]),
    [pathProvider, "aws-bedrock"], [pathProvider, "chutes"], [pathProvider, "mock"]
  ]);
  let server: FastifyInstance;

  beforeEach(async () => {
    server = await buildPool(PLANNED, { stateDir: newStateDir() });
  });

  it("covers every ordered pair", () => {
    expect(crossings).toHaveLength(6 * 5 + 6 * 3);
  });

  it("is refused on every operation, with no fence call and no provider request", async () => {
    for (const [pathProvider, bodyProvider] of crossings) {
      for (const [operation, body] of Object.entries(bodies)) {
        const response = await server.inject({
          method: "POST",
          url: `/internal/${pathProvider}/${operation}`,
          headers: AUTH,
          payload: { ...body, providerName: bodyProvider }
        });
        const label = `${bodyProvider} on /internal/${pathProvider}/${operation}`;
        expect(response.statusCode, label).toBe(400);
        expect(response.json().error, label).toMatchObject({
          type: "worker_provider_forbidden",
          message: `This worker accepts only the ${pathProvider} provider`
        });
      }
    }
    // 48 crossings x 9 operations, and not one request left the process: no
    // fence was asked and no provider was called.
    expect(recorder.calls).toEqual([]);
  });

  it("lets the same bodies through on their own provider's path", async () => {
    // The positive control: without it the refusals would pass against a
    // server that refused everything.
    for (const provider of PLANNED.filter((entry) => entry !== "tinfoil")) {
      recorder.calls = [];
      const response = await server.inject({ method: "POST", url: `/internal/${provider}/chat`, headers: AUTH, payload: chatBody(provider) });
      expect(response.statusCode, provider).toBe(200);
      expect(controlCalls().map((call) => call.kind), provider).toEqual(["dispatch-attempt"]);
      expect(providerCalls().map((call) => [call.kind, call.bearerOf]), provider).toEqual([["chat", provider]]);
    }
  });
});

// --- per-provider metadata tokens -----------------------------------------------

describe("each provider's metadata calls present that provider's token and no other", () => {
  let server: FastifyInstance;
  let stateDir = "";

  beforeEach(async () => {
    stateDir = newStateDir();
    server = await buildPool(PLANNED, { stateDir });
  });

  it("holds six distinct tokens, so presenting the wrong one would show", () => {
    expect(new Set(PLANNED.map(metadataToken)).size).toBe(6);
    expect(new Set(PLANNED.map(providerKey)).size).toBe(6);
  });

  it.each(PLANNED)("%s: catalog push, health push, dispatch fence, attestation fence, credential outcome", async (provider) => {
    tinfoilCatalog.payload = {
      schema_version: CATALOG_SCHEMA_VERSION, provider: "tinfoil", fetched_at: new Date().toISOString(), source_hash: "0".repeat(64), models: []
    };

    // 1 + 2: a sync whose answer asks for one health probe.
    recorder.healthTargets = { [provider]: ["probe-model"] };
    await server.catalogSyncNow!(provider);
    recorder.healthTargets = {};
  recorder.leaseMode = "valid";

    // 3: an inference dispatch is fenced before the provider is called.
    await server.inject({ method: "POST", url: `/internal/${provider}/chat`, headers: AUTH, payload: chatBody(provider) });

    // 4: so is an attestation fetch.
    await server.inject({ method: "POST", url: `/internal/${provider}/attestation`, headers: AUTH, payload: attestationBody(provider) });

    // 5: a credential operation reports its outcome.
    const signed = capability(provider, "register", "installed-01");
    const install = await server.inject({
      method: "POST",
      url: `/internal/credentials/${provider}/secret`,
      payload: { capability: signed, secret: "sk-DEVDUMMY-pool-installed-secret" }
    });
    expect(install.statusCode).toBe(provider === "venice" ? 200 : 503);

    const control = controlCalls();
    expect(control.map((call) => call.kind)).toEqual([
      "catalog",
      "health",
      "dispatch-attempt",
      "attestation-attempt",
      // Only Venice has a store, so only its install is applied and re-syncs.
      ...(provider === "venice" ? ["catalog"] : []),
      "credential-outcome"
    ]);
    // Every one under THIS provider's token. The process holds five others.
    for (const call of control) {
      expect(call.authorization, call.kind).toBe(`Bearer ${metadataToken(provider)}`);
    }
    // And each names the provider and deployment that token is bound to.
    expect(control[0]!.body).toMatchObject({ deploymentId: DEPLOYMENT_ID, payload: { provider } });
    expect(control[1]!.body).toMatchObject({ deploymentId: DEPLOYMENT_ID, provider, healthChecks: [{ externalModelId: "probe-model" }] });
    expect(control[2]!.body).toMatchObject({ deploymentId: DEPLOYMENT_ID, providerName: provider, dispatchToken: "dsp_test" });
    expect(control[3]!.body).toMatchObject({ deploymentId: DEPLOYMENT_ID, providerName: provider, dispatchToken: "atd_test" });
    expect(control.at(-1)!.body).toMatchObject({
      capabilityId: capabilityIdOf(signed),
      ...(provider === "venice"
        ? { outcome: "applied", outcomeCode: "registered" }
        : { outcome: "failed", outcomeCode: "credential_store_unavailable" })
    });

    // The Venice key manifest rides ONLY Venice's catalog push.
    for (const call of control.filter((entry) => entry.kind === "catalog")) {
      if (provider === "venice") expect(call.body?.veniceKeys).toBeDefined();
      else expect(call.body).not.toHaveProperty("veniceKeys");
      if (provider !== "venice") expect(call.body).not.toHaveProperty("rateLimits");
    }

    // Whatever went to a provider carried this provider's key, or none.
    for (const call of providerCalls()) {
      expect(call.authorization, call.url).toBe(`Bearer ${providerKey(provider)}`);
    }
    // No other pooled provider's token or key appears on anything this did.
    const others = PLANNED.filter((entry) => entry !== provider);
    for (const call of recorder.calls) {
      for (const other of others) {
        expect(call.authorization ?? "", call.url).not.toContain(metadataToken(other));
        expect(call.authorization ?? "", call.url).not.toContain(providerKey(other));
      }
    }
    // The secret went nowhere but, for Venice, into the store.
    expect(JSON.stringify(recorder.calls)).not.toContain("sk-DEVDUMMY-pool-installed-secret");
  });

  it("syncs only the provider named, and refuses one it does not serve or none at all", async () => {
    await server.catalogSyncNow!("fireworks");
    expect(controlCalls().map((call) => [call.kind, call.bearerOf])).toEqual([["catalog", "fireworks"]]);

    recorder.calls = [];
    // A single-provider worker defaults to its own provider. The pool has no
    // provider to default to.
    for (const provider of [undefined, "chutes", "aws-bedrock", "mock", "__proto__", "toString"]) {
      await expect(server.catalogSyncNow!(provider), String(provider)).rejects.toThrow("catalog_sync_unavailable");
    }
    expect(recorder.calls).toEqual([]);
  });

  it("routes each provider's catalog-sync RPC to that provider's synchronizer", async () => {
    for (const provider of ["venice", "deepinfra", "phala-ai"] as const) {
      recorder.calls = [];
      const response = await server.inject({ method: "POST", url: `/internal/${provider}/catalog-sync`, headers: AUTH });
      expect(response.statusCode).toBe(200);
      expect(controlCalls().map((call) => [call.kind, call.bearerOf, (call.body?.payload as { provider: string }).provider]))
        .toEqual([["catalog", provider, provider]]);
    }
  });
});

// --- denied attempts -------------------------------------------------------------

describe("a denied attempt makes no provider request, for every pooled provider", () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    server = await buildPool(PLANNED, { stateDir: newStateDir() });
  });

  it.each(PLANNED)("%s: a denied dispatch stops at the fence", async (provider) => {
    recorder.dispatch = "deny";
    for (const operation of ["chat", "stream"]) {
      recorder.calls = [];
      const response = await server.inject({ method: "POST", url: `/internal/${provider}/${operation}`, headers: AUTH, payload: chatBody(provider) });
      expect(response.statusCode, operation).toBe(503);
      expect(response.json().error.type, operation).toBe("provider_attempt_fence_failed");
      // Control was asked, under this provider's token ...
      expect(controlCalls().map((call) => [call.kind, call.authorization]), operation)
        .toEqual([["dispatch-attempt", `Bearer ${metadataToken(provider)}`]]);
      // ... and no provider was called, with a key or without.
      expect(providerCalls(), operation).toEqual([]);
      // NEAR resolves a model's endpoint BEFORE the fence, from its public
      // discovery map. That request is keyless and carries no request content;
      // it is the adapter's existing order, and the only thing left over here.
      const leftover = recorder.calls.filter((call) => call.to === "discovery");
      expect(leftover.every((call) => call.authorization === null)).toBe(true);
      if (provider !== "near-ai") expect(leftover).toEqual([]);
    }
  });

  it.each(PLANNED)("%s: a denied attestation stops at the fence", async (provider) => {
    recorder.attestation = "deny";
    const response = await server.inject({ method: "POST", url: `/internal/${provider}/attestation`, headers: AUTH, payload: attestationBody(provider) });
    expect(response.statusCode).toBe(503);
    expect(response.json().error.type).toBe("provider_attempt_fence_failed");
    expect(recorder.calls.map((call) => [call.to, call.kind, call.authorization]))
      .toEqual([["control", "attestation-attempt", `Bearer ${metadataToken(provider)}`]]);
  });

  it("cannot authorize an attempt for a provider the pool does not serve", async () => {
    // The routes refuse this in production. This is the layer under them: the
    // fence has no acknowledger for the provider, so nothing is asked of
    // control under some other provider's token and the adapter never runs.
    const small = await buildPool(["venice", "fireworks"], { stateDir: newStateDir() });
    for (const providerName of ["deepinfra", "near-ai", "chutes", "mock"]) {
      await expect(small.workerClient.chat(chatBody(providerName)), providerName)
        .rejects.toMatchObject({ code: "provider_attempt_fence_failed" });
      await expect(small.workerClient.attestation(attestationBody(providerName)), providerName)
        .rejects.toMatchObject({ code: "provider_attempt_fence_failed" });
    }
    // Bedrock's adapter refuses before it ever asks the fence: it is not
    // enabled in this process. Its attestation does reach the fence.
    await expect(small.workerClient.chat(chatBody("aws-bedrock"))).rejects.toMatchObject({ code: "provider_not_configured" });
    await expect(small.workerClient.attestation(attestationBody("aws-bedrock")))
      .rejects.toMatchObject({ code: "provider_attempt_fence_failed" });
    // Only NEAR's keyless pre-fence discovery, as above. No control call at
    // all, and no provider call.
    expect(recorder.calls.filter((call) => call.to !== "discovery")).toEqual([]);
    expect(recorder.calls.every((call) => call.authorization === null)).toBe(true);
  });
});

// --- credential administration ---------------------------------------------------

describe("credential administration is namespaced by provider on the pool", () => {
  let server: FastifyInstance;
  let stateDir = "";
  let overlayPath = "";

  beforeEach(async () => {
    stateDir = newStateDir();
    overlayPath = join(stateDir, "venice-keyset-overlay.json");
    server = await buildPool(PLANNED, { stateDir });
    // An operator-added key, so the overlay file exists and "unchanged"
    // compares real bytes instead of two absences.
    server.veniceKeyStore.addKey({ id: "operator-added", label: "Seed", key: "sk-DEVDUMMY-pool-seed" });
    recorder.calls = [];
  });

  const snapshot = () => ({ bytes: readFileSync(overlayPath), keys: server.veniceKeyStore.effectiveKeys() });

  it("states, per provider, what its endpoint is and what it will perform", async () => {
    for (const provider of PLANNED) {
      const response = await server.inject({ method: "GET", url: `/internal/credentials/${provider}/identity` });
      expect(response.statusCode, provider).toBe(200);
      expect(response.json(), provider).toEqual({
        deployment_id: DEPLOYMENT_ID,
        // The canonical name, which is what a capability must be bound to.
        provider,
        tls_spki_sha256: SPKI,
        capability_protocol: expect.any(String),
        capability_signer_key_ids: [SIGNER_ID],
        // Truthful: only Venice has a store.
        accepted_actions: provider === "venice" ? ["register", "rotate", "revoke"] : []
      });
    }
  });

  const mutations: Array<{ name: string; action: CapabilityAction; credentialId: string; leaf: string; withSecret: boolean }> = [
    // Aimed where each would do the most damage if the store were shared: a
    // fresh id joins the Venice keyset, an existing id REPLACES a live Venice
    // key, and an existing id is revoked.
    { name: "install", action: "register", credentialId: "foreign-install-01", leaf: "secret", withSecret: true },
    { name: "rotate", action: "rotate", credentialId: "primary", leaf: "secret", withSecret: true },
    { name: "revoke", action: "revoke", credentialId: "operator-added", leaf: "revoke", withSecret: false }
  ];
  const nonVenice = PLANNED.filter((provider) => provider !== "venice");

  describe.each(nonVenice)("a valid %s capability on its own path", (provider) => {
    it.each(mutations)("$name leaves the Venice store byte-for-byte unchanged", async ({ action, credentialId, leaf, withSecret }) => {
      const before = snapshot();
      const secret = `fw-DEVDUMMY-foreign-${provider}-secret`;
      const signed = capability(provider, action, credentialId);
      const payload = { capability: signed, ...(withSecret ? { secret } : {}) };

      const response = await server.inject({ method: "POST", url: `/internal/credentials/${provider}/${leaf}`, payload });

      expect(response.statusCode).toBe(503);
      expect(response.json().error.type).toBe("credential_store_unavailable");
      expect(response.body).not.toContain(secret);
      const after = snapshot();
      expect(after.bytes.equals(before.bytes)).toBe(true);
      expect(after.keys).toEqual(before.keys);
      expect(readFileSync(overlayPath, "utf8")).not.toContain(secret);

      // Control is told exactly that, under THIS provider's token, and nothing
      // else was pushed: a refused mutation triggers no catalog sync.
      expect(recorder.calls.map((call) => [call.to, call.kind, call.authorization])).toEqual([
        ["control", "credential-outcome", `Bearer ${metadataToken(provider)}`]
      ]);
      expect(recorder.calls[0]!.body).toEqual({
        capabilityId: capabilityIdOf(signed), outcome: "failed", outcomeCode: "credential_store_unavailable"
      });
    });
  });

  it("refuses a Venice capability on every other provider's path, unconsumed", async () => {
    const before = snapshot();
    for (const provider of nonVenice) {
      for (const [action, leaf] of [["register", "secret"], ["rotate", "secret"], ["revoke", "revoke"]] as Array<[CapabilityAction, string]>) {
        const response = await server.inject({
          method: "POST",
          url: `/internal/credentials/${provider}/${leaf}`,
          payload: { capability: capability("venice", action, "primary"), ...(leaf === "secret" ? { secret: "sk-DEVDUMMY-pool-venice-moved" } : {}) }
        });
        expect(response.statusCode, `${provider} ${action}`).toBe(403);
        expect(response.json().error.type, `${provider} ${action}`).toBe("capability_wrong_provider");
      }
    }
    expect(snapshot().bytes.equals(before.bytes)).toBe(true);
    expect(snapshot().keys).toEqual(before.keys);
    // Refused before anything was consumed, stored or reported.
    expect(recorder.calls).toEqual([]);
    expect(readdirSync(stateDir).filter((name) => name.startsWith("consumed-"))).toEqual([]);
  });

  it("refuses every other provider's capability on the Venice path", async () => {
    const before = snapshot();
    for (const provider of [...nonVenice, "chutes", "aws-bedrock"]) {
      for (const [action, leaf] of [["register", "secret"], ["revoke", "revoke"]] as Array<[CapabilityAction, string]>) {
        const response = await server.inject({
          method: "POST",
          url: `/internal/credentials/venice/${leaf}`,
          payload: { capability: capability(provider, action, "primary"), ...(leaf === "secret" ? { secret: "fw-DEVDUMMY-foreign-secret" } : {}) }
        });
        expect(response.statusCode, `${provider} ${action}`).toBe(403);
        expect(response.json().error.type, `${provider} ${action}`).toBe("capability_wrong_provider");
      }
    }
    expect(snapshot().bytes.equals(before.bytes)).toBe(true);
    expect(recorder.calls).toEqual([]);
  });

  it("still administers Venice's own store, at the overlay path the Venice worker uses", async () => {
    const install = await server.inject({
      method: "POST",
      url: "/internal/credentials/venice/secret",
      payload: { capability: capability("venice", "register", "installed-01"), secret: "sk-DEVDUMMY-pool-venice-installed" }
    });
    expect(install.statusCode).toBe(200);
    expect(install.json()).toMatchObject({ ok: true, credential_id: "installed-01", provider: "venice", action: "register", status: "active" });
    expect(server.veniceKeyStore.keyById("installed-01")).toBe("sk-DEVDUMMY-pool-venice-installed");
    // Written to the configured overlay file and nowhere else.
    expect(server.config.providers.veniceKeysetOverlayFile).toBe(overlayPath);
    expect(readFileSync(overlayPath, "utf8")).toContain("sk-DEVDUMMY-pool-venice-installed");

    const revoke = await server.inject({
      method: "POST",
      url: "/internal/credentials/venice/revoke",
      payload: { capability: capability("venice", "revoke", "installed-01") }
    });
    expect(revoke.statusCode).toBe(200);
    expect(server.veniceKeyStore.keyById("installed-01")).toBeNull();

    // Each applied change re-synced VENICE's catalog and was reported under
    // Venice's token. No other provider's synchronizer or token was involved.
    const control = controlCalls();
    expect(control.map((call) => call.kind)).toEqual(["catalog", "credential-outcome", "catalog", "credential-outcome"]);
    for (const call of control) expect(call.authorization).toBe(`Bearer ${metadataToken("venice")}`);
    const manifests = control.filter((call) => call.kind === "catalog")
      .map((call) => (call.body!.veniceKeys as Array<{ id: string }>).map((entry) => entry.id));
    expect(manifests).toEqual([["primary", "operator-added", "installed-01"], ["primary", "operator-added"]]);
    for (const call of recorder.calls) expect(JSON.stringify(call.body)).not.toContain("sk-DEVDUMMY-pool-venice-installed");
  });

  it("the live keyset an install changes is the one inference dispatches with", async () => {
    // One store for every Venice consumer in the process: retire the boot key
    // through the capability route and the next dispatch uses the new one.
    await server.inject({
      method: "POST",
      url: "/internal/credentials/venice/secret",
      payload: { capability: capability("venice", "register", "installed-01"), secret: "sk-DEVDUMMY-pool-venice-rotated" }
    });
    for (const id of ["primary", "operator-added"]) {
      const revoke = await server.inject({
        method: "POST", url: "/internal/credentials/venice/revoke", payload: { capability: capability("venice", "revoke", id) }
      });
      expect(revoke.statusCode, id).toBe(200);
    }
    recorder.calls = [];

    const chat = await server.inject({ method: "POST", url: "/internal/venice/chat", headers: AUTH, payload: chatBody("venice") });
    expect(chat.statusCode).toBe(200);
    await server.catalogSyncNow!("venice");
    // Inference, the catalog fetch and the rate-limit fetch: all the new key.
    expect(providerCalls().map((call) => call.authorization)).toEqual([
      "Bearer sk-DEVDUMMY-pool-venice-rotated",
      "Bearer sk-DEVDUMMY-pool-venice-rotated",
      "Bearer sk-DEVDUMMY-pool-venice-rotated"
    ]);
  });
});

// --- replay ---------------------------------------------------------------------

describe("consumed capabilities are recorded per provider, under today's filenames (C5)", () => {
  const consumedIds = (file: string): string[] =>
    (JSON.parse(readFileSync(file, "utf8")) as Array<{ capabilityId: string }>).map((entry) => entry.capabilityId);

  it("records A's capability in A's file, not B's, and still refuses it after a rebuild on the same directory", async () => {
    const stateDir = newStateDir();
    const first = await buildPool(PLANNED, { stateDir });
    const used: Partial<Record<Planned, { capability: string; signature: string; keyId: string }>> = {};

    for (const provider of PLANNED) {
      const signed = capability(provider, "revoke", "no-such-credential");
      used[provider] = signed;
      const response = await first.inject({ method: "POST", url: `/internal/credentials/${provider}/revoke`, payload: { capability: signed } });
      // Verified and consumed either way: Venice has no such key, the others no store.
      expect(response.statusCode, provider).toBe(provider === "venice" ? 404 : 503);
    }

    // One file per provider, each named as that provider's own worker names it.
    expect(readdirSync(stateDir).filter((name) => name.startsWith("consumed-")).sort()).toEqual([
      "consumed-deepinfra.json", "consumed-fireworks.json", "consumed-near.json",
      "consumed-phala-ai.json", "consumed-tinfoil.json", "consumed-venice.json"
    ]);
    // The single shared file the pool must never fall back to.
    expect(existsSync(join(stateDir, "consumed-capabilities.json"))).toBe(false);
    for (const provider of PLANNED) {
      const own = join(stateDir, consumedCapabilityFileName(provider));
      // A's capability is in A's file, and A's file holds nothing else.
      expect(consumedIds(own), provider).toEqual([capabilityIdOf(used[provider]!)]);
    }

    await first.close();
    const second = await buildPool(PLANNED, { stateDir });
    for (const provider of PLANNED) {
      const replay = await second.inject({ method: "POST", url: `/internal/credentials/${provider}/revoke`, payload: { capability: used[provider]! } });
      expect(replay.statusCode, provider).toBe(409);
      expect(replay.json().error.type, provider).toBe("capability_already_used");
    }
  });

  it("fails closed when a provider's replay log is unreadable, for that provider only", async () => {
    const stateDir = newStateDir();
    writeFileSync(join(stateDir, "consumed-fireworks.json"), "{ not json");
    const server = await buildPool(["venice", "fireworks", "deepinfra"], { stateDir });

    const refused = await server.inject({
      method: "POST", url: "/internal/credentials/fireworks/revoke", payload: { capability: capability("fireworks", "revoke", "any-credential") }
    });
    // An unreadable log is not "nothing consumed yet".
    expect(refused.statusCode).toBeGreaterThanOrEqual(500);
    const other = await server.inject({
      method: "POST", url: "/internal/credentials/deepinfra/revoke", payload: { capability: capability("deepinfra", "revoke", "any-credential") }
    });
    expect(other.statusCode).toBe(503);
    expect(other.json().error.type).toBe("credential_store_unavailable");
  });

  it.each([
    ["near-worker", "near-ai", "consumed-near.json"],
    ["fireworks-worker", "fireworks", "consumed-fireworks.json"],
    ["venice-worker", "venice", "consumed-venice.json"]
  ] as Array<[string, Planned, string]>)(
    "round trip with %s: old worker -> pool -> restart -> old worker all see one record",
    async (role, provider, fileName) => {
      const stateDir = newStateDir();
      const expected = provider === "venice" ? 404 : 503;

      // OLD: today's worker, its replay log where the production compose puts it.
      singleEnvironment(role, provider, { stateDir });
      expect(process.env.CONSUMED_CAPABILITY_FILE).toBe(join(stateDir, fileName));
      const old = await build();
      const usedByOld = capability(provider, "revoke", "no-such-credential");
      expect((await old.inject({ method: "POST", url: "/internal/credentials/revoke", payload: { capability: usedByOld } })).statusCode).toBe(expected);
      await old.close();

      // POOL on the same volume: refuses what the old worker consumed ...
      const pool = await buildPool(PLANNED, { stateDir });
      const replayInPool = await pool.inject({ method: "POST", url: `/internal/credentials/${provider}/revoke`, payload: { capability: usedByOld } });
      expect(replayInPool.statusCode).toBe(409);
      // ... and consumes one of its own, into the same file.
      const usedByPool = capability(provider, "revoke", "no-such-credential");
      expect((await pool.inject({ method: "POST", url: `/internal/credentials/${provider}/revoke`, payload: { capability: usedByPool } })).statusCode).toBe(expected);
      await pool.close();
      expect(consumedIds(join(stateDir, fileName))).toEqual([capabilityIdOf(usedByOld), capabilityIdOf(usedByPool)]);

      // RESTART of the pool: both still refused.
      const restarted = await buildPool(PLANNED, { stateDir });
      for (const signed of [usedByOld, usedByPool]) {
        expect((await restarted.inject({ method: "POST", url: `/internal/credentials/${provider}/revoke`, payload: { capability: signed } })).statusCode).toBe(409);
      }
      await restarted.close();

      // ROLLBACK to the old worker: it finds what the pool consumed.
      singleEnvironment(role, provider, { stateDir });
      const rolledBack = await build();
      for (const signed of [usedByOld, usedByPool]) {
        const replay = await rolledBack.inject({ method: "POST", url: "/internal/credentials/revoke", payload: { capability: signed } });
        expect(replay.statusCode).toBe(409);
        expect(replay.json().error.type).toBe("capability_already_used");
      }
    }
  );

  it("keeps Venice's overlay across the same round trip: additions and revocation tombstones", async () => {
    const stateDir = newStateDir();
    // OLD Venice worker: add a key and retire the boot key.
    singleEnvironment("venice-worker", "venice", { stateDir });
    const old = await build();
    await old.inject({ method: "POST", url: "/internal/credentials/secret", payload: { capability: capability("venice", "register", "added-by-old"), secret: "sk-DEVDUMMY-pool-added-by-old" } });
    await old.inject({ method: "POST", url: "/internal/credentials/revoke", payload: { capability: capability("venice", "revoke", "primary") } });
    expect(old.veniceKeyStore.effectiveKeys().map((entry) => entry.id)).toEqual(["added-by-old"]);
    await old.close();

    // POOL: sees exactly that keyset. The boot key stays revoked.
    const pool = await buildPool(PLANNED, { stateDir });
    expect(pool.veniceKeyStore.effectiveKeys().map((entry) => entry.id)).toEqual(["added-by-old"]);
    await pool.inject({ method: "POST", url: "/internal/credentials/venice/secret", payload: { capability: capability("venice", "register", "added-by-pool"), secret: "sk-DEVDUMMY-pool-added-by-pool" } });
    await pool.close();

    // ROLLBACK: the old worker sees the pool's addition and its own tombstone.
    singleEnvironment("venice-worker", "venice", { stateDir });
    const rolledBack = await build();
    expect(rolledBack.veniceKeyStore.effectiveKeys().map((entry) => entry.id)).toEqual(["added-by-old", "added-by-pool"]);
  });
});

// --- startup and containment -----------------------------------------------------

describe("startup and failure containment (S6)", () => {
  function hang(): { respond: () => Promise<Response>; release: (response: Response) => void } {
    let release!: (response: Response) => void;
    const pending = new Promise<Response>((resolve) => { release = resolve; });
    return { respond: () => pending, release };
  }

  const pushed = (kind: string) => controlCalls().filter((call) => call.kind === kind).map((call) => call.bearerOf);

  it("serves before any first sync has finished, and one hung or failing provider stops no other", async () => {
    const providers: Planned[] = ["venice", "fireworks", "deepinfra", "phala-ai"];
    const fireworks = hang();
    recorder.catalog = { fireworks: fireworks.respond, deepinfra: "fail" };

    const started = Date.now();
    const server = await buildPool(providers, { stateDir: newStateDir(), sync: true });
    // It returned with Fireworks' first sync still open. A boot that waited
    // for it would not have returned at all.
    expect(Date.now() - started).toBeLessThan(5_000);

    // The healthy providers synced on their own.
    await vi.waitFor(() => expect(pushed("catalog").sort()).toEqual(["phala-ai", "venice"]));
    // Fireworks is still waiting on its catalog; DeepInfra's failed. Neither pushed.
    expect(providerCalls().filter((call) => call.kind === "catalog").map((call) => call.bearerOf).sort())
      .toEqual(["deepinfra", "fireworks", "phala-ai", "venice"]);

    // Every provider serves meanwhile, the two with no catalog included:
    // serving does not wait on a sync.
    for (const provider of providers) {
      const response = await server.inject({ method: "POST", url: `/internal/${provider}/chat`, headers: AUTH, payload: chatBody(provider) });
      expect(response.statusCode, provider).toBe(200);
    }

    // On demand, each provider's failure is its own.
    await expect(server.catalogSyncNow!("deepinfra")).rejects.toThrow("catalog_fetch_failed");
    await expect(server.catalogSyncNow!("venice")).resolves.toBeUndefined();
    const failing = await server.inject({ method: "POST", url: "/internal/deepinfra/catalog-sync", headers: AUTH });
    expect(failing.statusCode).toBe(502);
    expect(pushed("catalog")).not.toContain("fireworks");
    expect(pushed("catalog")).not.toContain("deepinfra");

    // Fireworks answers at last, and its own poller finishes the sync it began.
    fireworks.release(json({ models: [] }));
    await vi.waitFor(() => expect(pushed("catalog")).toContain("fireworks"));
    for (const call of controlCalls().filter((entry) => entry.kind === "catalog")) {
      expect(call.authorization).toBe(`Bearer ${metadataToken(call.bearerOf!)}`);
      expect((call.body!.payload as { provider: string }).provider).toBe(call.bearerOf);
    }
  });

  it("a single-provider worker still boots behind its first sync, exactly as before", async () => {
    const venice = hang();
    recorder.catalog = { venice: venice.respond };
    singleEnvironment("venice-worker", "venice", { stateDir: newStateDir(), sync: true });

    let built = false;
    const building = buildWorkerServer(loadConfig()).then((server) => {
      built = true;
      servers.push(server);
      return server;
    });
    await vi.waitFor(() => expect(providerCalls().map((call) => call.kind)).toEqual(["catalog"]));
    await sleep(50);
    // Still waiting on the sync. The pool, in the test above, was not.
    expect(built).toBe(false);
    expect(controlCalls()).toEqual([]);

    venice.release(json({ data: [] }));
    await building;
    expect(built).toBe(true);
    // And the sync it waited for had completed: catalog pushed before it returned.
    expect(controlCalls().map((call) => [call.kind, call.bearerOf])).toEqual([["catalog", "venice"]]);
  });

  it("the same pool does not wait even when EVERY provider's first sync hangs", async () => {
    const hangs = { venice: hang(), fireworks: hang() };
    recorder.catalog = { venice: hangs.venice.respond, fireworks: hangs.fireworks.respond };
    const server = await buildPool(["venice", "fireworks"], { stateDir: newStateDir(), sync: true });
    expect(controlCalls()).toEqual([]);
    const response = await server.inject({ method: "POST", url: "/internal/venice/chat", headers: AUTH, payload: chatBody("venice") });
    expect(response.statusCode).toBe(200);
    expect((await server.inject({ method: "GET", url: "/healthz" })).statusCode).toBe(200);
    hangs.venice.release(json({ data: [] }));
    hangs.fireworks.release(json({ models: [] }));
    await vi.waitFor(() => expect(pushed("catalog").sort()).toEqual(["fireworks", "venice"]));
  });

  it("runs each provider's poller on its own timer, and stops every one on close", async () => {
    const providers: Planned[] = ["venice", "fireworks", "phala-ai"];
    // The shortest interval config accepts, so a second round is observable.
    const server = await buildPool(providers, { stateDir: newStateDir(), sync: true, intervalSeconds: 1 });
    const rounds = (provider: string) => pushed("catalog").filter((entry) => entry === provider).length;

    await vi.waitFor(() => {
      for (const provider of providers) expect(rounds(provider), provider).toBeGreaterThanOrEqual(2);
    }, { timeout: 5_000, interval: 50 });

    await server.close();
    // Let anything already in flight land, then watch for a full interval.
    await sleep(200);
    const settled = recorder.calls.length;
    await sleep(1_500);
    expect(recorder.calls.length).toBe(settled);
  }, 15_000);

  it("does not start a poller at all with CATALOG_SYNC_ENABLED=false, but syncs on demand", async () => {
    const server = await buildPool(["venice", "fireworks"], { stateDir: newStateDir(), sync: false });
    await sleep(100);
    expect(recorder.calls).toEqual([]);
    await server.catalogSyncNow!("fireworks");
    expect(pushed("catalog")).toEqual(["fireworks"]);
  });
});

describe("health probes share one budget across the pool (S6)", () => {
  it.each(["missing", "malformed", "expired"] as const)("does not dispatch paid probes with a %s grant, including on-demand sync", async mode => {
    const server = await buildPool(["venice", "fireworks"], { stateDir: newStateDir(), sync: false });
    recorder.healthTargets = { venice: ["model-v"], fireworks: ["model-f"] };
    recorder.leaseMode = mode;
    await Promise.all([server.catalogSyncNow!("venice"), server.catalogSyncNow!("fireworks")]);
    expect(controlCalls().filter(call => call.kind === "catalog")).toHaveLength(2);
    expect(controlCalls().filter(call => call.kind === "catalog").every(call => call.probeLeaseOptIn === "1")).toBe(true);
    expect(providerCalls().filter(call => call.kind === "chat")).toHaveLength(0);
    expect(controlCalls().filter(call => call.kind === "health")).toHaveLength(0);
  });
  const providers: Planned[] = ["venice", "fireworks", "deepinfra", "phala-ai"];
  const models = (provider: string) => Array.from({ length: 6 }, (_, index) => `${provider}-model-${index}`);

  it("never runs more than four probes at once across providers, nor more than two for one", async () => {
    const server = await buildPool(providers, { stateDir: newStateDir() });
    recorder.healthTargets = Object.fromEntries(providers.map((provider) => [provider, models(provider)]));
    recorder.chatDelayMs = 25;

    await Promise.all(providers.map((provider) => server.catalogSyncNow!(provider)));

    // 24 probes ran. Unbounded, sixteen would have been in flight at once
    // (four providers, four each).
    expect(providerCalls().filter((call) => call.kind === "chat")).toHaveLength(24);
    expect(recorder.maxInFlightTotal).toBe(4);
    for (const provider of providers) {
      expect(recorder.maxInFlight[provider], provider).toBeGreaterThanOrEqual(1);
      expect(recorder.maxInFlight[provider], provider).toBeLessThanOrEqual(2);
    }

    // Every provider's results still arrived, complete, under its own token.
    const reports = controlCalls().filter((call) => call.kind === "health");
    expect(reports.map((call) => call.bearerOf).sort()).toEqual([...providers].sort());
    for (const report of reports) {
      const provider = report.body!.provider as string;
      expect(report.bearerOf).toBe(provider);
      expect(report.body!.healthProbeLeaseId).toBe("11".repeat(16));
      expect((report.body!.healthChecks as Array<{ externalModelId: string }>).map((check) => check.externalModelId).sort())
        .toEqual(models(provider).sort());
      for (const call of providerCalls().filter((entry) => entry.kind === "chat" && (entry.body?.model as string).startsWith(`${provider}-model-`))) {
        expect(call.authorization).toBe(`Bearer ${providerKey(provider)}`);
      }
    }
  });

  it("leaves a single-provider worker's own bound of four as it was", async () => {
    singleEnvironment("venice-worker", "venice", { stateDir: newStateDir() });
    const server = await build();
    recorder.healthTargets = { venice: models("venice") };
    recorder.chatDelayMs = 25;
    await server.catalogSyncNow!();
    expect(providerCalls().filter((call) => call.kind === "chat")).toHaveLength(6);
    expect(recorder.maxInFlightTotal).toBe(4);
  });
});
