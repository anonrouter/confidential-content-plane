// The release-collateral role's configuration, and the pool's side of it
// (PROVIDER_POOL_PLAN.md, W3; review finding C6).
//
// The role answers a caller it does not trust with public, keyless lookups. So
// what it may hold is decided at boot: one token, the one that admits that
// caller, and no other authority of any kind. Every refusal below is reached
// with exactly ONE thing wrong and compared as the whole message, so no other
// problem can be what failed the boot.
//
// The same is done for the pool, which must be told where the release-collateral role
// is, and for every other role, which must not be.

import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../../src/config.js";
import { releaseCollateralClientFor } from "../../src/releaseCollateral/client.js";
import { releaseCollateralPath, RELEASE_COLLATERAL_OPERATIONS } from "../../src/releaseCollateral/contract.js";
import { buildReleaseCollateralServer } from "../../src/roles.js";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const distinct = (seed: string) => `prod-${seed}-${"x".repeat(40)}`.slice(0, 48);
// A value an operator might paste, recognisable so a refusal can be searched for it.
const LEAKED = "sk-DEVDUMMY-leaked-into-the-role-0123456789abcdef";

let snapshot: NodeJS.ProcessEnv;
let directory = "";
let keyFile = "";
let keysetFile = "";
let scopesFile = "";

function clearRelevant() {
  for (const key of Object.keys(process.env)) {
    if (/^(RUNTIME_ROLE|POOL_PROVIDERS|RELEASE_COLLATERAL_|PROVIDER_TRANSPORT_PROFILE|LOG_LEVEL|RELAY_RPC|WORKER_RPC|METADATA_RPC|CONTROL_RPC|CONTROL_METADATA|COMPAT_RPC|VENICE_|FIREWORKS_|DEEPINFRA_|CHUTES_|TINFOIL_|NEAR_|PHALA_AI_|BEDROCK_|AWS_|MOCK_PROVIDER_|ALLOW_INLINE_TICKET|ALLOW_COMPAT_MODE|APP_SECRET|EMAIL_HASH_SECRET|EMAIL_ENCRYPTION_KEY|COOKIE_SECRET|BETTER_AUTH_SECRET|ADMIN_|CORS_ORIGIN|SMTP_|DATABASE_URL|MIGRATION_DATABASE_URL|APP_DB|GATEWAY_|DSTACK_|REDIS_URL|STRIPE_|PAYMENTS_MODE|CONSUMED_CAPABILITY|CREDENTIAL_|CONTENT_TLS|PROVIDER_CAPABILITY|PROVIDER_CREDENTIAL|TRUST_PROXY_HOPS)/.test(key)) {
      delete process.env[key];
    }
  }
}

/** A production release-collateral role with the one thing it requires, and nothing else. */
function productionReleaseCollateral() {
  clearRelevant();
  process.env.NODE_ENV = "production";
  process.env.RUNTIME_ROLE = "release-collateral";
  process.env.RELEASE_COLLATERAL_RPC_TOKEN = distinct("release-collateral-token");
}

const PLANNED = [
  ["venice", "METADATA_RPC_TOKEN_VENICE", "VENICE_INFERENCE_KEY_FILE"],
  ["fireworks", "METADATA_RPC_TOKEN_FIREWORKS", "FIREWORKS_API_KEY_FILE"],
  ["deepinfra", "METADATA_RPC_TOKEN_DEEPINFRA", "DEEPINFRA_API_KEY_FILE"],
  ["tinfoil", "METADATA_RPC_TOKEN_TINFOIL", "TINFOIL_API_KEY_FILE"],
  ["near-ai", "METADATA_RPC_TOKEN_NEAR", "NEAR_API_KEY_FILE"],
  ["phala-ai", "METADATA_RPC_TOKEN_PHALA_AI", "PHALA_AI_API_KEY_FILE"]
] as const;

/** A production pool with everything it requires, the release-collateral role included. */
function productionPool() {
  clearRelevant();
  process.env.NODE_ENV = "production";
  process.env.RUNTIME_ROLE = "pool-worker";
  process.env.POOL_PROVIDERS = PLANNED.map(([provider]) => provider).join(",");
  process.env.WORKER_RPC_TOKEN = distinct("workertoken");
  process.env.CONTROL_METADATA_URL = "http://control:3000";
  process.env.CREDENTIAL_ADMIN_MODE = "capability";
  process.env.RELEASE_COLLATERAL_RPC_URL = "http://release-collateral:3000";
  process.env.RELEASE_COLLATERAL_RPC_TOKEN = distinct("release-collateral-token");
  for (const [provider, tokenVariable, keyVariable] of PLANNED) {
    process.env[tokenVariable] = distinct(`metadata-${provider}`);
    process.env[keyVariable] = keyFile;
  }
}

/** A production single-provider worker, as it boots today: no release-collateral variable at all. */
function productionWorker(role: string, keyVariable: string) {
  clearRelevant();
  process.env.NODE_ENV = "production";
  process.env.RUNTIME_ROLE = role;
  process.env.WORKER_RPC_TOKEN = distinct("workertoken");
  process.env.METADATA_RPC_TOKEN = distinct("metadatatoken");
  process.env.CONTROL_METADATA_URL = "http://control:3000";
  process.env[keyVariable] = keyFile;
}

function productionRelay() {
  clearRelevant();
  process.env.NODE_ENV = "production";
  process.env.RUNTIME_ROLE = "relay";
  process.env.TRUST_PROXY_HOPS = "1";
  process.env.ALLOW_INLINE_TICKET = "false";
  process.env.CORS_ORIGIN = "https://anonrouter.example";
  process.env.RELAY_RPC_TOKEN = distinct("relaytoken");
  process.env.WORKER_RPC_TOKEN = distinct("workertoken");
}

function productionCompat() {
  clearRelevant();
  process.env.NODE_ENV = "production";
  process.env.RUNTIME_ROLE = "compat";
  process.env.TRUST_PROXY_HOPS = "1";
  process.env.CORS_ORIGIN = "https://anonrouter.example";
}

function productionGatewayAttestation() {
  clearRelevant();
  process.env.NODE_ENV = "production";
  process.env.RUNTIME_ROLE = "gateway-attestation";
  process.env.GATEWAY_ATTESTATION_ENABLED = "true";
  process.env.GATEWAY_PUBLIC_ORIGIN = "https://api.anonrouter.example";
  process.env.GATEWAY_RELEASE_ID = "unit-release-1";
}

/** The whole boot error for exactly these problems, in the order config raises them. */
function refusal(...problems: string[]) {
  return `Split-role configuration is invalid (${problems.join("; ")})`;
}

function bootError(): Error {
  try {
    loadConfig();
  } catch (error) {
    return error as Error;
  }
  throw new Error("the configuration booted");
}

beforeAll(() => {
  directory = mkdtempSync(join(tmpdir(), "anonrouter-release-collateral-config-"));
  keyFile = join(directory, "provider_key");
  writeFileSync(keyFile, "unit-test-provider-key");
  keysetFile = join(directory, "venice_keyset.json");
  writeFileSync(keysetFile, JSON.stringify([{ id: "primary", label: "Boot", key: "unit-test-venice-key" }]));
  scopesFile = join(directory, "scopes.json");
  writeFileSync(scopesFile, "[]");
});

afterAll(() => {
  rmSync(directory, { recursive: true, force: true });
});

beforeEach(() => {
  snapshot = { ...process.env };
});

afterEach(() => {
  process.env = snapshot;
});

/** A value for `variable` that the schema accepts, so the fence is what refuses it. */
function valueFor(variable: string): string {
  const fixed: Record<string, string> = {
    METADATA_RPC_DEPLOYMENT_SCOPES: "[]",
    METADATA_RPC_DEPLOYMENT_SCOPES_FILE: scopesFile,
    BEDROCK_BASE_URL: "https://bedrock-mantle.us-east-1.api.aws/v1",
    CREDENTIAL_ADMIN_MODE: "capability",
    PROVIDER_CREDENTIAL_ADMIN_MODE: "direct-to-tee",
    CONTENT_TLS_SPKI_SHA256: "7c".repeat(32),
    CONSUMED_CAPABILITY_FILE: "/var/lib/anonrouter-worker/consumed-near.json",
    CONSUMED_CAPABILITY_DIR: "/var/lib/anonrouter-worker",
    VENICE_KEYSET_OVERLAY_FILE: "/var/lib/anonrouter-worker/venice-keyset-overlay.json",
    REDIS_URL: "redis://valkey:6379",
    DSTACK_ENDPOINT: "/var/run/dstack.sock",
    DSTACK_SIMULATOR_ENDPOINT: "http://127.0.0.1:8090"
  };
  if (variable in fixed) return fixed[variable]!;
  // A path for the file forms: where config reads the file, it must exist.
  return variable.endsWith("_FILE") ? keyFile : `${LEAKED}-${variable.toLowerCase()}`;
}

function expectRefusedByName(variable: string) {
  productionReleaseCollateral();
  process.env[variable] = valueFor(variable);
  const error = bootError();
  expect(error.message).toBe(refusal(`release-collateral must not be given ${variable}`));
  // Names only, never values.
  expect(error.message).not.toContain(LEAKED);
  expect(error.message).not.toContain(directory);
}

// --- the role ---------------------------------------------------------------------

describe("a production release-collateral role", () => {
  it("boots holding its own token and nothing else", () => {
    productionReleaseCollateral();
    const config = loadConfig();
    expect(config.internal.role).toBe("release-collateral");
    expect(config.internal.releaseCollateralRpcToken).toBe(distinct("release-collateral-token"));
    // It is the server. It has no release-collateral role of its own to call.
    expect(config.internal.releaseCollateralRpcUrl).toBe("");
    expect(releaseCollateralClientFor(config)).toBeNull();
    // Every other authority is empty.
    expect(config.internal.workerRpcToken).toBe("");
    expect(config.internal.relayRpcToken).toBe("");
    expect(config.internal.compatRpcToken).toBe("");
    expect(config.internal.metadataRpcToken).toBe("");
    expect(config.internal.deploymentMetadataToken).toBe("");
    expect(config.internal.workerMetadataToken).toBe("");
    expect(config.internal.providerMetadataTokens).toEqual({});
    expect(config.internal.poolProviders).toEqual([]);
    expect(config.providers.veniceKeys).toEqual([]);
    expect(config.internal.gatewayAttestation.enabled).toBe(false);
  });

  it("accepts its token from a file, as the compose mounts it", () => {
    productionReleaseCollateral();
    delete process.env.RELEASE_COLLATERAL_RPC_TOKEN;
    const tokenFile = join(directory, "release_collateral_token");
    writeFileSync(tokenFile, distinct("release-collateral-from-file"));
    process.env.RELEASE_COLLATERAL_RPC_TOKEN_FILE = tokenFile;
    expect(loadConfig().internal.releaseCollateralRpcToken).toBe(distinct("release-collateral-from-file"));
  });

  it.each([
    ["unset", undefined],
    ["empty", ""],
    ["short", "too-short"],
    ["a placeholder", `change-me-${"x".repeat(40)}`],
    ["the dev fallback", "dev-only-release-collateral-rpc-token-change-me-32-bytes"]
  ])("requires a strong RELEASE_COLLATERAL_RPC_TOKEN: refuses %s", (_label, value) => {
    productionReleaseCollateral();
    if (value === undefined) delete process.env.RELEASE_COLLATERAL_RPC_TOKEN;
    else process.env.RELEASE_COLLATERAL_RPC_TOKEN = value;
    expect(bootError().message).toBe(refusal("RELEASE_COLLATERAL_RPC_TOKEN must be a >= 32-byte non-placeholder value"));
  });

  it("has no dev fallback token in production, and one outside it", () => {
    productionReleaseCollateral();
    delete process.env.RELEASE_COLLATERAL_RPC_TOKEN;
    process.env.NODE_ENV = "test";
    expect(loadConfig().internal.releaseCollateralRpcToken).toBe("dev-only-release-collateral-rpc-token-change-me-32-bytes");
  });

  // --- no provider credential of any kind ---
  it.each<[string, string, () => string, string]>([
    ["Venice, a direct key", "VENICE_INFERENCE_KEY", () => LEAKED, "the release-collateral service must not hold a Venice credential"],
    ["Venice, the older variable", "VENICE_INFERENCE_API_KEY", () => LEAKED, "the release-collateral service must not hold a Venice credential"],
    ["Venice, the oldest variable", "VENICE_API_KEY", () => LEAKED, "the release-collateral service must not hold a Venice credential"],
    ["Venice, a key file", "VENICE_INFERENCE_KEY_FILE", () => keyFile, "the release-collateral service must not hold a Venice credential"],
    ["Venice, a direct keyset", "VENICE_INFERENCE_KEYS", () => JSON.stringify([{ id: "primary", label: "x", key: LEAKED }]), "the release-collateral service must not hold a Venice credential"],
    ["Venice, a keyset file", "VENICE_INFERENCE_KEYS_FILE", () => keysetFile, "the release-collateral service must not hold a Venice credential"],
    ["Fireworks", "FIREWORKS_API_KEY", () => LEAKED, "the release-collateral service must not hold a Fireworks credential"],
    ["Fireworks, file", "FIREWORKS_API_KEY_FILE", () => keyFile, "the release-collateral service must not hold a Fireworks credential"],
    ["DeepInfra", "DEEPINFRA_API_KEY", () => LEAKED, "the release-collateral service must not hold a DeepInfra credential"],
    ["DeepInfra, file", "DEEPINFRA_API_KEY_FILE", () => keyFile, "the release-collateral service must not hold a DeepInfra credential"],
    ["Chutes", "CHUTES_API_KEY", () => LEAKED, "only the Chutes worker may hold a Chutes credential"],
    ["Chutes, file", "CHUTES_API_KEY_FILE", () => keyFile, "only the Chutes worker may hold a Chutes credential"],
    ["Tinfoil", "TINFOIL_API_KEY", () => LEAKED, "only the Tinfoil worker may hold a Tinfoil credential"],
    ["Tinfoil, file", "TINFOIL_API_KEY_FILE", () => keyFile, "only the Tinfoil worker may hold a Tinfoil credential"],
    ["NEAR AI", "NEAR_API_KEY", () => LEAKED, "only the NEAR AI worker may hold a NEAR AI credential"],
    ["NEAR AI, file", "NEAR_API_KEY_FILE", () => keyFile, "only the NEAR AI worker may hold a NEAR AI credential"],
    ["Phala AI", "PHALA_AI_API_KEY", () => LEAKED, "only the Phala AI worker may hold a Phala AI credential"],
    ["Phala AI, file", "PHALA_AI_API_KEY_FILE", () => keyFile, "only the Phala AI worker may hold a Phala AI credential"]
  ])("refuses a provider credential: %s", (_label, variable, value, message) => {
    productionReleaseCollateral();
    process.env[variable] = value();
    const error = bootError();
    expect(error.message).toBe(refusal(message));
    expect(error.message).not.toContain(LEAKED);
  });

  // --- no metadata token of any kind ---
  it.each([
    "METADATA_RPC_TOKEN", "METADATA_RPC_TOKEN_FILE",
    "METADATA_RPC_TOKEN_VENICE", "METADATA_RPC_TOKEN_VENICE_FILE",
    "METADATA_RPC_TOKEN_FIREWORKS", "METADATA_RPC_TOKEN_FIREWORKS_FILE",
    "METADATA_RPC_TOKEN_BEDROCK", "METADATA_RPC_TOKEN_BEDROCK_FILE",
    "METADATA_RPC_TOKEN_DEEPINFRA", "METADATA_RPC_TOKEN_DEEPINFRA_FILE",
    "METADATA_RPC_TOKEN_CHUTES", "METADATA_RPC_TOKEN_CHUTES_FILE",
    "METADATA_RPC_TOKEN_TINFOIL", "METADATA_RPC_TOKEN_TINFOIL_FILE",
    "METADATA_RPC_TOKEN_NEAR", "METADATA_RPC_TOKEN_NEAR_FILE",
    "METADATA_RPC_TOKEN_PHALA_AI", "METADATA_RPC_TOKEN_PHALA_AI_FILE",
    "METADATA_RPC_DEPLOYMENT_TOKEN", "METADATA_RPC_DEPLOYMENT_TOKEN_FILE",
    "METADATA_RPC_DEPLOYMENT_SCOPES", "METADATA_RPC_DEPLOYMENT_SCOPES_FILE"
  ])("refuses metadata authority %s", (variable) => {
    expectRefusedByName(variable);
  });

  it("names every metadata token variable the schema defines", () => {
    // Read from the source, so a provider added tomorrow with its own metadata
    // token is refused here without anyone remembering this file.
    const defined = [...readFileSync(join(ROOT, "src/config.ts"), "utf8").matchAll(/^\s{2}(METADATA_RPC_[A-Z_]+): z\./gm)].map((match) => match[1]!);
    expect(defined.length).toBeGreaterThanOrEqual(22);
    for (const variable of defined) expectRefusedByName(variable);
  });

  // --- no other role's service token ---
  it.each([
    "WORKER_RPC_TOKEN", "WORKER_RPC_TOKEN_FILE",
    "RELAY_RPC_TOKEN", "RELAY_RPC_TOKEN_FILE",
    "COMPAT_RPC_TOKEN", "COMPAT_RPC_TOKEN_FILE"
  ])("refuses another role's service token %s", (variable) => {
    expectRefusedByName(variable);
  });

  // --- the existing content-tier list ---
  it.each([
    "DATABASE_URL", "DATABASE_URL_FILE", "MIGRATION_DATABASE_URL", "MIGRATION_DATABASE_URL_FILE",
    "REDIS_URL", "APP_DB_PASSWORD", "BETTER_AUTH_SECRET", "BETTER_AUTH_SECRET_FILE",
    "COOKIE_SECRET", "COOKIE_SECRET_FILE", "EMAIL_ENCRYPTION_KEY", "EMAIL_ENCRYPTION_KEY_FILE",
    "ADMIN_ACCESS_TOKEN", "ADMIN_ACCESS_TOKEN_FILE", "STRIPE_API_KEY", "STRIPE_API_KEY_FILE",
    "SMTP_PASSWORD", "SMTP_PASSWORD_FILE"
  ])("refuses the database, cache, auth, payment or mail secret %s", (variable) => {
    expectRefusedByName(variable);
  });

  it.each(["APP_SECRET", "APP_SECRET_FILE", "EMAIL_HASH_SECRET", "EMAIL_HASH_SECRET_FILE"])("refuses the hashing secret %s", (variable) => {
    expectRefusedByName(variable);
  });

  // --- no AWS credentials or Bedrock settings ---
  it.each(["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"])("refuses static AWS key %s", (variable) => {
    productionReleaseCollateral();
    process.env[variable] = "AKIAUNITTESTCANARY00";
    expect(bootError().message).toBe(refusal("this role must not hold static AWS credentials"));
  });

  it.each([
    "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "BEDROCK_BASE_URL"
  ])("refuses the AWS credential source or Bedrock setting %s", (variable) => {
    expectRefusedByName(variable);
  });

  it("refuses Bedrock being enabled or a Bedrock profile", () => {
    productionReleaseCollateral();
    process.env.BEDROCK_ENABLED = "true";
    expect(bootError().message).toBe(refusal("BEDROCK_ENABLED must not be true on the release-collateral service"));

    productionReleaseCollateral();
    process.env.BEDROCK_AWS_PROFILE = "anonrouter-bedrock";
    expect(bootError().message).toBe(refusal("the release-collateral service must not select an AWS Bedrock credential profile"));

    // Explicitly off is not a Bedrock setting worth refusing a boot over.
    productionReleaseCollateral();
    process.env.BEDROCK_ENABLED = "false";
    expect(() => loadConfig()).not.toThrow();
  });

  // --- no gateway attestation or dstack endpoint ---
  it("refuses a guest-agent binding", () => {
    productionReleaseCollateral();
    process.env.GATEWAY_ATTESTATION_ENABLED = "true";
    process.env.GATEWAY_PUBLIC_ORIGIN = "https://api.anonrouter.example";
    process.env.GATEWAY_RELEASE_ID = "unit-release-1";
    expect(bootError().message).toBe(refusal("GATEWAY_ATTESTATION_ENABLED must not be true on the release-collateral service"));
  });

  it.each(["DSTACK_ENDPOINT", "DSTACK_SIMULATOR_ENDPOINT"])("refuses the guest-agent endpoint %s", (variable) => {
    expectRefusedByName(variable);
  });

  // --- no pool list ---
  it.each(["venice,fireworks", "near-ai", "nonsense"])("refuses POOL_PROVIDERS=%s", (value) => {
    productionReleaseCollateral();
    process.env.POOL_PROVIDERS = value;
    expect(() => loadConfig()).toThrow(new Error("POOL_PROVIDERS is only valid for RUNTIME_ROLE=pool-worker"));
  });

  it("refuses a release-collateral URL of its own: it is the server, not a client", () => {
    productionReleaseCollateral();
    process.env.RELEASE_COLLATERAL_RPC_URL = "http://release-collateral:3000";
    expect(() => loadConfig()).toThrow(new Error("RELEASE_COLLATERAL_RPC_URL is only valid for RUNTIME_ROLE=pool-worker"));
  });

  // --- no credential-admin settings ---
  it.each([
    "CREDENTIAL_ADMIN_MODE", "CREDENTIAL_CAPABILITY_SIGNERS", "CONTENT_TLS_SPKI_SHA256",
    "CONSUMED_CAPABILITY_FILE", "CONSUMED_CAPABILITY_DIR", "VENICE_KEYSET_OVERLAY_FILE",
    "PROVIDER_CREDENTIAL_ADMIN_MODE", "PROVIDER_CAPABILITY_SIGNING_KEY"
  ])("refuses the credential-administration setting %s", (variable) => {
    expectRefusedByName(variable);
  });

  it("refuses credential administration even set to its default", () => {
    // `legacy` is the schema default. Set explicitly it is still a setting this
    // role was handed and has no use for.
    productionReleaseCollateral();
    process.env.CREDENTIAL_ADMIN_MODE = "legacy";
    expect(bootError().message).toBe(refusal("release-collateral must not be given CREDENTIAL_ADMIN_MODE"));
  });

  // --- no debug or trace logging ---
  it.each(["debug", "trace"])("refuses LOG_LEVEL=%s", (level) => {
    productionReleaseCollateral();
    process.env.LOG_LEVEL = level;
    expect(bootError().message).toBe(refusal("LOG_LEVEL must not be debug or trace on a content or credential role in production"));
  });

  it("tolerates the empty string a compose file passes for an unset value", () => {
    productionReleaseCollateral();
    for (const variable of ["WORKER_RPC_TOKEN", "RELAY_RPC_TOKEN", "METADATA_RPC_TOKEN", "DATABASE_URL", "APP_SECRET", "DSTACK_ENDPOINT", "RELEASE_COLLATERAL_RPC_URL", "POOL_PROVIDERS"]) {
      process.env[variable] = "";
    }
    expect(loadConfig().internal.role).toBe("release-collateral");
  });

  it("reports every problem at once when several things are wrong", () => {
    productionReleaseCollateral();
    process.env.WORKER_RPC_TOKEN = distinct("workertoken");
    process.env.NEAR_API_KEY_FILE = keyFile;
    process.env.RELEASE_COLLATERAL_RPC_TOKEN = "weak";
    expect(bootError().message).toBe(refusal(
      "release-collateral must not be given WORKER_RPC_TOKEN",
      "RELEASE_COLLATERAL_RPC_TOKEN must be a >= 32-byte non-placeholder value",
      "only the NEAR AI worker may hold a NEAR AI credential"
    ));
  });
});

describe("the release-collateral role as built", () => {
  it("serves its three operations and a health route, and no worker, relay or credential route", async () => {
    productionReleaseCollateral();
    process.env.LOG_LEVEL = "silent";
    const routes: string[] = [];
    const server = await buildReleaseCollateralServer(loadConfig(), {
      observe: (instance) => {
        instance.addHook("onRoute", (route) => {
          for (const method of [route.method].flat()) routes.push(`${method} ${route.url}`);
        });
      }
    });
    try {
      await server.ready();
      // CORS preflight and HEAD are added by the framework for what is listed.
      expect(routes.filter((route) => !route.startsWith("HEAD ") && !route.startsWith("OPTIONS ")).sort()).toEqual([
        "GET /healthz",
        ...RELEASE_COLLATERAL_OPERATIONS.map((operation) => `POST ${releaseCollateralPath(operation)}`)
      ].sort());
      expect(server.hasDecorator("workerClient")).toBe(false);
      expect(server.hasDecorator("controlClient")).toBe(false);
      expect(server.hasDecorator("veniceKeyStore")).toBe(false);
      expect(server.hasDecorator("gatewayAttestation")).toBe(false);
      expect((await server.inject({ method: "GET", url: "/healthz" })).statusCode).toBe(200);
    } finally {
      await server.close();
    }
  });
});

// --- the pool ------------------------------------------------------------------------

describe("a production pool-worker and the release-collateral role", () => {
  it("boots told where the release-collateral role is, and holds a token for it", () => {
    productionPool();
    const config = loadConfig();
    expect(config.internal.releaseCollateralRpcUrl).toBe("http://release-collateral:3000");
    expect(config.internal.releaseCollateralRpcToken).toBe(distinct("release-collateral-token"));
    expect(config.internal.releaseCollateralRpcTimeoutMs).toBe(20_000);
    expect(releaseCollateralClientFor(config)).not.toBeNull();
  });

  it.each([
    ["unset", undefined],
    ["empty", ""]
  ])("requires RELEASE_COLLATERAL_RPC_URL: refuses %s", (_label, value) => {
    productionPool();
    if (value === undefined) delete process.env.RELEASE_COLLATERAL_RPC_URL;
    else process.env.RELEASE_COLLATERAL_RPC_URL = value;
    expect(bootError().message).toBe(refusal("RELEASE_COLLATERAL_RPC_URL is required on the pool worker"));
  });

  it.each([
    ["a path", "http://release-collateral:3000/internal/release-collateral/v1"],
    ["credentials", `http://pool:${LEAKED}@release-collateral:3000`],
    ["a query string", `http://release-collateral:3000/?k=${LEAKED}`],
    ["a fragment", "http://release-collateral:3000/#x"],
    ["another scheme", "ftp://release-collateral:3000"],
    ["a file", "file:///var/run/release-collateral.sock"]
  ])("requires RELEASE_COLLATERAL_RPC_URL to be a bare origin: refuses %s", (_label, value) => {
    productionPool();
    process.env.RELEASE_COLLATERAL_RPC_URL = value;
    const error = bootError();
    expect(error.message).toBe(refusal("RELEASE_COLLATERAL_RPC_URL must be an http(s) origin with no credentials, path, query or fragment"));
    expect(error.message).not.toContain(LEAKED);
  });

  it("accepts an http or https origin, with or without a trailing slash", () => {
    for (const value of ["http://release-collateral:3000", "http://release-collateral:3000/", "https://release-collateral.internal", "http://10.0.0.7:3000"]) {
      productionPool();
      process.env.RELEASE_COLLATERAL_RPC_URL = value;
      expect(loadConfig().internal.releaseCollateralRpcUrl, value).toBe(value.replace(/\/$/, ""));
    }
  });

  it.each([
    ["unset", undefined],
    ["short", "too-short"],
    ["a placeholder", `change-me-${"x".repeat(40)}`]
  ])("requires a strong RELEASE_COLLATERAL_RPC_TOKEN: refuses %s", (_label, value) => {
    productionPool();
    if (value === undefined) delete process.env.RELEASE_COLLATERAL_RPC_TOKEN;
    else process.env.RELEASE_COLLATERAL_RPC_TOKEN = value;
    expect(bootError().message).toBe(refusal("RELEASE_COLLATERAL_RPC_TOKEN must be a >= 32-byte non-placeholder value"));
  });

  it.each(["WORKER_RPC_TOKEN", ...PLANNED.map(([, tokenVariable]) => tokenVariable)])(
    "requires the release-collateral token to be no other service's: refuses one equal to %s",
    (variable) => {
      productionPool();
      process.env.RELEASE_COLLATERAL_RPC_TOKEN = process.env[variable];
      expect(bootError().message).toBe(refusal("RELEASE_COLLATERAL_RPC_TOKEN must be distinct from the pool's worker and metadata tokens"));
    }
  );

  it("refuses Chutes, whose release collateral the release-collateral role does not serve", () => {
    productionPool();
    process.env.POOL_PROVIDERS = `${process.env.POOL_PROVIDERS},chutes`;
    process.env.METADATA_RPC_TOKEN_CHUTES = distinct("metadata-chutes");
    process.env.CHUTES_API_KEY_FILE = keyFile;
    expect(bootError().message).toBe(refusal(
      "POOL_PROVIDERS must not list chutes on a production pool: its release collateral is not served by the release-collateral role, so the pool would fetch it from GitHub and api.chutes.ai itself"
    ));
  });

  it("the deadline is configurable within bounds, and never absent", () => {
    productionPool();
    process.env.RELEASE_COLLATERAL_RPC_TIMEOUT_MS = "5000";
    expect(loadConfig().internal.releaseCollateralRpcTimeoutMs).toBe(5_000);
    for (const value of ["0", "999", "60001", "never"]) {
      productionPool();
      process.env.RELEASE_COLLATERAL_RPC_TIMEOUT_MS = value;
      expect(() => loadConfig(), value).toThrow(/RELEASE_COLLATERAL_RPC_TIMEOUT_MS/);
    }
  });
});

// --- every other role ---------------------------------------------------------------------

describe("the roles that are neither", () => {
  // Every role the schema admits. Read from the source, so a role added
  // tomorrow is covered without anyone remembering this file.
  const roles = [...readFileSync(join(ROOT, "src/config.ts"), "utf8")
    .match(/RUNTIME_ROLE: z\.enum\(\[([^\]]+)\]\)/)![1]!
    .matchAll(/"([a-z-]+)"/g)].map((match) => match[1]!);

  it("RELEASE_COLLATERAL_RPC_URL is refused, not ignored, on every role but the pool, in every environment", () => {
    expect(roles).toContain("release-collateral");
    expect(roles.length).toBeGreaterThanOrEqual(19);
    for (const role of roles.filter((entry) => entry !== "pool-worker")) {
      clearRelevant();
      process.env.NODE_ENV = "test";
      process.env.RUNTIME_ROLE = role;
      // The role loads on its own, making its own lookups ...
      const config = loadConfig();
      expect(config.internal.releaseCollateralRpcUrl, role).toBe("");
      expect(releaseCollateralClientFor(config), role).toBeNull();
      // ... tolerates the empty string a compose file passes for an unset value ...
      process.env.RELEASE_COLLATERAL_RPC_URL = "";
      expect(() => loadConfig(), role).not.toThrow();
      // ... and refuses a URL.
      process.env.RELEASE_COLLATERAL_RPC_URL = "http://release-collateral:3000";
      expect(() => loadConfig(), role).toThrow(new Error("RELEASE_COLLATERAL_RPC_URL is only valid for RUNTIME_ROLE=pool-worker"));
    }
  });

  const others: Array<[string, () => void]> = [
    ["venice-worker", () => productionWorker("venice-worker", "VENICE_INFERENCE_KEY_FILE")],
    ["near-worker", () => productionWorker("near-worker", "NEAR_API_KEY_FILE")],
    ["fireworks-worker", () => productionWorker("fireworks-worker", "FIREWORKS_API_KEY_FILE")],
    ["chutes-worker", () => productionWorker("chutes-worker", "CHUTES_API_KEY_FILE")],
    ["relay", productionRelay],
    ["compat", productionCompat],
    ["gateway-attestation", productionGatewayAttestation]
  ];

  it.each(others)("a production %s boots exactly as before, and is refused the release-collateral token", (role, environment) => {
    environment();
    const config = loadConfig();
    expect(config.internal.role).toBe(role);
    // Unchanged: no release-collateral role, so its lookups are its own.
    expect(config.internal.releaseCollateralRpcUrl).toBe("");
    expect(config.internal.releaseCollateralRpcToken).toBe("");
    expect(releaseCollateralClientFor(config)).toBeNull();

    for (const variable of ["RELEASE_COLLATERAL_RPC_TOKEN", "RELEASE_COLLATERAL_RPC_TOKEN_FILE"]) {
      environment();
      process.env[variable] = variable.endsWith("_FILE") ? keyFile : distinct("release-collateral-token");
      expect(bootError().message, variable).toBe(refusal(`${role} must not be given ${variable}`));
    }
    environment();
    process.env.RELEASE_COLLATERAL_RPC_URL = "http://release-collateral:3000";
    expect(() => loadConfig()).toThrow(new Error("RELEASE_COLLATERAL_RPC_URL is only valid for RUNTIME_ROLE=pool-worker"));
  });
});

// --- every place roles are enumerated --------------------------------------------------------

describe("every place roles are enumerated names the release-collateral role", () => {
  const source = (file: string) => readFileSync(join(ROOT, file), "utf8");

  it("is in the split-role gate and the content-tier check BY NAME", () => {
    const config = source("src/config.ts");
    const statement = (name: string) => {
      const start = config.indexOf(`const ${name} = `);
      expect(start, name).toBeGreaterThan(-1);
      return config.slice(start, config.indexOf(";", start));
    };
    // Without the first, none of the production fences run for it. Without the
    // second it is refused nothing: its name does not end in "-worker".
    expect(statement("isSplitRole")).toContain('env.RUNTIME_ROLE === "release-collateral"');
    expect(statement("contentTierRole")).toContain('env.RUNTIME_ROLE === "release-collateral"');
    expect("release-collateral".endsWith("-worker")).toBe(false);
  });

  it.skipIf(!existsSync(join(ROOT, "src/index.ts")))("the monolith entry point admits release-collateral", () => {
    // src/index.ts falls through to the monolith for a role it does not name,
    // which here would start a control plane where a keyless service belongs.
    const index = source("src/index.ts");
    const branch = index.slice(index.indexOf('role === "release-collateral"'), index.indexOf("// `api` (dev monolith)"));
    expect(branch).toContain("buildReleaseCollateralServer(config)");
    expect(index.indexOf('role === "release-collateral"')).toBeGreaterThan(-1);
    expect(index.indexOf('role === "release-collateral"')).toBeLessThan(index.indexOf('await import("./server.js")'));

  });

  it("the portable content-plane entry point admits release-collateral", () => {
    const contentPlane = source("src/contentPlane.ts");
    const admitted = contentPlane.slice(contentPlane.indexOf("const CONTENT_ROLES"), contentPlane.indexOf("]);"));
    expect(admitted).toContain('"release-collateral"');
    // Named before the fall-through that builds a worker for anything else.
    expect(contentPlane.indexOf('if (role === "release-collateral") return roles.buildReleaseCollateralServer(config);')).toBeGreaterThan(-1);
    expect(contentPlane.indexOf('role === "release-collateral"')).toBeLessThan(contentPlane.indexOf("return roles.buildWorkerServer(config);"));
  });

  it("is not a provider worker anywhere a provider is derived from the role", async () => {
    const { workerProviderForRole, isPoolWorkerRole, workerProvidersForRole } = await import("../../src/providers/workerProviders.js");
    expect(workerProviderForRole("release-collateral")).toBeNull();
    expect(isPoolWorkerRole("release-collateral")).toBe(false);
    // The worker builder's default for a role it does not know is Venice, which
    // is why the entry points must never hand it this role.
    expect(workerProvidersForRole("release-collateral")).toEqual(["venice"]);
  });

  it("the release-collateral code holds no provider key and builds no provider request", () => {
    const files = readdirSync(join(ROOT, "src/releaseCollateral")).sort();
    expect(files).toEqual(["client.ts", "contract.ts", "server.ts"]);
    for (const file of files) {
      const text = source(`src/releaseCollateral/${file}`);
      expect(text, file).not.toMatch(/providers\.(?:[A-Za-z]+ApiKey|veniceInferenceKey|veniceKeys)/);
      expect(text, file).not.toMatch(/providerTransport|ProviderTransport|workerRpcToken|metadataRpcToken|relayRpcToken/);
    }
    // The server never calls fetch itself: every outbound request is a fetcher's.
    expect(source("src/releaseCollateral/server.ts")).not.toMatch(/\bfetch\(/);
  });
});
