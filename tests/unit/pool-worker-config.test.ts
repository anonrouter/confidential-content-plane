// The pool-worker role's configuration (PROVIDER_POOL_PLAN.md, W1b; review
// findings C5, C6, S4).
//
// One process, several providers' credentials. What it may hold is decided at
// boot, here: the provider list, a file-backed credential and a metadata token
// for each listed provider and for no other, and none of the authority any
// other role holds. Every refusal below is reached with exactly ONE thing
// wrong, and compared as the whole message, so no other problem can be what
// failed the boot.
//
// Production configs are built the way tests/unit/role-config.test.ts builds
// them: a cleared environment, the role's own variables, then a load.

import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../../src/config.js";
import {
  PROVIDER_CREDENTIAL_ORIGINS,
  SYNTHETIC_CREDENTIAL_ORIGIN,
  SYNTHETIC_CREDENTIAL_ORIGINS
} from "../../src/providers/providerOrigins.js";
import {
  consumedCapabilityFileName,
  isPoolWorkerRole,
  parsePoolProviders,
  POOL_WORKER_ROLE,
  POOLABLE_PROVIDERS,
  WORKER_PROVIDER_BY_ROLE,
  workerMetadataTokenFor,
  workerProviderForRole,
  workerProvidersForRole,
  type PoolProviderName
} from "../../src/providers/workerProviders.js";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));

interface Pooled {
  readonly provider: PoolProviderName;
  readonly label: string;
  readonly tokenVariable: string;
  /** The file variable the pool is given, and every file variable that satisfies the rule. */
  readonly keyFileVariable: string;
  readonly fileRequired: string;
  readonly required: string;
  /** A way to hold the credential that is NOT file-backed. */
  readonly directVariable: string;
}

// Written out, not derived from the source: a provider added to the pool has
// to be added here, with the variable names an operator would actually set.
const POOLED: readonly Pooled[] = [
  {
    provider: "venice", label: "Venice", tokenVariable: "METADATA_RPC_TOKEN_VENICE",
    keyFileVariable: "VENICE_INFERENCE_KEY_FILE", directVariable: "VENICE_INFERENCE_KEY",
    fileRequired: "VENICE_INFERENCE_KEY_FILE or VENICE_INFERENCE_KEYS_FILE (file-backed) is required",
    required: "A Venice inference credential is required"
  },
  {
    provider: "fireworks", label: "Fireworks", tokenVariable: "METADATA_RPC_TOKEN_FIREWORKS",
    keyFileVariable: "FIREWORKS_API_KEY_FILE", directVariable: "FIREWORKS_API_KEY",
    fileRequired: "FIREWORKS_API_KEY_FILE (file-backed) is required",
    required: "A Fireworks API credential is required"
  },
  {
    provider: "deepinfra", label: "DeepInfra", tokenVariable: "METADATA_RPC_TOKEN_DEEPINFRA",
    keyFileVariable: "DEEPINFRA_API_KEY_FILE", directVariable: "DEEPINFRA_API_KEY",
    fileRequired: "DEEPINFRA_API_KEY_FILE (file-backed) is required",
    required: "A DeepInfra API credential is required"
  },
  {
    provider: "tinfoil", label: "Tinfoil", tokenVariable: "METADATA_RPC_TOKEN_TINFOIL",
    keyFileVariable: "TINFOIL_API_KEY_FILE", directVariable: "TINFOIL_API_KEY",
    fileRequired: "TINFOIL_API_KEY_FILE (file-backed) is required",
    required: "A Tinfoil API credential is required"
  },
  {
    provider: "near-ai", label: "NEAR AI", tokenVariable: "METADATA_RPC_TOKEN_NEAR",
    keyFileVariable: "NEAR_API_KEY_FILE", directVariable: "NEAR_API_KEY",
    fileRequired: "NEAR_API_KEY_FILE (file-backed) is required",
    required: "A NEAR AI API credential is required"
  },
  {
    provider: "phala-ai", label: "Phala AI", tokenVariable: "METADATA_RPC_TOKEN_PHALA_AI",
    keyFileVariable: "PHALA_AI_API_KEY_FILE", directVariable: "PHALA_AI_API_KEY",
    fileRequired: "PHALA_AI_API_KEY_FILE (file-backed) is required",
    required: "A Phala AI API credential is required"
  },
  {
    provider: "chutes", label: "Chutes", tokenVariable: "METADATA_RPC_TOKEN_CHUTES",
    keyFileVariable: "CHUTES_API_KEY_FILE", directVariable: "CHUTES_API_KEY",
    fileRequired: "CHUTES_API_KEY_FILE (file-backed) is required",
    required: "A Chutes API credential is required"
  }
];

// The pool the plan deploys: every poolable provider but Chutes.
const PLANNED = POOLED.filter((entry) => entry.provider !== "chutes");
const CHUTES = POOLED.find((entry) => entry.provider === "chutes")!;
const PLANNED_LIST = PLANNED.map((entry) => entry.provider).join(",");

const distinct = (seed: string) => `prod-${seed}-${"x".repeat(40)}`.slice(0, 48);

let snapshot: NodeJS.ProcessEnv;
let directory = "";
let keyFile = "";

function clearRelevant() {
  for (const key of Object.keys(process.env)) {
    if (/^(RUNTIME_ROLE|POOL_PROVIDERS|RELEASE_COLLATERAL_|PROVIDER_TRANSPORT_PROFILE|LOG_LEVEL|RELAY_RPC|WORKER_RPC|METADATA_RPC|CONTROL_RPC|CONTROL_METADATA|COMPAT_RPC|VENICE_|FIREWORKS_|DEEPINFRA_|CHUTES_|TINFOIL_|NEAR_|PHALA_AI_|BEDROCK_|AWS_|MOCK_PROVIDER_|ALLOW_INLINE_TICKET|ALLOW_COMPAT_MODE|APP_SECRET|EMAIL_HASH_SECRET|EMAIL_ENCRYPTION_KEY|COOKIE_SECRET|BETTER_AUTH_SECRET|ADMIN_|CORS_ORIGIN|SMTP_|DATABASE_URL|MIGRATION_DATABASE_URL|APP_DB|GATEWAY_|DSTACK_|REDIS_URL|STRIPE_|PAYMENTS_MODE|CONSUMED_CAPABILITY|CREDENTIAL_|PROVIDER_CAPABILITY|TRUST_PROXY_HOPS)/.test(key)) {
      delete process.env[key];
    }
  }
}

/** A production pool with everything it requires, for `entries`, and nothing else. */
function productionPool(entries: readonly Pooled[] = PLANNED) {
  clearRelevant();
  process.env.NODE_ENV = "production";
  process.env.RUNTIME_ROLE = "pool-worker";
  process.env.POOL_PROVIDERS = entries.map((entry) => entry.provider).join(",");
  process.env.WORKER_RPC_TOKEN = distinct("workertoken");
  process.env.CONTROL_METADATA_URL = "http://control:3000";
  process.env.CREDENTIAL_ADMIN_MODE = "capability";
  // Required since W3: where the pool's release-authority lookups go, and the
  // token that admits it there. tests/unit/release-collateral-role-config.test.ts holds
  // the refusals for each.
  process.env.RELEASE_COLLATERAL_RPC_URL = "http://release-collateral:3000";
  process.env.RELEASE_COLLATERAL_RPC_TOKEN = distinct("release-collateral-token");
  for (const entry of entries) {
    process.env[entry.tokenVariable] = distinct(`metadata-${entry.provider}`);
    process.env[entry.keyFileVariable] = keyFile;
  }
}

// A production pool refuses Chutes (W3): its release collateral is not served
// by the release-collateral role. Where a test below still lists it, this is the extra
// problem the boot reports, ahead of whatever the test is about.
const CHUTES_NOT_POOLABLE = "POOL_PROVIDERS must not list chutes on a production pool: its release collateral is not served by the release-collateral role, so the pool would fetch it from GitHub and api.chutes.ai itself";

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
  directory = mkdtempSync(join(tmpdir(), "anonrouter-pool-config-"));
  keyFile = join(directory, "provider_key");
  writeFileSync(keyFile, "unit-test-provider-key");
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

describe("POOL_PROVIDERS", () => {
  it("accepts every poolable provider, in the order given", () => {
    expect(parsePoolProviders("venice,fireworks,deepinfra,tinfoil,near-ai,phala-ai,chutes"))
      .toEqual(["venice", "fireworks", "deepinfra", "tinfoil", "near-ai", "phala-ai", "chutes"]);
    expect(parsePoolProviders("phala-ai, venice")).toEqual(["phala-ai", "venice"]);
    expect(parsePoolProviders("fireworks")).toEqual(["fireworks"]);
    expect([...POOLABLE_PROVIDERS].sort()).toEqual(POOLED.map((entry) => entry.provider).sort());
  });

  it.each([
    ["unset", undefined, "POOL_PROVIDERS is required for RUNTIME_ROLE=pool-worker"],
    ["empty", "", "POOL_PROVIDERS is required for RUNTIME_ROLE=pool-worker"],
    ["blank", "   ", "POOL_PROVIDERS is required for RUNTIME_ROLE=pool-worker"],
    ["a doubled comma", "venice,,fireworks", "POOL_PROVIDERS entry 2 is empty"],
    ["a trailing comma", "venice,fireworks,", "POOL_PROVIDERS entry 3 is empty"],
    ["a leading comma", ",venice", "POOL_PROVIDERS entry 1 is empty"],
    ["a blank entry", "venice, ,fireworks", "POOL_PROVIDERS entry 2 is empty"],
    ["a repeated provider", "venice,fireworks,venice", "POOL_PROVIDERS lists venice more than once"],
    ["Bedrock", "venice,aws-bedrock", "POOL_PROVIDERS must not list aws-bedrock: Bedrock holds no bearer key and stays in its own worker"]
  ])("refuses %s", (_label, raw, message) => {
    expect(() => parsePoolProviders(raw)).toThrow(new Error(message));
  });

  it.each([
    ["a public slug that is not the canonical name", "near"],
    ["the Bedrock compose key", "bedrock"],
    ["a provider that does not exist", "openai"],
    ["the mock provider", "mock"],
    ["a canonical name in another case", "Venice"],
    ["a role name", "venice-worker"],
    ["an object key", "__proto__"]
  ])("refuses %s, by position and without echoing it", (_label, entry) => {
    const error = (() => {
      try {
        parsePoolProviders(`venice,${entry}`);
      } catch (thrown) {
        return thrown as Error;
      }
      throw new Error("parsed");
    })();
    expect(error.message).toBe(
      "POOL_PROVIDERS entry 2 is not a poolable provider (allowed: venice, fireworks, deepinfra, tinfoil, near-ai, phala-ai, chutes)"
    );
  });

  it("never echoes an entry that could be a pasted secret", () => {
    expect(() => parsePoolProviders("venice,sk-canary-0123456789")).toThrow(/entry 2 is not a poolable provider/);
    try {
      parsePoolProviders("venice,sk-canary-0123456789");
    } catch (error) {
      expect((error as Error).message).not.toContain("sk-canary");
    }
  });

  it("is required for pool-worker in every environment", () => {
    for (const nodeEnv of ["test", "development", "production"]) {
      productionPool();
      process.env.NODE_ENV = nodeEnv;
      delete process.env.POOL_PROVIDERS;
      expect(() => loadConfig(), nodeEnv).toThrow(new Error("POOL_PROVIDERS is required for RUNTIME_ROLE=pool-worker"));
      process.env.POOL_PROVIDERS = "venice,near";
      expect(() => loadConfig(), nodeEnv).toThrow(/POOL_PROVIDERS entry 2 is not a poolable provider/);
    }
  });

  // Every role the schema admits but the pool. Read from the source, so a role
  // added tomorrow is covered without anyone remembering this file.
  const roles = [...readFileSync(join(ROOT, "src/config.ts"), "utf8")
    .match(/RUNTIME_ROLE: z\.enum\(\[([^\]]+)\]\)/)![1]!
    .matchAll(/"([a-z-]+)"/g)].map((match) => match[1]!);

  it("is refused, not ignored, on every other role", () => {
    expect(roles).toContain("pool-worker");
    expect(roles.length).toBeGreaterThanOrEqual(18);
    for (const role of roles.filter((entry) => entry !== "pool-worker")) {
      clearRelevant();
      process.env.NODE_ENV = "test";
      process.env.RUNTIME_ROLE = role;
      // The role loads on its own ...
      expect(loadConfig().internal.poolProviders, role).toEqual([]);
      // ... tolerates the empty string a compose file passes for an unset value ...
      process.env.POOL_PROVIDERS = "";
      expect(() => loadConfig(), role).not.toThrow();
      // ... and refuses a list, valid or not.
      for (const value of ["venice,fireworks", "venice", "nonsense"]) {
        process.env.POOL_PROVIDERS = value;
        expect(() => loadConfig(), role).toThrow(new Error("POOL_PROVIDERS is only valid for RUNTIME_ROLE=pool-worker"));
      }
    }
  });

  it("is refused on a production single-provider worker too", () => {
    clearRelevant();
    process.env.NODE_ENV = "production";
    process.env.RUNTIME_ROLE = "fireworks-worker";
    process.env.WORKER_RPC_TOKEN = distinct("workertoken");
    process.env.METADATA_RPC_TOKEN = distinct("metadatatoken");
    process.env.CONTROL_METADATA_URL = "http://control:3000";
    process.env.FIREWORKS_API_KEY_FILE = keyFile;
    expect(loadConfig().internal.role).toBe("fireworks-worker");
    process.env.POOL_PROVIDERS = "fireworks";
    expect(() => loadConfig()).toThrow(new Error("POOL_PROVIDERS is only valid for RUNTIME_ROLE=pool-worker"));
  });
});

describe("the provider list a worker server is built from", () => {
  it("is the configured list for the pool, and never a default", () => {
    expect(isPoolWorkerRole("pool-worker")).toBe(true);
    expect(POOL_WORKER_ROLE).toBe("pool-worker");
    expect(workerProvidersForRole("pool-worker", ["fireworks", "venice"])).toEqual(["fireworks", "venice"]);
    // No list is a misconfigured pool. Venice here would be a pool that looks
    // healthy and serves one provider.
    expect(() => workerProvidersForRole("pool-worker")).toThrow("pool-worker has no configured provider list (POOL_PROVIDERS)");
    expect(() => workerProvidersForRole("pool-worker", [])).toThrow("pool-worker has no configured provider list (POOL_PROVIDERS)");
  });

  it("gives the pool no provider of its own", () => {
    // config.ts and the credential routes ask this question; an answer would be
    // true of only one pooled provider.
    expect(workerProviderForRole("pool-worker")).toBeNull();
    expect(Object.keys(WORKER_PROVIDER_BY_ROLE)).not.toContain("pool-worker");
  });

  it("ignores a pool list on a single-provider role", () => {
    for (const [role, provider] of Object.entries(WORKER_PROVIDER_BY_ROLE)) {
      expect(workerProvidersForRole(role, ["fireworks", "venice"])).toEqual([provider]);
    }
    expect(workerProvidersForRole("api", ["fireworks"])).toEqual(["venice"]);
  });

  it("returns a copy, so a caller cannot edit the configured list", () => {
    const configured: PoolProviderName[] = ["venice", "fireworks"];
    workerProvidersForRole("pool-worker", configured).push("deepinfra");
    expect(configured).toEqual(["venice", "fireworks"]);
  });

  it("carries the configured list on the loaded config", () => {
    productionPool();
    const config = loadConfig();
    expect(config.internal.role).toBe("pool-worker");
    expect(config.internal.poolProviders).toEqual(PLANNED.map((entry) => entry.provider));
    expect(workerProvidersForRole(config.internal.role, config.internal.poolProviders))
      .toEqual(["venice", "fireworks", "deepinfra", "tinfoil", "near-ai", "phala-ai"]);
  });
});

describe("a production pool-worker", () => {
  it("boots with a file-backed credential and a metadata token for every listed provider", () => {
    productionPool();
    const config = loadConfig();
    expect(config.internal.role).toBe("pool-worker");
    expect(config.providers.transportProfile).toBe("production");
    // One token per provider, and no single token for the role.
    expect(config.internal.workerMetadataToken).toBe("");
    expect(config.internal.metadataRpcToken).toBe("");
    expect(config.internal.deploymentMetadataToken).toBe("");
    expect(Object.keys(config.internal.providerMetadataTokens).sort()).toEqual(PLANNED.map((entry) => entry.provider).sort());
    for (const entry of PLANNED) {
      expect(workerMetadataTokenFor(config.internal, entry.provider)).toBe(distinct(`metadata-${entry.provider}`));
    }
  });

  it("boots with every planned provider, and with one; Chutes is refused until its collateral is served", () => {
    productionPool(PLANNED);
    expect(loadConfig().internal.poolProviders).toEqual(PLANNED.map((entry) => entry.provider));
    productionPool([POOLED[1]!]);
    expect(loadConfig().internal.poolProviders).toEqual(["fireworks"]);
    // Was "boots with every poolable provider, Chutes included". Chutes fetches
    // its own release collateral from GitHub and api.chutes.ai, which is the
    // direct lookup a production pool no longer makes.
    productionPool(POOLED);
    expect(bootError().message).toBe(refusal(CHUTES_NOT_POOLABLE));
    productionPool([CHUTES]);
    expect(bootError().message).toBe(refusal(CHUTES_NOT_POOLABLE));
    // Outside production the list is still accepted: dev and test stacks pool it.
    productionPool(POOLED);
    process.env.NODE_ENV = "test";
    expect(loadConfig().internal.poolProviders).toEqual(POOLED.map((entry) => entry.provider));
  });

  it("accepts a file-backed Venice keyset as well as a single key file", () => {
    productionPool();
    delete process.env.VENICE_INFERENCE_KEY_FILE;
    const keyset = join(directory, "venice_keyset.json");
    writeFileSync(keyset, JSON.stringify([{ id: "primary", label: "Boot", key: "unit-test-venice-key" }]));
    process.env.VENICE_INFERENCE_KEYS_FILE = keyset;
    expect(loadConfig().providers.veniceKeys).toHaveLength(1);
  });

  describe.each(PLANNED)("credential for listed provider $provider", (entry) => {
    it("is required", () => {
      productionPool();
      delete process.env[entry.keyFileVariable];
      expect(bootError().message).toBe(refusal(entry.fileRequired, entry.required));
    });

    it("must be file-backed", () => {
      productionPool();
      delete process.env[entry.keyFileVariable];
      process.env[entry.directVariable] = "unit-test-direct-key";
      // Held, but not from a file: the one problem is the file rule.
      expect(bootError().message).toBe(refusal(entry.fileRequired));
    });
  });

  it("does not count a Venice key file that a direct keyset overrides as file-backed", () => {
    // A direct keyset takes precedence over VENICE_INFERENCE_KEY_FILE, so the
    // keys in use came from the environment while a file variable was defined.
    productionPool();
    process.env.VENICE_INFERENCE_KEYS = JSON.stringify([{ id: "primary", label: "Direct", key: "unit-test-direct-key" }]);
    expect(bootError().message).toBe(refusal(POOLED[0]!.fileRequired));
  });

  describe.each(POOLED)("credential for unlisted provider $provider", (entry) => {
    // Every provider a production pool may list, but this one. (Chutes is never
    // among the others: listing it is refused on its own.)
    const others = PLANNED.filter((other) => other.provider !== entry.provider);
    const message = `the pool worker must not hold a ${entry.label} credential: ${entry.provider} is not in POOL_PROVIDERS`;

    it("is refused, file-backed or not", () => {
      productionPool(others);
      process.env[entry.keyFileVariable] = keyFile;
      expect(bootError().message).toBe(refusal(message));

      productionPool(others);
      process.env[entry.directVariable] = "unit-test-direct-key";
      expect(bootError().message).toBe(refusal(message));
    });
  });

  describe.each(PLANNED)("metadata token for listed provider $provider", (entry) => {
    const message = `${entry.tokenVariable} must be a >= 32-byte non-placeholder value for pooled provider ${entry.provider}`;

    it("is required", () => {
      productionPool();
      delete process.env[entry.tokenVariable];
      expect(bootError().message).toBe(refusal(message));
    });

    it.each([
      ["short", "too-short"],
      ["a placeholder", `change-me-${"x".repeat(40)}`],
      ["a dev fallback", "dev-only-metadata-rpc-token-change-me-32-bytes"]
    ])("must be strong: refuses %s", (_label, value) => {
      productionPool();
      process.env[entry.tokenVariable] = value;
      expect(bootError().message).toBe(refusal(message));
    });
  });

  it("requires the listed providers' tokens to be distinct", () => {
    for (const [first, second] of [[PLANNED[0]!, PLANNED[1]!], [PLANNED[2]!, PLANNED[5]!], [PLANNED[3]!, PLANNED[4]!]]) {
      productionPool();
      process.env[second.tokenVariable] = process.env[first.tokenVariable];
      expect(bootError().message, `${first.provider}/${second.provider}`)
        .toBe(refusal("metadata RPC tokens must be distinct across pooled providers"));
    }
  });

  it.each([
    [CHUTES.tokenVariable, "chutes"],
    ["METADATA_RPC_TOKEN_BEDROCK", "aws-bedrock"]
  ])("refuses %s: a token for a provider it does not list", (variable, provider) => {
    productionPool();
    process.env[variable] = distinct(`metadata-${provider}`);
    expect(bootError().message).toBe(refusal(`${variable} must not be set on the pool worker: ${provider} is not in POOL_PROVIDERS`));
  });

  it("refuses the token of a provider dropped from the list, though its value is strong", () => {
    for (const dropped of PLANNED) {
      productionPool(PLANNED.filter((entry) => entry.provider !== dropped.provider));
      process.env[dropped.tokenVariable] = distinct(`metadata-${dropped.provider}`);
      expect(bootError().message, dropped.provider)
        .toBe(refusal(`${dropped.tokenVariable} must not be set on the pool worker: ${dropped.provider} is not in POOL_PROVIDERS`));
    }
  });

  it("refuses the shared metadata token: there is no fallback (S4)", () => {
    const message = "METADATA_RPC_TOKEN must not be set on the pool worker: every pooled provider presents its own token and there is no shared fallback";
    productionPool();
    process.env.METADATA_RPC_TOKEN = distinct("metadata-shared");
    expect(bootError().message).toBe(refusal(message));

    const tokenFile = join(directory, "metadata_token");
    writeFileSync(tokenFile, distinct("metadata-shared"));
    productionPool();
    process.env.METADATA_RPC_TOKEN_FILE = tokenFile;
    expect(bootError().message).toBe(refusal(message));
  });

  it("refuses the deployment metadata token: there is no override (S4)", () => {
    const message = "METADATA_RPC_DEPLOYMENT_TOKEN must not be set on the pool worker: it would override every pooled provider's own token";
    productionPool();
    process.env.METADATA_RPC_DEPLOYMENT_TOKEN = distinct("metadata-deployment");
    expect(bootError().message).toBe(refusal(message));

    const tokenFile = join(directory, "deployment_token");
    writeFileSync(tokenFile, distinct("metadata-deployment"));
    productionPool();
    process.env.METADATA_RPC_DEPLOYMENT_TOKEN_FILE = tokenFile;
    expect(bootError().message).toBe(refusal(message));
  });

  it("requires a strong WORKER_RPC_TOKEN", () => {
    const message = "WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value";
    for (const value of [undefined, "too-short", `change-me-${"x".repeat(40)}`]) {
      productionPool();
      if (value === undefined) delete process.env.WORKER_RPC_TOKEN;
      else process.env.WORKER_RPC_TOKEN = value;
      expect(bootError().message, String(value)).toBe(refusal(message));
    }
  });

  it("requires an explicit CONTROL_METADATA_URL", () => {
    // The schema has a default, so the fence asks whether it was SET.
    for (const value of [undefined, "", "   "]) {
      productionPool();
      if (value === undefined) delete process.env.CONTROL_METADATA_URL;
      else process.env.CONTROL_METADATA_URL = value;
      const error = bootError();
      // A blank value fails the URL schema before the fence is reached; both
      // are a refusal for this one variable.
      expect(error.message, JSON.stringify(value)).toMatch(/CONTROL_METADATA_URL/);
      if (value === undefined) expect(error.message).toBe(refusal("CONTROL_METADATA_URL is required"));
    }
  });

  it.each(["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"])("refuses static AWS key %s", (variable) => {
    productionPool();
    process.env[variable] = "AKIAUNITTESTCANARY00";
    expect(bootError().message).toBe(refusal("this role must not hold static AWS credentials"));
  });

  it("refuses Bedrock settings", () => {
    productionPool();
    process.env.BEDROCK_ENABLED = "true";
    expect(bootError().message).toBe(refusal("BEDROCK_ENABLED must not be true on the pool worker"));

    productionPool();
    process.env.BEDROCK_AWS_PROFILE = "anonrouter-bedrock";
    expect(bootError().message).toBe(refusal("the pool worker must not select an AWS Bedrock credential profile"));

    // Explicitly off is not a Bedrock setting worth refusing a boot over.
    productionPool();
    process.env.BEDROCK_ENABLED = "false";
    expect(() => loadConfig()).not.toThrow();
  });

  it.each([
    ["left at its legacy default", undefined],
    ["set to legacy", "legacy"]
  ])("refuses credential administration %s", (_label, mode) => {
    productionPool();
    if (mode === undefined) delete process.env.CREDENTIAL_ADMIN_MODE;
    else process.env.CREDENTIAL_ADMIN_MODE = mode;
    expect(bootError().message).toBe(refusal("CREDENTIAL_ADMIN_MODE must be capability on the pool worker"));
  });

  it("refuses a guest-agent binding", () => {
    productionPool();
    process.env.GATEWAY_ATTESTATION_ENABLED = "true";
    process.env.GATEWAY_PUBLIC_ORIGIN = "https://api.anonrouter.example";
    process.env.GATEWAY_RELEASE_ID = "unit-release-1";
    expect(bootError().message).toBe(refusal("GATEWAY_ATTESTATION_ENABLED must not be true on the pool worker"));
  });

  it.each(["debug", "trace"])("refuses LOG_LEVEL=%s, as every content role does", (level) => {
    productionPool();
    process.env.LOG_LEVEL = level;
    expect(bootError().message).toBe(refusal("LOG_LEVEL must not be debug or trace on a content or credential role in production"));
  });

  // The content-tier list, written out. The pool must be refused each of them
  // because it is NAMED in that check, which the last test in this file pins.
  it.each([
    "DATABASE_URL", "DATABASE_URL_FILE", "MIGRATION_DATABASE_URL", "MIGRATION_DATABASE_URL_FILE",
    "REDIS_URL", "APP_DB_PASSWORD", "BETTER_AUTH_SECRET", "BETTER_AUTH_SECRET_FILE",
    "COOKIE_SECRET", "COOKIE_SECRET_FILE", "EMAIL_ENCRYPTION_KEY", "EMAIL_ENCRYPTION_KEY_FILE",
    "ADMIN_ACCESS_TOKEN", "ADMIN_ACCESS_TOKEN_FILE", "STRIPE_API_KEY", "STRIPE_API_KEY_FILE",
    "SMTP_PASSWORD", "SMTP_PASSWORD_FILE"
  ])("is refused %s, with everything else the content tier is refused", (variable) => {
    productionPool();
    // A path for the file forms; the fence reads the environment, not the file.
    process.env[variable] = variable.endsWith("_FILE") ? keyFile : `unit-test-${variable.toLowerCase()}-value-0123456789abcdef`;
    const error = bootError();
    expect(error.message).toBe(refusal(`pool-worker must not be given ${variable}`));
    // The value never appears in the refusal.
    expect(error.message).not.toContain("unit-test-");
    expect(error.message).not.toContain(keyFile);
  });

  it.each([
    "RELAY_RPC_TOKEN", "RELAY_RPC_TOKEN_FILE", "COMPAT_RPC_TOKEN", "COMPAT_RPC_TOKEN_FILE",
    "METADATA_RPC_DEPLOYMENT_SCOPES", "METADATA_RPC_DEPLOYMENT_SCOPES_FILE",
    "PROVIDER_CAPABILITY_SIGNING_KEY", "BEDROCK_BASE_URL",
    "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "DSTACK_ENDPOINT", "CONSUMED_CAPABILITY_FILE"
  ])("is additionally refused %s", (variable) => {
    productionPool();
    const files: Record<string, string> = {
      RELAY_RPC_TOKEN_FILE: keyFile,
      COMPAT_RPC_TOKEN_FILE: keyFile,
      METADATA_RPC_DEPLOYMENT_SCOPES_FILE: join(directory, "scopes.json")
    };
    writeFileSync(join(directory, "scopes.json"), "[]");
    const values: Record<string, string> = {
      METADATA_RPC_DEPLOYMENT_SCOPES: "[]",
      BEDROCK_BASE_URL: "https://bedrock-mantle.us-east-1.api.aws/v1"
    };
    process.env[variable] = files[variable] ?? values[variable] ?? `unit-test-${variable.toLowerCase()}-value-0123456789abcdef`;
    expect(bootError().message).toBe(refusal(`pool-worker must not be given ${variable}`));
  });

  it("does not extend those extra refusals to the single-provider workers", () => {
    // They are the pool's. A worker that boots today with one of these set
    // must still boot.
    clearRelevant();
    process.env.NODE_ENV = "production";
    process.env.RUNTIME_ROLE = "fireworks-worker";
    process.env.WORKER_RPC_TOKEN = distinct("workertoken");
    process.env.METADATA_RPC_TOKEN = distinct("metadatatoken");
    process.env.CONTROL_METADATA_URL = "http://control:3000";
    process.env.FIREWORKS_API_KEY_FILE = keyFile;
    process.env.CONSUMED_CAPABILITY_FILE = "/var/lib/anonrouter-worker/consumed-fireworks.json";
    process.env.RELAY_RPC_TOKEN = distinct("relaytoken");
    process.env.METADATA_RPC_DEPLOYMENT_TOKEN = distinct("metadata-deployment");
    expect(loadConfig().internal.role).toBe("fireworks-worker");
  });
});

describe("a production pool-worker: credential-bearing origins (W2) for every listed provider", () => {
  const MOCK_URL = `${SYNTHETIC_CREDENTIAL_ORIGIN}/v1`;

  function originRefusal(entry: Pooled, variable: string, profile: "production" | "synthetic", before: string[] = []) {
    const origins = profile === "synthetic"
      ? SYNTHETIC_CREDENTIAL_ORIGINS.join(" or ")
      : PROVIDER_CREDENTIAL_ORIGINS[entry.provider].origins.join(" or ");
    return refusal(...before, `${variable} must be on ${origins} (PROVIDER_TRANSPORT_PROFILE=${profile})`);
  }

  // The pool each provider's origin check is exercised in: the planned list,
  // or for Chutes the full list, where the boot also reports that Chutes is not
  // poolable. Its origin check must still run, so both problems are expected.
  const poolListing = (entry: Pooled) => entry.provider === "chutes" ? POOLED : PLANNED;
  const alsoRefused = (entry: Pooled) => entry.provider === "chutes" ? [CHUTES_NOT_POOLABLE] : [];

  it.each(POOLED)("$provider: a base URL off its pinned origin refuses the boot", (entry) => {
    for (const variable of PROVIDER_CREDENTIAL_ORIGINS[entry.provider].baseUrlVariables) {
      productionPool(poolListing(entry));
      process.env[variable] = "https://attacker.example/leak?k=sk-canary-0123456789";
      const error = bootError();
      expect(error.message, variable).toBe(originRefusal(entry, variable, "production", alsoRefused(entry)));
      expect(error.message).not.toContain("attacker.example");
      expect(error.message).not.toContain("sk-canary");
    }
  });

  it.each(POOLED)("$provider: another pooled provider's origin is not its own", (entry) => {
    // The mistake pooling makes possible: provider A's base URL pointed at
    // provider B's host, which this process can also reach and holds a key for.
    const other = POOLED.find((candidate) => candidate.provider !== entry.provider)!;
    const otherOrigin = PROVIDER_CREDENTIAL_ORIGINS[other.provider].origins[0];
    for (const variable of PROVIDER_CREDENTIAL_ORIGINS[entry.provider].baseUrlVariables) {
      productionPool(poolListing(entry));
      process.env[variable] = `${otherOrigin}/v1`;
      expect(bootError().message, variable).toBe(originRefusal(entry, variable, "production", alsoRefused(entry)));
    }
  });

  it("checks only the providers it lists", () => {
    // An unlisted provider's base URL carries no key from this process.
    productionPool(PLANNED);
    process.env.CHUTES_BASE_URL = "https://api.other-provider.example/v1";
    expect(() => loadConfig()).not.toThrow();
  });

  it("boots synthetic only with EVERY listed provider on the fixture origin", () => {
    // The planned list: a production pool cannot list Chutes under any profile.
    productionPool(PLANNED);
    process.env.PROVIDER_TRANSPORT_PROFILE = "synthetic";
    for (const entry of PLANNED) {
      for (const variable of PROVIDER_CREDENTIAL_ORIGINS[entry.provider].baseUrlVariables) process.env[variable] = MOCK_URL;
    }
    expect(loadConfig().providers.transportProfile).toBe("synthetic");

    // One left on its real origin refuses the whole pool.
    for (const entry of PLANNED) {
      const variable = PROVIDER_CREDENTIAL_ORIGINS[entry.provider].baseUrlVariables[0];
      const real = process.env[variable];
      delete process.env[variable];
      expect(bootError().message, variable).toBe(originRefusal(entry, variable, "synthetic"));
      process.env[variable] = real;
    }
  });
});

describe("the pool's metadata token selection has no fallback and no override", () => {
  const SHARED = distinct("metadata-shared");
  const DEPLOYMENT = distinct("metadata-deployment");
  const own = (provider: string) => distinct(`metadata-${provider}`);
  const providerMetadataTokens = { venice: own("venice"), fireworks: own("fireworks") };

  it("returns the named provider's own token and ignores both other sources", () => {
    const sources = { role: "pool-worker", deploymentMetadataToken: DEPLOYMENT, providerMetadataTokens, metadataRpcToken: SHARED };
    expect(workerMetadataTokenFor(sources, "venice")).toBe(own("venice"));
    expect(workerMetadataTokenFor(sources, "fireworks")).toBe(own("fireworks"));
    // The same sources under a single-provider role: the deployment token wins,
    // as it always has. The pool rule is the role's, not a change to the rest.
    expect(workerMetadataTokenFor({ ...sources, role: "venice-worker" }, "venice")).toBe(DEPLOYMENT);
    expect(workerMetadataTokenFor({ ...sources, role: undefined }, "venice")).toBe(DEPLOYMENT);
  });

  it.each(["deepinfra", "aws-bedrock", "mock", "toString", "__proto__", "constructor", null])(
    "throws for %s instead of presenting another authority",
    (provider) => {
      const sources = { role: "pool-worker", deploymentMetadataToken: DEPLOYMENT, providerMetadataTokens, metadataRpcToken: SHARED };
      expect(() => workerMetadataTokenFor(sources, provider)).toThrow(/pool-worker has no metadata token for provider/);
    }
  );

  it("holds outside production too, where the shared token has a dev fallback", () => {
    clearRelevant();
    process.env.NODE_ENV = "test";
    process.env.RUNTIME_ROLE = "pool-worker";
    process.env.POOL_PROVIDERS = "venice,fireworks";
    process.env.METADATA_RPC_TOKEN_VENICE = own("venice");
    process.env.METADATA_RPC_DEPLOYMENT_TOKEN = DEPLOYMENT;
    const internal = loadConfig().internal;
    // Both other sources are populated here, and neither is ever selected.
    expect(internal.metadataRpcToken).not.toBe("");
    expect(internal.deploymentMetadataToken).toBe(DEPLOYMENT);
    expect(internal.workerMetadataToken).toBe("");
    expect(workerMetadataTokenFor(internal, "venice")).toBe(own("venice"));
    expect(() => workerMetadataTokenFor(internal, "fireworks")).toThrow("pool-worker has no metadata token for provider fireworks");
  });
});

describe("replay-log filenames are the per-provider workers' own (C5)", () => {
  // Read from the committed production compose: the filename each provider's
  // worker writes TODAY. A pool file under any other name would read as an
  // empty log and re-open every unexpired capability.
  const compose = readFileSync(join(ROOT, "deploy/phala/docker-compose.prod5-xl.yml"), "utf8");
  const deployed = new Map<string, string>();
  let role = "";
  for (const line of compose.split("\n")) {
    const roleMatch = line.match(/^\s+RUNTIME_ROLE: (\S+)$/);
    if (roleMatch) role = roleMatch[1]!;
    const fileMatch = line.match(/^\s+CONSUMED_CAPABILITY_FILE: (\S+)$/);
    if (fileMatch) deployed.set(role, fileMatch[1]!);
  }

  it("finds a replay log for every bearer-key worker in the production compose", () => {
    expect([...deployed.keys()].sort()).toEqual([
      "chutes-worker", "deepinfra-worker", "fireworks-worker", "near-worker",
      "phala-ai-worker", "tinfoil-worker", "venice-worker"
    ]);
  });

  it.each(POOLED)("$provider uses its worker's exact path under the default directory", (entry) => {
    const workerRole = Object.entries(WORKER_PROVIDER_BY_ROLE).find(([, provider]) => provider === entry.provider)![0];
    clearRelevant();
    process.env.NODE_ENV = "test";
    process.env.RUNTIME_ROLE = "pool-worker";
    process.env.POOL_PROVIDERS = entry.provider;
    const directoryDefault = loadConfig().internal.credentialAdmin.consumedCapabilityDir;
    expect(join(directoryDefault, consumedCapabilityFileName(entry.provider))).toBe(deployed.get(workerRole));
  });

  it("names NEAR's file by its compose key, not its canonical name", () => {
    expect(consumedCapabilityFileName("near-ai")).toBe("consumed-near.json");
    expect(consumedCapabilityFileName("phala-ai")).toBe("consumed-phala-ai.json");
    expect(new Set(POOLED.map((entry) => consumedCapabilityFileName(entry.provider))).size).toBe(POOLED.length);
  });

  it("leaves the Venice overlay path where the Venice worker keeps it", () => {
    productionPool();
    const overlay = compose.match(/^\s+VENICE_KEYSET_OVERLAY_FILE: (\S+)$/m)![1];
    expect(loadConfig().providers.veniceKeysetOverlayFile).toBe(overlay);
  });
});

describe("every place roles are enumerated names the pool", () => {
  const source = (file: string) => readFileSync(join(ROOT, file), "utf8");

  it("is in the split-role gate and the content-tier check BY NAME", () => {
    const config = source("src/config.ts");
    const statement = (name: string) => {
      const start = config.indexOf(`const ${name} = `);
      expect(start, name).toBeGreaterThan(-1);
      return config.slice(start, config.indexOf(";", start));
    };
    expect(statement("isSplitRole")).toContain('env.RUNTIME_ROLE === "pool-worker"');
    // Named, so the check does not depend on the role's name ending "-worker".
    expect(statement("contentTierRole")).toContain('env.RUNTIME_ROLE === "pool-worker"');
  });

  it.skipIf(!existsSync(join(ROOT, "src/index.ts")))("the monolith entry point admits the pool as a worker", () => {
    // src/index.ts falls through to the monolith for a role it does not name,
    // which for the pool would start a control plane holding provider keys.
    const index = source("src/index.ts");
    const workerBranch = index.slice(index.indexOf('role === "venice-worker"'), index.indexOf("buildWorkerServer(config)"));
    expect(workerBranch).toContain('role === "pool-worker"');

  });

  it("the portable content-plane entry point admits pool-worker", () => {
    const contentPlane = source("src/contentPlane.ts");
    const roles = contentPlane.slice(contentPlane.indexOf("const CONTENT_ROLES"), contentPlane.indexOf("]);"));
    expect(roles).toContain('"pool-worker"');
  });

  it("is named wherever the eight single-provider roles are listed", () => {
    // The search the plan's audit uses (section 3, fact 11), kept as a test: a
    // new source file that enumerates the worker roles must name the pool or
    // say here why it need not.
    const sourceFiles = (readdirRecursive("src")).filter((file) => file.endsWith(".ts"));
    const enumerating = sourceFiles.filter((file) => {
      const text = source(file);
      return text.includes('"phala-ai-worker"') && text.includes('"near-worker"');
    });
    expect(enumerating.sort()).toEqual([
      "src/config.ts",
      "src/contentPlane.ts",
      ...(existsSync(join(ROOT, "src/index.ts")) ? ["src/index.ts"] : []),
      "src/providers/workerProviders.ts"
    ]);
    for (const file of enumerating) expect(source(file), file).toMatch(/pool-worker/);
  });
});

function readdirRecursive(relative: string): string[] {
  const entries = readdirSync(join(ROOT, relative), { withFileTypes: true });
  return entries.flatMap((entry) => entry.isDirectory()
    ? readdirRecursive(`${relative}/${entry.name}`)
    : [`${relative}/${entry.name}`]);
}
