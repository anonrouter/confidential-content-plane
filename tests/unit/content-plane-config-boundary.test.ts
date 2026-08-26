import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  computeClosure,
  controlPlaneLeakage,
  CONTENT_PLANE_ENTRIES,
  CONTROL_PLANE_FILES
} from "../../scripts/phala-usw/contentPlaneClosure.js";

// The confidential content plane has its own configuration boundary.
//
// D-22 split the plaintext-capable workload into its own image. This suite
// enforces the same split in configuration: a role that can see a prompt must
// not import, validate, expose or publish database settings.
//
// The finding that motivated this was concrete. The public content-plane export
// carried src/config.ts, which parsed DATABASE_URL for every role and defaulted
// it to a localhost PostgreSQL URL with an embedded password. Two independent
// secret scanners flagged the literal. The value protects nothing, but the
// right fix is not to waive it: the content plane has no database, so it should
// not have had the setting.
//
// These assertions fail if that regresses. They are deliberately structural,
// because "no one will re-add it" is not a control.

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const read = (relative: string) => readFileSync(join(ROOT, relative), "utf8");

// This suite ships in the public export, so it imports nothing from the control
// plane -- not even to assert against it. That is a constraint the export
// tooling enforces: a suite whose own module closure reaches control-plane
// source is refused rather than carried.
//
// In the MONOREPO it checks that the boundary between the two planes holds. In
// the EXPORT the control plane is absent entirely, which is the stronger
// result, and the absence assertions below say so directly.
//
// The complementary regressions -- that the control plane still resolves
// DATABASE_URL exactly as before -- live in tests/unit/control-plane-config.test.ts,
// which stays in the monorepo because running it requires the module this
// boundary exists to exclude.

describe("no database configuration is reachable from the content plane", () => {
  it("keeps the database config module out of both closures", () => {
    expect(existsSync(join(ROOT, "src/db/config.ts")) || !existsSync(join(ROOT, "src/server.ts"))).toBe(true);
    for (const mode of ["value", "compile"] as const) {
      const files = computeClosure(ROOT, CONTENT_PLANE_ENTRIES, mode);
      expect(files, mode).not.toContain("src/db/config.ts");
      expect(files, mode).not.toContain("src/appConfig.ts");
    }
  });

  it("names both modules as control-plane, so the general leakage check covers them", () => {
    expect(CONTROL_PLANE_FILES).toContain("src/db/config.ts");
    expect(CONTROL_PLANE_FILES).toContain("src/appConfig.ts");
    expect(controlPlaneLeakage(["src/db/config.ts"])).toEqual(["src/db/config.ts"]);
    expect(controlPlaneLeakage(["src/appConfig.ts"])).toEqual(["src/appConfig.ts"]);
  });

  it("publishes no connection string and no fallback password", () => {
    // Every file the public export would contain, not merely what executes.
    const offenders: string[] = [];
    for (const file of computeClosure(ROOT, CONTENT_PLANE_ENTRIES, "compile")) {
      for (const [index, line] of read(file).split("\n").entries()) {
        if (/postgres(ql)?:\/\/[^"'`\s]*:[^"'`\s]*@/.test(line) || /anonrouter_app_local_password/.test(line)) {
          offenders.push(`${file}:${index + 1}`);
        }
      }
    }
    expect(offenders, `credential-shaped literals in the content-plane export: ${offenders.join(", ")}`).toEqual([]);
  });

  it("mentions DATABASE_URL only to REFUSE it, never to read it", () => {
    // The content tier asserts an operator did not hand it a database URL. That
    // is the opposite of accepting one, and it must survive; what must not come
    // back is a read of the value into configuration.
    for (const file of computeClosure(ROOT, CONTENT_PLANE_ENTRIES, "compile")) {
      const source = read(file);
      expect(source, file).not.toMatch(/\benv\.DATABASE_URL\b/);
      expect(source, file).not.toMatch(/\benv\.MIGRATION_DATABASE_URL\b/);
      expect(source, file).not.toMatch(/\benv\.APP_DB_PASSWORD\b/);
    }
  });

  it("still refuses a database URL handed to a content-tier role", () => {
    // config.ts ships in the export, so this holds in both places.
    // The negative assertion is the half of the boundary that catches a
    // misconfigured deployment rather than a misdirected import.
    const config = read("src/config.ts");
    const forbidden = config.slice(config.indexOf("const forbidden = ["));
    for (const key of ["DATABASE_URL", "MIGRATION_DATABASE_URL", "APP_DB_PASSWORD", "REDIS_URL"]) {
      expect(forbidden.slice(0, forbidden.indexOf("]")), key).toContain(key);
    }
    expect(config).toContain("the gateway-attestation service must not be given a database URL");
  });
});

describe("the shared configuration no longer carries a database", () => {
  let snapshot: NodeJS.ProcessEnv;

  beforeEach(() => {
    snapshot = { ...process.env };
  });

  afterEach(() => {
    process.env = snapshot;
  });

  it("loadConfig() returns no db key at all", async () => {
    const { loadConfig } = await import("../../src/config.js");
    const config = loadConfig();
    expect(Object.keys(config)).not.toContain("db");
    expect((config as Record<string, unknown>).db).toBeUndefined();
  });

  it("loadConfig() succeeds with no database variables in the environment", async () => {
    for (const key of ["DATABASE_URL", "DATABASE_URL_FILE", "MIGRATION_DATABASE_URL", "MIGRATION_DATABASE_URL_FILE", "APP_DB_USER", "APP_DB_PASSWORD", "APP_DB_PASSWORD_FILE"]) {
      delete process.env[key];
    }
    const { loadConfig } = await import("../../src/config.js");
    expect(() => loadConfig()).not.toThrow();
  });

  it("does not introduce a new required variable for the content plane", async () => {
    // The point of the split is that the content plane needs LESS configuration,
    // not that the setting moved somewhere it must still be supplied.
    process.env.RUNTIME_ROLE = "relay";
    delete process.env.DATABASE_URL;
    const { loadConfig } = await import("../../src/config.js");
    expect(() => loadConfig()).not.toThrow();
  });
});

describe("the content-plane config type excludes control-plane configuration", () => {
  const source = read("src/contentPlaneConfig.ts");

  it("admits only the sections a prompt-bearing role needs", () => {
    const picked = source.slice(source.indexOf("Pick<"), source.indexOf(">", source.indexOf("Pick<")));
    for (const section of ["env", "runtimeRole", "server", "logging", "providers", "internal", "routing"]) {
      expect(picked, section).toContain(`"${section}"`);
    }
    for (const section of ["db", "redis", "auth", "admin", "billing", "connect", "monitoring", "security"]) {
      expect(picked, section).not.toContain(`"${section}"`);
    }
  });

  it("narrows secrets to the one the content plane uses", () => {
    expect(source).toContain("appSecret");
    for (const secret of ["cookieSecret", "adminAccessToken", "emailHashSecret", "emailEncryptionKey"]) {
      expect(source, secret).not.toContain(`readonly ${secret}`);
    }
  });

  it("is the type the content plane's own modules are written against", () => {
    // A type nothing uses proves nothing. These are leaf modules on the prompt
    // path, and each declares the narrow requirement rather than the full config.
    for (const file of ["src/routes/helpers.ts", "src/providers/registry.ts", "src/inference/workerClient.ts"]) {
      expect(read(file), file).toContain("ContentPlaneConfig");
    }
  });

  it("keeps the crypto helpers on structural types so neither plane over-shares", () => {
    // security/crypto.ts runs in the content plane but also holds the email
    // encryption helpers. Asking for the exact secret per function means the
    // content plane never needs a config type carrying the email keys.
    const crypto = read("src/security/crypto.ts");
    expect(crypto).not.toMatch(/:\s*AppConfig\b/);
    expect(crypto).toContain("WithAppSecret");
    expect(crypto).toContain("WithEmailEncryptionKey");
  });
});
