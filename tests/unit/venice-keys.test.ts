import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  parseVeniceKeyset,
  upsertVeniceKeyManifest,
  veniceKeyFingerprint,
  veniceKeyManifest,
  VeniceKeySelector
} from "../../src/providers/veniceKeys.js";
import { VeniceKeysetStore } from "../../src/providers/veniceKeyStore.js";
import { AppError } from "../../src/security/errors.js";
import type { DbPool } from "../../src/db/pool.js";
import type { Redis } from "ioredis";

function fakeDb(rows: Array<{ key_id: string; enabled: boolean; priority?: number; strategy?: string }>) {
  return { query: async () => ({ rows }) } as unknown as DbPool;
}

function fakeRedis(behavior: { incr?: () => Promise<number> } = {}) {
  let counter = 0;
  return {
    incr: behavior.incr ?? (async () => ++counter)
  } as unknown as Redis;
}

describe("parseVeniceKeyset", () => {
  it("parses ids, labels, and keys", () => {
    const keys = parseVeniceKeyset(
      JSON.stringify([
        { id: "primary", label: "Primary", key: "sk-a" },
        { id: "backup-1", key: " sk-b " }
      ]),
      "VENICE_INFERENCE_KEYS"
    );
    expect(keys).toEqual([
      { id: "primary", label: "Primary", key: "sk-a" },
      { id: "backup-1", label: null, key: "sk-b" }
    ]);
  });

  it("rejects invalid JSON, empty arrays, bad ids, duplicates, and empty keys", () => {
    expect(() => parseVeniceKeyset("nope", "SRC")).toThrow(/valid JSON/);
    expect(() => parseVeniceKeyset("[]", "SRC")).toThrow(/non-empty/);
    expect(() => parseVeniceKeyset(JSON.stringify([{ id: "Bad Id", key: "x" }]), "SRC")).toThrow(/id must match/);
    expect(() =>
      parseVeniceKeyset(JSON.stringify([{ id: "a", key: "x" }, { id: "a", key: "y" }]), "SRC")
    ).toThrow(/duplicate/);
    expect(() => parseVeniceKeyset(JSON.stringify([{ id: "a", key: "  " }]), "SRC")).toThrow(/non-empty string/);
  });
});

describe("veniceKeyManifest", () => {
  it("never contains key material", () => {
    const manifest = veniceKeyManifest([
      { id: "primary", label: null, key: "sk-secret-value" },
      { id: "backup", label: "Backup", key: "sk-other-secret" }
    ]);
    expect(JSON.stringify(manifest)).not.toContain("sk-secret-value");
    expect(JSON.stringify(manifest)).not.toContain("sk-other-secret");
    expect(manifest[0]).toEqual({
      id: "primary",
      label: null,
      fingerprint: veniceKeyFingerprint("sk-secret-value")
    });
    expect(manifest[0]!.fingerprint).toHaveLength(12);
  });
});

describe("regional Venice key manifests", () => {
  it("writes and prunes only the named deployment namespace", async () => {
    const queries: Array<{ sql: string; params: unknown[] }> = [];
    const db = {
      query: async (sql: string, params: unknown[] = []) => {
        queries.push({ sql, params });
        return { rows: [] };
      }
    } as unknown as DbPool;
    await upsertVeniceKeyManifest(db, [
      { id: "primary", label: "AMS", fingerprint: "0123456789ab" }
    ], "eu-ams-1");
    expect(queries).toHaveLength(2);
    expect(queries[0]!.sql).toContain("providers.venice_deployment_keys");
    expect(queries[0]!.params).toEqual(["eu-ams-1", "primary", "AMS", "0123456789ab"]);
    expect(queries[1]!.sql).toContain("DELETE FROM providers.venice_deployment_keys");
    expect(queries[1]!.params).toEqual(["eu-ams-1", ["primary"]]);
  });

  it("clears a regional namespace when its authoritative manifest is empty", async () => {
    const queries: Array<{ sql: string; params: unknown[] }> = [];
    const db = {
      query: async (sql: string, params: unknown[] = []) => {
        queries.push({ sql, params });
        return { rows: [] };
      }
    } as unknown as DbPool;
    await upsertVeniceKeyManifest(db, [], "eu-ams-1");
    expect(queries).toHaveLength(1);
    expect(queries[0]!.sql).toContain("DELETE FROM providers.venice_deployment_keys");
    expect(queries[0]!.params).toEqual(["eu-ams-1", []]);
  });

  it("keeps the legacy primary manifest in the existing operator table", async () => {
    const queries: string[] = [];
    const db = {
      query: async (sql: string) => { queries.push(sql); return { rows: [] }; }
    } as unknown as DbPool;
    await upsertVeniceKeyManifest(db, [
      { id: "primary", label: null, fingerprint: "0123456789ab" }
    ]);
    expect(queries).toHaveLength(1);
    expect(queries[0]).toContain("providers.venice_keys");
    expect(queries[0]).not.toContain("venice_deployment_keys");
  });
});

describe("VeniceKeySelector", () => {
  it("returns null when no keys are registered (pre-manifest compatibility)", async () => {
    const selector = new VeniceKeySelector(fakeDb([]), fakeRedis());
    expect(await selector.selectKeyId()).toBeNull();
  });

  it("selects only from the requested confidential deployment namespace", async () => {
    const queries: Array<{ sql: string; params: unknown[] }> = [];
    const db = {
      query: async (sql: string, params: unknown[] = []) => {
        queries.push({ sql, params });
        const deploymentId = params[0];
        return {
          rows: deploymentId === "eu-ams-1"
            ? [{ key_id: "ams-primary", enabled: true, priority: 100, strategy: "round_robin" }]
            : deploymentId === "us-east-1"
              ? [{ key_id: "east-primary", enabled: true, priority: 100, strategy: "round_robin" }]
              : [{ key_id: "production-primary", enabled: true, priority: 100, strategy: "round_robin" }]
        };
      }
    } as unknown as DbPool;
    const selector = new VeniceKeySelector(db, fakeRedis());
    expect(await selector.selectKeyId("eu-ams-1")).toBe("ams-primary");
    expect(await selector.selectKeyId("us-east-1")).toBe("east-primary");
    expect(await selector.selectKeyId()).toBe("production-primary");
    expect(queries.map((query) => query.params)).toEqual([["eu-ams-1"], ["us-east-1"], []]);
  });

  it("fails closed when every registered key is disabled", async () => {
    const selector = new VeniceKeySelector(fakeDb([{ key_id: "a", enabled: false }]), fakeRedis());
    await expect(selector.selectKeyId()).rejects.toMatchObject({
      statusCode: 503,
      code: "provider_key_unavailable"
    });
    await expect(selector.selectKeyId()).rejects.toBeInstanceOf(AppError);
  });

  it("pins to a single enabled key without touching the rotation counter", async () => {
    let incrCalls = 0;
    const redis = fakeRedis({ incr: async () => { incrCalls += 1; return 1; } });
    const selector = new VeniceKeySelector(
      fakeDb([
        { key_id: "a", enabled: false },
        { key_id: "b", enabled: true }
      ]),
      redis
    );
    expect(await selector.selectKeyId()).toBe("b");
    expect(await selector.selectKeyId()).toBe("b");
    expect(incrCalls).toBe(0);
  });

  it("round-robins across enabled keys only", async () => {
    const selector = new VeniceKeySelector(
      fakeDb([
        { key_id: "a", enabled: true },
        { key_id: "b", enabled: false },
        { key_id: "c", enabled: true }
      ]),
      fakeRedis()
    );
    const picks = [await selector.selectKeyId(), await selector.selectKeyId(), await selector.selectKeyId(), await selector.selectKeyId()];
    expect(picks).toEqual(["c", "a", "c", "a"]);
    expect(picks).not.toContain("b");
  });

  it("keeps dispatching when the rotation counter is unavailable", async () => {
    const redis = fakeRedis({ incr: async () => { throw new Error("valkey down"); } });
    const selector = new VeniceKeySelector(
      fakeDb([
        { key_id: "a", enabled: true },
        { key_id: "b", enabled: true }
      ]),
      redis
    );
    const picked = await selector.selectKeyId();
    expect(["a", "b"]).toContain(picked);
  });

  it("pins all traffic to the lowest priority number under the priority strategy", async () => {
    let incrCalls = 0;
    const redis = fakeRedis({ incr: async () => { incrCalls += 1; return 1; } });
    const selector = new VeniceKeySelector(
      fakeDb([
        { key_id: "a", enabled: true, priority: 200, strategy: "priority" },
        { key_id: "b", enabled: true, priority: 10, strategy: "priority" },
        { key_id: "c", enabled: false, priority: 1, strategy: "priority" }
      ]),
      redis
    );
    expect(await selector.selectKeyId()).toBe("b");
    expect(await selector.selectKeyId()).toBe("b");
    expect(incrCalls).toBe(0);
  });

  it("breaks priority ties on key id", async () => {
    const selector = new VeniceKeySelector(
      fakeDb([
        { key_id: "zeta", enabled: true, priority: 5, strategy: "priority" },
        { key_id: "alpha", enabled: true, priority: 5, strategy: "priority" }
      ]),
      fakeRedis()
    );
    expect(await selector.selectKeyId()).toBe("alpha");
  });

  it("draws uniformly among enabled keys under the random strategy", async () => {
    let incrCalls = 0;
    const redis = fakeRedis({ incr: async () => { incrCalls += 1; return 1; } });
    const selector = new VeniceKeySelector(
      fakeDb([
        { key_id: "a", enabled: true, priority: 100, strategy: "random" },
        { key_id: "b", enabled: true, priority: 100, strategy: "random" },
        { key_id: "c", enabled: false, priority: 100, strategy: "random" }
      ]),
      redis
    );
    const picks = new Set<string | null>();
    for (let i = 0; i < 200; i += 1) picks.add(await selector.selectKeyId());
    expect([...picks].sort()).toEqual(["a", "b"]);
    expect(incrCalls).toBe(0);
  });

  it("falls back to round robin on an unknown strategy value", async () => {
    const selector = new VeniceKeySelector(
      fakeDb([
        { key_id: "a", enabled: true, strategy: "bogus" },
        { key_id: "b", enabled: true, strategy: "bogus" }
      ]),
      fakeRedis()
    );
    expect([await selector.selectKeyId(), await selector.selectKeyId()]).toEqual(["b", "a"]);
  });

  it("still fails closed when strategies are configured but no key is enabled", async () => {
    const selector = new VeniceKeySelector(
      fakeDb([{ key_id: "a", enabled: false, priority: 1, strategy: "priority" }]),
      fakeRedis()
    );
    await expect(selector.selectKeyId()).rejects.toMatchObject({
      statusCode: 503,
      code: "provider_key_unavailable"
    });
  });
});

describe("VeniceKeysetStore", () => {
  const bootKeys = [
    { id: "primary", label: "Primary", key: "sk-boot-primary" },
    { id: "backup", label: null, key: "sk-boot-backup" }
  ];
  let dir: string;

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function newStore() {
    dir = mkdtempSync(join(tmpdir(), "venice-keyset-"));
    return new VeniceKeysetStore(bootKeys, join(dir, "overlay.json"));
  }

  it("starts from the boot keyset when no overlay exists", () => {
    const store = newStore();
    expect(store.effectiveKeys()).toEqual(bootKeys);
    expect(store.keyById("primary")).toBe("sk-boot-primary");
    expect(store.defaultKey()).toBe("sk-boot-primary");
  });

  it("adds operator keys durably and lets an added key win an id collision", () => {
    const store = newStore();
    store.addKey({ id: "extra", label: "Extra", key: "sk-added-extra" });
    store.addKey({ id: "primary", label: "Rotated", key: "sk-rotated-primary" });
    expect(store.keyById("extra")).toBe("sk-added-extra");
    expect(store.keyById("primary")).toBe("sk-rotated-primary");
    // A fresh store over the same overlay file sees the same effective keyset.
    const reloaded = new VeniceKeysetStore(bootKeys, join(dir, "overlay.json"));
    expect(reloaded.keyById("extra")).toBe("sk-added-extra");
    expect(reloaded.keyById("primary")).toBe("sk-rotated-primary");
    expect(reloaded.keyById("backup")).toBe("sk-boot-backup");
  });

  it("hides removed boot keys and forgets removed added keys", () => {
    const store = newStore();
    store.addKey({ id: "extra", label: null, key: "sk-added-extra" });
    store.removeKey("backup");
    store.removeKey("extra");
    expect(store.effectiveKeys().map((entry) => entry.id)).toEqual(["primary"]);
    expect(store.keyById("backup")).toBeNull();
    const reloaded = new VeniceKeysetStore(bootKeys, join(dir, "overlay.json"));
    expect(reloaded.effectiveKeys().map((entry) => entry.id)).toEqual(["primary"]);
  });

  it("re-adding a removed boot key id restores it with the new secret", () => {
    const store = newStore();
    store.removeKey("primary");
    expect(store.keyById("primary")).toBeNull();
    store.addKey({ id: "primary", label: null, key: "sk-new-primary" });
    expect(store.keyById("primary")).toBe("sk-new-primary");
  });

  it("flags the last remaining key and reports unknown removals", () => {
    const store = newStore();
    expect(store.isLastRemaining("primary")).toBe(false);
    store.removeKey("backup");
    expect(store.isLastRemaining("primary")).toBe(true);
    expect(store.removeKey("does-not-exist")).toBe(false);
  });

  it("persists the overlay with owner-only permissions and picks up external changes", () => {
    const store = newStore();
    store.addKey({ id: "extra", label: null, key: "sk-added-extra" });
    const overlayPath = join(dir, "overlay.json");
    expect(statSync(overlayPath).mode & 0o777).toBe(0o600);
    expect(readFileSync(overlayPath, "utf8")).toContain("sk-added-extra");
    // A second store instance (same volume, different process in production)
    // mutates the file; the first instance observes it without a restart.
    const other = new VeniceKeysetStore(bootKeys, overlayPath);
    other.removeKey("extra");
    expect(store.keyById("extra")).toBeNull();
  });

  it("refuses corrupt state in both current and restarted stores, then recovers from a valid overlay", () => {
    const store = newStore();
    store.removeKey("primary");
    const overlayPath = join(dir, "overlay.json");
    const valid = readFileSync(overlayPath, "utf8");
    const corrupt = "{synthetic-sensitive-value-not-json";
    writeFileSync(overlayPath, corrupt);
    const reloaded = new VeniceKeysetStore(bootKeys, overlayPath);
    for (const reader of [store, reloaded]) {
      expect(() => reader.defaultKey()).toThrowError(AppError);
      try { reader.keyById("primary"); } catch (error) {
        expect(error).toMatchObject({ statusCode: 503, code: "provider_key_state_unavailable" });
        expect(String(error)).not.toContain("synthetic-sensitive-value");
      }
      expect(() => reader.addKey({ id: "extra", label: null, key: "sk-synthetic-extra" })).toThrowError(AppError);
      expect(() => reader.removeKey("backup")).toThrowError(AppError);
    }
    expect(readFileSync(overlayPath, "utf8")).toBe(corrupt);
    writeFileSync(overlayPath, valid);
    for (const reader of [store, reloaded]) {
      expect(reader.keyById("primary")).toBeNull();
      expect(reader.defaultKey()).toBe("sk-boot-backup");
    }
  });

  it("refuses a disappeared overlay after observing a persisted revocation", () => {
    const store = newStore();
    store.removeKey("primary");
    rmSync(join(dir, "overlay.json"));
    expect(() => store.defaultKey()).toThrowError(AppError);
    expect(() => store.addKey({ id: "extra", label: null, key: "sk-synthetic-extra" })).toThrowError(AppError);
  });

  it("refuses an unreadable overlay instead of treating it as initial boot", () => {
    const store = newStore();
    mkdirSync(join(dir, "overlay.json"));
    expect(() => store.defaultKey()).toThrowError(AppError);
  });

  it("does not expose an unpersisted mutation after a write fails", () => {
    const store = newStore();
    store.removeKey("primary");
    const valid = readFileSync(join(dir, "overlay.json"), "utf8");
    chmodSync(dir, 0o500);
    try {
      expect(() => store.addKey({ id: "primary", label: null, key: "sk-unpersisted" })).toThrow();
      expect(store.keyById("primary")).toBeNull();
      expect(readFileSync(join(dir, "overlay.json"), "utf8")).toBe(valid);
    } finally { chmodSync(dir, 0o700); }
  });

  it.each([
    null, [], {}, { added: [], removedIds: "primary" },
    { added: [], removedIds: ["primary", 7] },
    { added: [], removedIds: ["primary", "primary"] },
    { added: [], removedIds: ["invalid id"] },
    { added: [null], removedIds: ["primary"] },
    { added: [{ id: "backup", key: "" }], removedIds: ["primary"] },
    { added: [{ id: "backup", key: "sk-synthetic", label: 7 }], removedIds: ["primary"] },
    { added: [{ id: "backup", key: "sk-synthetic" }, { id: "backup", key: "sk-synthetic-other" }], removedIds: ["primary"] },
    { added: [{ id: "primary", key: "sk-synthetic" }], removedIds: ["primary"] },
    { added: [], removedIds: ["primary"], unexpected: true }
  ])("refuses malformed revocation metadata instead of dropping entries: %j", overlay => {
    newStore();
    const path = join(dir, "overlay.json");
    writeFileSync(path, JSON.stringify(overlay));
    const restarted = new VeniceKeysetStore(bootKeys, path);
    expect(() => restarted.effectiveKeys()).toThrowError(AppError);
  });
});
