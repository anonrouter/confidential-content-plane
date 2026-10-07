import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ConsumedCapabilityLog, ConsumedCapabilityLogError } from "../../src/credentials/consumedCapabilities.js";

describe("ambiguous capability replay state refuses", () => {
  let directory: string, path: string;
  const time = 1_700_000_000_000;
  const entry = { capabilityId: "cap-first", consumedAtMs: time, expiresAtMs: time + 300_000 };
  beforeEach(() => { directory = mkdtempSync(join(tmpdir(), "ar-replay-state-")); path = join(directory, "consumed.json"); });
  afterEach(() => rmSync(directory, { recursive: true, force: true }));

  it.each([
    {}, null, [null], ["invalid"], [{ ...entry, capabilityId: "../invalid" }],
    [{ ...entry, consumedAtMs: "invalid" }], [{ ...entry, consumedAtMs: -1 }],
    [{ ...entry, expiresAtMs: 0.5 }], [{ ...entry, expiresAtMs: null }],
    [{ ...entry, expiresAtMs: Number.MAX_SAFE_INTEGER + 1 }],
    [{ ...entry, extra: "unexpected" }], [entry, entry], [entry, {}]
  ])("never drops invalid entries from a syntactically valid log: %j", parsed => {
    const bytes = JSON.stringify(parsed); writeFileSync(path, bytes);
    const store = new ConsumedCapabilityLog(path, () => time);
    expect(() => store.wasConsumed("cap-first")).toThrow(ConsumedCapabilityLogError);
    expect(() => store.consume("cap-next", (time + 300_000) / 1000)).toThrow(ConsumedCapabilityLogError);
    expect(readFileSync(path, "utf8")).toBe(bytes);
  });

  it("refuses an inaccessible path component rather than creating empty history", () => {
    writeFileSync(path, "ordinary-file");
    const store = new ConsumedCapabilityLog(join(path, "nested.json"), () => time);
    expect(() => store.wasConsumed("cap-first")).toThrow(ConsumedCapabilityLogError);
    expect(() => store.consume("cap-next", time / 1000 + 300)).toThrow(ConsumedCapabilityLogError);
    expect(readFileSync(path, "utf8")).toBe("ordinary-file");
  });

  it("refuses symlinks, including broken ones, instead of treating their target as new state", () => {
    const target = join(directory, "target.json"); symlinkSync(target, path);
    expect(() => new ConsumedCapabilityLog(path).wasConsumed("cap-first")).toThrow(ConsumedCapabilityLogError);
    writeFileSync(target, JSON.stringify([entry]));
    expect(() => new ConsumedCapabilityLog(path).wasConsumed("cap-first")).toThrow(ConsumedCapabilityLogError);
  });

  it("refuses loss after persistence, then recovers only when valid state is restored", () => {
    const store = new ConsumedCapabilityLog(path, () => time);
    expect(store.consume("cap-first", time / 1000 + 300).firstUse).toBe(true);
    const bytes = readFileSync(path); rmSync(path);
    expect(() => store.wasConsumed("cap-first")).toThrow(ConsumedCapabilityLogError);
    expect(() => store.consume("cap-first", time / 1000 + 300)).toThrow(ConsumedCapabilityLogError);
    writeFileSync(path, bytes);
    expect(store.consume("cap-first", time / 1000 + 300).firstUse).toBe(false);
    expect(new ConsumedCapabilityLog(path).wasConsumed("cap-first")).toBe(true);
  });

  it("retains every live id at capacity and prunes only after expiry plus grace", () => {
    const entries = Array.from({ length: 10_000 }, (_, i) => ({ ...entry, capabilityId: `cap-full-${i}` }));
    const bytes = JSON.stringify(entries); writeFileSync(path, bytes);
    let current = time;
    const store = new ConsumedCapabilityLog(path, () => current);
    expect(store.consume("cap-full-0", time / 1000 + 300).firstUse).toBe(false);
    expect(() => store.consume("cap-extra", time / 1000 + 300)).toThrow(ConsumedCapabilityLogError);
    expect(readFileSync(path, "utf8")).toBe(bytes);
    expect(new ConsumedCapabilityLog(path).wasConsumed("cap-full-0")).toBe(true);
    current = entry.expiresAtMs + 24 * 60 * 60 * 1000;
    expect(store.consume("cap-extra", current / 1000 + 300).firstUse).toBe(true);
    expect(JSON.parse(readFileSync(path, "utf8"))).toHaveLength(1);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it.each([NaN, Infinity, -1, 0.5, Number.MAX_SAFE_INTEGER])("refuses invalid expiry without writing state: %s", expiry => {
    expect(() => new ConsumedCapabilityLog(path).consume("cap-next", expiry)).toThrow(ConsumedCapabilityLogError);
  });
});
