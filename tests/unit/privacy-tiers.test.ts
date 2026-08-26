import { describe, expect, it } from "vitest";
import {
  DEFAULT_ROUTABLE_PRIVACY_CLASSES,
  isDefaultRoutableClass,
  isDowngradeFromDefault,
  resolveRequestedPrivacyClasses
} from "../../src/privacy/tiers.js";

describe("privacy tiers", () => {
  it("treats only private/tee/e2ee as default-routable", () => {
    expect(isDefaultRoutableClass("private")).toBe(true);
    expect(isDefaultRoutableClass("tee")).toBe(true);
    expect(isDefaultRoutableClass("e2ee")).toBe(true);
    expect(isDefaultRoutableClass("anonymous")).toBe(false);
    expect(isDefaultRoutableClass("unknown")).toBe(false);
  });

  it("defaults an unspecified privacy request to the privacy-preserving tiers", () => {
    const resolved = resolveRequestedPrivacyClasses(undefined);
    expect([...resolved].sort()).toEqual([...DEFAULT_ROUTABLE_PRIVACY_CLASSES].sort());
    expect(resolveRequestedPrivacyClasses([]).has("anonymous")).toBe(false);
  });

  it("lets an explicit opt-in widen to anonymous", () => {
    expect(resolveRequestedPrivacyClasses(["anonymous"]).has("anonymous")).toBe(true);
  });

  it("ignores invalid classes and falls back to the default set", () => {
    const resolved = resolveRequestedPrivacyClasses(["nonsense"]);
    expect([...resolved].sort()).toEqual([...DEFAULT_ROUTABLE_PRIVACY_CLASSES].sort());
  });

  it("flags anonymous/unknown as downgrades from the default", () => {
    expect(isDowngradeFromDefault("anonymous")).toBe(true);
    expect(isDowngradeFromDefault("unknown")).toBe(true);
    expect(isDowngradeFromDefault("private")).toBe(false);
  });
});
