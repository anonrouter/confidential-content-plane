import { describe, expect, it } from "vitest";
import { pinnedMeasurementPolicyFor } from "../../src/providers/attestation/policies.js";

describe("Tinfoil provider-authority policy", () => {
  const policy = pinnedMeasurementPolicyFor("tinfoil", "openai/gpt-oss-120b");

  it("pins the release authority and repository instead of release outputs", () => {
    expect(policy).toEqual({
      source: "tinfoil-official-verifier+github-actions-sigstore",
      version: "provider-authority/v1",
      accepted: {
        authority: "github-actions-sigstore",
        configRepo: "tinfoilsh/confidential-model-router",
        releaseSelection: "latest",
        requireTaggedRelease: true
      }
    });
  });

  it("contains no static release tag, digest, or measurement fingerprint", () => {
    const serialized = JSON.stringify(policy);
    expect(serialized).not.toMatch(/v0\.0\.\d+/);
    expect(serialized).not.toMatch(/[0-9a-f]{64}/);
    expect(serialized).not.toContain("codeFingerprint");
    expect(serialized).not.toContain("enclaveFingerprint");
  });
});
