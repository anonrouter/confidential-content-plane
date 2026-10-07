import { describe, expect, it } from "vitest";
import {
  WORKER_HEALTH_TARGET_LIMIT,
  workerHealthReportSchema,
  workerHealthTargetsResponseSchema
} from "../../src/providers/health/workerMetadata.js";

describe("worker health metadata boundary", () => {
  it("accepts only bounded, content-free health outcomes", () => {
    expect(workerHealthReportSchema.parse({
      deploymentId: "us-west-1-prod5-xl",
      provider: "tinfoil",
      healthChecks: [{
        externalModelId: "openai/gpt-oss-120b",
        ok: false,
        latencyMs: 1500,
        statusCode: 503,
        errorCode: "provider_http_error"
      }]
    })).toMatchObject({ provider: "tinfoil" });

    for (const forbidden of ["prompt", "response", "accountId", "apiKey", "rawError", "checkedAt"]) {
      const parsed = workerHealthReportSchema.safeParse({
        provider: "tinfoil",
        healthChecks: [{ externalModelId: "openai/gpt-oss-120b", ok: true, latencyMs: 1 }],
        [forbidden]: "must-not-cross"
      });
      expect(parsed.success, forbidden).toBe(false);
    }
  });

  it("rejects raw error text, duplicate models, and failure metadata on success", () => {
    expect(workerHealthReportSchema.safeParse({
      provider: "tinfoil",
      healthChecks: [{
        externalModelId: "openai/gpt-oss-120b",
        ok: false,
        latencyMs: 1,
        errorCode: "upstream said the prompt was bad"
      }]
    }).success).toBe(false);

    expect(workerHealthReportSchema.safeParse({
      provider: "tinfoil",
      healthChecks: [
        { externalModelId: "openai/gpt-oss-120b", ok: true, latencyMs: 1 },
        { externalModelId: "openai/gpt-oss-120b", ok: true, latencyMs: 1 }
      ]
    }).success).toBe(false);

    expect(workerHealthReportSchema.safeParse({
      provider: "tinfoil",
      healthChecks: [{
        externalModelId: "openai/gpt-oss-120b",
        ok: true,
        latencyMs: 1,
        statusCode: 200
      }]
    }).success).toBe(false);
  });

  it("caps report and target cardinality", () => {
    const checks = Array.from({ length: WORKER_HEALTH_TARGET_LIMIT + 1 }, (_, index) => ({
      externalModelId: `model-${index}`,
      ok: true,
      latencyMs: 1
    }));
    expect(workerHealthReportSchema.safeParse({ provider: "venice", healthChecks: checks }).success).toBe(false);
  });

  it("refuses repeated targets and over-disclosing or malformed lease fields", () => {
    expect(workerHealthTargetsResponseSchema.safeParse({ health_probe_targets: [
      { externalModelId: "same" }, { externalModelId: "same" }
    ] }).success).toBe(false);
    for (const lease of [{ leaseId: "bad", ttlMs: 1 }, { leaseId: "11".repeat(16), ttlMs: 1_800_001 },
      { leaseId: "11".repeat(16), ttlMs: 1_800_000, prompt: "forbidden" }]) {
      expect(workerHealthTargetsResponseSchema.safeParse({ health_probe_lease: lease }).success).toBe(false);
    }
  });

  it("treats a previous control release as an empty target set", () => {
    expect(workerHealthTargetsResponseSchema.parse({ accepted: true, changed: false })).toEqual({
      accepted: true,
      changed: false,
      health_probe_targets: []
    });
  });
});
