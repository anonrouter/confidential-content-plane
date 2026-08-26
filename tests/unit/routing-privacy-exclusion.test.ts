import { describe, expect, it } from "vitest";
import type { ChatCompletionRequestBody, ModelRecord } from "../../src/providers/types.js";
import type { RoutingClassification } from "../../src/routing/classifier.js";
import { filterRoutingPolicyModels, selectRoutingModel } from "../../src/routing/selector.js";

function model(overrides: Partial<ModelRecord> & Pick<ModelRecord, "publicModelId">): ModelRecord {
  return {
    id: `id-${overrides.publicModelId}`,
    providerId: "provider",
    providerName: "venice",
    providerStatus: "active",
    providerPrivacyClass: "private",
    externalModelId: overrides.publicModelId,
    displayName: overrides.publicModelId,
    modelType: "text",
    unitPriceUsd: null,
    contextWindow: 65_536,
    maxOutputTokens: 8_192,
    inputPricePerMillion: 0.2,
    outputPricePerMillion: 0.5,
    privacyClass: "private",
    supportsStreaming: true,
    supportsTools: false,
    routingEnabled: true,
    qualityTier: 3,
    routingTasks: ["general"],
    supportsWeb: false,
    expectedLatencyMs: 100,
    reasoningCapabilities: {
      supported: false,
      effortConfigurable: false,
      supportedEfforts: [],
      canDisable: false,
      defaultEffort: null,
      alwaysOn: false
    },
    ...overrides
  };
}

const classification: RoutingClassification = {
  task: "general",
  effectiveTask: "general",
  complexity: "low",
  needsWeb: false,
  maybeSensitive: false,
  taskConfidence: 0.9,
  taskMargin: 0.8,
  complexityConfidence: 0.9,
  nearestSimilarity: 0.8,
  abstained: false,
  classifierVersion: 1,
  latencyMs: 10
};

function body(overrides: Partial<ChatCompletionRequestBody> = {}): ChatCompletionRequestBody {
  return { model: "auto", messages: [{ role: "user", content: "hello" }], stream: false, ...overrides };
}

describe("opt-in and anonymous exclusion from automatic routing", () => {
  const veniceModel = model({ publicModelId: "venice-uncensored", providerName: "venice" });
  // Any model kept routing_enabled=false is opt-in only and must never be picked
  // by /auto, even at the highest quality tier.
  const optInModel = model({
    publicModelId: "venice-optin-large",
    providerName: "venice",
    qualityTier: 5,
    routingEnabled: false
  });
  const anonymousModel = model({
    publicModelId: "anon-fast",
    providerName: "venice",
    privacyClass: "anonymous",
    providerPrivacyClass: "anonymous"
  });

  it("excludes routing-disabled (opt-in) models even at the highest quality tier", () => {
    const pool = filterRoutingPolicyModels([veniceModel, optInModel], body());
    expect(pool.map((m) => m.publicModelId)).not.toContain("venice-optin-large");
    const decision = selectRoutingModel({
      models: [veniceModel, optInModel],
      body: body({ routing: { strategy: "quality" } }),
      classification,
      inputTokens: 100,
      requestedMaxOutputTokens: 100
    });
    expect(decision.model.publicModelId).toBe("venice-uncensored");
  });

  it("excludes anonymous-tier models by default (no silent downgrade)", () => {
    const pool = filterRoutingPolicyModels([veniceModel, anonymousModel], body());
    expect(pool.map((m) => m.publicModelId)).not.toContain("anon-fast");
  });

  it("includes anonymous models only when explicitly opted in", () => {
    const pool = filterRoutingPolicyModels([anonymousModel], body({ routing: { privacy_classes: ["anonymous"] } }));
    expect(pool.map((m) => m.publicModelId)).toContain("anon-fast");
  });
});
