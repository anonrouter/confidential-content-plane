import type { NormalizedModel, NormalizedReasoningCapabilities, RoutingProfile } from "./normalized.js";

export interface RawBedrockMantleModel {
  id?: unknown;
  model_id?: unknown;
  name?: unknown;
  status?: unknown;
  allowed_modes?: unknown;
  data_retention?: { mode?: unknown; allowed_modes?: unknown } | unknown;
}

interface ApprovedBedrockRoute {
  displayName: string;
  canonicalId: string;
  context: number;
  maxOutput: number;
  input: number;
  output: number;
  modalities: ("text" | "image")[];
  qualityTier: number;
  tasks: string[];
  expectedLatencyMs: number;
}

export const APPROVED_BEDROCK_ROUTES: Readonly<Record<string, ApprovedBedrockRoute>> = {
  "openai.gpt-oss-20b": {
    displayName: "OpenAI GPT OSS 20B", canonicalId: "openai/gpt-oss-20b",
    context: 128_000, maxOutput: 16_000, input: 0.07, output: 0.3,
    modalities: ["text"], qualityTier: 3, tasks: ["general", "writing", "coding", "analysis"], expectedLatencyMs: 700
  },
  "openai.gpt-oss-120b": {
    displayName: "OpenAI GPT OSS 120B", canonicalId: "openai/openai-gpt-oss-120b",
    context: 128_000, maxOutput: 16_000, input: 0.15, output: 0.6,
    modalities: ["text"], qualityTier: 4, tasks: ["general", "writing", "coding", "analysis"], expectedLatencyMs: 1_000
  },
  "qwen.qwen3-coder-next": {
    displayName: "Qwen3 Coder Next", canonicalId: "qwen/qwen3-coder-next",
    context: 256_000, maxOutput: 16_000, input: 0.5, output: 1.2,
    modalities: ["text"], qualityTier: 4, tasks: ["coding", "analysis"], expectedLatencyMs: 1_000
  },
  "deepseek.v3.2": {
    displayName: "DeepSeek V3.2", canonicalId: "deepseek/deepseek-v3.2",
    context: 164_000, maxOutput: 8_000, input: 0.62, output: 1.85,
    modalities: ["text"], qualityTier: 4, tasks: ["general", "writing", "math", "coding", "analysis"], expectedLatencyMs: 1_000
  },
  "mistral.mistral-large-3-675b-instruct": {
    displayName: "Mistral Large 3 675B Instruct", canonicalId: "mistralai/mistral-large-3-675b-instruct",
    context: 256_000, maxOutput: 32_000, input: 0.5, output: 1.5,
    modalities: ["text", "image"], qualityTier: 4, tasks: ["general", "writing", "coding", "analysis", "vision"], expectedLatencyMs: 1_200
  },
  "google.gemma-3-4b-it": {
    displayName: "Gemma 3 4B IT", canonicalId: "google/gemma-3-4b-it",
    context: 128_000, maxOutput: 8_000, input: 0.04, output: 0.08,
    modalities: ["text", "image"], qualityTier: 2, tasks: ["general", "writing", "vision"], expectedLatencyMs: 500
  },
  "qwen.qwen3-vl-235b-a22b-instruct": {
    displayName: "Qwen3 VL 235B A22B Instruct", canonicalId: "qwen/qwen3-vl-235b",
    context: 256_000, maxOutput: 8_000, input: 0.53, output: 2.66,
    modalities: ["text", "image"], qualityTier: 4, tasks: ["general", "analysis", "vision"], expectedLatencyMs: 1_300
  },
  "xai.grok-4.3": {
    displayName: "Grok 4.3", canonicalId: "x-ai/grok-4.3",
    context: 1_000_000, maxOutput: 32_768, input: 1.25, output: 2.5,
    modalities: ["text", "image"], qualityTier: 5, tasks: ["general", "writing", "coding", "analysis", "vision"], expectedLatencyMs: 1_500
  }
};

const NO_REASONING: NormalizedReasoningCapabilities = {
  supported: false, effortConfigurable: false, supportedEfforts: [], canDisable: false,
  defaultEffort: null, alwaysOn: false
};
const SOURCES = [
  { label: "Amazon Bedrock Mantle models", url: "https://docs.aws.amazon.com/bedrock/latest/userguide/bedrock-mantle.html" },
  { label: "Amazon Bedrock data protection", url: "https://docs.aws.amazon.com/bedrock/latest/userguide/data-protection.html" }
];

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function routeId(raw: RawBedrockMantleModel): string | null {
  return text(raw.id) ?? text(raw.model_id) ?? text(raw.name);
}

function isEffectiveNone(raw: RawBedrockMantleModel): boolean {
  const retentionObject = raw.data_retention && typeof raw.data_retention === "object"
    ? raw.data_retention as { mode?: unknown; allowed_modes?: unknown }
    : undefined;
  const allowed = Array.isArray(retentionObject?.allowed_modes)
    ? retentionObject.allowed_modes
    : Array.isArray(raw.allowed_modes) ? raw.allowed_modes : [];
  const retention = retentionObject?.mode;
  return raw.status === "available" && allowed.includes("none") && retention === "none";
}

/** Only reviewed routes that the live account attests as effective `none`. */
export function normalizeBedrockCatalog(raw: RawBedrockMantleModel[]): NormalizedModel[] {
  const result: NormalizedModel[] = [];
  for (const candidate of raw) {
    const providerModelId = routeId(candidate);
    if (!providerModelId) continue;
    const approved = APPROVED_BEDROCK_ROUTES[providerModelId];
    if (!approved || !isEffectiveNone(candidate)) continue;
    const supportsVision = approved.modalities.includes("image");
    // `publicSlug` is a provider-scoped database route key retained for the
    // legacy storage column's global uniqueness. It is not the model's public
    // API slug: `publicMetadata.id` below is always creator/model-name, while
    // the AWS-native id stays route metadata.
    const publicSlug = `aws-bedrock/${providerModelId}`;
    const routing: RoutingProfile = {
      qualityTier: approved.qualityTier,
      tasks: approved.tasks,
      supportsWeb: false,
      expectedLatencyMs: approved.expectedLatencyMs
    };
    const privacyNotes = [
      "This route is listed only when Bedrock Mantle reports account retention mode none and the model allows none.",
      "AWS Bedrock is an upstream processor; this route does not provide TEE or end-to-end encryption.",
      "AnonRouter removes prompt-cache controls and does not persist prompts or responses."
    ];
    result.push({
      providerModelId,
      publicSlug,
      displayName: approved.displayName,
      description: `${approved.displayName} served through Amazon Bedrock Mantle.`,
      providerType: "text",
      primaryModality: "text",
      modalities: approved.modalities,
      contextTokens: approved.context,
      maxOutputTokens: approved.maxOutput,
      pricing: {
        priceModel: "per_token",
        inputPerMillionUsd: approved.input,
        outputPerMillionUsd: approved.output,
        cacheReadPerMillionUsd: null,
        cacheWritePerMillionUsd: null,
        unitUsd: null, unit: null, inputLabel: null, outputLabel: null,
        note: "Bedrock Mantle pricing in USD per 1M tokens."
      },
      online: true,
      privacyClass: "private",
      supportsE2ee: false,
      supportsTee: false,
      capabilities: {
        functionCalling: false, responseSchema: false, reasoning: false, webSearch: false,
        vision: supportsVision, optimizedForCode: providerModelId.includes("coder"), promptCaching: false
      },
      reasoningCapabilities: { ...NO_REASONING, supportedEfforts: [] },
      beta: false, deprecation: null, regionRestrictions: ["us-east-1"],
      traits: ["bedrock-mantle", "zero-data-retention"], moderation: "unknown",
      voices: null, releasedAt: null, supportsStreaming: true, supportsTools: false,
      supportsVision, maxImages: supportsVision ? 1 : 0, routing,
      publicMetadata: {
        id: approved.canonicalId,
        displayName: approved.displayName,
        provider: "aws-bedrock",
        providerName: "AWS Bedrock",
        providerRouteId: providerModelId,
        routeId: providerModelId,
        shortDescription: `${approved.displayName} through Amazon Bedrock Mantle with zero retention.`,
        primaryModality: "text", modalities: approved.modalities,
        contextTokens: approved.context, maxOutputTokens: approved.maxOutput,
        inputPriceUsdPerMillion: approved.input, outputPriceUsdPerMillion: approved.output,
        cacheReadPriceUsdPerMillion: null, cacheWritePriceUsdPerMillion: null,
        pricingNote: "Bedrock Mantle pricing in USD per 1M tokens.",
        privacyLevel: "private", privacySummary: "Bedrock Mantle zero-retention route",
        privacyNotes, moderation: "unknown",
        features: ["streaming", ...(supportsVision ? ["vision"] : []), ...(providerModelId.includes("coder") ? ["code-optimized"] : [])],
        routingModes: ["anonrouter-hosted", "provider-direct"],
        regionRoutingNote: "Currently verified in AWS us-east-1.",
        availability: "available", sourceReferences: SOURCES
      }
    });
  }
  return result.sort((a, b) => a.providerModelId.localeCompare(b.providerModelId));
}
