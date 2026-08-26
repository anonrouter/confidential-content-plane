import type {
  NormalizedModel,
  NormalizedReasoningCapabilities,
  PrivacyClass,
  RoutingProfile
} from "./normalized.js";

const PRIVACY_SOURCE = {
  label: "Chutes security architecture",
  url: "https://chutes.ai/docs/core-concepts/security-architecture"
};
const MODEL_SOURCE = {
  label: "Chutes models",
  url: "https://llm.chutes.ai/v1/models"
};

// Chutes caps generation length per chute; keep a conservative product ceiling
// when the live entry publishes no explicit max output length.
const MAX_OUTPUT_CEILING = 32_768;

const TEE_PRIVACY_SUMMARY = "Chutes confidential compute (Intel TDX + NVIDIA CC) enclave";
const PRIVATE_PRIVACY_SUMMARY = "Chutes decentralized serverless inference";
const TEE_PRIVACY_NOTES = [
  "This route reports confidential_compute=true: Chutes runs it inside an Intel TDX CPU enclave with NVIDIA confidential-compute GPUs, and AnonRouter can pull a fresh-nonce TDX + NVIDIA attestation quote and diff its measurements against the published golden measurement allowlist.",
  "For confidential text routes, AnonRouter exposes Chutes' ML-KEM whole-body transport: ciphertext is relayed unchanged and only the attested serving instance can decrypt it.",
  "AnonRouter treats the -TEE id suffix and confidential_compute flag as routing hints; E2EE is advertised only when live confidential_compute metadata, attested key binding, and the opaque relay are all present."
];
const PRIVATE_PRIVACY_NOTES = [
  "This route does not report confidential_compute=true, so AnonRouter classifies it as a standard private serverless route rather than a verified TEE.",
  "Chutes is a decentralized inference network; AnonRouter uses only the OpenAI-compatible Chat Completions and Embeddings paths and does not persist prompts or generations.",
  "AnonRouter never derives a TEE tier from the -TEE id suffix alone; the confidential-compute tier requires the machine-readable confidential_compute flag plus verified attestation evidence."
];

export interface RawChutesModel {
  id?: unknown;
  root?: unknown;
  chute_id?: unknown;
  owned_by?: unknown;
  quantization?: unknown;
  context_length?: unknown;
  max_model_len?: unknown;
  max_output_length?: unknown;
  input_modalities?: unknown;
  output_modalities?: unknown;
  supported_features?: unknown;
  confidential_compute?: unknown;
  pricing?: { prompt?: unknown; completion?: unknown; input_cache_read?: unknown } | unknown;
}

interface ApprovedChutesRoute {
  /** Provider-qualified, globally-unique public slug suffix (chutes/<slug>). */
  slug: string;
  /** Stable canonical creator/model id (dedup identity), derived from `root`. */
  canonicalId: string;
  displayName: string;
  modality: "text" | "embeddings";
  canDisableReasoning: boolean;
  codeOptimized?: boolean;
  /** Conservative default context when the live entry omits context_length. */
  context: number;
  qualityTier: number;
  expectedLatencyMs: number;
}

/**
 * Explicit launch allowlist. Chutes exposes a large decentralized model set;
 * only these reviewed Chat Completions / Embeddings routes may ever become
 * public routes through discovery. Pricing, context, capabilities, and the
 * confidential-compute (TEE) classification are all read from the LIVE raw
 * entry; this table only carries curated identity and routing hints.
 */
export const APPROVED_CHUTES_ROUTES: Readonly<Record<string, ApprovedChutesRoute>> = {
  "deepseek-ai/DeepSeek-V3.2-TEE": {
    slug: "deepseek-v3.2", canonicalId: "deepseek/deepseek-v3.2", displayName: "DeepSeek V3.2",
    modality: "text", canDisableReasoning: true, context: 163_840, qualityTier: 5, expectedLatencyMs: 1_500
  },
  "moonshotai/Kimi-K2.6-TEE": {
    slug: "kimi-k2.6", canonicalId: "moonshotai/kimi-k2.6", displayName: "Kimi K2.6",
    modality: "text", canDisableReasoning: true, context: 262_144, qualityTier: 5, expectedLatencyMs: 1_500
  },
  "zai-org/GLM-5.2-TEE": {
    slug: "glm-5.2", canonicalId: "z-ai/glm-5.2", displayName: "GLM 5.2",
    modality: "text", canDisableReasoning: true, context: 1_048_576, qualityTier: 5, expectedLatencyMs: 1_500
  },
  "Qwen/Qwen3-32B-TEE": {
    slug: "qwen3-32b", canonicalId: "qwen/qwen3-32b", displayName: "Qwen3 32B",
    modality: "text", canDisableReasoning: true, context: 40_960, qualityTier: 4, expectedLatencyMs: 900
  },
  "openai/gpt-oss-120b": {
    slug: "gpt-oss-120b", canonicalId: "openai/gpt-oss-120b", displayName: "OpenAI GPT OSS 120B",
    modality: "text", canDisableReasoning: false, context: 131_072, qualityTier: 4, expectedLatencyMs: 800
  },
  "Qwen/Qwen3-Embedding-8B": {
    slug: "qwen3-embedding-8b", canonicalId: "qwen/qwen3-embedding-8b", displayName: "Qwen3 Embedding 8B",
    modality: "embeddings", canDisableReasoning: false, context: 32_768, qualityTier: 3, expectedLatencyMs: 300
  }
};

const NO_REASONING: NormalizedReasoningCapabilities = {
  supported: false,
  effortConfigurable: false,
  supportedEfforts: [],
  canDisable: false,
  defaultEffort: null,
  alwaysOn: false
};

// Chutes exposes a `reasoning_effort` control for reasoning-capable chutes; we
// attest low/medium/high and fold "none" into canDisable. Reasoning support is
// read from the live entry's supported_features, never assumed.
function reasoningCaps(reasoning: boolean, canDisable: boolean): NormalizedReasoningCapabilities {
  if (!reasoning) return { ...NO_REASONING };
  return {
    supported: true,
    effortConfigurable: true,
    supportedEfforts: ["low", "medium", "high"],
    canDisable,
    defaultEffort: null,
    alwaysOn: !canDisable
  };
}

function string(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function integer(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

// Missing or malformed prices become null (never 0) so an unpriced route stays
// non-enable-able. Chutes publishes pricing.{prompt,completion,input_cache_read}
// in USD per 1,000,000 tokens.
function price(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

/** Chutes /v1/models -> the reviewed confidential-compute chat + embedding routes. */
export function normalizeChutesCatalog(raw: RawChutesModel[]): NormalizedModel[] {
  const normalized: NormalizedModel[] = [];
  for (const candidate of raw) {
    const providerModelId = string(candidate.id);
    if (!providerModelId) continue;
    const approved = APPROVED_CHUTES_ROUTES[providerModelId];
    if (!approved) continue;

    const isEmbedding = approved.modality === "embeddings";
    const contextTokens = integer(candidate.context_length) ?? approved.context;
    const maxOutputTokens = isEmbedding
      ? null
      : integer(candidate.max_output_length) ?? Math.min(contextTokens, MAX_OUTPUT_CEILING);

    // TEE classification is gated ONLY on the machine-readable confidential_compute
    // flag from the live entry, never on the -TEE id suffix.
    const confidential = candidate.confidential_compute === true;
    const e2ee = confidential && !isEmbedding;
    const privacyClass: PrivacyClass = e2ee ? "e2ee" : confidential ? "tee" : "private";
    const privacyLevel = e2ee ? "e2ee" : confidential ? "tee" : "private";

    const features = stringArray(candidate.supported_features);
    const inputModalities = stringArray(candidate.input_modalities);
    const supportsTools = !isEmbedding && features.includes("tools");
    const supportsVision = !isEmbedding && inputModalities.includes("image");
    const reasoning = !isEmbedding && features.includes("reasoning");
    const responseSchema =
      !isEmbedding && (features.includes("structured_outputs") || features.includes("json_mode"));
    const reasoningCapabilities = reasoningCaps(reasoning, approved.canDisableReasoning);

    const pricingObj =
      candidate.pricing && typeof candidate.pricing === "object"
        ? (candidate.pricing as { prompt?: unknown; completion?: unknown; input_cache_read?: unknown })
        : null;
    const inputPerMillionUsd = pricingObj ? price(pricingObj.prompt) : null;
    const outputPerMillionUsd = isEmbedding ? null : pricingObj ? price(pricingObj.completion) : null;
    const cacheReadPerMillionUsd = pricingObj ? price(pricingObj.input_cache_read) : null;

    // A route surfaced by the live /v1/models list is online.
    const online = true;
    const publicSlug = `chutes/${approved.slug}`;
    const modalities = isEmbedding
      ? (["embeddings"] as const)
      : supportsVision
        ? (["text", "image"] as const)
        : (["text"] as const);
    const routing: RoutingProfile | null = isEmbedding
      ? null
      : { qualityTier: approved.qualityTier, tasks: [], supportsWeb: false, expectedLatencyMs: null };
    const featureList = isEmbedding
      ? ["embeddings"]
      : [
          "streaming",
          ...(supportsTools ? ["tool-calling"] : []),
          ...(supportsVision ? ["vision"] : []),
          ...(reasoning ? ["reasoning"] : []),
          ...(approved.codeOptimized ? ["code-optimized"] : []),
          ...(cacheReadPerMillionUsd != null ? ["prompt-caching"] : []),
          ...(confidential ? ["confidential-compute"] : [])
        ];
    const shortDescription = confidential
      ? `${approved.displayName} served in a Chutes confidential-compute enclave.`
      : `${approved.displayName} served on Chutes decentralized inference.`;
    const privacySummary = confidential ? TEE_PRIVACY_SUMMARY : PRIVATE_PRIVACY_SUMMARY;
    const privacyNotes = confidential ? TEE_PRIVACY_NOTES : PRIVATE_PRIVACY_NOTES;

    normalized.push({
      providerModelId,
      publicSlug,
      displayName: approved.displayName,
      description: null,
      providerType: isEmbedding ? "embedding" : "text",
      primaryModality: isEmbedding ? "embeddings" : "text",
      modalities: [...modalities],
      contextTokens,
      maxOutputTokens,
      pricing: {
        priceModel: "per_token",
        inputPerMillionUsd,
        outputPerMillionUsd,
        cacheReadPerMillionUsd,
        cacheWritePerMillionUsd: null,
        unitUsd: null,
        unit: null,
        inputLabel: null,
        outputLabel: null,
        note: "Chutes pricing in USD per 1M tokens."
      },
      online,
      privacyClass,
      supportsE2ee: e2ee,
      supportsTee: confidential,
      capabilities: {
        functionCalling: supportsTools,
        responseSchema,
        reasoning,
        webSearch: false,
        vision: supportsVision,
        optimizedForCode: approved.codeOptimized === true,
        promptCaching: cacheReadPerMillionUsd != null
      },
      reasoningCapabilities,
      beta: false,
      deprecation: null,
      regionRestrictions: null,
      traits: [],
      moderation: "unknown",
      voices: null,
      releasedAt: null,
      supportsStreaming: !isEmbedding,
      supportsTools,
      supportsVision,
      maxImages: supportsVision ? 1 : 0,
      routing,
      publicMetadata: {
        id: approved.canonicalId,
        displayName: approved.displayName,
        provider: "chutes",
        providerName: "Chutes",
        providerRouteId: publicSlug,
        routeId: providerModelId,
        shortDescription,
        primaryModality: isEmbedding ? "embeddings" : "text",
        modalities: [...modalities],
        contextTokens,
        maxOutputTokens,
        inputPriceUsdPerMillion: inputPerMillionUsd,
        outputPriceUsdPerMillion: outputPerMillionUsd,
        cacheReadPriceUsdPerMillion: cacheReadPerMillionUsd,
        cacheWritePriceUsdPerMillion: null,
        pricingNote: "Chutes pricing in USD per 1M tokens.",
        privacyLevel,
        privacySummary,
        privacyNotes: [...privacyNotes],
        moderation: "unknown",
        ...(reasoning ? { reasoning: reasoningCapabilities } : {}),
        features: featureList,
        routingModes: ["anonrouter-hosted", "provider-direct"],
        availability: online ? "available" : "needs-verification",
        sourceReferences: [PRIVACY_SOURCE, MODEL_SOURCE]
      }
    });
  }
  return normalized.sort((a, b) => a.providerModelId.localeCompare(b.providerModelId));
}
