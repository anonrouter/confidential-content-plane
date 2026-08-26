import type {
  NormalizedModel,
  NormalizedReasoningCapabilities,
  RoutingProfile
} from "./normalized.js";

const PRIVACY_SOURCE = {
  label: "Tinfoil attestation architecture",
  url: "https://docs.tinfoil.sh/verification/attestation-architecture"
};
const MODEL_SOURCE = {
  label: "Tinfoil models",
  url: "https://inference.tinfoil.sh/v1/models"
};

// Tinfoil caps generation length per enclave; keep a conservative product
// ceiling since the OpenAI-style model list omits a generation cap.
const MAX_OUTPUT_CEILING = 32_768;

const PRIVACY_SUMMARY = "Tinfoil verified enclave (AMD SEV-SNP + NVIDIA CC)";
const PRIVACY_NOTES = [
  "Tinfoil runs this model inside an attested confidential enclave (AMD SEV-SNP measured boot, NVIDIA Hopper/Blackwell confidential compute, Sigstore-logged code measurement, and model-weight fingerprint binding); AnonRouter's worker verifies the attestation before routing.",
  "AnonRouter uses the TLS (certificate-pinned) transport, so the verified enclave sees plaintext prompts and generations: this is a TEE guarantee, not end-to-end encryption.",
  "Tinfoil also offers an HPKE (EHBP) body-encryption transport, but its model selector is inside the ciphertext and the documented outer metadata cannot bind it to an AnonRouter ticket and reservation; AnonRouter therefore fails closed and exposes only the standard TEE route."
];

export interface RawTinfoilModel {
  id?: unknown;
  object?: unknown;
  created?: unknown;
  owned_by?: unknown;
  /** Tinfoil's /v1/models publishes real per-1M-token prices here. */
  pricing?: {
    inputTokenPricePer1M?: unknown;
    outputTokenPricePer1M?: unknown;
    cachedInputTokenPricePer1M?: unknown;
  } | unknown;
}

interface ApprovedTinfoilRoute {
  /** Provider-qualified, globally-unique public slug suffix (tinfoil/<slug>). */
  slug: string;
  /** Stable canonical creator/model id (dedup identity). */
  canonicalId: string;
  displayName: string;
  modality: "text" | "embeddings";
  context: number;
  supportsTools: boolean;
  supportsVision: boolean;
  reasoning: boolean;
  canDisableReasoning: boolean;
  codeOptimized?: boolean;
  /** Optional reviewed USD / 1M-token fallback. Live catalog pricing wins;
   *  without either source the route stays non-enable-able. */
  input?: number;
  output?: number;
  qualityTier: number;
  expectedLatencyMs: number;
}

/**
 * Explicit launch allowlist. Every approved Tinfoil route runs server-side in a
 * verified confidential enclave, so all classify as `tee` (AnonRouter sees
 * plaintext inside the attested boundary). Missing live and fallback prices emit
 * null pricing and keep the route disabled.
 */
export const APPROVED_TINFOIL_ROUTES: Readonly<Record<string, ApprovedTinfoilRoute>> = {
  "deepseek-v4-flash": {
    slug: "deepseek-v4-flash", canonicalId: "deepseek/deepseek-v4-flash", displayName: "DeepSeek V4 Flash",
    modality: "text", context: 1_048_576, supportsTools: true, supportsVision: false,
    reasoning: true, canDisableReasoning: true, qualityTier: 4, expectedLatencyMs: 900
  },
  "deepseek-v4-pro": {
    slug: "deepseek-v4-pro", canonicalId: "deepseek/deepseek-v4-pro", displayName: "DeepSeek V4 Pro",
    modality: "text", context: 163_840, supportsTools: true, supportsVision: false,
    reasoning: true, canDisableReasoning: true, input: 1.5, output: 5.25, qualityTier: 5, expectedLatencyMs: 2_000
  },
  "glm-5-2": {
    slug: "glm-5.2", canonicalId: "z-ai/glm-5.2", displayName: "GLM 5.2",
    modality: "text", context: 393_216, supportsTools: true, supportsVision: false,
    reasoning: true, canDisableReasoning: true, qualityTier: 5, expectedLatencyMs: 1_500
  },
  "kimi-k3": {
    slug: "kimi-k3", canonicalId: "moonshotai/kimi-k3", displayName: "Kimi K3",
    modality: "text", context: 262_144, supportsTools: true, supportsVision: true,
    reasoning: true, canDisableReasoning: true, qualityTier: 5, expectedLatencyMs: 2_000
  },
  "gemma4-31b": {
    slug: "gemma-4-31b", canonicalId: "google/gemma-4-31b-instruct", displayName: "Gemma 4 31B",
    modality: "text", context: 262_144, supportsTools: true, supportsVision: true,
    reasoning: false, canDisableReasoning: false, qualityTier: 4, expectedLatencyMs: 800
  },
  "gpt-oss-120b": {
    slug: "gpt-oss-120b", canonicalId: "openai/gpt-oss-120b", displayName: "OpenAI GPT OSS 120B",
    modality: "text", context: 131_072, supportsTools: true, supportsVision: false,
    reasoning: true, canDisableReasoning: false, qualityTier: 4, expectedLatencyMs: 800
  },
  "llama3-3-70b": {
    slug: "llama-3.3-70b", canonicalId: "meta-llama/llama-3.3-70b", displayName: "Llama 3.3 70B",
    modality: "text", context: 131_072, supportsTools: true, supportsVision: false,
    reasoning: false, canDisableReasoning: false, qualityTier: 4, expectedLatencyMs: 900
  },
  "qwen3-vl-30b": {
    slug: "qwen3-vl-30b", canonicalId: "qwen/qwen3-vl-30b", displayName: "Qwen3 VL 30B",
    modality: "text", context: 262_144, supportsTools: true, supportsVision: true,
    reasoning: true, canDisableReasoning: false, qualityTier: 4, expectedLatencyMs: 1_000
  },
  "nomic-embed-text": {
    slug: "nomic-embed-text", canonicalId: "nomic-ai/nomic-embed-text", displayName: "Nomic Embed Text",
    modality: "embeddings", context: 8_192, supportsTools: false, supportsVision: false,
    reasoning: false, canDisableReasoning: false, qualityTier: 3, expectedLatencyMs: 300
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

// Missing prices become null (never 0) so an unpriced route stays
// non-enable-able. Reviewed values are USD / 1M tokens.
function price(value: number | undefined): number | null {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;
}

/** Tinfoil /v1/models -> the reviewed confidential-enclave chat + embedding routes. */
export function normalizeTinfoilCatalog(raw: RawTinfoilModel[]): NormalizedModel[] {
  const normalized: NormalizedModel[] = [];
  for (const candidate of raw) {
    const providerModelId = string(candidate.id);
    if (!providerModelId) continue;
    const approved = APPROVED_TINFOIL_ROUTES[providerModelId];
    if (!approved) continue;

    const isEmbedding = approved.modality === "embeddings";
    const contextTokens = approved.context;
    const maxOutputTokens = isEmbedding ? null : Math.min(contextTokens, MAX_OUTPUT_CEILING);
    const reasoningCapabilities = reasoningCaps(approved.reasoning, approved.canDisableReasoning);
    // Prefer Tinfoil's live per-1M-token prices from /v1/models; fall back to the
    // reviewed allowlist value only when the live entry omits a usable price.
    const livePricing = candidate.pricing && typeof candidate.pricing === "object"
      ? (candidate.pricing as { inputTokenPricePer1M?: unknown; outputTokenPricePer1M?: unknown; cachedInputTokenPricePer1M?: unknown })
      : undefined;
    const livePrice = (value: unknown): number | null =>
      typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;
    const inputPerMillionUsd = livePrice(livePricing?.inputTokenPricePer1M) ?? price(approved.input);
    const outputPerMillionUsd = isEmbedding ? null : (livePrice(livePricing?.outputTokenPricePer1M) ?? price(approved.output));
    const cacheReadPerMillionUsd = livePrice(livePricing?.cachedInputTokenPricePer1M);

    // A route surfaced by the live /v1/models list is online.
    const online = true;
    const publicSlug = `tinfoil/${approved.slug}`;
    const modalities = isEmbedding
      ? (["embeddings"] as const)
      : approved.supportsVision
        ? (["text", "image"] as const)
        : (["text"] as const);
    const routing: RoutingProfile | null = isEmbedding
      ? null
      : { qualityTier: approved.qualityTier, tasks: [], supportsWeb: false, expectedLatencyMs: null };
    const featureList = isEmbedding
      ? ["embeddings", "confidential-compute"]
      : [
          "streaming",
          ...(approved.supportsTools ? ["tool-calling"] : []),
          ...(approved.supportsVision ? ["vision"] : []),
          ...(approved.reasoning ? ["reasoning"] : []),
          ...(approved.codeOptimized ? ["code-optimized"] : []),
          "confidential-compute"
        ];
    const shortDescription = `${approved.displayName} served in a Tinfoil verified confidential enclave.`;

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
        cacheReadPerMillionUsd: isEmbedding ? null : cacheReadPerMillionUsd,
        cacheWritePerMillionUsd: null,
        unitUsd: null,
        unit: null,
        inputLabel: null,
        outputLabel: null,
        note: "Tinfoil pricing in USD per 1M tokens."
      },
      online,
      privacyClass: "tee",
      // Tinfoil supports EHBP upstream, but the route/model selector remains
      // inside the ciphertext and cannot be bound to the outer AnonRouter
      // ticket/reservation. Do not expose an unbound ciphertext proxy.
      supportsE2ee: false,
      supportsTee: true,
      capabilities: {
        functionCalling: approved.supportsTools,
        responseSchema: false,
        reasoning: approved.reasoning,
        webSearch: false,
        vision: approved.supportsVision,
        optimizedForCode: approved.codeOptimized === true,
        promptCaching: false
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
      supportsTools: approved.supportsTools,
      supportsVision: approved.supportsVision,
      maxImages: approved.supportsVision ? 1 : 0,
      routing,
      publicMetadata: {
        id: approved.canonicalId,
        displayName: approved.displayName,
        provider: "tinfoil",
        providerName: "Tinfoil",
        providerRouteId: publicSlug,
        routeId: providerModelId,
        shortDescription,
        primaryModality: isEmbedding ? "embeddings" : "text",
        modalities: [...modalities],
        contextTokens,
        maxOutputTokens,
        inputPriceUsdPerMillion: inputPerMillionUsd,
        outputPriceUsdPerMillion: outputPerMillionUsd,
        cacheReadPriceUsdPerMillion: null,
        cacheWritePriceUsdPerMillion: null,
        pricingNote: "Tinfoil pricing in USD per 1M tokens.",
        privacyLevel: "tee",
        privacySummary: PRIVACY_SUMMARY,
        privacyNotes: [...PRIVACY_NOTES],
        moderation: "unknown",
        ...(approved.reasoning ? { reasoning: reasoningCapabilities } : {}),
        features: featureList,
        routingModes: ["anonrouter-hosted", "provider-direct"],
        availability: online ? "available" : "needs-verification",
        sourceReferences: [PRIVACY_SOURCE, MODEL_SOURCE]
      }
    });
  }
  return normalized.sort((a, b) => a.providerModelId.localeCompare(b.providerModelId));
}
