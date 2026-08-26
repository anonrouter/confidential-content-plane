import type {
  NormalizedModel,
  NormalizedReasoningCapabilities,
  RoutingProfile
} from "./normalized.js";

const PRIVACY_SOURCE = {
  label: "NEAR AI TLS-in-TEE verification",
  url: "https://docs.near.ai/cloud/verification/tls/"
};
const MODEL_SOURCE = {
  label: "NEAR AI models",
  url: "https://cloud-api.near.ai/v1/models"
};

// NEAR caps generation length per model; keep a conservative product ceiling
// when the live entry omits an explicit generation cap.
const MAX_OUTPUT_CEILING = 32_768;

// Upstream-proxy owners: models NEAR merely proxies to a third-party frontier
// API are NOT verifiable and must NEVER be classified TEE. A route whose live
// owned_by matches one of these is excluded even if it appears in the allowlist.
const PROXY_OWNERS: ReadonlySet<string> = new Set(["anthropic", "openai", "google", "qwen"]);

const DIRECT_TEE_NOTES = [
  "This is a NEAR AI direct confidential route: TLS terminates inside the model's own TEE, so AnonRouter attests the enclave (Intel TDX quote + NVIDIA GPU attestation, TLS key bound into the attestation report) before routing.",
  "Direct routes support end-to-end encryption (Curve25519/X25519 + XChaCha20-Poly1305) and per-request model-TEE signatures that AnonRouter can verify by recovering the attested signing address.",
  "AnonRouter gates the confidential tier on membership in NEAR's authoritative /endpoints list, never on owned_by alone; it excludes NEAR's upstream frontier-proxy routes entirely."
];
const ATTESTED_3P_NOTES = [
  "This is a NEAR AI attested third-party route: the model runs in a partner TEE (owned_by \"attested 3p\") behind the NEAR gateway. The current adapter has no direct enclave attestation or compatible per-request signature for this route.",
  "AnonRouter sees plaintext inside the attested boundary; this is a TEE guarantee, not end-to-end encryption of the standard route.",
  "AnonRouter gates this tier on the curated allowlist and excludes NEAR's upstream frontier-proxy routes, which are not verifiable."
];

export interface RawNearModel {
  id?: unknown;
  owned_by?: unknown;
  name?: unknown;
  pricing?:
    | { input?: unknown; output?: unknown; input_cache_read?: unknown }
    | unknown;
  context_length?: unknown;
  max_output_length?: unknown;
  input_modalities?: unknown;
  output_modalities?: unknown;
  supported_features?: unknown;
  is_ready?: unknown;
}

type NearRouteClass = "direct-tee" | "attested-3p";

interface ApprovedNearRoute {
  /** Provider-qualified, globally-unique public slug suffix (near-ai/<slug>). */
  slug: string;
  /** Stable canonical creator/model id (dedup identity). */
  canonicalId: string;
  displayName: string;
  routeClass: NearRouteClass;
  /** Direct-TEE endpoint host (TLS terminates in the model enclave). */
  endpointDomain?: string;
  canDisableReasoning: boolean;
  codeOptimized?: boolean;
  qualityTier: number;
}

/**
 * Explicit launch allowlist. NEAR's unified /v1/models mixes three route
 * classes: direct-TEE (in NEAR's authoritative /endpoints list), attested
 * third-party (owned_by "attested 3p"), and non-verifiable upstream proxies
 * (owned_by anthropic/openai/google/qwen). Only the curated verifiable routes
 * below are ever emitted; upstream proxies are excluded entirely, and any live
 * entry whose owned_by matches a proxy vendor is dropped even if listed here.
 */
export const APPROVED_NEAR_ROUTES: Readonly<Record<string, ApprovedNearRoute>> = {
  "openai/gpt-oss-120b": {
    slug: "gpt-oss-120b", canonicalId: "openai/gpt-oss-120b", displayName: "OpenAI GPT OSS 120B",
    routeClass: "direct-tee", endpointDomain: "gpt-oss-120b.completions.near.ai",
    canDisableReasoning: false, qualityTier: 4
  },
  "z-ai/glm-5.2": {
    slug: "glm-5.2", canonicalId: "z-ai/glm-5.2", displayName: "GLM 5.2",
    routeClass: "direct-tee", endpointDomain: "glm-5-2.completions.near.ai",
    canDisableReasoning: true, qualityTier: 5
  },
  "qwen/qwen3-32b": {
    slug: "qwen3-32b", canonicalId: "qwen/qwen3-32b", displayName: "Qwen3 32B",
    routeClass: "attested-3p", canDisableReasoning: true, qualityTier: 4
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

function integer(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

// Missing or malformed prices become null (never 0) so an unpriced route stays
// non-enable-able. NEAR pricing.input/output are USD per 1M tokens.
function price(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

// NEAR's input_cache_read is a per-token string; scale to USD per 1M tokens.
function perTokenToMillion(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) && number > 0 ? number * 1_000_000 : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

/** NEAR /v1/models -> the reviewed direct-TEE and attested-3p confidential routes. */
export function normalizeNearCatalog(raw: RawNearModel[]): NormalizedModel[] {
  const normalized: NormalizedModel[] = [];
  for (const candidate of raw) {
    const providerModelId = string(candidate.id);
    if (!providerModelId) continue;
    const approved = APPROVED_NEAR_ROUTES[providerModelId];
    if (!approved) continue;

    // Never classify an upstream frontier-proxy route as TEE: if the live entry
    // reports a proxy vendor as owned_by, drop it regardless of the allowlist.
    const owner = string(candidate.owned_by)?.toLowerCase() ?? "";
    if (PROXY_OWNERS.has(owner)) continue;

    const isDirect = approved.routeClass === "direct-tee";
    const contextTokens = integer(candidate.context_length);
    const maxOutputTokens =
      integer(candidate.max_output_length) ??
      (contextTokens === null ? null : Math.min(contextTokens, MAX_OUTPUT_CEILING));

    const features = stringArray(candidate.supported_features);
    const inputModalities = stringArray(candidate.input_modalities);
    const supportsTools = features.includes("tools");
    const supportsVision = inputModalities.includes("image");
    const reasoning = features.includes("reasoning");
    const responseSchema = features.includes("structured_outputs") || features.includes("json_mode");
    const reasoningCapabilities = reasoningCaps(reasoning, approved.canDisableReasoning);

    const pricingObj =
      candidate.pricing && typeof candidate.pricing === "object"
        ? (candidate.pricing as { input?: unknown; output?: unknown; input_cache_read?: unknown })
        : null;
    const inputPerMillionUsd = pricingObj ? price(pricingObj.input) : null;
    const outputPerMillionUsd = pricingObj ? price(pricingObj.output) : null;
    const cacheReadPerMillionUsd = pricingObj ? perTokenToMillion(pricingObj.input_cache_read) : null;

    const online = candidate.is_ready === true;
    const publicSlug = `near-ai/${approved.slug}`;
    const modalities = supportsVision ? (["text", "image"] as const) : (["text"] as const);
    const routing: RoutingProfile = {
      qualityTier: approved.qualityTier,
      tasks: [],
      supportsWeb: false,
      expectedLatencyMs: null
    };
    const featureList = [
      "streaming",
      ...(supportsTools ? ["tool-calling"] : []),
      ...(supportsVision ? ["vision"] : []),
      ...(reasoning ? ["reasoning"] : []),
      ...(approved.codeOptimized ? ["code-optimized"] : []),
      ...(cacheReadPerMillionUsd != null ? ["prompt-caching"] : []),
      "confidential-compute",
      ...(isDirect ? ["end-to-end-encryption", "per-request-signatures"] : [])
    ];
    const shortDescription = isDirect
      ? `${approved.displayName} served in a NEAR AI direct TLS-in-TEE enclave.`
      : `${approved.displayName} served in a NEAR AI attested third-party enclave.`;
    const privacyNotes = isDirect ? DIRECT_TEE_NOTES : ATTESTED_3P_NOTES;
    const privacySummary = isDirect
      ? "NEAR AI direct TLS-in-TEE enclave (Intel TDX + NVIDIA CC)"
      : "NEAR AI attested third-party TEE (no direct signature in this adapter)";
    const endpointReference =
      isDirect && approved.endpointDomain
        ? [{ label: "Direct TEE endpoint", url: `https://${approved.endpointDomain}/v1` }]
        : [];

    normalized.push({
      providerModelId,
      publicSlug,
      displayName: approved.displayName,
      description: null,
      providerType: "text",
      primaryModality: "text",
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
        note: "NEAR AI pricing in USD per 1M tokens."
      },
      online,
      // One DB route cannot represent both plaintext and ciphertext modalities
      // (provider_id/external_model_id is unique). Direct enclave routes are
      // therefore ciphertext-only through AnonRouter; gateway partner routes
      // remain plaintext TEE.
      privacyClass: isDirect ? "e2ee" : "tee",
      supportsE2ee: isDirect,
      supportsTee: true,
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
      supportsStreaming: true,
      supportsTools,
      supportsVision,
      maxImages: supportsVision ? 1 : 0,
      routing,
      publicMetadata: {
        id: approved.canonicalId,
        displayName: approved.displayName,
        provider: "near-ai",
        providerName: "NEAR AI",
        providerRouteId: publicSlug,
        routeId: providerModelId,
        shortDescription,
        primaryModality: "text",
        modalities: [...modalities],
        contextTokens,
        maxOutputTokens,
        inputPriceUsdPerMillion: inputPerMillionUsd,
        outputPriceUsdPerMillion: outputPerMillionUsd,
        cacheReadPriceUsdPerMillion: cacheReadPerMillionUsd,
        cacheWritePriceUsdPerMillion: null,
        pricingNote: "NEAR AI pricing in USD per 1M tokens.",
        privacyLevel: isDirect ? "e2ee" : "tee",
        privacySummary,
        privacyNotes: [...privacyNotes],
        moderation: "unknown",
        ...(reasoning ? { reasoning: reasoningCapabilities } : {}),
        features: featureList,
        routingModes: ["anonrouter-hosted", "provider-direct"],
        availability: online ? "available" : "needs-verification",
        ...(!online ? { statusNote: "NEAR AI does not currently report this route ready." } : {}),
        sourceReferences: [PRIVACY_SOURCE, ...endpointReference, MODEL_SOURCE]
      }
    });
  }
  return normalized.sort((a, b) => a.providerModelId.localeCompare(b.providerModelId));
}
