import { applyCapabilityOverride } from "./capabilityOverrides.js";
import { createHash } from "node:crypto";
import { DEEPINFRA_REVIEWED_ROUTES } from "./deepinfraReviewed.generated.js";
import type {
  NormalizedModel,
  NormalizedReasoningCapabilities,
  RoutingProfile
} from "./normalized.js";

const PRICING_SOURCE = {
  label: "DeepInfra pricing",
  url: "https://deepinfra.com/pricing"
};
const PRIVACY_SOURCE = {
  label: "DeepInfra data privacy",
  url: "https://docs.deepinfra.com/account/data-privacy"
};
const MODEL_SOURCE = {
  label: "DeepInfra models",
  url: "https://deepinfra.com/models"
};

// DeepInfra caps generation length for most open models; keep a conservative
// product ceiling rather than the full context window (docs: max_tokens hard cap
// of 16384 for most models).
const MAX_OUTPUT_CEILING = 16_384;

// DeepInfra's data-privacy page: standard inference inputs/outputs are held only
// in memory and deleted afterward. Partner routes may forward data to another
// model endpoint whose retention policy applies, so they remain visible but are
// classified Anonymous rather than inheriting DeepInfra's Private guarantee.
const PRIVATE_PRIVACY_SUMMARY = "DeepInfra in-memory inference, no post-request retention";
const PRIVATE_PRIVACY_NOTES = [
  "DeepInfra states inference inputs and outputs are held only in memory during the request and deleted afterward; they are not written to disk.",
  "DeepInfra says it generally does not log request content, logging only metadata such as request id, cost, and sampling parameters, and reserves the right to log a small fraction of requests for debugging or security.",
  "This is a DeepInfra-hosted route (is_partner=false), not a partner endpoint that forwards the request to another model provider."
];
const PARTNER_PRIVACY_SUMMARY = "Identity-shielded DeepInfra partner route; zero retention is not guaranteed";
const PARTNER_PRIVACY_NOTES = [
  "AnonRouter does not forward the end user's identity, but DeepInfra marks this as a partner route and the partner inference endpoint can see the prompt and response.",
  "DeepInfra says data for certain models may be shared with the relevant model API endpoint; that endpoint's retention and training policies apply.",
  "DeepInfra specifically discloses retention exceptions for Google and Anthropic models. AnonRouter therefore does not claim zero retention for any DeepInfra partner route."
];

// Metadata review and endpoint reachability are separate gates. These routes
// matched the reviewed identity/capability/pricing manifest but failed repeated
// minimal Chat Completions probes on the review date, so they stay visible and
// fail closed until a successful re-test removes the block.
const DEEPINFRA_ROUTE_BLOCKS: Readonly<Record<string, string>> = {
  "google/gemini-2.5-pro": "DeepInfra's Google bridge rejected repeated Chat Completions probes because it supplied an unsupported zero thinking budget; this route is disabled pending a provider fix.",
  "deepseek-ai/DeepSeek-V3-0324": "DeepInfra returned engine_overloaded for repeated Chat Completions probes; this route is temporarily disabled pending a successful re-test."
};

export interface RawDeepInfraModel {
  model_name?: unknown;
  type?: unknown;
  reported_type?: unknown;
  description?: unknown;
  tags?: unknown;
  max_tokens?: unknown;
  max_output_tokens?: unknown;
  deprecated?: unknown;
  private?: unknown;
  is_partner?: unknown;
  pricing?: {
    type?: unknown;
    cents_per_input_token?: unknown;
    cents_per_output_token?: unknown;
    rate_per_input_token_cached?: unknown;
    rate_per_input_token_cache_write?: unknown;
    rate_per_service_tier_priority?: unknown;
    rate_per_service_tier_flex?: unknown;
    rate_per_explicit_cache_write_token?: unknown;
    explicit_cache_granularity_tokens?: unknown;
    discount?: unknown;
    discount_ends_at?: unknown;
  } | unknown;
}

interface DeepInfraNormalizedRoute {
  /** Provider-qualified, globally-unique public slug suffix (deepinfra/<slug>). */
  slug: string;
  /** Stable canonical creator/model id (dedup identity). Provider-independent. */
  canonicalId: string;
  displayName: string;
  /** Fixed USD / 1M tokens (verified against deepinfra.com/pricing). */
  input: number;
  output: number;
  /** Cached-input read price USD / 1M tokens (DeepInfra bills cached reads at
   *  `rate_per_input_token_cached` x input). Absent when the model publishes no
   *  cache rate. */
  cacheRead?: number;
  context: number;
  supportsTools: boolean;
  supportsVision: boolean;
  reasoning: boolean;
  canDisableReasoning: boolean;
  responseSchema?: boolean;
  codeOptimized?: boolean;
  qualityTier: number;
  expectedLatencyMs: number | null;
}

interface DeepInfraRouteOverride {
  slug: string;
  canonicalId: string;
  displayName: string;
  codeOptimized?: boolean;
  qualityTier: number;
  expectedLatencyMs: number | null;
}

/**
 * Stable identity/routing overrides for routes that predate automatic DeepInfra
 * discovery. Prices, privacy, limits, and capabilities are deliberately NOT
 * trusted from this table: they are derived from the live provider payload and
 * must match the generated review-manifest fingerprint below.
 *
 * `canonicalId` is the stable creator/model slug used for cross-provider dedup:
 * an id byte-identical to an existing Venice/Fireworks/Bedrock model co-lists
 * DeepInfra as an additional provider route rather than a duplicate page.
 */
const DEEPINFRA_ROUTE_OVERRIDES: Readonly<Record<string, DeepInfraRouteOverride>> = {
  "deepseek-ai/DeepSeek-V4-Flash": {
    slug: "deepseek-v4-flash", canonicalId: "deepseek/deepseek-v4-flash", displayName: "DeepSeek V4 Flash",
    qualityTier: 4, expectedLatencyMs: 700
  },
  "deepseek-ai/DeepSeek-V4-Pro": {
    slug: "deepseek-v4-pro", canonicalId: "deepseek/deepseek-v4-pro", displayName: "DeepSeek V4 Pro",
    qualityTier: 5, expectedLatencyMs: 2_000
  },
  "deepseek-ai/DeepSeek-V3.2": {
    slug: "deepseek-v3.2", canonicalId: "deepseek/deepseek-v3.2", displayName: "DeepSeek V3.2",
    qualityTier: 4, expectedLatencyMs: 1_000
  },
  "zai-org/GLM-5.2": {
    slug: "glm-5.2", canonicalId: "z-ai/glm-5.2", displayName: "GLM 5.2",
    qualityTier: 5, expectedLatencyMs: 1_500
  },
  "zai-org/GLM-5.1": {
    slug: "glm-5.1", canonicalId: "z-ai/glm-5.1", displayName: "GLM 5.1",
    qualityTier: 5, expectedLatencyMs: 1_500
  },
  "moonshotai/Kimi-K2.6": {
    slug: "kimi-k2.6", canonicalId: "moonshotai/kimi-k2.6", displayName: "Kimi K2.6",
    qualityTier: 5, expectedLatencyMs: 1_500
  },
  "moonshotai/Kimi-K2.5": {
    slug: "kimi-k2.5", canonicalId: "moonshotai/kimi-k2.5", displayName: "Kimi K2.5",
    qualityTier: 4, expectedLatencyMs: 1_400
  },
  "moonshotai/Kimi-K2.7-Code": {
    slug: "kimi-k2.7-code", canonicalId: "moonshotai/kimi-k2.7-code", displayName: "Kimi K2.7 Code",
    codeOptimized: true, qualityTier: 4, expectedLatencyMs: 1_300
  },
  "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B": {
    slug: "nvidia-nemotron-3-ultra-550b-a55b", canonicalId: "nvidia/nvidia-nemotron-3-ultra",
    displayName: "NVIDIA Nemotron 3 Ultra 550B A55B",
    qualityTier: 5, expectedLatencyMs: 1_800
  },
  "google/gemma-4-31B-it": {
    slug: "gemma-4-31b-it", canonicalId: "google/gemma-4-31b-instruct", displayName: "Gemma 4 31B Instruct",
    qualityTier: 4, expectedLatencyMs: 800
  },
  "openai/gpt-oss-20b": {
    slug: "gpt-oss-20b", canonicalId: "openai/gpt-oss-20b", displayName: "OpenAI GPT OSS 20B",
    qualityTier: 3, expectedLatencyMs: 700
  },
  "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B": {
    slug: "nvidia-nemotron-3-super-120b-a12b", canonicalId: "nvidia/nvidia-nemotron-3-super-120b-a12b",
    displayName: "NVIDIA Nemotron 3 Super 120B A12B",
    qualityTier: 4, expectedLatencyMs: 900
  },
  "Qwen/Qwen3.6-35B-A3B": {
    slug: "qwen3.6-35b-a3b", canonicalId: "qwen/qwen-3.6-35b-a3b", displayName: "Qwen3.6 35B A3B",
    qualityTier: 4, expectedLatencyMs: 900
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

// DeepInfra exposes a unified `reasoning_effort` control ("none"|"low"|"medium"
// |"high") for reasoning models; "none" is the disable form (canDisable). We
// attest low/medium/high and leave the provider default unspecified.
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

function positiveNumber(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string").map((entry) => entry.toLowerCase())
    : [];
}

// DeepInfra publishes token rates in cents per token. Multiplying by 10,000
// converts that value to USD per 1M tokens (1M / 100 cents per dollar).
function centsPerTokenToMillionUsd(value: unknown): number | null {
  const cents = positiveNumber(value);
  return cents === null ? null : Number((cents * 10_000).toFixed(6));
}

function safeDiscoveredId(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._/-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^[-/]+|[-/]+$/g, "");
  return normalized || `model-${createHash("sha256").update(value).digest("hex").slice(0, 12)}`;
}

// DeepInfra's native owner names are not always the public creator slugs used by
// the rest of the catalog. Normalize stable organization aliases here so a new
// DeepInfra route joins an existing model instead of becoming a second card.
const DEEPINFRA_CREATOR_ALIASES: Readonly<Record<string, string>> = {
  "deepseek-ai": "deepseek",
  "minimaxai": "minimax",
  "xiaomimimo": "xiaomi",
  "zai-org": "z-ai"
};

// Explicit equivalences are intentionally narrow. These are the same model
// revisions whose serving providers publish different punctuation or omit
// deployment-only suffixes. Turbo/Ultra/Thinking variants stay distinct.
const DEEPINFRA_CANONICAL_MODEL_IDS: Readonly<Record<string, string>> = {
  "NousResearch/Hermes-3-Llama-3.1-405B": "meta-llama/hermes-3-llama-3.1-405b",
  "Qwen/Qwen2.5-7B-Instruct": "qwen/qwen-2.5-7b",
  "Qwen/Qwen3-235B-A22B-Instruct-2507": "qwen/qwen-3-235b-a22b-instruct-2507",
  "Qwen/Qwen3-235B-A22B-Thinking-2507": "qwen/qwen-3-235b-a22b-thinking-2507",
  "Qwen/Qwen3-Coder-480B-A35B-Instruct-Turbo": "qwen/qwen-3-coder-480b-turbo",
  "Qwen/Qwen3-Next-80B-A3B-Instruct": "qwen/qwen-3-next-80b",
  "Qwen/Qwen3-VL-235B-A22B-Instruct": "qwen/qwen3-vl-235b",
  "Qwen/Qwen3-VL-30B-A3B-Instruct": "qwen/qwen3-vl-30b-a3b",
  "Qwen/Qwen3.5-35B-A3B": "qwen/qwen-3.5-35b-a3b",
  "Qwen/Qwen3.5-397B-A17B": "qwen/qwen-3.5-397b",
  "Qwen/Qwen3.5-9B": "qwen/qwen-3.5-9b",
  "Qwen/Qwen3.6-27B": "qwen/qwen-3.6-27b",
  "Qwen/Qwen3.6-35B-A3B": "qwen/qwen-3.6-35b-a3b",
  "Qwen/Qwen3.7-Max": "qwen/qwen-3.7-max",
  "Qwen/Qwen3.8-2.4T-A95B": "qwen/qwen-3.8-2.4t",
  "Qwen/Qwen3.8-Max": "qwen/qwen-3.8-max",
  "anthropic/claude-opus-4-7": "anthropic/claude-opus-4.7",
  "anthropic/claude-opus-4-8": "anthropic/claude-opus-4.8",
  "anthropic/claude-sonnet-4-6": "anthropic/claude-sonnet-4.6",
  "meta-llama/Llama-3.2-3B-Instruct": "meta-llama/llama-3.2-3b",
  "meta-llama/Llama-3.3-70B-Instruct": "meta-llama/llama-3.3-70b",
  "thinkingmachines/Inkling": "thinking-machines/inkling",
  "thinkingmachines/Inkling-Small": "thinking-machines/inkling-small"
};

function discoveredCanonicalId(providerModelId: string): string {
  const explicit = DEEPINFRA_CANONICAL_MODEL_IDS[providerModelId];
  if (explicit) return explicit;
  const safe = safeDiscoveredId(providerModelId);
  const separator = safe.indexOf("/");
  if (separator < 0) return safe;
  const creator = safe.slice(0, separator);
  const model = safe.slice(separator + 1);
  return `${DEEPINFRA_CREATOR_ALIASES[creator] ?? creator}/${model}`;
}

function discoveredSlug(providerModelId: string): string {
  const normalized = safeDiscoveredId(providerModelId).replace(/[/.]+/g, "-");
  const maxSuffixLength = 256 - "deepinfra/".length;
  if (normalized.length <= maxSuffixLength) return normalized;
  const hash = createHash("sha256").update(providerModelId).digest("hex").slice(0, 12);
  return `${normalized.slice(0, maxSuffixLength - hash.length - 1)}-${hash}`;
}

function discoveredDisplayName(providerModelId: string): string {
  const leaf = providerModelId.split("/").pop() ?? providerModelId;
  return (leaf.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim() || providerModelId).slice(0, 200);
}

function discoveredRoute(candidate: RawDeepInfraModel, providerModelId: string): DeepInfraNormalizedRoute | null {
  const tags = stringArray(candidate.tags);
  const type = string(candidate.reported_type) ?? string(candidate.type);
  // Only routes the DeepInfra adapter can actually call are discoverable. An
  // explicit partner flag is required so a missing/changed privacy field fails
  // closed instead of accidentally assigning a stronger privacy label.
  if (typeof candidate.is_partner !== "boolean" || type !== "text-generation" || !tags.includes("openai")) return null;

  const pricing = candidate.pricing && typeof candidate.pricing === "object"
    ? candidate.pricing as {
        type?: unknown;
        cents_per_input_token?: unknown;
        cents_per_output_token?: unknown;
        rate_per_input_token_cached?: unknown;
      }
    : null;
  if (string(pricing?.type) !== "tokens") return null;
  const input = centsPerTokenToMillionUsd(pricing?.cents_per_input_token);
  const output = centsPerTokenToMillionUsd(pricing?.cents_per_output_token);
  // Keep malformed/unpriced discoveries visible but non-enable-able. The
  // normalized schema represents missing prices as null; the enablement policy
  // will reject them until an operator supplies reviewed pricing.
  const cacheRate = positiveNumber(pricing?.rate_per_input_token_cached);
  const supportsVision = tags.includes("multimodal");
  const reasoning = tags.includes("reasoning") || tags.includes("can-disable-reasoning");
  const identityOverride = DEEPINFRA_ROUTE_OVERRIDES[providerModelId];
  const codeOptimized = identityOverride?.codeOptimized === true || /(?:^|[/_.-])(code|coder)(?:$|[/_.-])/i.test(providerModelId);

  return {
    slug: identityOverride?.slug ?? discoveredSlug(providerModelId),
    canonicalId: identityOverride?.canonicalId ?? discoveredCanonicalId(providerModelId),
    displayName: identityOverride?.displayName ?? discoveredDisplayName(providerModelId),
    input: input ?? 0,
    output: output ?? 0,
    ...(input !== null && cacheRate !== null ? { cacheRead: Number((input * cacheRate).toFixed(6)) } : {}),
    context: integer(candidate.max_tokens) ?? 0,
    // The provider's own tag, then any observed correction. DeepInfra tags
    // mistral-nemo "tools" while its tool calling is intermittent, and an
    // intermittently-structured response is worse for an agent than none.
    supportsTools: applyCapabilityOverride("deepinfra", providerModelId,
      { supportsTools: tags.includes("tools") }).supportsTools,
    supportsVision,
    reasoning,
    canDisableReasoning: tags.includes("can-disable-reasoning"),
    responseSchema: tags.includes("structured-output") || tags.includes("json"),
    codeOptimized,
    qualityTier: identityOverride?.qualityTier ?? 3,
    expectedLatencyMs: identityOverride?.expectedLatencyMs ?? null
  };
}

function stableReviewValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableReviewValue);
  if (!value || typeof value !== "object") return value ?? null;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, stableReviewValue(entry)])
  );
}

/**
 * Fingerprint of every live list field that can change the public identity,
 * privacy label, callable surface, context, or billable price. `featured` is
 * excluded because DeepInfra uses it only as a merchandising flag and omits it
 * from the otherwise-identical detail endpoint.
 */
export function deepInfraReviewFingerprint(candidate: RawDeepInfraModel): string | null {
  const providerModelId = string(candidate.model_name);
  if (!providerModelId) return null;
  const route = discoveredRoute(candidate, providerModelId);
  if (!route || route.input <= 0 || route.output <= 0 || route.context <= 0) return null;
  const pricing = candidate.pricing && typeof candidate.pricing === "object"
    ? candidate.pricing as Record<string, unknown>
    : null;
  if (!pricing) return null;
  const material = {
    version: 1,
    providerModelId,
    providerType: string(candidate.reported_type) ?? string(candidate.type),
    isPartner: candidate.is_partner,
    canonicalId: route.canonicalId,
    publicSlug: `deepinfra/${route.slug}`,
    displayName: route.displayName,
    contextTokens: route.context,
    tags: stringArray(candidate.tags).filter((tag) => tag !== "featured").sort(),
    capabilities: {
      tools: route.supportsTools,
      vision: route.supportsVision,
      reasoning: route.reasoning,
      canDisableReasoning: route.canDisableReasoning,
      responseSchema: route.responseSchema === true,
      codeOptimized: route.codeOptimized === true
    },
    pricing: stableReviewValue({
      type: pricing.type,
      cents_per_input_token: pricing.cents_per_input_token,
      cents_per_output_token: pricing.cents_per_output_token,
      rate_per_input_token_cached: pricing.rate_per_input_token_cached,
      rate_per_input_token_cache_write: pricing.rate_per_input_token_cache_write,
      rate_per_service_tier_priority: pricing.rate_per_service_tier_priority,
      rate_per_service_tier_flex: pricing.rate_per_service_tier_flex,
      rate_per_explicit_cache_write_token: pricing.rate_per_explicit_cache_write_token,
      explicit_cache_granularity_tokens: pricing.explicit_cache_granularity_tokens,
      discount: pricing.discount,
      discount_ends_at: pricing.discount_ends_at
    })
  };
  return createHash("sha256").update(JSON.stringify(material)).digest("hex");
}

function deepInfraPricingNote(candidate: RawDeepInfraModel): string {
  const pricing = candidate.pricing && typeof candidate.pricing === "object"
    ? candidate.pricing as Record<string, unknown>
    : {};
  const notes = ["Standard DeepInfra serverless pricing in USD per 1M tokens."];
  const priority = positiveNumber(pricing.rate_per_service_tier_priority);
  const flex = positiveNumber(pricing.rate_per_service_tier_flex);
  if (priority !== null || flex !== null) {
    const tiers = [
      ...(priority !== null ? [`priority ${priority}x`] : []),
      ...(flex !== null ? [`flex ${flex}x`] : [])
    ].join(", ");
    notes.push(`Published optional service-tier multipliers (${tiers}) are not exposed by AnonRouter.`);
  }
  const explicitWrite = pricing.rate_per_explicit_cache_write_token;
  if (explicitWrite && typeof explicitWrite === "object") {
    const rates = Object.entries(explicitWrite as Record<string, unknown>)
      .flatMap(([duration, rate]) => positiveNumber(rate) === null ? [] : [`${duration} ${positiveNumber(rate)}x`]);
    if (rates.length) notes.push(`Explicit cache-write multipliers (${rates.join(", ")}) are not exposed by AnonRouter.`);
  }
  return notes.join(" ").slice(0, 400);
}

function truncate(value: unknown, max: number): string | null {
  const text = string(value)?.replace(/\s+/g, " ");
  if (!text) return null;
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}

/** DeepInfra `deprecated` is a unix seconds timestamp (or null). */
function deprecation(value: unknown): NormalizedModel["deprecation"] {
  if (!value) return null;
  const seconds = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) return { deprecated: true, sunsetAt: null, replacementModelId: null };
  return { deprecated: true, sunsetAt: new Date(seconds * 1000).toISOString(), replacementModelId: null };
}

/** DeepInfra /models/list -> reviewed routes plus safe pending-review discoveries. */
export function normalizeDeepInfraCatalog(raw: RawDeepInfraModel[]): NormalizedModel[] {
  const normalized: NormalizedModel[] = [];
  for (const candidate of raw) {
    const providerModelId = string(candidate.model_name);
    if (!providerModelId) continue;
    // Privacy is route-specific and the live partner bit is its authoritative
    // classification boundary. Even reviewed routes fail closed if it vanishes.
    if (typeof candidate.is_partner !== "boolean") continue;
    const route = discoveredRoute(candidate, providerModelId);
    if (!route) continue;

    const attestation = DEEPINFRA_REVIEWED_ROUTES[providerModelId];
    const observedMaxOutput = integer(candidate.max_output_tokens);
    const reviewMatches = attestation !== undefined &&
      attestation.catalogFingerprint === deepInfraReviewFingerprint(candidate) &&
      (observedMaxOutput === null || observedMaxOutput === attestation.maxOutputTokens);
    const routeBlock = DEEPINFRA_ROUTE_BLOCKS[providerModelId];
    const reviewed = reviewMatches && routeBlock === undefined;

    const description = truncate(candidate.description, 1_000);
    const contextTokens = integer(candidate.max_tokens) ?? route.context;
    const deprecated = deprecation(candidate.deprecated);
    // A model surfaced by /models/list with no deprecation timestamp is live.
    const online = deprecated === null;
    const maxOutputTokens = reviewed
      ? attestation.maxOutputTokens
      : observedMaxOutput ?? Math.min(contextTokens, MAX_OUTPUT_CEILING);
    const publicSlug = `deepinfra/${route.slug}`;
    const candidateTags = stringArray(candidate.tags);
    const modalities: Array<"text" | "image" | "audio" | "video"> = ["text"];
    if (route.supportsVision) modalities.push("image");
    if (candidateTags.includes("input-audio")) modalities.push("audio");
    if (candidateTags.includes("input-video")) modalities.push("video");
    const reasoningCapabilities = reasoningCaps(route.reasoning, route.canDisableReasoning);
    const routing: RoutingProfile = {
      qualityTier: route.qualityTier,
      tasks: route.supportsVision
        ? ["general", "writing", "math", "coding", "analysis", "vision"]
        : ["general", "writing", "math", "coding", "analysis"],
      supportsWeb: false,
      expectedLatencyMs: route.expectedLatencyMs
    };
    const supportsCaching = route.cacheRead != null;
    const features = [
      "streaming",
      ...(route.supportsTools ? ["tool-calling"] : []),
      ...(route.supportsVision ? ["vision"] : []),
      ...(candidateTags.includes("input-audio") ? ["audio-input"] : []),
      ...(candidateTags.includes("input-video") ? ["video-input"] : []),
      ...(route.reasoning ? ["reasoning"] : []),
      ...(route.codeOptimized ? ["code-optimized"] : []),
      ...(supportsCaching ? ["prompt-caching"] : [])
    ];
    const shortDescription = description ?? `${route.displayName} served on DeepInfra serverless inference.`;
    const partnerRoute = candidate.is_partner;
    const privacyClass = partnerRoute ? "anonymous" : "private";
    const privacySummary = partnerRoute ? PARTNER_PRIVACY_SUMMARY : PRIVATE_PRIVACY_SUMMARY;
    const privacyNotes = partnerRoute ? PARTNER_PRIVACY_NOTES : PRIVATE_PRIVACY_NOTES;
    const inputPerMillionUsd = route.input > 0 ? route.input : null;
    const outputPerMillionUsd = route.output > 0 ? route.output : null;
    const pricingNote = deepInfraPricingNote(candidate);

    normalized.push({
      providerModelId,
      publicSlug,
      displayName: route.displayName,
      description,
      providerType: "text",
      primaryModality: "text",
      modalities: [...modalities],
      contextTokens,
      maxOutputTokens,
      pricing: {
        priceModel: "per_token",
        inputPerMillionUsd,
        outputPerMillionUsd,
        // The standard tier is the only tier accepted by AnonRouter's request
        // contract. Optional priority/flex and explicit-write multipliers remain
        // in the audited fingerprint and are disclosed in the note below.
        cacheReadPerMillionUsd: route.cacheRead ?? null,
        cacheWritePerMillionUsd: null,
        unitUsd: null,
        unit: null,
        inputLabel: null,
        outputLabel: null,
        note: pricingNote
      },
      online,
      privacyClass,
      supportsE2ee: false,
      supportsTee: false,
      capabilities: {
        functionCalling: route.supportsTools,
        responseSchema: route.responseSchema === true,
        reasoning: route.reasoning,
        webSearch: false,
        vision: route.supportsVision,
        optimizedForCode: route.codeOptimized === true,
        promptCaching: supportsCaching
      },
      reasoningCapabilities,
      beta: false,
      deprecation: deprecated,
      regionRestrictions: null,
      traits: ["serverless", reviewed ? "catalog-reviewed" : "provider-discovered"],
      moderation: "unknown",
      voices: null,
      releasedAt: null,
      supportsStreaming: true,
      supportsTools: route.supportsTools,
      supportsVision: route.supportsVision,
      // AnonRouter accepts one image per request until DeepInfra publishes a
      // provider-specific maximum; zero when the model has no image input.
      maxImages: route.supportsVision ? 1 : 0,
      routing,
      publicMetadata: {
        id: route.canonicalId,
        displayName: route.displayName,
        provider: "deepinfra",
        providerName: "DeepInfra",
        providerRouteId: publicSlug,
        routeId: providerModelId,
        shortDescription: truncate(shortDescription, 400) ?? route.displayName,
        ...(description ? { description } : {}),
        primaryModality: "text",
        modalities: [...modalities],
        contextTokens,
        maxOutputTokens,
        inputPriceUsdPerMillion: inputPerMillionUsd,
        outputPriceUsdPerMillion: outputPerMillionUsd,
        cacheReadPriceUsdPerMillion: route.cacheRead ?? null,
        cacheWritePriceUsdPerMillion: null,
        pricingNote,
        privacyLevel: privacyClass,
        privacySummary,
        privacyNotes: [...privacyNotes],
        moderation: "unknown",
        ...(route.reasoning ? { reasoning: reasoningCapabilities } : {}),
        features,
        routingModes: ["anonrouter-hosted", "provider-direct"],
        availability: deprecated ? "deprecated" : reviewed && online ? "available" : "needs-verification",
        ...(!reviewed
          ? { statusNote: routeBlock ?? (attestation
              ? "DeepInfra changed identity, capability, privacy, context, or pricing metadata after this route was reviewed; re-audit is required."
              : "This DeepInfra route is not in the reviewed endpoint manifest and cannot be enabled.") }
          : !online && !deprecated
            ? { statusNote: "DeepInfra does not currently report this route available." }
            : {}),
        sourceReferences: [PRICING_SOURCE, PRIVACY_SOURCE, MODEL_SOURCE]
      }
    });
  }
  return normalized.sort((a, b) => a.providerModelId.localeCompare(b.providerModelId));
}
