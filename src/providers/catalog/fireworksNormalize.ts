import type {
  NormalizedModel,
  NormalizedReasoningCapabilities,
  RoutingProfile
} from "./normalized.js";

const PRICING_SOURCE = {
  label: "Fireworks serverless pricing",
  url: "https://docs.fireworks.ai/serverless/pricing"
};
const PRIVACY_SOURCE = {
  label: "Fireworks zero data retention",
  url: "https://docs.fireworks.ai/guides/security_compliance/data_handling"
};
const MODEL_SOURCE = {
  label: "Fireworks serverless models",
  url: "https://docs.fireworks.ai/serverless/overview"
};

export interface RawFireworksModel {
  name?: unknown;
  displayName?: unknown;
  description?: unknown;
  contextLength?: unknown;
  supportsServerless?: unknown;
  supportsTools?: unknown;
  supportsImageInput?: unknown;
  deprecationDate?: unknown;
  status?: { code?: unknown; message?: unknown } | unknown;
}

interface ApprovedFireworksRoute {
  displayName: string;
  input: number;
  cachedInput: number;
  output: number;
  qualityTier: number;
  tasks: string[];
  expectedLatencyMs: number;
  codeOptimized?: boolean;
}

/**
 * Explicit launch allowlist. The Fireworks registry also contains deployable,
 * non-serverless artifacts; those must never become public routes through
 * discovery alone. Prices are Fireworks Standard serving-path USD / 1M tokens.
 */
export const APPROVED_FIREWORKS_ROUTES: Readonly<Record<string, ApprovedFireworksRoute>> = {
  "deepseek-v4-flash": {
    displayName: "DeepSeek V4 Flash", input: 0.14, cachedInput: 0.028, output: 0.28,
    qualityTier: 4, tasks: ["general", "writing", "math", "coding", "analysis"], expectedLatencyMs: 600
  },
  "deepseek-v4-pro": {
    displayName: "DeepSeek V4 Pro", input: 1.74, cachedInput: 0.145, output: 3.48,
    qualityTier: 5, tasks: ["general", "writing", "math", "coding", "analysis"], expectedLatencyMs: 2_000
  },
  "glm-5p2": {
    displayName: "GLM 5.2", input: 1.4, cachedInput: 0.14, output: 4.4,
    qualityTier: 5, tasks: ["general", "writing", "math", "coding", "analysis"], expectedLatencyMs: 1_500
  },
  "gpt-oss-20b": {
    displayName: "OpenAI GPT OSS 20B", input: 0.07, cachedInput: 0.035, output: 0.3,
    qualityTier: 3, tasks: ["general", "writing", "coding", "analysis"], expectedLatencyMs: 700
  },
  "kimi-k2p6": {
    displayName: "Kimi K2.6", input: 0.95, cachedInput: 0.16, output: 4,
    qualityTier: 5, tasks: ["general", "writing", "math", "coding", "analysis", "vision"], expectedLatencyMs: 1_500
  },
  "kimi-k2p7-code": {
    displayName: "Kimi K2.7 Code", input: 0.95, cachedInput: 0.19, output: 4,
    qualityTier: 4, tasks: ["coding", "analysis", "vision"], expectedLatencyMs: 1_200, codeOptimized: true
  },
  "kimi-k3": {
    displayName: "Kimi K3", input: 3, cachedInput: 0.3, output: 15,
    qualityTier: 5, tasks: ["general", "writing", "math", "coding", "analysis", "vision"], expectedLatencyMs: 2_000
  },
  "minimax-m2p7": {
    displayName: "MiniMax M2.7", input: 0.3, cachedInput: 0.06, output: 1.2,
    qualityTier: 4, tasks: ["general", "writing", "math", "coding", "analysis"], expectedLatencyMs: 1_000
  }
};

// Public catalog identity is the underlying model, not the serving route. The
// database `publicSlug` remains provider-qualified and globally unique for
// runtime resolution; only the sanitized catalog projection is canonicalized.
const FIREWORKS_CANONICAL_MODEL_IDS: Readonly<Record<string, string>> = {
  "deepseek-v4-flash": "deepseek/deepseek-v4-flash",
  "deepseek-v4-pro": "deepseek/deepseek-v4-pro",
  "glm-5p2": "z-ai/glm-5.2",
  "gpt-oss-20b": "openai/gpt-oss-20b",
  "kimi-k2p6": "moonshotai/kimi-k2.6",
  "kimi-k2p7-code": "moonshotai/kimi-k2.7-code",
  "kimi-k3": "moonshotai/kimi-k3",
  "minimax-m2p7": "minimax/minimax-m2.7"
};

const NO_REASONING_CONTROLS: NormalizedReasoningCapabilities = {
  supported: false,
  effortConfigurable: false,
  supportedEfforts: [],
  canDisable: false,
  defaultEffort: null,
  alwaysOn: false
};

function string(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function integer(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

function truncate(value: unknown, max: number): string | null {
  const text = string(value)?.replace(/\s+/g, " ");
  if (!text) return null;
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}

function deprecation(value: unknown): NormalizedModel["deprecation"] {
  const date = string(value);
  if (!date) return null;
  const parsed = new Date(date);
  if (Number.isNaN(parsed.getTime())) return { deprecated: true, sunsetAt: null, replacementModelId: null };
  return { deprecated: true, sunsetAt: parsed.toISOString(), replacementModelId: null };
}

/** Fireworks registry -> the eight reviewed serverless Chat Completions routes. */
export function normalizeFireworksCatalog(raw: RawFireworksModel[]): NormalizedModel[] {
  const normalized: NormalizedModel[] = [];
  for (const candidate of raw) {
    const providerModelId = string(candidate.name);
    const shortId = providerModelId?.split("/").pop() ?? null;
    if (!providerModelId || !shortId) continue;
    const approved = APPROVED_FIREWORKS_ROUTES[shortId];
    if (!approved) continue;

    const displayName = truncate(candidate.displayName, 200) ?? approved.displayName;
    const description = truncate(candidate.description, 1_000);
    const contextTokens = integer(candidate.contextLength);
    const deprecated = deprecation(candidate.deprecationDate);
    const status = candidate.status && typeof candidate.status === "object"
      ? string((candidate.status as { code?: unknown }).code)
      : null;
    const supportsServerless = candidate.supportsServerless === true;
    const online = supportsServerless && status === "OK" && deprecated === null;
    const supportsTools = candidate.supportsTools === true;
    const supportsVision = candidate.supportsImageInput === true;
    const publicSlug = `fireworks/${shortId}`;
    const routing: RoutingProfile = {
      qualityTier: approved.qualityTier,
      tasks: approved.tasks,
      supportsWeb: false,
      expectedLatencyMs: approved.expectedLatencyMs
    };
    const features = [
      "streaming",
      ...(supportsTools ? ["tool-calling"] : []),
      ...(supportsVision ? ["vision"] : []),
      ...(approved.codeOptimized ? ["code-optimized"] : []),
      "prompt-caching"
    ];
    const shortDescription = description ?? `${displayName} served on Fireworks serverless inference.`;

    normalized.push({
      providerModelId,
      publicSlug,
      displayName,
      description,
      providerType: "text",
      primaryModality: "text",
      modalities: supportsVision ? ["text", "image"] : ["text"],
      contextTokens,
      // Fireworks publishes context length but not a separate generation cap in
      // its model registry. Keep a conservative AnonRouter product ceiling.
      maxOutputTokens: contextTokens === null ? null : Math.min(contextTokens, 32_768),
      pricing: {
        priceModel: "per_token",
        inputPerMillionUsd: approved.input,
        outputPerMillionUsd: approved.output,
        cacheReadPerMillionUsd: approved.cachedInput,
        cacheWritePerMillionUsd: null,
        unitUsd: null,
        unit: null,
        inputLabel: null,
        outputLabel: null,
        note: "Fireworks Standard serverless pricing in USD per 1M tokens."
      },
      online,
      privacyClass: "private",
      supportsE2ee: false,
      supportsTee: false,
      capabilities: {
        functionCalling: supportsTools,
        responseSchema: false,
        reasoning: false,
        webSearch: false,
        vision: supportsVision,
        optimizedForCode: approved.codeOptimized === true,
        promptCaching: true
      },
      reasoningCapabilities: { ...NO_REASONING_CONTROLS, supportedEfforts: [] },
      beta: false,
      deprecation: deprecated,
      regionRestrictions: null,
      traits: ["serverless", "zero-data-retention"],
      moderation: "unknown",
      voices: null,
      releasedAt: null,
      supportsStreaming: true,
      supportsTools,
      supportsVision,
      // AnonRouter accepts one image per request until Fireworks publishes a
      // provider-specific maximum; zero when the catalog says no image input.
      maxImages: supportsVision ? 1 : 0,
      routing,
      publicMetadata: {
        // Public identity belongs to the model creator, never the inference
        // host. Fireworks-specific ids remain route metadata below.
        id: FIREWORKS_CANONICAL_MODEL_IDS[shortId],
        displayName,
        provider: "fireworks",
        providerName: "Fireworks AI",
        providerRouteId: publicSlug,
        routeId: providerModelId,
        shortDescription: truncate(shortDescription, 400) ?? approved.displayName,
        ...(description ? { description } : {}),
        primaryModality: "text",
        modalities: supportsVision ? ["text", "image"] : ["text"],
        contextTokens,
        maxOutputTokens: contextTokens === null ? null : Math.min(contextTokens, 32_768),
        inputPriceUsdPerMillion: approved.input,
        outputPriceUsdPerMillion: approved.output,
        cacheReadPriceUsdPerMillion: approved.cachedInput,
        cacheWritePriceUsdPerMillion: null,
        pricingNote: "Fireworks Standard serverless pricing in USD per 1M tokens.",
        privacyLevel: "private",
        privacySummary: "Fireworks zero-data-retention routing",
        privacyNotes: [
          "Fireworks says it does not persist prompts or generations for open models unless a user explicitly opts in.",
          "AnonRouter uses Chat Completions only; it does not use the Fireworks Responses API whose store=true default retains conversations.",
          "Fireworks logs service metadata such as token counts, and its isolated prompt cache may keep prompt data in volatile memory for several minutes."
        ],
        moderation: "unknown",
        features,
        routingModes: ["anonrouter-hosted", "provider-direct"],
        availability: deprecated ? "deprecated" : online ? "available" : "needs-verification",
        ...(!online && !deprecated ? { statusNote: "Fireworks does not currently report this serverless route healthy." } : {}),
        sourceReferences: [PRICING_SOURCE, PRIVACY_SOURCE, MODEL_SOURCE]
      }
    });
  }
  return normalized.sort((a, b) => a.providerModelId.localeCompare(b.providerModelId));
}
