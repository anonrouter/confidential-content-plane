// The single normalizer: raw Venice `GET /models?type=all` -> strict, sanitized
// NormalizedModel[]. Decoding is permissive (unknown provider fields are ignored,
// so a newly-added Venice field never breaks sync), but the output contains ONLY
// the explicitly-normalized, sanitized fields declared in ./normalized.ts.
//
// This replaces BOTH the previous runtime normalizer and the website generator's
// independent mapping, so the gateway and the site can never disagree on a slug,
// price, privacy level, or capability.

import {
  assignCanonicalSlugs,
  canonicalGroupId,
  titleCaseFromId,
  type SlugInput
} from "../modelSlug.js";
import type {
  FlatUnit,
  NormalizedCapabilities,
  NormalizedModel,
  NormalizedPricing,
  NormalizedReasoningCapabilities,
  PriceModel,
  PrimaryModality,
  PrivacyClass,
  PublicCatalogModel,
  RoutingProfile
} from "./normalized.js";
import { REASONING_EFFORT_LEVELS, type ReasoningEffortLevel } from "../../inference/reasoning.js";

// Static, safe documentation references (label + url only; no secrets).
const PRICING_SOURCE = { label: "Venice pricing", url: "https://docs.venice.ai/overview/pricing" };
const PRIVACY_SOURCE = { label: "Venice privacy", url: "https://docs.venice.ai/overview/privacy" };
const TEE_SOURCE = { label: "Venice TEE/E2EE", url: "https://docs.venice.ai/guides/features/tee-e2ee-models" };

// A permissive view of a raw Venice model. Every field is `unknown` and read
// defensively; nothing here is trusted or forwarded verbatim.
export interface RawVeniceModel {
  id?: unknown;
  type?: unknown;
  context_length?: unknown;
  created?: unknown;
  model_spec?: Record<string, unknown>;
  [key: string]: unknown;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asBool(value: unknown): boolean {
  return value === true;
}

/** A finite, non-negative USD price, or null for anything missing/malformed.
 *  Critically, this NEVER returns 0 for a missing/invalid value. */
function priceOrNull(value: unknown): number | null {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) && n >= 0 ? Number(n.toFixed(6)) : null;
}

/** A strictly positive, finite USD price, or null. Used for flat unit prices
 *  where a zero price would mean "free" and must not be inferred. */
function positivePriceOrNull(value: unknown): number | null {
  const n = priceOrNull(value);
  return n !== null && n > 0 ? n : null;
}

function intOrNull(value: unknown): number | null {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) && n >= 0 ? Math.trunc(n) : null;
}

function leafUsdValues(node: unknown): number[] {
  if (node === null || typeof node !== "object") return [];
  const record = node as Record<string, unknown>;
  if (typeof record.usd === "number") return [record.usd];
  return Object.values(record).flatMap(leafUsdValues);
}

function truncate(text: string, max = 200): string {
  const collapsed = String(text).replace(/\s+/g, " ").trim();
  if (collapsed.length <= max) return collapsed;
  return `${collapsed.slice(0, max).replace(/\s+\S*$/, "")}…`;
}

function isoDate(unixSeconds: unknown): string | null {
  if (typeof unixSeconds !== "number" || unixSeconds <= 0) return null;
  return new Date(unixSeconds * 1000).toISOString().slice(0, 10);
}

function money(value: number | null): string | null {
  if (value === null || !Number.isFinite(value)) return null;
  if (value === 0) return "$0";
  if (value < 0.01) return `$${Number(value.toFixed(6))}`;
  return `$${value.toFixed(2)}`;
}

// --- model size / routing heuristics (ported from the runtime profiler) -------

function modelSizeBillions(value: string): number | null {
  const sizes = [...value.toLowerCase().matchAll(/(\d+(?:\.\d+)?)b\b/g)].map((match) => Number(match[1]));
  return sizes.length > 0 ? Math.max(...sizes) : null;
}

function routingQualityTier(id: string, displayName: string): number {
  const value = `${id} ${displayName}`.toLowerCase();
  const size = modelSizeBillions(value);
  // Tier 5 means FRONTIER: a current flagship family (family patterns cover
  // future point releases like kimi-k3 / glm-5.2 / grok-4.5) or an explicit
  // flagship build keyword. Parameter count alone never reaches tier 5: a big
  // open-weights model (GPT-OSS 120B, Llama 405B, Qwen 235B) is capable but not
  // frontier, so it lands at tier 4 and is preferred by cost routing, not the
  // default. Light builds of frontier families (flash/mini/turbo/...) drop to 4.
  const frontierFamily =
    /\b(opus|fable|ultra|max|pro|glm[- ]?[5-9]|grok[- ]?[4-9]|kimi[- ]?k[2-9]|deepseek[- ]?v[4-9]|gpt[- ]?[5-9]|gemini[- ]?[3-9]|minimax[- ]?m[3-9])\b/.test(value);
  const lightBuild = /\b(flash|nano|mini|small|lite|turbo)\b/.test(value);
  if (frontierFamily && !lightBuild) return 5;
  if (frontierFamily || /\b(sonnet|aion[- ]?[3-9])\b/.test(value) || (size !== null && size >= 70)) return 4;
  if (lightBuild || (size !== null && size <= 12)) return 2;
  return 3;
}

function expectedLatencyMs(id: string, displayName: string): number {
  const value = `${id} ${displayName}`.toLowerCase();
  if (/\b(flash|turbo|nano|mini|small)\b/.test(value)) return 600;
  if (/\b(opus|fable|ultra|max|pro)\b/.test(value) || (modelSizeBillions(value) ?? 0) >= 200) return 2_000;
  return 1_000;
}

// --- capability / modality / privacy extraction ------------------------------

function extractCapabilities(spec: Record<string, unknown>): NormalizedCapabilities {
  const caps = asRecord(spec.capabilities);
  const pricing = asRecord(spec.pricing);
  return {
    functionCalling: asBool(caps.supportsFunctionCalling),
    responseSchema: asBool(caps.supportsResponseSchema),
    reasoning: asBool(caps.supportsReasoning),
    webSearch: asBool(caps.supportsWebSearch),
    vision: asBool(caps.supportsVision),
    optimizedForCode: asBool(caps.optimizedForCode),
    promptCaching: Boolean(asRecord(pricing.cache_input).usd !== undefined || asRecord(pricing.cache_write).usd !== undefined)
  };
}

/**
 * Extract the reasoning-control surface from a raw Venice model spec. Every
 * capability is read independently and fails closed:
 *   - `supportsReasoning` alone marks a model reasoning-capable.
 *   - Effort options are honored only when `supportsReasoningEffort` is true,
 *     and only values Venice attests in `reasoningEffortOptions` survive;
 *     unknown strings are dropped rather than guessed at.
 *   - "none" in the option list is the provider's attestation that reasoning
 *     can be disabled; it is folded into `canDisable`, not kept as a level.
 *   - `defaultReasoningEffort` is kept only when it names an attested level.
 * A reasoning-capable model without an attested "none" is always-on.
 */
function extractReasoningCapabilities(type: string, spec: Record<string, unknown>): NormalizedReasoningCapabilities {
  const none: NormalizedReasoningCapabilities = {
    supported: false,
    effortConfigurable: false,
    supportedEfforts: [],
    canDisable: false,
    defaultEffort: null,
    alwaysOn: false
  };
  if (type !== "text") return none;
  const caps = asRecord(spec.capabilities);
  if (!asBool(caps.supportsReasoning)) return none;

  const attestedOptions = asBool(caps.supportsReasoningEffort) && Array.isArray(caps.reasoningEffortOptions)
    ? caps.reasoningEffortOptions
        .map((option) => asString(option)?.toLowerCase())
        .filter((option): option is string => option !== null && option !== undefined)
    : [];
  const supportedEfforts = REASONING_EFFORT_LEVELS.filter((level) => attestedOptions.includes(level));
  const canDisable = attestedOptions.includes("none");
  const defaultRaw = asString(caps.defaultReasoningEffort)?.toLowerCase() ?? null;
  const defaultEffort =
    defaultRaw !== null && (supportedEfforts as string[]).includes(defaultRaw) ? (defaultRaw as ReasoningEffortLevel) : null;

  return {
    supported: true,
    effortConfigurable: supportedEfforts.length > 0,
    supportedEfforts,
    canDisable,
    defaultEffort,
    alwaysOn: !canDisable
  };
}

function primaryModalityFor(type: string): PrimaryModality {
  switch (type) {
    case "image":
    case "inpaint":
    case "upscale":
      return "image";
    case "video":
      return "video";
    case "tts":
    case "music":
    case "asr":
      return "audio";
    case "embedding":
      return "embeddings";
    default:
      return "text";
  }
}

function modalitiesFor(type: string, spec: Record<string, unknown>, caps: NormalizedCapabilities): PrimaryModality[] {
  const specCaps = asRecord(spec.capabilities);
  switch (type) {
    case "text": {
      const modalities: PrimaryModality[] = ["text"];
      if (caps.vision) modalities.push("image");
      if (asBool(specCaps.supportsVideoInput)) modalities.push("video");
      if (asBool(specCaps.supportsAudioInput)) modalities.push("audio");
      return modalities;
    }
    case "image":
    case "inpaint":
    case "upscale":
      return ["image"];
    case "video":
      return asRecord(spec.constraints).model_type === "image-to-video" ? ["image", "video"] : ["video"];
    case "tts":
    case "music":
    case "asr":
      return ["audio"];
    case "embedding":
      return ["text", "embeddings"];
    default:
      return ["text"];
  }
}

function classifyPrivacy(spec: Record<string, unknown>): {
  privacyClass: PrivacyClass;
  supportsE2ee: boolean;
  supportsTee: boolean;
} {
  const caps = asRecord(spec.capabilities);
  const supportsE2ee = asBool(caps.supportsE2EE);
  const supportsTee = asBool(caps.supportsTeeAttestation);
  const privacyClass: PrivacyClass = supportsE2ee
    ? "e2ee"
    : supportsTee
      ? "tee"
      : spec.privacy === "private"
        ? "private"
        : spec.privacy === "anonymized"
          ? "anonymous"
          : "unknown";
  return { privacyClass, supportsE2ee, supportsTee };
}

function privacyPresentation(privacyClass: Exclude<PrivacyClass, "unknown">): {
  privacyLevel: "anonymous" | "private" | "tee" | "e2ee";
  privacySummary: string;
  privacyNotes: string[];
} {
  switch (privacyClass) {
    case "e2ee":
      return {
        privacyLevel: "e2ee",
        privacySummary: "End-to-end encrypted inference",
        privacyNotes: [
          "The client encrypts prompts before relay and only the verified TEE can decrypt them.",
          "E2EE requires attestation verification, encrypted messages, E2EE headers, and response decryption."
        ]
      };
    case "tee":
      return {
        privacyLevel: "tee",
        privacySummary: "Hardware-isolated TEE inference",
        privacyNotes: [
          "Inference runs inside a hardware-secured enclave with remote attestation support.",
          "The request can use the normal API while the model runtime remains isolated from its host."
        ]
      };
    case "private":
      return {
        privacyLevel: "private",
        privacySummary: "Venice Private routing",
        privacyNotes: [
          "Venice lists this route as Private.",
          "Prompt and response content is processed for inference and not retained after completion."
        ]
      };
    case "anonymous":
    default:
      return {
        privacyLevel: "anonymous",
        privacySummary: "Venice Anonymous routing",
        privacyNotes: [
          "Venice obscures the caller's identity from the inference provider.",
          "The inference provider can see prompt content and no provider zero-retention guarantee applies."
        ]
      };
  }
}

// Allowlisted, sanitized traits: short lowercase tokens only.
function sanitizeTraits(spec: Record<string, unknown>): string[] {
  const traits = Array.isArray(spec.traits) ? spec.traits : [];
  return traits
    .map((trait) => asString(trait))
    .filter((trait): trait is string => trait !== null)
    .map((trait) => trait.toLowerCase())
    .filter((trait) => /^[a-z0-9_.:-]{1,60}$/.test(trait))
    .slice(0, 32);
}

function moderationFor(model: RawVeniceModel, spec: Record<string, unknown>): "uncensored" | "moderated" | "unknown" {
  const traits = Array.isArray(spec.traits) ? spec.traits : [];
  const modelSets = Array.isArray(spec.model_sets) ? spec.model_sets : [];
  const tagged =
    traits.some((trait) => String(trait).toLowerCase() === "most_uncensored") ||
    modelSets.some((set) => String(set).toLowerCase() === "uncensored");
  const described = /\b(?:uncensored|unfiltered)\b/i.test(
    [asString(model.id), asString(spec.name), asString(spec.description)].filter(Boolean).join(" ")
  );
  return tagged || described ? "uncensored" : "unknown";
}

function textFeatures(spec: Record<string, unknown>, caps: NormalizedCapabilities): string[] {
  const features = ["streaming"];
  if (caps.functionCalling) features.push("tool-calling");
  if (caps.reasoning) features.push("reasoning");
  if (caps.vision) features.push("vision");
  if (caps.responseSchema) features.push("json-schema");
  if (caps.webSearch) features.push("web-search");
  if (caps.optimizedForCode) features.push("code-optimized");
  if (caps.promptCaching) features.push("prompt-caching");
  return features;
}

// --- pricing extraction ------------------------------------------------------

function extractPricing(type: string, spec: Record<string, unknown>): NormalizedPricing {
  const pricing = asRecord(spec.pricing);
  const base: NormalizedPricing = {
    priceModel: "unpriced",
    inputPerMillionUsd: null,
    outputPerMillionUsd: null,
    cacheReadPerMillionUsd: null,
    cacheWritePerMillionUsd: null,
    unitUsd: null,
    unit: null,
    inputLabel: null,
    outputLabel: null,
    note: null
  };

  if (type === "text" || type === "embedding") {
    const input = priceOrNull(asRecord(pricing.input).usd);
    const output = priceOrNull(asRecord(pricing.output).usd);
    const notes: string[] = [];
    if (input !== null || output !== null) notes.push("USD per 1M tokens from the Venice models API.");
    if (pricing.extended) notes.push("Extended-context rates apply beyond the standard context window.");
    return {
      ...base,
      priceModel: input !== null || output !== null ? "per_token" : "unpriced",
      inputPerMillionUsd: input,
      outputPerMillionUsd: output,
      cacheReadPerMillionUsd: priceOrNull(asRecord(pricing.cache_input).usd),
      cacheWritePerMillionUsd: priceOrNull(asRecord(pricing.cache_write).usd),
      note: notes.length ? notes.join(" ") : null
    };
  }

  if (type === "image" || type === "inpaint" || type === "upscale") {
    const values = leafUsdValues(pricing.generation ?? pricing.resolutions ?? pricing.quality ?? pricing.inpaint);
    const distinct = [...new Set(values.filter((v) => Number.isFinite(v) && v > 0))];
    const unit: FlatUnit = type === "inpaint" ? "edit" : type === "upscale" ? "upscale" : "image";
    if (distinct.length === 1) {
      // Single deterministic per-call price: flat-unit billable.
      return {
        ...base,
        priceModel: "flat_unit",
        unitUsd: Number(distinct[0].toFixed(6)),
        unit,
        inputLabel: "–",
        outputLabel: `${money(distinct[0])}/${unit}`,
        note: null
      };
    }
    if (distinct.length > 1) {
      // Price varies by resolution/quality: display a floor, but not auto-billable.
      const min = Math.min(...distinct);
      return {
        ...base,
        priceModel: "variable",
        inputLabel: "–",
        outputLabel: `from ${money(min)}/${unit}`,
        note: "Price varies by resolution or quality tier."
      };
    }
    return base;
  }

  if (type === "tts") {
    const perMillionChars = positivePriceOrNull(asRecord(pricing.input).usd);
    if (perMillionChars !== null) {
      return {
        ...base,
        priceModel: "flat_unit",
        unitUsd: perMillionChars,
        unit: "tts_1m_chars",
        inputLabel: `${money(perMillionChars)}/1M chars`,
        outputLabel: "–",
        note: "Priced per 1M input characters."
      };
    }
    return base;
  }

  if (type === "asr") {
    const perSecond = priceOrNull(asRecord(pricing.per_audio_second).usd);
    if (perSecond !== null) {
      return {
        ...base,
        priceModel: "variable",
        inputLabel: `${money(perSecond * 60)}/min`,
        outputLabel: "–",
        note: `Priced at ${money(perSecond)} per second of input audio.`
      };
    }
    return base;
  }

  if (type === "music") {
    const notes: string[] = [];
    let outputLabel: string | null = null;
    if (pricing.generation) {
      outputLabel = `${money(leafUsdValues(pricing.generation)[0] ?? null)}/track`;
    } else if (pricing.durations) {
      outputLabel = `from ${money(Math.min(...leafUsdValues(pricing.durations)))}/track`;
      notes.push("Price scales with track duration.");
    } else if (pricing.per_second) {
      outputLabel = `${money((leafUsdValues(pricing.per_second)[0] ?? 0) * 60)}/min`;
      notes.push("Priced per second of generated audio.");
    } else if (pricing.per_thousand_characters) {
      outputLabel = `${money(leafUsdValues(pricing.per_thousand_characters)[0] ?? null)}/1K chars`;
      notes.push("Priced per 1K input characters.");
    }
    return { ...base, priceModel: "variable", inputLabel: "–", outputLabel, note: notes.length ? notes.join(" ") : null };
  }

  if (type === "video") {
    return {
      ...base,
      priceModel: "variable",
      inputLabel: "–",
      outputLabel: "Varies",
      note: "Video generation is priced per request by resolution and duration; see Venice pricing docs."
    };
  }

  return base;
}

// Visual-family blurbs keep image/video descriptions specific without a hand-written
// entry per model id. Matched against the lowercased "<canonicalId> <displayName>";
// first match wins. Audio (TTS/ASR/music) uses type-driven blurbs below instead, so
// a provider that makes both video and music (e.g. MiniMax) never crosses wires.
const VISUAL_FAMILY_BLURBS: { match: RegExp; blurb: string }[] = [
  { match: /flux/, blurb: "Photorealistic, high-detail output with excellent typography and layout." },
  { match: /seedream|seedance/, blurb: "Vivid color, sharp detail, and coherent multi-subject scenes." },
  { match: /nano-banana/, blurb: "Creative, high-quality results with strong instruction following and clean edits." },
  { match: /ideogram/, blurb: "Best-in-class in-image text and typography." },
  { match: /wan-|\bwan\b|z-image/, blurb: "High-fidelity results with strong prompt adherence and fast turnaround." },
  { match: /krea/, blurb: "Aesthetic-focused, with a distinctive and stylized look." },
  { match: /luma/, blurb: "Cinematic lighting and composition with photoreal detail." },
  { match: /gpt-image/, blurb: "Instruction-following generation with broad world knowledge and reliable text rendering." },
  { match: /recraft/, blurb: "Brand- and vector-friendly, with precise control over style." },
  { match: /qwen/, blurb: "Flexible across a wide range of prompts and edits." },
  { match: /sd35|sdxl|stable-diffusion|stability/, blurb: "Open-weight, with fine-grained control over style and composition." },
  { match: /veo|kling|hailuo|minimax|sora|pixverse|ltx|vidu|runway|longcat|hunyuan/, blurb: "Smooth motion with strong scene and subject consistency." }
];

function mediaNoun(type: string, isMusic: boolean): string {
  switch (type) {
    case "image":
      return "text-to-image model";
    case "inpaint":
      return "image editing and inpainting model";
    case "upscale":
      return "image upscaling model";
    case "video":
      return "video generation model";
    case "tts":
      return isMusic ? "music and audio generation model" : "text-to-speech model";
    case "asr":
      return "speech-to-text transcription model";
    default:
      return "model";
  }
}

function mediaBlurb(type: string, isMusic: boolean, haystack: string): string | undefined {
  if (type === "asr") return "Accurate transcription across languages, accents, and noisy audio.";
  if (type === "tts") {
    return isMusic
      ? "Expressive composition with control over genre, mood, and instrumentation."
      : "Natural, expressive speech with clear articulation.";
  }
  return VISUAL_FAMILY_BLURBS.find((entry) => entry.match.test(haystack))?.blurb;
}

function describe(
  model: RawVeniceModel,
  type: string,
  spec: Record<string, unknown>,
  displayName: string,
  canonicalId: string
): string {
  const description = asString(spec.description);
  if (description) return truncate(description);
  // Media models (image/video/audio) rarely ship a provider description; build a
  // specific one from the model family + kind instead of a bare generic line.
  if (["image", "inpaint", "upscale", "video", "tts", "asr"].includes(type)) {
    const haystack = `${canonicalId} ${displayName}`.toLowerCase();
    const isMusic = /music|lyria|stable-audio|ace-step|seed-audio|mmaudio/.test(haystack);
    const noun = mediaNoun(type, isMusic);
    const article = /^[aeiou]/.test(noun) ? "an" : "a";
    const blurb = mediaBlurb(type, isMusic, haystack);
    return `${displayName} is ${article} ${noun}.${blurb ? ` ${blurb}` : ""}`;
  }
  if (type === "embedding") return "Embedding model for semantic search and retrieval.";
  return `${displayName} is a text model.`;
}

function extractDeprecation(spec: Record<string, unknown>): NormalizedModel["deprecation"] {
  const deprecation = asRecord(spec.deprecation);
  const hasDeprecation = spec.deprecation !== undefined && spec.deprecation !== null;
  if (!hasDeprecation) return null;
  const sunsetRaw = asString(deprecation.removesAt) ?? asString(deprecation.sunsetAt);
  let sunsetAt: string | null = null;
  if (sunsetRaw) {
    const parsed = new Date(sunsetRaw);
    sunsetAt = Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
  }
  return {
    deprecated: true,
    sunsetAt,
    replacementModelId: asString(deprecation.replacementModelId)
  };
}

function extractRegionRestrictions(spec: Record<string, unknown>): string[] | null {
  const region = spec.regionRestrictions;
  if (!region) return null;
  if (Array.isArray(region)) {
    const list = region.map((r) => asString(r)).filter((r): r is string => r !== null);
    return list.length ? list.slice(0, 64) : null;
  }
  const one = asString(region);
  return one ? [one] : null;
}

function contextTokensFor(type: string, model: RawVeniceModel, spec: Record<string, unknown>): number | null {
  if (type === "text") {
    return intOrNull(spec.availableContextTokens) ?? intOrNull(model.context_length);
  }
  if (type === "embedding") {
    return intOrNull(spec.maxInputTokens);
  }
  return null;
}

/**
 * Normalize a full raw Venice `data` array into strict NormalizedModel[]. Slugs
 * are assigned over the COMPLETE snapshot (every type) so collision groups that
 * span types disambiguate identically to what callers resolve. Models without a
 * usable id are dropped.
 */
export function normalizeVeniceCatalog(rawModels: RawVeniceModel[]): NormalizedModel[] {
  const usable = rawModels.filter((model) => asString(model.id) !== null);

  const slugByRouteId = assignCanonicalSlugs(
    usable.map(
      (model): SlugInput => ({
        routeId: String(model.id),
        displayName: asString(asRecord(model.model_spec).name),
        type: asString(model.type)
      })
    )
  );

  const normalized: NormalizedModel[] = [];
  for (const model of usable) {
    const providerModelId = String(model.id);
    const publicSlug = slugByRouteId.get(providerModelId);
    if (!publicSlug) continue;
    const type = asString(model.type) ?? "text";
    const spec = asRecord(model.model_spec);
    const displayName = asString(spec.name) ?? titleCaseFromId(providerModelId);
    const caps = extractCapabilities(spec);
    const reasoningCapabilities = extractReasoningCapabilities(type, spec);
    const { privacyClass, supportsE2ee, supportsTee } = classifyPrivacy(spec);
    const online = spec.offline !== true;
    const pricing = extractPricing(type, spec);
    const contextTokens = contextTokensFor(type, model, spec);
    const maxOutputTokens = intOrNull(spec.maxCompletionTokens);
    const deprecation = extractDeprecation(spec);
    const regionRestrictions = extractRegionRestrictions(spec);
    const traits = sanitizeTraits(spec);
    const moderation = moderationFor(model, spec);
    const beta = asBool(spec.betaModel);
    const releasedAt = isoDate(model.created);
    const voices =
      type === "tts" && Array.isArray(spec.voices)
        ? spec.voices.map((v) => asString(v)).filter((v): v is string => v !== null).slice(0, 256)
        : null;
    const primaryModality = primaryModalityFor(type);
    const modalities = modalitiesFor(type, spec, caps);
    const supportsStreaming = type === "text";
    const supportsTools = type === "text" && (caps.functionCalling || caps.responseSchema);
    const supportsVision = type === "text" && caps.vision;
    // Venice attests a per-request image cap (capabilities.maxImages) alongside
    // supportsVision; fall back to a single image when vision is attested
    // without a count. Never invented for non-vision routes.
    const maxImages = supportsVision
      ? Math.max(1, intOrNull(asRecord(spec.capabilities).maxImages) ?? 1)
      : 0;

    // Automatic-routing profile (text only). Media/other never auto-route.
    let routing: RoutingProfile | null = null;
    if (type === "text") {
      // Venice marks nearly every frontier reasoning model "optimizedForCode"
      // (GLM 5.2, Kimi K3, Grok, DeepSeek V4, ...), so that flag alone cannot
      // mean "coding specialist". A dedicated code build is one that is
      // code-optimized WITHOUT general reasoning (Qwen Coder) or explicitly
      // named as one (Kimi K2.7 Code); those stay narrow specialists. Every
      // other reasoning-capable route is a frontier generalist serving every
      // task including math and coding, so default routing can favor them
      // instead of falling through to small generalist models.
      const codeBuildName = /\bcod(?:e|er|ex|ing)\b/.test(`${providerModelId} ${displayName}`.toLowerCase());
      const codeSpecialist = caps.optimizedForCode && (!caps.reasoning || codeBuildName);
      const generalistTasks = ["general", "writing", "translation", "summarization", "analysis", ...(caps.webSearch ? ["research"] : [])];
      const routingTasks = codeSpecialist
        ? ["coding", "analysis"]
        : caps.reasoning
          ? [...generalistTasks, "math", "coding"]
          : generalistTasks;
      routing = {
        qualityTier: routingQualityTier(providerModelId, displayName),
        tasks: routingTasks,
        // Venice attests web search independently of reasoning/code flags; the
        // frontier models ARE the web-capable pool, so never strip it from them
        // (doing so routed every needs-web request to small generalists).
        supportsWeb: caps.webSearch,
        expectedLatencyMs: expectedLatencyMs(providerModelId, displayName)
      };
    }

    const presentation = privacyPresentation(privacyClass === "unknown" ? "anonymous" : privacyClass);
    const confidential = privacyClass === "tee" || privacyClass === "e2ee";
    const availability: PublicCatalogModel["availability"] = deprecation ? "deprecated" : beta ? "preview" : "available";
    const statusNotes: string[] = [];
    if (deprecation?.sunsetAt) {
      statusNotes.push(
        `Venice removes this route on ${deprecation.sunsetAt.slice(0, 10)}${deprecation.replacementModelId ? `; replacement: ${deprecation.replacementModelId}` : ""}.`
      );
    } else if (beta) {
      statusNotes.push("Beta");
    }
    const features =
      type === "text"
        ? textFeatures(spec, caps)
        : type === "embedding"
          ? ["embeddings"]
          : caps.webSearch
            ? ["web-search"]
            : [];

    const publicMetadata: PublicCatalogModel = {
      // Canonical grouping id: an E2EE route shares one model with its plaintext
      // counterpart (E2EE is a serving modality, not a separate model). The unique
      // per-route id lives in public_model_id, not here.
      id: canonicalGroupId(publicSlug),
      displayName,
      provider: "venice",
      providerName: "Venice",
      providerRouteId: publicSlug,
      routeId: providerModelId,
      shortDescription: describe(model, type, spec, displayName, publicSlug),
      description: asString(spec.description) ? truncate(String(spec.description), 700) : describe(model, type, spec, displayName, publicSlug),
      primaryModality,
      modalities,
      contextTokens,
      ...(maxOutputTokens !== null ? { maxOutputTokens } : {}),
      inputPriceUsdPerMillion: pricing.inputPerMillionUsd,
      outputPriceUsdPerMillion: pricing.outputPerMillionUsd,
      cacheReadPriceUsdPerMillion: pricing.cacheReadPerMillionUsd,
      cacheWritePriceUsdPerMillion: pricing.cacheWritePerMillionUsd,
      ...(pricing.inputLabel ? { inputPriceLabel: pricing.inputLabel } : {}),
      ...(pricing.outputLabel ? { outputPriceLabel: pricing.outputLabel } : {}),
      ...(pricing.note ? { pricingNote: pricing.note } : {}),
      privacyLevel: presentation.privacyLevel,
      privacySummary: presentation.privacySummary,
      privacyNotes: presentation.privacyNotes,
      moderation,
      ...(voices && voices.length ? { voices } : {}),
      ...(reasoningCapabilities.supported ? { reasoning: reasoningCapabilities } : {}),
      features,
      routingModes: ["anonrouter-hosted", "provider-direct"],
      ...(regionRestrictions ? { regionRoutingNote: `Venice region restrictions apply: ${regionRestrictions.join(", ")}` } : {}),
      ...(releasedAt ? { releasedAt } : {}),
      availability,
      ...(statusNotes.length ? { statusNote: statusNotes.join(" ") } : {}),
      sourceReferences: [
        PRICING_SOURCE,
        PRIVACY_SOURCE,
        ...(confidential ? [TEE_SOURCE] : []),
        ...(asString(spec.modelSource) ? [{ label: "Model source", url: String(spec.modelSource) }] : [])
      ]
    };

    normalized.push({
      providerModelId,
      publicSlug,
      displayName,
      description: asString(spec.description),
      providerType: type,
      primaryModality,
      modalities,
      contextTokens,
      maxOutputTokens,
      pricing,
      online,
      privacyClass,
      supportsE2ee,
      supportsTee,
      capabilities: caps,
      reasoningCapabilities,
      beta,
      deprecation,
      regionRestrictions,
      traits,
      moderation,
      voices,
      releasedAt,
      supportsStreaming,
      supportsTools,
      supportsVision,
      maxImages,
      routing,
      publicMetadata
    });
  }

  return normalized;
}
