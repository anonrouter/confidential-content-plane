// The single, server-side normalized catalog model. This is the ONE
// representation shared by the runtime (routing/billing) and the website; it
// replaces the previously-duplicated runtime + website mappings.
//
// Decoding of a raw provider response is deliberately permissive (unknown
// provider fields are tolerated and dropped, see ./normalize.ts), but only the
// explicitly normalized and sanitized fields defined here are ever allowed to
// cross into the control plane or the public catalog. Nothing in this module
// carries credentials, authorization headers, or raw provider payloads.

import { z } from "zod";
import { reasoningEffortLevelSchema } from "../../inference/reasoning.js";

/** Bump when the normalized wire schema changes incompatibly. Part of the hash. */
export const CATALOG_SCHEMA_VERSION = 1 as const;

export const catalogProviderSchema = z.enum([
  "venice",
  "fireworks",
  "aws-bedrock",
  "deepinfra",
  "chutes",
  "tinfoil",
  "near-ai"
]);
export type CatalogProvider = z.infer<typeof catalogProviderSchema>;

// Effective, single privacy level for a route, ordered anonymous < private < TEE < E2EE.
export const privacyClassSchema = z.enum(["anonymous", "private", "tee", "e2ee", "unknown"]);
export type PrivacyClass = z.infer<typeof privacyClassSchema>;

// What the model fundamentally IS (drives the catalog type tabs / support matrix).
export const primaryModalitySchema = z.enum(["text", "image", "audio", "video", "embeddings"]);
export type PrimaryModality = z.infer<typeof primaryModalitySchema>;

export const modalitySchema = z.enum(["text", "image", "audio", "video", "embeddings"]);

// How a route is billed. `per_token` = text token pricing; `flat_unit` = a single
// deterministic per-call price (per image / per 1M TTS chars); `variable` =
// provider quotes per request (video/some music) — never auto-billable; `unpriced`
// = provider published no usable price.
export const priceModelSchema = z.enum(["per_token", "flat_unit", "variable", "unpriced"]);
export type PriceModel = z.infer<typeof priceModelSchema>;

export const flatUnitSchema = z.enum(["image", "edit", "upscale", "tts_1m_chars", "per_minute", "track"]);
export type FlatUnit = z.infer<typeof flatUnitSchema>;

const finiteNonNegative = z
  .number()
  .refine((value) => Number.isFinite(value) && value >= 0, "must be a finite, non-negative number");

// Sanitized pricing. Every present numeric price is finite and >= 0. Missing or
// malformed provider prices are represented as `null` — NEVER coerced to 0 —
// so an enabled model can never be silently billed at zero (see enablement.ts).
export const normalizedPricingSchema = z
  .object({
    priceModel: priceModelSchema,
    inputPerMillionUsd: finiteNonNegative.nullable(),
    outputPerMillionUsd: finiteNonNegative.nullable(),
    cacheReadPerMillionUsd: finiteNonNegative.nullable(),
    cacheWritePerMillionUsd: finiteNonNegative.nullable(),
    /** Flat, deterministic per-call price where `priceModel === "flat_unit"`. */
    unitUsd: finiteNonNegative.nullable(),
    unit: flatUnitSchema.nullable(),
    /** Display-only labels (already sanitized) for the website. */
    inputLabel: z.string().max(120).nullable(),
    outputLabel: z.string().max(120).nullable(),
    note: z.string().max(400).nullable()
  })
  .strict();
export type NormalizedPricing = z.infer<typeof normalizedPricingSchema>;

export const deprecationSchema = z
  .object({
    deprecated: z.boolean(),
    /** ISO-8601 sunset instant, or null if deprecated without a firm date. */
    sunsetAt: z.string().max(40).nullable(),
    replacementModelId: z.string().max(256).nullable()
  })
  .strict();
export type NormalizedDeprecation = z.infer<typeof deprecationSchema>;

// Routing-relevant capabilities (sanitized booleans only).
export const capabilitiesSchema = z
  .object({
    functionCalling: z.boolean(),
    responseSchema: z.boolean(),
    reasoning: z.boolean(),
    webSearch: z.boolean(),
    vision: z.boolean(),
    optimizedForCode: z.boolean(),
    promptCaching: z.boolean()
  })
  .strict();
export type NormalizedCapabilities = z.infer<typeof capabilitiesSchema>;

// Sanitized reasoning-control capabilities. Each field is an INDEPENDENT
// provider-attested capability (see src/inference/reasoning.ts): a model may
// reason without accepting effort, accept effort without supporting "off", etc.
// `supportedEfforts` holds the exact catalog-attested levels in canonical
// order; "none" from the provider option list is folded into `canDisable`.
export const modelReasoningCapabilitiesSchema = z
  .object({
    supported: z.boolean(),
    effortConfigurable: z.boolean(),
    supportedEfforts: z.array(reasoningEffortLevelSchema).max(8),
    canDisable: z.boolean(),
    defaultEffort: reasoningEffortLevelSchema.nullable(),
    alwaysOn: z.boolean()
  })
  .strict();
export type NormalizedReasoningCapabilities = z.infer<typeof modelReasoningCapabilitiesSchema>;

const FAIL_CLOSED_REASONING: NormalizedReasoningCapabilities = {
  supported: false,
  effortConfigurable: false,
  supportedEfforts: [],
  canDisable: false,
  defaultEffort: null,
  alwaysOn: false
};

// The computed automatic-routing profile for a text model (null for media/other).
export const routingProfileSchema = z
  .object({
    qualityTier: z.number().int().min(1).max(5),
    tasks: z.array(z.string().max(40)).max(16),
    supportsWeb: z.boolean(),
    expectedLatencyMs: z.number().int().positive().max(600_000).nullable()
  })
  .strict();
export type RoutingProfile = z.infer<typeof routingProfileSchema>;

const sourceReferenceSchema = z
  .object({ label: z.string().max(120), url: z.string().max(400) })
  .strict();

// The sanitized, display-oriented public projection. Structurally a superset-safe
// match for the website's CatalogModel (minus the volatile `updatedAt`, which the
// serving layer stamps from catalog freshness so it does not perturb the hash).
export const publicCatalogModelSchema = z
  .object({
    id: z.string().max(256),
    displayName: z.string().max(200),
    provider: catalogProviderSchema,
    providerName: z.string().max(60),
    providerRouteId: z.string().max(256),
    routeId: z.string().max(256).optional(),
    shortDescription: z.string().max(400),
    description: z.string().max(1000).optional(),
    primaryModality: primaryModalitySchema,
    modalities: z.array(modalitySchema).max(8),
    contextTokens: z.number().int().nonnegative().nullable(),
    maxOutputTokens: z.number().int().nonnegative().nullable().optional(),
    inputPriceUsdPerMillion: z.number().nullable(),
    outputPriceUsdPerMillion: z.number().nullable(),
    cacheReadPriceUsdPerMillion: z.number().nullable().optional(),
    cacheWritePriceUsdPerMillion: z.number().nullable().optional(),
    inputPriceLabel: z.string().max(120).optional(),
    outputPriceLabel: z.string().max(120).optional(),
    pricingNote: z.string().max(400).optional(),
    privacyLevel: z.enum(["anonymous", "private", "tee", "e2ee"]),
    privacySummary: z.string().max(200),
    privacyNotes: z.array(z.string().max(400)).max(8),
    moderation: z.enum(["uncensored", "moderated", "unknown"]),
    voices: z.array(z.string().max(80)).max(256).optional(),
    /** Present only for reasoning-capable text routes; the exact sanitized
     *  control surface the client may rely on (nothing provider-raw). */
    reasoning: modelReasoningCapabilitiesSchema.optional(),
    features: z.array(z.string().max(40)).max(16),
    routingModes: z.array(z.string().max(40)).max(8),
    regionRoutingNote: z.string().max(400).optional(),
    releasedAt: z.string().max(40).optional(),
    availability: z.enum(["available", "preview", "planned", "deprecated", "needs-verification"]),
    statusNote: z.string().max(400).optional(),
    sourceReferences: z.array(sourceReferenceSchema).max(8)
  })
  .strict();
export type PublicCatalogModel = z.infer<typeof publicCatalogModelSchema>;

/**
 * The strict, versioned internal model. This is what is hashed, persisted as a
 * snapshot, and diffed by the apply engine. `providerModelId` is the stable
 * provider route id; `publicSlug` is the stable public model id.
 */
export const normalizedModelSchema = z
  .object({
    providerModelId: z.string().min(1).max(256),
    publicSlug: z.string().min(1).max(256),
    displayName: z.string().min(1).max(200),
    description: z.string().max(1000).nullable(),
    /** Raw provider type (text|image|inpaint|upscale|video|tts|music|asr|embedding|…). */
    providerType: z.string().min(1).max(40),
    primaryModality: primaryModalitySchema,
    modalities: z.array(modalitySchema).min(1).max(8),
    contextTokens: z.number().int().nonnegative().nullable(),
    maxOutputTokens: z.number().int().nonnegative().nullable(),
    pricing: normalizedPricingSchema,
    online: z.boolean(),
    privacyClass: privacyClassSchema,
    supportsE2ee: z.boolean(),
    supportsTee: z.boolean(),
    capabilities: capabilitiesSchema,
    /** Reasoning-control capabilities. Defaulted (fail closed: no controls) so a
     *  payload from a pre-reasoning worker still validates during a deploy skew
     *  instead of freezing the catalog; the next synced snapshot restores them. */
    reasoningCapabilities: modelReasoningCapabilitiesSchema.default(() => ({ ...FAIL_CLOSED_REASONING, supportedEfforts: [] })),
    beta: z.boolean(),
    deprecation: deprecationSchema.nullable(),
    regionRestrictions: z.array(z.string().max(120)).max(64).nullable(),
    traits: z.array(z.string().max(60)).max(32),
    moderation: z.enum(["uncensored", "moderated", "unknown"]),
    voices: z.array(z.string().max(80)).max(256).nullable(),
    releasedAt: z.string().max(40).nullable(),
    supportsStreaming: z.boolean(),
    supportsTools: z.boolean(),
    /** Vision (image input) capability. Defaulted (fail closed: no vision) so a
     *  payload from a pre-vision worker still validates during a deploy skew. */
    supportsVision: z.boolean().default(false),
    /** Provider-attested per-request image cap; 0 when vision is unsupported. */
    maxImages: z.number().int().nonnegative().default(0),
    routing: routingProfileSchema.nullable(),
    /** Sanitized display projection (website consumes this verbatim). */
    publicMetadata: publicCatalogModelSchema
  })
  .strict();
export type NormalizedModel = z.infer<typeof normalizedModelSchema>;

// Hard ceiling on models in one snapshot (defense-in-depth vs a runaway provider
// response). The apply engine rejects a snapshot that exceeds it.
export const MAX_MODELS_PER_SNAPSHOT = 5000;

/**
 * The versioned envelope produced by the credential-bearing worker and consumed
 * by the control plane. `source_hash` is computed over the deterministically
 * sorted normalized catalog (see ./hash.ts).
 */
export const normalizedCatalogPayloadSchema = z
  .object({
    schema_version: z.literal(CATALOG_SCHEMA_VERSION),
    provider: catalogProviderSchema,
    fetched_at: z.string().min(1).max(40),
    source_hash: z.string().regex(/^[0-9a-f]{64}$/, "source_hash must be a lowercase sha-256 hex digest"),
    models: z.array(normalizedModelSchema).max(MAX_MODELS_PER_SNAPSHOT)
  })
  .strict();
export type NormalizedCatalogPayload = z.infer<typeof normalizedCatalogPayloadSchema>;
