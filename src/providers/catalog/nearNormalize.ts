import type {
  NormalizedModel,
  NormalizedReasoningCapabilities,
  RoutingProfile
} from "./normalized.js";
import { NEAR_RELAY_OWNERS, normalizeNearRelayCatalog } from "./nearRelay.js";
import { providerQualifiedRouteId, publicProviderName } from "../publicIdentity.js";

// PUBLIC COPY IS WHITE-LABELLED: NEAR AI's models are listed under the public
// provider "Other" (../publicIdentity.ts), so nothing that lands in
// `publicMetadata` names NEAR or links to NEAR's pages. The routes' NEAR
// sources are recorded in docs/hardware-verification/status/near-models.md;
// the attestation EVIDENCE for a direct route (its TLS domain, NEAR's release
// repositories) is served by the attestation endpoints, not the catalog.
const INTERNAL_PROVIDER = "near-ai";

// NEAR caps generation length per model; keep a conservative product ceiling
// when the live entry omits an explicit generation cap.
const MAX_OUTPUT_CEILING = 32_768;

// Upstream-proxy owners: models NEAR merely proxies to a third-party frontier
// API are NOT verifiable and must NEVER be classified TEE. A route whose live
// owned_by matches one of these is excluded even if it appears in the allowlist.
// Shared with the relay normalizer (./nearRelay.ts), which is the only place
// these owners' routes are emitted, and only as anonymous/private.
const PROXY_OWNERS: ReadonlySet<string> = NEAR_RELAY_OWNERS;

const DIRECT_TEE_NOTES = [
  "This is a direct confidential route: TLS terminates inside the model's own TEE, so AnonRouter attests the enclave (Intel TDX quote + NVIDIA GPU attestation, TLS key bound into the attestation report) before routing.",
  "Direct routes support end-to-end encryption (Curve25519/X25519 + XChaCha20-Poly1305) and per-request model-TEE signatures that AnonRouter can verify by recovering the attested signing address.",
  "AnonRouter gates the confidential tier on membership in the provider's authoritative endpoint list, never on the model's owner field alone, and keeps the provider's relayed routes out of it."
];
const ATTESTED_3P_NOTES = [
  "This is an attested third-party route: the model runs in a partner TEE behind the provider's gateway. The current adapter has no direct enclave attestation or compatible per-request signature for this route.",
  "AnonRouter sees plaintext inside the attested boundary; this is a TEE guarantee, not end-to-end encryption of the standard route.",
  "AnonRouter gates this tier on the curated allowlist and keeps the provider's relayed routes, which are not verifiable, out of it."
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
  /** Provider-qualified, globally-unique public slug suffix (other/<slug>; see ../publicIdentity.ts). */
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
  // Withdrawn upstream and removed 2026-10-01 (status/authority.md, "NEAR
  // re-enable checklist"): openai/gpt-oss-120b (decommissioned by NEAR),
  // z-ai/glm-5.2 (NEAR's gateway aliases it to glm-5.3-flash, so the route
  // would serve a different model) and qwen/qwen3-32b (attested-3p, gone from
  // NEAR's catalog). None is in NEAR's /v1/models; their direct hosts are out
  // of the NEAR egress allowlist and the endpoint pins too. Re-adding one is a
  // product decision plus an attestation and egress change, never a revert.
  //
  // Added 2026-10-01 (hwv/near-models): the one NEAR "nearai" model whose live
  // TDs pass NEAR's release authority (authority/near.ts) on today's evidence.
  // Context, output cap, pricing and modalities come from NEAR's catalog at
  // sync time; displayName is NEAR's `name`; canDisableReasoning and
  // qualityTier are this canonical model's existing values in our catalog
  // (phalaAiNormalize.ts, Venice snapshot), not new judgements.
  "z-ai/glm-5.3-flash": {
    slug: "glm-5.3-flash", canonicalId: "z-ai/glm-5.3-flash", displayName: "GLM 5.3 Flash",
    routeClass: "direct-tee", endpointDomain: "glm-5-3-flash.completions.near.ai",
    canDisableReasoning: true, qualityTier: 4
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

/** NEAR /v1/models -> the reviewed direct-TEE and attested-3p confidential routes,
 *  plus the reviewed relayed (anonymous) routes from ./nearRelay.ts. */
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
    const publicSlug = providerQualifiedRouteId(INTERNAL_PROVIDER, approved.slug);
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
      ? `${approved.displayName} served in a direct TLS-in-TEE enclave.`
      : `${approved.displayName} served in an attested third-party enclave.`;
    const privacyNotes = isDirect ? DIRECT_TEE_NOTES : ATTESTED_3P_NOTES;
    const privacySummary = isDirect
      ? "Direct TLS-in-TEE enclave (Intel TDX + NVIDIA CC)"
      : "Attested third-party TEE (no direct signature in this adapter)";

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
        note: "Pricing in USD per 1M tokens."
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
        // Internal provider id (schema + eligibility); presented as `other` by
        // the public read boundary (publicView.ts).
        provider: INTERNAL_PROVIDER,
        providerName: publicProviderName(INTERNAL_PROVIDER, "NEAR AI"),
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
        pricingNote: "Pricing in USD per 1M tokens.",
        privacyLevel: isDirect ? "e2ee" : "tee",
        privacySummary,
        privacyNotes: [...privacyNotes],
        moderation: "unknown",
        ...(reasoning ? { reasoning: reasoningCapabilities } : {}),
        features: featureList,
        routingModes: ["anonrouter-hosted", "provider-direct"],
        availability: online ? "available" : "needs-verification",
        ...(!online ? { statusNote: "The provider does not currently report this route ready." } : {}),
        // No public source links: every published page for these routes is
        // NEAR's own. Verification is the attestation endpoint, not a link.
        sourceReferences: []
      }
    });
  }
  // Relayed (non-TEE) upstream routes are a separate class with their own
  // reviewed table; an id already emitted above is never emitted twice.
  const confidentialIds = new Set(normalized.map((model) => model.providerModelId));
  normalized.push(...normalizeNearRelayCatalog(raw, confidentialIds));
  return normalized.sort((a, b) => a.providerModelId.localeCompare(b.providerModelId));
}
