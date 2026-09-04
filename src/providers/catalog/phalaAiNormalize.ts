// Phala AI (`phala-ai`) catalog normalization.
//
// READ THIS BEFORE CHANGING A PRIVACY FIELD. Phala AI is an AGGREGATOR GATEWAY,
// and it says so itself: `GET /v1/aci/attestation` reports
// `service_capabilities.serving = "aggregator"`, its attested TD reports
// `vm_config.num_gpus = 0`, and the upstream gateway source
// (Dstack-TEE/private-ai-gateway) documents that it DECRYPTS downstream E2EE at
// the frontend and re-encrypts upstream if needed. Inference therefore does not
// happen inside the enclave Phala attests, and the gateway sees plaintext.
//
// Under `docs/MODELS_AND_PRIVACY_LABELS.md` that is `private`, and only
// `private`:
//   - `tee` requires that "inference runs inside an attestable hardware-isolated
//     enclave". The enclave Phala attests is a router with no GPU.
//   - `e2ee` requires that "only that verified enclave can decrypt it". The
//     gateway decrypts.
// The governing precedent is already in that document: NEAR AI's "attested third
// party" routes run in a partner TEE behind NEAR's gateway and are classified
// plaintext, and NEAR's pure upstream-proxy routes are excluded outright "so a
// proxy route can never be mislabelled `tee`".
//
// So `privacyClass` is hard-coded `private` here rather than derived. There is no
// live flag that may promote it, `supportsTee` and `supportsE2ee` are constant
// false, and `tests/unit/phala-ai-normalize.test.ts` fails if any of that moves.
//
// PRICING UNIT. Phala publishes `pricing.{prompt,completion,input_cache_read}` in
// USD PER TOKEN, not per million — this differs from Chutes, whose identically
// named fields are already per million. Cross-checked against Phala's published
// figures: the API returns 0.0000003 / 0.0000015 for
// `phala/qwen3.6-35b-a3b-uncensored`, which its own listing prices at $0.30/M and
// $1.50/M. PRICE_SCALE below is that conversion and getting it wrong is a
// 1,000,000x billing error in either direction.

import type {
  NormalizedModel,
  NormalizedReasoningCapabilities,
  RoutingProfile
} from "./normalized.js";

const PRIVACY_SOURCE = {
  label: "Phala Confidential AI overview",
  url: "https://docs.phala.com/phala-cloud/confidential-ai/overview"
};
const MODEL_SOURCE = {
  label: "Phala AI models",
  url: "https://inference.phala.com/v1/models"
};

/** Phala prices per token; AnonRouter stores USD per 1,000,000 tokens. */
const PRICE_SCALE = 1_000_000;

/** Conservative product ceiling when the live entry omits a generation cap. */
const MAX_OUTPUT_CEILING = 32_768;

/**
 * The upstream tag that means "Phala served this itself".
 *
 * Phala's `/v1/models` is an aggregator listing: `providers[]` names who actually
 * runs the weights, and the values observed live are `phala`, `chutes`,
 * `near-ai`, `tinfoil` and `secretai`. Three of those are providers AnonRouter
 * already integrates DIRECTLY. Reselling them through Phala would add a second
 * plaintext gateway to a route AnonRouter can already reach in one hop, and would
 * duplicate a canonical route behind a weaker privacy class.
 */
const SELF_SERVED_UPSTREAM = "phala";

const PRIVACY_SUMMARY = "Phala AI private routing (aggregator gateway)";

/**
 * Customer-visible privacy notes. Every sentence is a fact this repository has
 * measured or a primary source states. Nothing here claims Phala cannot see a
 * prompt, because it can.
 */
const PRIVACY_NOTES = [
  "Phala AI runs this model on confidential hardware, but AnonRouter routes it through Phala's aggregator gateway, and that gateway decrypts the request before forwarding it upstream. Phala can therefore see prompt and response content.",
  "Phala's gateway publishes Intel TDX attestation for the gateway itself. That evidence is not bound to your request, not bound to a model, and carries no GPU attestation, so AnonRouter does not treat these routes as verified enclave routes and shows no attestation badge for them.",
  "AnonRouter obscures the caller's identity from Phala AI. Provider retention beyond serving the request is not guaranteed by AnonRouter."
];

/**
 * Why a route is held out of customer service.
 *
 * Only ONE reason survives. The `alias` hold is gone because the owner decided
 * those four mappings on 2026-09-03; what remains is the case nobody can decide
 * from the outside.
 *
 * `upstream-indeterminate` — the live entry names more than one upstream, so a
 * request may be served by Phala or by a third party AnonRouter cannot pin
 * (Phala exposes no per-request upstream selector this adapter can bind). The
 * privacy note would be untrue for part of the traffic, and a `private` label
 * that is conditionally false is worse than no route.
 */
export type PhalaAiHoldReason = "upstream-indeterminate";

interface ApprovedPhalaAiRoute {
  /** Provider-qualified, globally-unique public slug suffix (phala-ai/<slug>). */
  slug: string;
  /**
   * The AnonRouter canonical id this route attaches to.
   *
   * Where it differs from the Phala id, this is a MERGE the owner approved on
   * 2026-09-03: the Phala route joins an existing public model as an additional
   * provider route rather than becoming a second public model for the same
   * weights. `equivalence` records what actually supports each merge, because
   * two of the four rest on the owner's decision alone and saying so is the
   * point of writing it down.
   */
  canonicalId: string;
  displayName: string;
  qualityTier: number;
  /**
   * Held out of customer service. A held route is still seeded and still visible
   * to an operator, but the catalog marks it `needs-verification`, the migration
   * seeds it unlisted and quarantined, and no customer surface can serve it.
   */
  hold?: PhalaAiHoldReason;
  /**
   * Whether this route is a candidate for operator enablement after the release
   * and its canary. NOT the same as "callable": every row seeds disabled, and
   * this only records which four the owner named. A route that is not a
   * candidate seeds quarantined, so enabling it needs an explicit decision
   * rather than an oversight.
   */
  enablementCandidate?: boolean;
  /** What supports treating the Phala route and `canonicalId` as one model. */
  equivalence?: string;
}

/**
 * The ten routes Phala AI serves itself. Keyed by the EXACT id Phala publishes.
 *
 * An allowlist, not a denylist, and the direction is the point: a model that
 * appears in Phala's catalog tomorrow is ignored until somebody reviews it,
 * rather than served until somebody notices. Adding an eleventh fails
 * `tests/unit/phala-ai-normalize.test.ts` instead of shipping itself.
 */
export const APPROVED_PHALA_AI_ROUTES: Readonly<Record<string, ApprovedPhalaAiRoute>> = {
  // --- the four enablement candidates ---------------------------------------
  // Phala's id already IS the AnonRouter canonical id and Phala is the only
  // upstream, so there is nothing to merge and nothing ambiguous to resolve.
  "z-ai/glm-5.3": {
    slug: "glm-5.3", canonicalId: "z-ai/glm-5.3", displayName: "GLM 5.3",
    qualityTier: 5, enablementCandidate: true
  },
  "z-ai/glm-5.3-flash": {
    slug: "glm-5.3-flash", canonicalId: "z-ai/glm-5.3-flash", displayName: "GLM 5.3 Flash",
    qualityTier: 4, enablementCandidate: true
  },
  "deepseek/deepseek-v4-flash-0731": {
    slug: "deepseek-v4-flash-0731", canonicalId: "deepseek/deepseek-v4-flash-0731",
    displayName: "DeepSeek V4 Flash 0731", qualityTier: 4, enablementCandidate: true
  },
  "openai/gpt-oss-20b": {
    slug: "gpt-oss-20b", canonicalId: "openai/gpt-oss-20b", displayName: "OpenAI GPT OSS 20B",
    qualityTier: 3, enablementCandidate: true
  },

  // --- merged into an existing canonical model, owner-approved 2026-09-03 ----
  //
  // Each of these joins a public model AnonRouter already serves, as an
  // ADDITIONAL provider route. None becomes a second public model for the same
  // weights, and none is an enablement candidate yet: the merge settles identity,
  // not readiness.
  //
  // `equivalence` is deliberately uneven, because the evidence is. Two of the
  // four are corroborated by Phala's own `hugging_face_id`; two are not
  // corroborated by anything Phala publishes, and rest on the owner's decision.
  // Recording that difference is the whole reason the field exists.
  "meta/muse-glimmer-30b": {
    slug: "muse-glimmer-30b", canonicalId: "meta-models/muse-glimmer-30b",
    displayName: "Muse Glimmer 30B", qualityTier: 4,
    equivalence: "CORROBORATED: Phala publishes hugging_face_id `meta-models/Muse-Glimmer-30B`, "
      + "which is the AnonRouter canonical id case-for-case. Context matches at 131,072."
  },
  "qwen/qwen-2.5-7b-instruct": {
    slug: "qwen-2.5-7b-instruct", canonicalId: "qwen/qwen-2.5-7b",
    displayName: "Qwen 2.5 7B Instruct", qualityTier: 2,
    equivalence: "CORROBORATED: Phala publishes hugging_face_id `Qwen/Qwen2.5-7B-Instruct`, the "
      + "instruction-tuned 7B checkpoint the AnonRouter canonical names. Context 32,768 against "
      + "Venice's 32,000, which is a publisher rounding difference rather than a different model."
  },
  "phala/gemma-4-26b-a4b-uncensored": {
    slug: "gemma-4-26b-a4b-uncensored", canonicalId: "google/gemma-4-26b-a4b-uncensored",
    displayName: "Gemma 4 26B A4B Uncensored", qualityTier: 3,
    equivalence: "OWNER DECISION, not corroborated by the provider. Phala publishes NO "
      + "hugging_face_id for this row; its description says an uncensored `Heretic` ablation of "
      + "google/gemma-4-26B-A4B-it. Whether Venice's identically-named route is the same ablation "
      + "is not established by anything either provider publishes."
  },
  "phala/qwen3.6-35b-a3b-uncensored": {
    slug: "qwen3.6-35b-a3b-uncensored", canonicalId: "qwen/qwen3.6-35b-a3b-uncensored",
    displayName: "Qwen3.6 35B A3B Uncensored", qualityTier: 4,
    equivalence: "OWNER DECISION, not corroborated by the provider. Phala publishes NO "
      + "hugging_face_id; its description names an `Aggressive` fine-tune by HauhauCS. Venice's "
      + "identically-named route may be a different de-censoring of the same base."
  },

  // --- held: more than one upstream can serve the request --------------------
  //
  // NOT mapped to a canonical id, deliberately. `google/gemma-4-31b-it` was
  // considered for `google/gemma-4-31b-instruct` and the mapping is NOT made:
  // Phala's own hugging_face_id is `google/gemma-4-31B-it`, which does not
  // establish equivalence with a route named `-instruct`, and the owner's
  // instruction was to map only if identity is established. Keeping the Phala id
  // as its own canonical means withholding it withholds exactly one route.
  "qwen/qwen3.8-27b": {
    slug: "qwen3.8-27b", canonicalId: "qwen/qwen3.8-27b", displayName: "Qwen3.8 27B",
    qualityTier: 4, hold: "upstream-indeterminate"
  },
  "google/gemma-4-31b-it": {
    slug: "gemma-4-31b-it", canonicalId: "google/gemma-4-31b-it", displayName: "Gemma 4 31B IT",
    qualityTier: 4, hold: "upstream-indeterminate",
    equivalence: "NOT ESTABLISHED. Phala publishes hugging_face_id `google/gemma-4-31B-it`; the "
      + "candidate AnonRouter canonical is `google/gemma-4-31b-instruct`. `-it` and `-instruct` "
      + "are plausibly the same instruction-tuned checkpoint and nothing published says so, so no "
      + "mapping is made."
  }
};


/**
 * The routes an operator may enable after the release and its canary.
 *
 * Derived, never a second list. A route that is not here seeds quarantined, so
 * enabling it is an explicit decision rather than something that happens because
 * a row looked healthy.
 */
export const PHALA_AI_ENABLEMENT_CANDIDATES: readonly string[] = Object.freeze(
  Object.entries(APPROVED_PHALA_AI_ROUTES)
    .filter(([, route]) => route.enablementCandidate === true)
    .map(([id]) => id)
    .sort()
);

/** Routes withheld from every customer surface. Also derived. */
export const PHALA_AI_HELD_ROUTES: readonly string[] = Object.freeze(
  Object.entries(APPROVED_PHALA_AI_ROUTES)
    .filter(([, route]) => route.hold !== undefined)
    .map(([id]) => id)
    .sort()
);

export interface RawPhalaAiModel {
  id?: unknown;
  name?: unknown;
  context_length?: unknown;
  max_output_length?: unknown;
  input_modalities?: unknown;
  output_modalities?: unknown;
  supported_features?: unknown;
  supported_parameters?: unknown;
  /** USD PER TOKEN. See PRICE_SCALE. */
  pricing?: { prompt?: unknown; completion?: unknown; input_cache_read?: unknown } | unknown;
  /** Who actually serves the weights. See SELF_SERVED_UPSTREAM. */
  providers?: unknown;
  /** Phala's own confidential-hardware flag. Never promotes the privacy class. */
  is_tee?: unknown;
}

const NO_REASONING: NormalizedReasoningCapabilities = {
  supported: false,
  effortConfigurable: false,
  supportedEfforts: [],
  canDisable: false,
  defaultEffort: null,
  alwaysOn: false
};

/**
 * Reasoning controls, read from the live entry and never assumed. Phala publishes
 * `supported_features` and `supported_parameters` per model, so both halves are
 * attested rather than inferred from a name: `reasoning_effort` is what makes the
 * effort selector real, and the object-form `reasoning` parameter is what lets a
 * caller turn it off.
 */
function reasoningCaps(reasoning: boolean, effortConfigurable: boolean, canDisable: boolean): NormalizedReasoningCapabilities {
  if (!reasoning) return { ...NO_REASONING };
  return {
    supported: true,
    effortConfigurable,
    supportedEfforts: effortConfigurable ? ["low", "medium", "high"] : [],
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

/**
 * A per-token price scaled to USD per 1M tokens. Missing or malformed prices
 * become null, NEVER 0: `enablement.ts` refuses to make an unpriced text route
 * callable, and a 0 would bill at zero instead of failing closed.
 */
function price(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(number) || number <= 0) return null;
  const scaled = number * PRICE_SCALE;
  return Number.isFinite(scaled) && scaled > 0 ? scaled : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

/**
 * Phala `/v1/models` -> the reviewed Phala-served private chat routes.
 *
 * Two filters run before anything is normalized and both are load-bearing:
 *   1. the id must be in APPROVED_PHALA_AI_ROUTES;
 *   2. `providers[]` must contain `phala`, so a row Phala merely RESELLS from
 *      Chutes/NEAR/Tinfoil/SecretAI is dropped rather than re-listed behind an
 *      extra hop.
 */
export function normalizePhalaAiCatalog(raw: RawPhalaAiModel[]): NormalizedModel[] {
  const normalized: NormalizedModel[] = [];
  for (const candidate of raw) {
    const providerModelId = string(candidate.id);
    if (!providerModelId) continue;
    const approved = APPROVED_PHALA_AI_ROUTES[providerModelId];
    if (!approved) continue;

    // The resale filter. A row Phala does not serve itself never becomes a route,
    // whatever the allowlist says, because the allowlist describes intent and
    // `providers[]` describes what is actually running.
    const upstreams = stringArray(candidate.providers);
    if (!upstreams.includes(SELF_SERVED_UPSTREAM)) continue;

    // More than one upstream means the serving party is not determined at request
    // time. That is held even if the allowlist entry did not anticipate it, so a
    // provider-side change adds a hold instead of silently widening a claim.
    const upstreamIndeterminate = upstreams.length > 1;
    const hold: PhalaAiHoldReason | null = approved.hold
      ?? (upstreamIndeterminate ? "upstream-indeterminate" : null);

    const contextTokens = integer(candidate.context_length);
    const maxOutputTokens = integer(candidate.max_output_length)
      ?? (contextTokens ? Math.min(contextTokens, MAX_OUTPUT_CEILING) : null);

    const features = stringArray(candidate.supported_features);
    const parameters = stringArray(candidate.supported_parameters);
    const inputModalities = stringArray(candidate.input_modalities);
    const supportsTools = features.includes("tools");
    const supportsVision = inputModalities.includes("image");
    const reasoning = features.includes("reasoning");
    const responseSchema = features.includes("structured_outputs") || features.includes("json_mode");
    const reasoningCapabilities = reasoningCaps(
      reasoning,
      parameters.includes("reasoning_effort"),
      parameters.includes("reasoning")
    );

    const pricingObj = candidate.pricing && typeof candidate.pricing === "object"
      ? (candidate.pricing as { prompt?: unknown; completion?: unknown; input_cache_read?: unknown })
      : null;
    const inputPerMillionUsd = pricingObj ? price(pricingObj.prompt) : null;
    const outputPerMillionUsd = pricingObj ? price(pricingObj.completion) : null;
    const cacheReadPerMillionUsd = pricingObj ? price(pricingObj.input_cache_read) : null;

    // A held route reports `needs-verification`, which keeps it out of every
    // customer surface through the SAME path an unhealthy route uses, rather than
    // through a second mechanism somebody has to remember.
    const availability = hold ? "needs-verification" : "available";
    const publicSlug = `phala-ai/${approved.slug}`;
    const modalities = supportsVision ? (["text", "image"] as const) : (["text"] as const);
    const routing: RoutingProfile | null = {
      qualityTier: approved.qualityTier, tasks: [], supportsWeb: false, expectedLatencyMs: null
    };
    const featureList = [
      "streaming",
      ...(supportsTools ? ["tool-calling"] : []),
      ...(supportsVision ? ["vision"] : []),
      ...(reasoning ? ["reasoning"] : []),
      ...(cacheReadPerMillionUsd != null ? ["prompt-caching"] : [])
    ];
    const shortDescription = `${approved.displayName} served through the Phala AI private gateway.`;
    const holdNote = hold === "upstream-indeterminate"
      ? `Withheld: Phala lists more than one upstream for this model (${upstreams.join(", ")}), so AnonRouter cannot pin which party serves a given request and the privacy note above would be untrue for part of the traffic.`
      : null;

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
        note: "Phala AI pricing in USD per 1M tokens, converted from its per-token list price."
      },
      online: !hold,
      // CONSTANT. See the header. `is_tee` on the live entry is deliberately not
      // read: it describes Phala's hardware, not the boundary AnonRouter's label
      // is about.
      privacyClass: "private",
      supportsE2ee: false,
      supportsTee: false,
      capabilities: {
        functionCalling: supportsTools,
        responseSchema,
        reasoning,
        webSearch: false,
        vision: supportsVision,
        optimizedForCode: false,
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
        provider: "phala-ai",
        providerName: "Phala AI",
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
        pricingNote: "Phala AI pricing in USD per 1M tokens, converted from its per-token list price.",
        privacyLevel: "private",
        privacySummary: PRIVACY_SUMMARY,
        privacyNotes: holdNote ? [...PRIVACY_NOTES, holdNote] : [...PRIVACY_NOTES],
        moderation: "unknown",
        ...(reasoning ? { reasoning: reasoningCapabilities } : {}),
        features: featureList,
        routingModes: ["anonrouter-hosted", "provider-direct"],
        availability,
        sourceReferences: [PRIVACY_SOURCE, MODEL_SOURCE]
      }
    });
  }
  return normalized.sort((a, b) => a.providerModelId.localeCompare(b.providerModelId));
}
