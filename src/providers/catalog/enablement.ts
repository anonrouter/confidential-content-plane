// Pure enablement + quarantine policy. Given a normalized model, decide whether
// it is technically safe to LIST, CALL, and AUTO-ROUTE. This is a capability
// decision, not operator authorization: the apply engine layers provider state,
// quarantine, and the explicit approve/enable gate on top.
//
// Design invariants enforced here:
//  - Never enable a text model whose prices are missing/zero/malformed. A missing
//    price is never coerced to 0 for an enabled model (that would bill at zero).
//  - Only model types with an implemented route AND billing unit are callable
//    (chat/embedding token billing, image flat unit, TTS flat unit). Everything else is
//    listed-only until routing + billing support exists.
//  - A privacy label never widens routability: TEE/E2EE are addressable where the
//    protocol exists but are never blindly auto-routed; unknown privacy is neither.

import type { NormalizedModel, PrivacyClass } from "./normalized.js";
import { STALE_AFTER_MS } from "./freshness.js";

export type AvailabilityStatus =
  | "available" // callable for inference
  | "unsupported" // listed, but no implemented route/billing/pricing/privacy support
  | "offline" // provider marked the route offline
  | "deprecated" // deprecation sunset has passed
  | "quarantined" // price anomaly held for operator review
  | "retired" // absent from the provider for 3+ accepted snapshots
  | "frozen"; // newly-changed route withheld while the catalog is critically stale

export interface EnablementDecision {
  listed: boolean;
  callable: boolean;
  routingEnabled: boolean;
  status: AvailabilityStatus;
  /** Machine reason for observability (never user secrets). */
  reason: string;
}

export type ModelEligibilityReason =
  | "eligible"
  | "provider_offline"
  | "provider_deprecated"
  | "provider_missing"
  | "model_retired"
  | "missing_sync_threshold"
  | "catalog_stale"
  | "catalog_frozen"
  | "unsupported_type"
  | "invalid_pricing"
  | "price_above_supported_ceiling"
  | "invalid_privacy_metadata"
  | "invalid_capability_metadata"
  | "operator_review_required"
  | "operator_rejected"
  | "independent_quarantine"
  | "not_listed";

export interface StoredModelEligibilityInput {
  modelType: string;
  providerAvailability: string;
  availabilityStatus: string;
  listed: boolean;
  missingSyncCount: number;
  reviewStatus: string;
  quarantineReason: string | null;
  privacyClass: string;
  contextWindow: number | null;
  maxOutputTokens: number | null;
  inputPricePerMillion: number | null;
  outputPricePerMillion: number | null;
  unitPriceUsd: number | null;
  /** Null means the provider is not managed by the synchronized catalog. */
  catalogLastSuccessAt: Date | null;
  catalogStatePresent: boolean;
}

export interface StoredModelEligibilityDecision {
  eligible: boolean;
  reason: ModelEligibilityReason;
  detail: string;
  routingEligible: boolean;
}

/** Quarantines that an explicit operator review is permitted to resolve. */
export const REVIEW_RESOLVABLE_QUARANTINES = new Set([
  "pending_operator_review",
  "price_change_threshold",
  "operator_rejected"
]);

const eligibilityDetails: Record<ModelEligibilityReason, string> = {
  eligible: "Eligible for operator enablement",
  provider_offline: "Provider reports this model offline",
  provider_deprecated: "Provider reports this model deprecated",
  provider_missing: "Model is missing from the provider catalog",
  model_retired: "Model is retired after repeated missing catalog syncs",
  missing_sync_threshold: "Model exceeded the missing-sync safety threshold",
  catalog_stale: "Provider catalog is stale",
  catalog_frozen: "Provider catalog is frozen pending a healthy sync",
  unsupported_type: "Model type has no supported route and billing unit",
  invalid_pricing: "Required pricing is missing or invalid",
  price_above_supported_ceiling: "Price exceeds the supported safety ceiling",
  invalid_privacy_metadata: "Required privacy metadata is invalid",
  invalid_capability_metadata: "Required capability metadata is invalid",
  operator_review_required: "Operator review is required",
  operator_rejected: "Model was rejected by an operator",
  independent_quarantine: "Model has an independent safety quarantine",
  not_listed: "Model is not in the callable catalog"
};

function ineligible(reason: Exclude<ModelEligibilityReason, "eligible">): StoredModelEligibilityDecision {
  return { eligible: false, reason, detail: eligibilityDetails[reason], routingEligible: false };
}

/**
 * Central eligibility decision for a persisted model. Approval uses this after
 * applying reviewed candidate prices to decide whether a review quarantine may
 * be cleared. Enablement uses it again under the row lock immediately before the
 * mutation. Provider/catalog state always wins over operator intent.
 */
export function evaluateStoredModelEligibility(
  model: StoredModelEligibilityInput,
  options: { now?: Date; allowReviewResolvableQuarantine?: boolean; assumeApproved?: boolean } = {}
): StoredModelEligibilityDecision {
  const now = options.now ?? new Date();

  if (model.providerAvailability === "offline") return ineligible("provider_offline");
  if (model.providerAvailability === "deprecated") return ineligible("provider_deprecated");
  if (model.providerAvailability === "missing") return ineligible("provider_missing");
  if (model.availabilityStatus === "retired") return ineligible("model_retired");
  if (model.missingSyncCount >= 3) return ineligible("missing_sync_threshold");
  if (model.availabilityStatus === "frozen") return ineligible("catalog_frozen");

  if (model.catalogStatePresent) {
    if (!model.catalogLastSuccessAt) return ineligible("catalog_frozen");
    if (now.getTime() - model.catalogLastSuccessAt.getTime() > STALE_AFTER_MS) return ineligible("catalog_stale");
  }

  if (!options.assumeApproved) {
    if (model.reviewStatus === "rejected") return ineligible("operator_rejected");
    if (model.reviewStatus !== "approved") return ineligible("operator_review_required");
  }

  if (!["text", "embedding", "image", "tts"].includes(model.modelType)) return ineligible("unsupported_type");
  if (!["anonymous", "private", "tee", "e2ee"].includes(model.privacyClass)) return ineligible("invalid_privacy_metadata");
  if (["text", "embedding"].includes(model.modelType) && (!Number.isInteger(model.contextWindow) || (model.contextWindow ?? 0) <= 0)) {
    return ineligible("invalid_capability_metadata");
  }

  if (model.modelType === "text") {
    if (!Number.isSafeInteger(model.maxOutputTokens) || (model.maxOutputTokens ?? 0) <= 0) {
      return ineligible("invalid_capability_metadata");
    }
    if (
      model.inputPricePerMillion === null || !Number.isFinite(model.inputPricePerMillion) || model.inputPricePerMillion <= 0 ||
      model.outputPricePerMillion === null || !Number.isFinite(model.outputPricePerMillion) || model.outputPricePerMillion <= 0
    ) return ineligible("invalid_pricing");
  } else if (model.modelType === "embedding") {
    if (
      model.inputPricePerMillion === null
      || !Number.isFinite(model.inputPricePerMillion)
      || model.inputPricePerMillion <= 0
    ) return ineligible("invalid_pricing");
  } else if (model.unitPriceUsd === null || !Number.isFinite(model.unitPriceUsd) || model.unitPriceUsd <= 0) {
    return ineligible("invalid_pricing");
  }

  if (findPriceCeilingBreach({
    modelType: model.modelType,
    inputPerMillionUsd: model.inputPricePerMillion,
    outputPerMillionUsd: model.outputPricePerMillion,
    unitUsd: model.unitPriceUsd
  })) return ineligible("price_above_supported_ceiling");

  const reviewResolvableQuarantine = Boolean(
    options.allowReviewResolvableQuarantine &&
    model.quarantineReason &&
    REVIEW_RESOLVABLE_QUARANTINES.has(model.quarantineReason)
  );
  // Quarantine is a fail-closed state in its own right. A malformed legacy or
  // tampered row with no reason must never become callable merely because the
  // reason string is absent. Only an explicitly classified, review-resolvable
  // quarantine may pass while an operator is actively reviewing it.
  if (model.availabilityStatus === "quarantined" && !reviewResolvableQuarantine) {
    return ineligible("independent_quarantine");
  }
  if (model.quarantineReason && !reviewResolvableQuarantine) {
    return ineligible("independent_quarantine");
  }

  if (!model.listed || ["offline", "deprecated", "unsupported", "retired", "frozen"].includes(model.availabilityStatus)) {
    if (model.availabilityStatus === "offline") return ineligible("provider_offline");
    if (model.availabilityStatus === "deprecated") return ineligible("provider_deprecated");
    if (model.availabilityStatus === "retired") return ineligible("model_retired");
    if (model.availabilityStatus === "frozen") return ineligible("catalog_frozen");
    if (model.availabilityStatus === "unsupported") return ineligible("unsupported_type");
    return ineligible("not_listed");
  }

  return {
    eligible: true,
    reason: "eligible",
    detail: eligibilityDetails.eligible,
    routingEligible: model.modelType === "text" && isAutoRoutablePrivacy(model.privacyClass as PrivacyClass)
  };
}

/** Privacy modes whose protocol the platform can actually satisfy end-to-end.
 *  `unknown` is never satisfiable; a route with unknown privacy is not callable. */
export function protocolSupportsPrivacy(privacyClass: PrivacyClass): boolean {
  // anonymous/private use the ordinary inference path; tee runs server-side in an
  // enclave (ordinary API); e2ee has an enforced attestation + ciphertext path
  // (src/metering/e2ee.ts, src/routes/chat.ts). unknown cannot be guaranteed.
  return privacyClass !== "unknown";
}

/** Privacy classes eligible for BLIND automatic routing. TEE/E2EE and unknown are
 *  excluded: automatic routing cannot guarantee the client-side handshake / an
 *  unknown posture, so they are addressable directly but never auto-selected. */
export function isAutoRoutablePrivacy(privacyClass: PrivacyClass): boolean {
  return privacyClass === "anonymous" || privacyClass === "private";
}

/** Types with an implemented inference route AND a deterministic billing unit. */
export function supportsCallableType(model: NormalizedModel): boolean {
  if (model.providerType === "text") return true;
  if (model.providerType === "embedding") return true;
  // image/tts are callable only with a single deterministic flat unit price.
  if (model.providerType === "image") return model.pricing.priceModel === "flat_unit" && model.pricing.unit === "image";
  if (model.providerType === "tts") return model.pricing.priceModel === "flat_unit" && model.pricing.unit === "tts_1m_chars";
  return false;
}

/** Text pricing is valid only when BOTH input and output are finite and > 0. */
export function hasValidTextPricing(model: NormalizedModel): boolean {
  const { inputPerMillionUsd: input, outputPerMillionUsd: output } = model.pricing;
  return (
    input !== null && output !== null && Number.isFinite(input) && Number.isFinite(output) && input > 0 && output > 0
  );
}

/** Embeddings are billed for input tokens only; provider output prices are ignored. */
export function hasValidEmbeddingPricing(model: NormalizedModel): boolean {
  const input = model.pricing.inputPerMillionUsd;
  return input !== null && Number.isFinite(input) && input > 0;
}

/** A callable media route needs a finite, strictly-positive flat unit price. */
export function hasValidUnitPricing(model: NormalizedModel): boolean {
  return model.pricing.unitUsd !== null && Number.isFinite(model.pricing.unitUsd) && model.pricing.unitUsd > 0;
}

function hasValidTextLimits(model: NormalizedModel): boolean {
  return model.contextTokens !== null
    && Number.isInteger(model.contextTokens)
    && model.contextTokens > 0
    && model.maxOutputTokens !== null
    && Number.isSafeInteger(model.maxOutputTokens)
    && model.maxOutputTokens > 0;
}

/**
 * The base enablement decision for a healthy, present model. The apply engine
 * overrides this for offline (immediate), passed-sunset deprecation (immediate),
 * price quarantine, three-strike missing, and >60m stale freeze.
 */
export function baseEnablement(model: NormalizedModel): EnablementDecision {
  // Offline routes are not listed and never callable.
  if (!model.online) {
    return { listed: false, callable: false, routingEnabled: false, status: "offline", reason: "provider_offline" };
  }

  // Valid public metadata (guaranteed by strict normalization) means listable.
  const listed = true;

  if (!supportsCallableType(model)) {
    return { listed, callable: false, routingEnabled: false, status: "unsupported", reason: "unsupported_type" };
  }

  if (model.providerType === "text" || model.providerType === "embedding") {
    if (!protocolSupportsPrivacy(model.privacyClass)) {
      return { listed, callable: false, routingEnabled: false, status: "unsupported", reason: "unknown_privacy" };
    }
    if (
      model.contextTokens === null
      || !Number.isInteger(model.contextTokens)
      || model.contextTokens <= 0
      || (model.providerType === "text" && !hasValidTextLimits(model))
    ) {
      return { listed, callable: false, routingEnabled: false, status: "unsupported", reason: "invalid_limits" };
    }
    if (model.providerType === "text" ? !hasValidTextPricing(model) : !hasValidEmbeddingPricing(model)) {
      // Never enable at $0: list it, hold it out of inference until priced.
      return { listed, callable: false, routingEnabled: false, status: "unsupported", reason: "invalid_pricing" };
    }
    return {
      listed,
      callable: true,
      routingEnabled: model.providerType === "text" && isAutoRoutablePrivacy(model.privacyClass),
      status: "available",
      reason: "ok"
    };
  }

  // image / tts flat-unit routes.
  if (!hasValidUnitPricing(model)) {
    return { listed, callable: false, routingEnabled: false, status: "unsupported", reason: "invalid_unit_price" };
  }
  return { listed, callable: true, routingEnabled: false, status: "available", reason: "ok" };
}

// --- absolute price ceilings -------------------------------------------------
//
// The relative quarantine (below) protects EXISTING models by comparing against
// their last-known-good price. A first-seen model has no such history, so a
// malformed first-seen price could pass the positive/finite check and become
// callable. These fixed, per-category ABSOLUTE ceilings are the safety floor for
// that case; they also catch an existing model that crosses the ceiling without
// tripping the relative threshold.
//
// The ceilings are 1.5x the highest observed price in the trusted Venice catalog
// of 2026-07-17 (source_hash e921c43f8af4c71747891c3374b5cccc95d18c847a0fadada515e9bf3e341e9f,
// 288 models). Current catalog maximums used to derive them:
//   text input   $37.50/1M  -> ceiling $56.25/1M
//   text output  $225.00/1M -> ceiling $337.50/1M
//   embeddings   $0.25/1M input -> ceiling $1.00/1M
//   image        $0.29/img  -> ceiling $0.435/img
//   tts          $187.50/1M chars -> ceiling $281.25/1M chars
//
// They are FIXED constants, deliberately NOT derived from any incoming snapshot,
// so malformed provider data can never raise its own ceiling. Units are kept
// strictly separate: image, TTS, token-input and token-output prices are each
// compared only against their own ceiling. A legitimate future model priced above
// a ceiling requires MANUAL review and an intentional edit to these constants.
//
// Cache prices are provider-published optional rates. Authorization reserves
// all prompt tokens at the maximum of ordinary input, cache-read, and
// cache-write rates, so a cache-write premium cannot exceed the prepaid ceiling.
export const ABSOLUTE_PRICE_CEILINGS = {
  textInputPerMillionUsd: 56.25,
  textOutputPerMillionUsd: 337.5,
  embeddingInputPerMillionUsd: 1,
  imageUnitUsd: 0.435,
  ttsPerMillionCharsUsd: 281.25
} as const;

export type PriceCeilingCategory = "text_input" | "text_output" | "embedding_input" | "image" | "tts";

export interface PriceCeilingBreach {
  /** Which billing field/category exceeded its ceiling. */
  category: PriceCeilingCategory;
  /** The configured ceiling that was exceeded. */
  ceiling: number;
  /** The offending value. */
  value: number;
}

// Model-type buckets that select which ceilings apply. `other` types have no
// callable billing unit and are never ceiling-checked.
function ceilingModelType(modelType: string): "text" | "embedding" | "image" | "tts" | "other" {
  return modelType === "text" || modelType === "embedding" || modelType === "image" || modelType === "tts" ? modelType : "other";
}

/**
 * The single source of truth for absolute ceiling checks, shared by catalog apply,
 * the manual admin pricing route, and runtime authorization. Returns the first
 * per-category ceiling a set of prices breaches, or null if all are within their
 * ceilings. A price exactly equal to its ceiling is valid (strict `>`). Units are
 * strictly separate: only prices for the model's own category are checked, each
 * against its own ceiling.
 */
export function findPriceCeilingBreach(params: {
  modelType: string;
  inputPerMillionUsd?: number | null;
  outputPerMillionUsd?: number | null;
  unitUsd?: number | null;
}): PriceCeilingBreach | null {
  const c = ABSOLUTE_PRICE_CEILINGS;
  switch (ceilingModelType(params.modelType)) {
    case "text":
      if (params.inputPerMillionUsd != null && params.inputPerMillionUsd > c.textInputPerMillionUsd) {
        return { category: "text_input", ceiling: c.textInputPerMillionUsd, value: params.inputPerMillionUsd };
      }
      if (params.outputPerMillionUsd != null && params.outputPerMillionUsd > c.textOutputPerMillionUsd) {
        return { category: "text_output", ceiling: c.textOutputPerMillionUsd, value: params.outputPerMillionUsd };
      }
      return null;
    case "embedding":
      if (params.inputPerMillionUsd != null && params.inputPerMillionUsd > c.embeddingInputPerMillionUsd) {
        return { category: "embedding_input", ceiling: c.embeddingInputPerMillionUsd, value: params.inputPerMillionUsd };
      }
      return null;
    case "image":
      if (params.unitUsd != null && params.unitUsd > c.imageUnitUsd) {
        return { category: "image", ceiling: c.imageUnitUsd, value: params.unitUsd };
      }
      return null;
    case "tts":
      if (params.unitUsd != null && params.unitUsd > c.ttsPerMillionCharsUsd) {
        return { category: "tts", ceiling: c.ttsPerMillionCharsUsd, value: params.unitUsd };
      }
      return null;
    default:
      return null;
  }
}

/** Whether a normalized model's prices exceed any absolute ceiling. */
export function exceedsAbsolutePriceCeiling(model: NormalizedModel): boolean {
  return (
    findPriceCeilingBreach({
      modelType: model.providerType,
      inputPerMillionUsd: model.pricing.inputPerMillionUsd,
      outputPerMillionUsd: model.pricing.outputPerMillionUsd,
      unitUsd: model.pricing.unitUsd
    }) !== null
  );
}

/**
 * Whether a live `providers.models` row's stored prices exceed any absolute
 * ceiling. Used as a fail-closed defense-in-depth check at runtime authorization,
 * so a tampered/legacy enabled row can never be billed above the ceiling.
 */
export function modelRowCeilingBreach(row: {
  modelType: string;
  inputPricePerMillion: number | null;
  outputPricePerMillion: number | null;
  unitPriceUsd: number | null;
}): PriceCeilingBreach | null {
  return findPriceCeilingBreach({
    modelType: row.modelType,
    inputPerMillionUsd: row.inputPricePerMillion,
    outputPerMillionUsd: row.outputPricePerMillion,
    unitUsd: row.unitPriceUsd
  });
}

// --- price quarantine thresholds --------------------------------------------

export interface PriceQuarantineInput {
  /** Previous accepted value for the billing field, or null if none/new. */
  previous: number | null;
  /** Proposed new value, or null if missing/malformed. */
  next: number | null;
}

/**
 * Whether a single sync's change to ONE existing billing field is large enough
 * to quarantine the model: a >100% increase or a >50% decrease relative to the
 * last accepted value. Establishing a first price (previous null/<=0) is governed
 * by enablement, not quarantine. A previously-priced field becoming missing or
 * non-positive is a full decrease and quarantines (never bill at zero).
 */
export function isPriceQuarantineTriggered({ previous, next }: PriceQuarantineInput): boolean {
  if (previous === null || previous <= 0) return false; // no baseline: not a change to an existing field
  if (next === null || next <= 0) return true; // priced -> unpriced/zero on an enabled field
  if (next > previous * 2) return true; // > 100% increase
  if (next < previous * 0.5) return true; // > 50% decrease
  return false;
}

/** All billing fields that participate in quarantine, compared pairwise. */
export function anyPriceQuarantineTriggered(
  previous: { input: number | null; output: number | null; unit: number | null },
  next: { input: number | null; output: number | null; unit: number | null }
): boolean {
  return (
    isPriceQuarantineTriggered({ previous: previous.input, next: next.input }) ||
    isPriceQuarantineTriggered({ previous: previous.output, next: next.output }) ||
    isPriceQuarantineTriggered({ previous: previous.unit, next: next.unit })
  );
}
