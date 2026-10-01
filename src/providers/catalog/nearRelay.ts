// NEAR AI relayed (non-TEE) routes.
//
// NEAR AI Cloud's unified `/v1/models` mixes three route classes behind one
// gateway (`cloud-api.near.ai`):
//
//   direct TEE      owned_by "nearai", served from {slug}.completions.near.ai
//   attested 3p     owned_by "attested 3p", a partner TEE behind the gateway
//   RELAYED         owned_by a third-party lab (anthropic, openai, google, x-ai,
//                   deepseek, qwen, typesafe). NEAR's gateway forwards the
//                   request to that lab's (or an aggregator's) API on NEAR's own
//                   account. Nothing about these routes is attestable.
//
// The first two are handled by ./nearNormalize.ts (confidential tiers). This
// module handles ONLY the third, and it can never produce `tee` or `e2ee`: the
// privacy class comes from the reviewed family table below, whose type admits
// only `anonymous` and `private`.
//
// WHAT IS REVIEWED, AND WHAT IS NOT. Every route here is in a hand-reviewed
// identity + privacy table (NEAR_RELAY_ROUTES). A route is `catalog-reviewed`
// only while its live catalog entry still matches the generated fingerprint in
// ./nearRelayReviewed.generated.ts, which binds owner, limits, modalities,
// capability flags, accepted sampling parameters and every published price tier.
// Drift demotes the route to `provider-discovered` (pending review) through the
// manifest scheme in ./reviewEvidence.ts. A NEAR model that is not in the table
// is dropped entirely: a new upstream lab needs a privacy review before it can
// even be listed. Reachability is a separate gate (operator enablement after a
// live canary; see docs/hardware-verification/status/near-relay.md).

import { createHash } from "node:crypto";
import type {
  NormalizedModel,
  NormalizedReasoningCapabilities,
  RoutingProfile
} from "./normalized.js";
import type { ReasoningEffortLevel } from "../../inference/reasoning.js";
import { NEAR_RELAY_REVIEWED_ROUTES } from "./nearRelayReviewed.generated.js";
import { providerQualifiedRouteId, publicProviderName } from "../publicIdentity.js";

// PUBLIC COPY IS WHITE-LABELLED. NEAR AI's approval to offer these models is
// conditional on listing them under the public provider "Other" rather than
// under NEAR's name (../publicIdentity.ts). Everything that lands in
// `publicMetadata` (route id, provider name, summaries, notes, pricing and
// status notes, source references) therefore says "the provider" and links to
// the UPSTREAM developer's own retention terms, never to NEAR's pages. The facts
// are unchanged; their NEAR citations live in
// docs/hardware-verification/status/near-relay.md. Comments and internal fields
// (traits, review manifest) may name NEAR.
const INTERNAL_PROVIDER = "near-ai";
const ANTHROPIC_RETENTION_SOURCE = { label: "Anthropic API data retention", url: "https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-my-organization-s-data" };
const OPENAI_DATA_SOURCE = { label: "OpenAI API data controls", url: "https://developers.openai.com/api/docs/guides/your-data" };
const GEMINI_TERMS_SOURCE = { label: "Gemini API terms", url: "https://ai.google.dev/gemini-api/terms" };
// Families served through a third-party routing service link no source: the
// service is not named in public copy (no competing router or infrastructure
// vendor is), and the developer behind it publishes nothing that covers this
// path. The facts and their citations are in near-relay.md.

/** owned_by values NEAR uses for its relayed (non-TEE) upstream routes. */
export const NEAR_RELAY_OWNERS: ReadonlySet<string> = new Set([
  "anthropic",
  "openai",
  "google",
  "x-ai",
  "deepseek",
  "qwen",
  "typesafe"
]);

/** Fingerprint material version. Bump when the material shape changes. */
const FINGERPRINT_VERSION = 1;

type RelayPrivacyClass = "anonymous" | "private";

/**
 * One reviewed privacy posture per upstream family. The class is a decision,
 * recorded with its reasons; it is part of every route's fingerprint, so
 * changing it re-requires a review.
 */
interface RelayPrivacyFamily {
  privacyClass: RelayPrivacyClass;
  /**
   * Whether a cached-prompt discount can ever apply on this family's routes,
   * which decides whether the route publishes NEAR's cache-read price at all.
   *
   *   automatic    the upstream caches by itself (OpenAI, and the hosts behind
   *                the routing service) and NEAR passes the cached and
   *                cache-write counts through in `prompt_tokens_details`, so
   *                they bill at NEAR's published cache-read / cache-write prices.
   *   unavailable  no discount can occur. Anthropic caches only at explicit
   *                `cache_control` breakpoints, which shapeNearRelayBody strips
   *                (NEAR adds none of its own), so no cache WRITE is ever
   *                created: NEAR bills Anthropic writes at 1.25x input, a rate
   *                it does not publish. NEAR's Gemini path reports no cached
   *                tokens at all and bills them as ordinary input. Every prompt
   *                token on these routes therefore bills at the input price.
   *
   * See "Prompt caching and cache billing" in
   * docs/hardware-verification/status/near-relay.md.
   */
  promptCaching: "automatic" | "unavailable";
  /** Who actually serves the model after NEAR's gateway. Public copy. */
  upstream: string;
  /** Public copy: never names NEAR (see the header note). */
  summary: string;
  notes: string[];
  /** The upstream's own data-handling terms, shown as the route's sources. */
  sources: Array<{ label: string; url: string }>;
}

// Facts behind every note below were read on 2026-10-01 from NEAR's terms
// (Sept 24, 2026: section 7.3 Incognito Routes, section 10.2 no training), its
// models documentation, the public `GET /v1/model/list` provider configuration,
// and the published nearai/cloud-api source. See
// docs/hardware-verification/status/near-relay.md for quotes and URLs.
const COMMON_RELAY_NOTE =
  "This is a relayed route: the provider's gateway forwards the prompt to the model's developer, or to an aggregator, using the provider's own account. The model runs outside any TEE and nothing about the serving path is attested.";
const IDENTITY_NOTE =
  "AnonRouter calls the provider with its own account and forwards no end-user identity or user field. The upstream developer can see the provider's account identifier, which all AnonRouter traffic shares, and anything inside the prompt itself.";
const TRAINING_NOTE =
  "The provider's terms say it will not use customer data to train models. That promise does not bind the upstream developer, whose own terms and retention apply.";

export const NEAR_RELAY_FAMILIES = {
  anthropic: {
    privacyClass: "anonymous",
    promptCaching: "unavailable",
    upstream: "Anthropic",
    summary: "Identity-shielded relay to Anthropic; not hardware-protected, and zero retention is not guaranteed",
    notes: [
      COMMON_RELAY_NOTE,
      IDENTITY_NOTE,
      TRAINING_NOTE,
      "The provider calls Anthropic's API directly. Anthropic's standard API retention applies (inputs and outputs deleted within 30 days, longer for policy violations), and the provider publishes no zero-retention agreement for its account."
    ],
    sources: [ANTHROPIC_RETENTION_SOURCE]
  },
  openai: {
    privacyClass: "anonymous",
    promptCaching: "automatic",
    upstream: "OpenAI",
    summary: "Identity-shielded relay to OpenAI; not hardware-protected, and zero retention is not guaranteed",
    notes: [
      COMMON_RELAY_NOTE,
      IDENTITY_NOTE,
      TRAINING_NOTE,
      "The provider calls OpenAI's API directly. OpenAI's standard API policy applies (abuse-monitoring logs kept up to 30 days), and the provider publishes no zero-retention approval for its account."
    ],
    sources: [OPENAI_DATA_SOURCE]
  },
  google: {
    privacyClass: "anonymous",
    promptCaching: "unavailable",
    upstream: "Google",
    summary: "Identity-shielded relay to Google Gemini; not hardware-protected, and zero retention is not guaranteed",
    notes: [
      COMMON_RELAY_NOTE,
      IDENTITY_NOTE,
      TRAINING_NOTE,
      "The provider calls the Gemini Developer API directly. Google logs prompts for a limited period for abuse monitoring, and the provider does not publish which Gemini API tier its account uses."
    ],
    sources: [GEMINI_TERMS_SOURCE]
  },
  "x-ai": {
    privacyClass: "anonymous",
    promptCaching: "automatic",
    upstream: "xAI via a third-party routing service",
    summary: "Identity-shielded relay to xAI through a third-party routing service; not hardware-protected, and zero retention is not guaranteed end to end",
    notes: [
      COMMON_RELAY_NOTE,
      IDENTITY_NOTE,
      TRAINING_NOTE,
      "The provider's published routing configuration sends this model through a third-party routing service to xAI's zero-data-retention endpoint, with fallbacks off. That is the provider's configuration, not a commitment to customers, and the provider's own gateway retention is undocumented, so the route is not classified Private."
    ],
    sources: []
  },
  "deepseek-openrouter": {
    privacyClass: "anonymous",
    promptCaching: "automatic",
    upstream: "a single zero-retention host via a third-party routing service",
    summary: "Identity-shielded relay to a third-party host through a routing service; not hardware-protected, and zero retention is not guaranteed end to end",
    notes: [
      COMMON_RELAY_NOTE,
      IDENTITY_NOTE,
      TRAINING_NOTE,
      "The provider says this model is served through a third-party routing service using zero-data-retention endpoints, and its published routing pins one such host with fallbacks off. That covers the host, not the provider's own gateway, whose retention is undocumented, so the route is not classified Private."
    ],
    sources: []
  },
  qwen: {
    privacyClass: "anonymous",
    promptCaching: "automatic",
    upstream: "a host chosen by a third-party routing service",
    summary: "Identity-shielded relay through a third-party routing service; not hardware-protected, and zero retention is not guaranteed",
    notes: [
      COMMON_RELAY_NOTE,
      IDENTITY_NOTE,
      TRAINING_NOTE,
      "The provider routes this model through a third-party routing service with no zero-data-retention restriction, so neither the serving host nor its retention is fixed."
    ],
    sources: []
  }
} as const satisfies Record<string, RelayPrivacyFamily>;

export type NearRelayFamily = keyof typeof NEAR_RELAY_FAMILIES;

export interface NearRelayRoute {
  /** The live owned_by this route must still report; anything else drops it. */
  owner: string;
  family: NearRelayFamily;
  /** Provider-qualified public route id suffix (other/<slug>; see ../publicIdentity.ts). */
  slug: string;
  /** Creator/model id shared with every other provider's route for the model. */
  canonicalId: string;
  displayName: string;
  qualityTier: number;
  /**
   * Reasoning efforts NEAR is documented to accept for this model. Absent means
   * none are attested: a reasoning model is then listed as reasoning, but a
   * request that sets an effort or disables reasoning is refused rather than
   * forwarded on hope.
   */
  reasoningEfforts?: readonly ReasoningEffortLevel[];
  codeOptimized?: boolean;
}

/**
 * The reviewed relay table. Canonical ids are the ones already used by other
 * providers' routes for the same model (so a NEAR route joins the existing model
 * page instead of creating a duplicate). `typesafe/jev-1.13` is deliberately
 * absent: it is a structured-decision model (output modality "decisions", no
 * output price), not a chat model, and has no billing unit here.
 */
export const NEAR_RELAY_ROUTES: Readonly<Record<string, NearRelayRoute>> = {
  "anthropic/claude-fable-5": { owner: "anthropic", family: "anthropic", slug: "claude-fable-5", canonicalId: "anthropic/claude-fable-5", displayName: "Claude Fable 5", qualityTier: 5 },
  "anthropic/claude-fable-5-1": { owner: "anthropic", family: "anthropic", slug: "claude-fable-5.1", canonicalId: "anthropic/claude-fable-5.1", displayName: "Claude Fable 5.1", qualityTier: 5 },
  "anthropic/claude-haiku-4-5": { owner: "anthropic", family: "anthropic", slug: "claude-haiku-4.5", canonicalId: "anthropic/claude-haiku-4-5", displayName: "Claude Haiku 4.5", qualityTier: 3 },
  "anthropic/claude-opus-4-6": { owner: "anthropic", family: "anthropic", slug: "claude-opus-4.6", canonicalId: "anthropic/claude-opus-4.6", displayName: "Claude Opus 4.6", qualityTier: 5 },
  "anthropic/claude-opus-4-7": { owner: "anthropic", family: "anthropic", slug: "claude-opus-4.7", canonicalId: "anthropic/claude-opus-4.7", displayName: "Claude Opus 4.7", qualityTier: 5 },
  "anthropic/claude-opus-4-8": { owner: "anthropic", family: "anthropic", slug: "claude-opus-4.8", canonicalId: "anthropic/claude-opus-4.8", displayName: "Claude Opus 4.8", qualityTier: 5 },
  "anthropic/claude-opus-5": { owner: "anthropic", family: "anthropic", slug: "claude-opus-5", canonicalId: "anthropic/claude-opus-5", displayName: "Claude Opus 5", qualityTier: 5 },
  "anthropic/claude-opus-5-5": { owner: "anthropic", family: "anthropic", slug: "claude-opus-5.5", canonicalId: "anthropic/claude-opus-5.5", displayName: "Claude Opus 5.5", qualityTier: 5 },
  "anthropic/claude-sonnet-4-5": { owner: "anthropic", family: "anthropic", slug: "claude-sonnet-4.5", canonicalId: "anthropic/claude-sonnet-4.5", displayName: "Claude Sonnet 4.5", qualityTier: 4 },
  "anthropic/claude-sonnet-4-6": { owner: "anthropic", family: "anthropic", slug: "claude-sonnet-4.6", canonicalId: "anthropic/claude-sonnet-4.6", displayName: "Claude Sonnet 4.6", qualityTier: 4 },
  "anthropic/claude-sonnet-5": { owner: "anthropic", family: "anthropic", slug: "claude-sonnet-5", canonicalId: "anthropic/claude-sonnet-5", displayName: "Claude Sonnet 5", qualityTier: 5 },
  "anthropic/claude-sonnet-5-5": { owner: "anthropic", family: "anthropic", slug: "claude-sonnet-5.5", canonicalId: "anthropic/claude-sonnet-5.5", displayName: "Claude Sonnet 5.5", qualityTier: 5 },

  "deepseek/deepseek-v4.1-flash": { owner: "deepseek", family: "deepseek-openrouter", slug: "deepseek-v4.1-flash", canonicalId: "deepseek/deepseek-v4.1-flash", displayName: "DeepSeek V4.1 Flash", qualityTier: 4 },

  "google/gemini-2.5-flash": { owner: "google", family: "google", slug: "gemini-2.5-flash", canonicalId: "google/gemini-2.5-flash", displayName: "Gemini 2.5 Flash", qualityTier: 3 },
  "google/gemini-2.5-flash-lite": { owner: "google", family: "google", slug: "gemini-2.5-flash-lite", canonicalId: "google/gemini-2.5-flash-lite", displayName: "Gemini 2.5 Flash-Lite", qualityTier: 2 },
  "google/gemini-2.5-pro": { owner: "google", family: "google", slug: "gemini-2.5-pro", canonicalId: "google/gemini-2.5-pro", displayName: "Gemini 2.5 Pro", qualityTier: 4 },
  "google/gemini-3.1-flash-lite": { owner: "google", family: "google", slug: "gemini-3.1-flash-lite", canonicalId: "google/gemini-3.1-flash-lite", displayName: "Gemini 3.1 Flash-Lite", qualityTier: 3 },
  "google/gemini-3.5-flash": { owner: "google", family: "google", slug: "gemini-3.5-flash", canonicalId: "google/gemini-3.5-flash", displayName: "Gemini 3.5 Flash", qualityTier: 4 },
  "google/gemini-3.8-flash": { owner: "google", family: "google", slug: "gemini-3.8-flash", canonicalId: "google/gemini-3.8-flash", displayName: "Gemini 3.8 Flash", qualityTier: 4 },

  "openai/gpt-4.1": { owner: "openai", family: "openai", slug: "gpt-4.1", canonicalId: "openai/gpt-4.1", displayName: "GPT-4.1", qualityTier: 4 },
  "openai/gpt-4.1-mini": { owner: "openai", family: "openai", slug: "gpt-4.1-mini", canonicalId: "openai/gpt-4.1-mini", displayName: "GPT-4.1 Mini", qualityTier: 3 },
  "openai/gpt-4.1-nano": { owner: "openai", family: "openai", slug: "gpt-4.1-nano", canonicalId: "openai/gpt-4.1-nano", displayName: "GPT-4.1 Nano", qualityTier: 2 },
  "openai/gpt-5": { owner: "openai", family: "openai", slug: "gpt-5", canonicalId: "openai/gpt-5", displayName: "GPT-5", qualityTier: 5 },
  "openai/gpt-5-mini": { owner: "openai", family: "openai", slug: "gpt-5-mini", canonicalId: "openai/gpt-5-mini", displayName: "GPT-5 Mini", qualityTier: 4 },
  "openai/gpt-5-nano": { owner: "openai", family: "openai", slug: "gpt-5-nano", canonicalId: "openai/gpt-5-nano", displayName: "GPT-5 Nano", qualityTier: 3 },
  "openai/gpt-5.1": { owner: "openai", family: "openai", slug: "gpt-5.1", canonicalId: "openai/gpt-5.1", displayName: "GPT-5.1", qualityTier: 5 },
  "openai/gpt-5.2": { owner: "openai", family: "openai", slug: "gpt-5.2", canonicalId: "openai/gpt-5.2", displayName: "GPT-5.2", qualityTier: 5 },
  "openai/gpt-5.4": { owner: "openai", family: "openai", slug: "gpt-5.4", canonicalId: "openai/gpt-5.4", displayName: "GPT-5.4", qualityTier: 5 },
  "openai/gpt-5.4-mini": { owner: "openai", family: "openai", slug: "gpt-5.4-mini", canonicalId: "openai/gpt-5.4-mini", displayName: "GPT-5.4 Mini", qualityTier: 4 },
  "openai/gpt-5.4-nano": { owner: "openai", family: "openai", slug: "gpt-5.4-nano", canonicalId: "openai/gpt-5.4-nano", displayName: "GPT-5.4 Nano", qualityTier: 3 },
  "openai/gpt-5.5": { owner: "openai", family: "openai", slug: "gpt-5.5", canonicalId: "openai/gpt-5.5", displayName: "GPT-5.5", qualityTier: 5 },
  "openai/gpt-5.6-luna": { owner: "openai", family: "openai", slug: "gpt-5.6-luna", canonicalId: "openai/gpt-5.6-luna", displayName: "GPT-5.6 Luna", qualityTier: 4 },
  "openai/gpt-5.6-sol": { owner: "openai", family: "openai", slug: "gpt-5.6-sol", canonicalId: "openai/gpt-5.6-sol", displayName: "GPT-5.6 Sol", qualityTier: 5 },
  "openai/gpt-6-astra": { owner: "openai", family: "openai", slug: "gpt-6-astra", canonicalId: "openai/gpt-6-astra", displayName: "GPT-6 Astra", qualityTier: 5 },
  "openai/gpt-6-luna": { owner: "openai", family: "openai", slug: "gpt-6-luna", canonicalId: "openai/gpt-6-luna", displayName: "GPT-6 Luna", qualityTier: 4 },
  "openai/gpt-6-sol": { owner: "openai", family: "openai", slug: "gpt-6-sol", canonicalId: "openai/gpt-6-sol", displayName: "GPT-6 Sol", qualityTier: 5 },
  "openai/gpt-6.1-sol": { owner: "openai", family: "openai", slug: "gpt-6.1-sol", canonicalId: "openai/gpt-6.1-sol", displayName: "GPT-6.1 Sol", qualityTier: 5 },
  "openai/o3": { owner: "openai", family: "openai", slug: "o3", canonicalId: "openai/o3", displayName: "o3", qualityTier: 5 },
  "openai/o3-mini": { owner: "openai", family: "openai", slug: "o3-mini", canonicalId: "openai/o3-mini", displayName: "o3 Mini", qualityTier: 4 },
  "openai/o4-mini": { owner: "openai", family: "openai", slug: "o4-mini", canonicalId: "openai/o4-mini", displayName: "o4 Mini", qualityTier: 4 },

  "qwen/qwen3.7-max": { owner: "qwen", family: "qwen", slug: "qwen3.7-max", canonicalId: "qwen/qwen-3.7-max", displayName: "Qwen 3.7 Max", qualityTier: 5 },

  "x-ai/grok-4.6": { owner: "x-ai", family: "x-ai", slug: "grok-4.6", canonicalId: "x-ai/grok-4.6", displayName: "Grok 4.6", qualityTier: 5 },
  "x-ai/grok-4.7": { owner: "x-ai", family: "x-ai", slug: "grok-4.7", canonicalId: "x-ai/grok-4.7", displayName: "Grok 4.7", qualityTier: 5 }
};

/**
 * Relayed NEAR models deliberately left out of the table, with the reason. The
 * audit script reports these as excluded rather than as unreviewed.
 */
export const NEAR_RELAY_EXCLUDED: Readonly<Record<string, string>> = {
  "typesafe/jev-1.13": "structured-decision model served on NEAR's /v1/systemone endpoint (output modality \"decisions\", no output price); not a chat model and no billing unit exists for it"
};

/** The NEAR catalog fields this module reads. Everything else is ignored. */
export interface RawNearRelayModel {
  id?: unknown;
  owned_by?: unknown;
  pricing?: unknown;
  textPricing?: unknown;
  context_length?: unknown;
  max_output_length?: unknown;
  input_modalities?: unknown;
  output_modalities?: unknown;
  supported_features?: unknown;
  supported_sampling_parameters?: unknown;
  is_ready?: unknown;
  deprecation_date?: unknown;
}

function string(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function integer(value: unknown): number | null {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

function positive(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

function micros(value: number): number {
  // Billing columns are numeric(14,6); per-token strings scaled by 1e6 carry
  // binary float noise (0.000000125 * 1e6 = 0.12499999999999999).
  return Number(value.toFixed(6));
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string").map((entry) => entry.trim().toLowerCase())
    : [];
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function stable(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== "object") return value ?? null;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, stable(entry)])
  );
}

/** NEAR's published standard ("default") tier for a text route, when present. */
interface DefaultTier {
  cacheWrite: number | null;
  /** Input tokens above which NEAR bills the `long` tier, if it publishes one. */
  longContextThreshold: number | null;
  /**
   * NEAR publishes a `long` tier but no usable threshold. The base tier's
   * extent is then unknown, so the route cannot be capped below it: fail
   * closed (no context, not callable) rather than admit any prompt length.
   */
  longTierWithoutThreshold: boolean;
}

function defaultTier(candidate: RawNearRelayModel): DefaultTier {
  const textPricing = record(candidate.textPricing);
  const tiers = record(textPricing?.tiers);
  const short = record(record(tiers?.default)?.short);
  const hasLong = record(record(tiers?.default)?.long) !== null;
  const threshold = hasLong ? integer(textPricing?.longContextThreshold) : null;
  return {
    cacheWrite: positive(short?.cacheWrite),
    longContextThreshold: threshold,
    longTierWithoutThreshold: hasLong && threshold === null
  };
}

/**
 * UPSTREAM long-context price tiers that NEAR does not publish.
 *
 * THE RULE. A relayed route's accepted context is capped at the base-tier
 * threshold whenever a prompt longer than that could be billed at a higher
 * rate by anyone in the chain:
 *   (a) NEAR publishes a long tier (`textPricing.longContextThreshold`), or
 *   (b) the upstream developer's own price list has a prompt-length tier for
 *       the model, or
 *   (c) the model belongs to a family the developer prices by prompt length,
 *       so a new member is capped until a review shows it is flat.
 * The lowest applicable threshold wins. With the cap every admitted prompt
 * stays in the base tier AnonRouter bills.
 *
 * WHY (b) AND (c) MATTER WHEN NEAR IS FLAT. NEAR bills a model without
 * `textPricing` at one rate today (nearai/cloud-api text_pricing.rs), so for
 * such a model the upstream's surcharge is NEAR's loss, not ours. Nothing
 * stops NEAR passing it on (its terms let it change pricing and routing), and
 * a surcharge we did not bill would be ours. The cap removes that exposure.
 *
 * Reviewed 2026-10-01 against each developer's pricing page (citations in
 * docs/hardware-verification/status/near-relay.md): of the relayed models
 * without a NEAR tier, only Gemini 2.5 Pro is tiered upstream. Anthropic
 * ("Claude 4.6 and later models ... include the full 1M token context window
 * at standard pricing"), Gemini Flash and Flash-Lite, GPT-4.1, GPT-5 to 5.2,
 * DeepSeek V4.1 Flash and Qwen 3.7 Max are flat.
 */
export interface NearRelayUpstreamLongContextTier {
  /** What the entry covers, for the review record. */
  readonly family: string;
  /** Matches NEAR's model id (the reviewed table's key). */
  readonly match: RegExp;
  /** Largest prompt the upstream still bills at its base rate. */
  readonly thresholdTokens: number;
  readonly source: string;
}

export const NEAR_RELAY_UPSTREAM_LONG_CONTEXT_TIERS: readonly NearRelayUpstreamLongContextTier[] = [
  {
    // "$1.25, prompts <= 200k tokens / $2.50, prompts > 200k tokens"; Gemini
    // 3 Pro and 3.1 Pro split at the same 200k.
    family: "Gemini Pro",
    match: /^google\/gemini-\d+(?:\.\d+)*-pro(?:-|$)/,
    thresholdTokens: 200_000,
    source: "https://ai.google.dev/gemini-api/docs/pricing"
  },
  {
    // Sonnet 4 and 4.5 billed prompts above 200k tokens at long-context rates
    // (Claude 4.6 and later are flat). NEAR lists Sonnet 4.5 at 200k already.
    family: "Claude Sonnet 4 and 4.5",
    match: /^anthropic\/claude-sonnet-4(?:-5)?$/,
    thresholdTokens: 200_000,
    source: "https://platform.claude.com/docs/en/about-claude/pricing"
  }
];

/** The upstream base-tier threshold for a relayed NEAR model id, or null when flat. */
export function nearRelayUpstreamLongContextThreshold(providerModelId: string): number | null {
  const thresholds = NEAR_RELAY_UPSTREAM_LONG_CONTEXT_TIERS
    .filter((tier) => tier.match.test(providerModelId))
    .map((tier) => tier.thresholdTokens);
  return thresholds.length === 0 ? null : Math.min(...thresholds);
}

/**
 * Sampling parameters NEAR says the model accepts (its own
 * `supported_sampling_parameters`). The adapter forwards only these, plus the
 * transport fields every chat request needs. Exported for the adapter.
 */
export function nearRelaySamplingParameters(candidate: RawNearRelayModel): string[] {
  return stringArray(candidate.supported_sampling_parameters).sort();
}

/**
 * Fingerprint of every live field that can change the public identity, privacy
 * label, callable surface, limits or billable price of a relay route, plus the
 * reviewed decision itself. `is_ready`, `name`, `description` and `created` are
 * deliberately excluded: availability is a separate signal and the display text
 * is ours, not NEAR's.
 */
export function nearRelayReviewFingerprint(candidate: RawNearRelayModel): string | null {
  const providerModelId = string(candidate.id);
  if (!providerModelId) return null;
  const route = NEAR_RELAY_ROUTES[providerModelId];
  if (!route) return null;
  const pricing = record(candidate.pricing);
  const material = {
    version: FINGERPRINT_VERSION,
    providerModelId,
    owner: string(candidate.owned_by)?.toLowerCase() ?? null,
    route: stable({ ...route, privacyClass: NEAR_RELAY_FAMILIES[route.family].privacyClass }),
    contextLength: candidate.context_length ?? null,
    maxOutputLength: candidate.max_output_length ?? null,
    inputModalities: stringArray(candidate.input_modalities).sort(),
    outputModalities: stringArray(candidate.output_modalities).sort(),
    features: stringArray(candidate.supported_features).sort(),
    samplingParameters: nearRelaySamplingParameters(candidate),
    pricing: stable({
      input: pricing?.input,
      output: pricing?.output,
      prompt: pricing?.prompt,
      completion: pricing?.completion,
      input_cache_read: pricing?.input_cache_read,
      image: pricing?.image,
      request: pricing?.request
    }),
    textPricing: stable(candidate.textPricing ?? null)
  };
  return createHash("sha256").update(JSON.stringify(material)).digest("hex");
}

function positiveNumber(value: unknown): boolean {
  const number = typeof value === "number" ? value : Number(value);
  return value !== null && value !== undefined && value !== "" && Number.isFinite(number) && number > 0;
}

/**
 * Why a table route cannot be attested from this catalog entry, or null when it
 * can. These are the review criteria the manifest generator applies
 * (scripts/audit-near-relay-models.ts): a route that fails any of them is never
 * written to the manifest and stays listed-only.
 */
export function nearRelayReviewRejection(candidate: RawNearRelayModel): string | null {
  const id = string(candidate.id) ?? "";
  const route = NEAR_RELAY_ROUTES[id];
  if (!route) return "not in the reviewed relay table";
  const owner = string(candidate.owned_by)?.toLowerCase() ?? null;
  if (owner !== route.owner) return `owned_by is ${JSON.stringify(owner)}, reviewed as ${JSON.stringify(route.owner)}`;
  const output = stringArray(candidate.output_modalities);
  if (output.length !== 1 || output[0] !== "text") return `output modalities ${JSON.stringify(output)} are not text`;
  const input = stringArray(candidate.input_modalities);
  if (!input.includes("text") || input.some((modality) => modality !== "text" && modality !== "image")) {
    return `input modalities ${JSON.stringify(input)} are not text or text+image`;
  }
  const pricing = record(candidate.pricing);
  if (!positiveNumber(pricing?.input) || !positiveNumber(pricing?.output)) return "input or output price is missing or zero";
  if (integer(candidate.context_length) === null) return "no published context length";
  if (defaultTier(candidate).longTierWithoutThreshold) return "publishes a long-context price tier without a usable longContextThreshold";
  if (integer(candidate.max_output_length) === null) return "no published generation cap (max_output_length)";
  // The adapter's only output bound for a relayed route is max_tokens; without
  // it the billing reservation would be an estimate rather than a bound.
  if (!nearRelaySamplingParameters(candidate).includes("max_tokens")) return "max_tokens is not a supported sampling parameter";
  return null;
}

/** Whether a live entry is still exactly the reviewed one. */
export function isReviewedNearRelayEntry(candidate: RawNearRelayModel): boolean {
  const providerModelId = string(candidate.id);
  if (!providerModelId) return false;
  const reviewed = NEAR_RELAY_REVIEWED_ROUTES[providerModelId];
  return reviewed !== undefined
    && reviewed.catalogFingerprint === nearRelayReviewFingerprint(candidate)
    && nearRelayReviewRejection(candidate) === null;
}

/** NEAR `deprecation_date` (ISO 8601, UTC hour) -> a dated deprecation, or null. */
function nearDeprecation(value: unknown): NormalizedModel["deprecation"] {
  const text = string(value);
  if (!text) return null;
  const at = Date.parse(text);
  return { deprecated: true, sunsetAt: Number.isFinite(at) ? new Date(at).toISOString() : null, replacementModelId: null };
}

const NO_REASONING: NormalizedReasoningCapabilities = {
  supported: false,
  effortConfigurable: false,
  supportedEfforts: [],
  canDisable: false,
  defaultEffort: null,
  alwaysOn: false
};

function relayReasoningCaps(reasoning: boolean, route: NearRelayRoute): NormalizedReasoningCapabilities {
  if (!reasoning) return { ...NO_REASONING, supportedEfforts: [] };
  const efforts = [...(route.reasoningEfforts ?? [])];
  return {
    supported: true,
    effortConfigurable: efforts.length > 0,
    supportedEfforts: efforts,
    // NEAR documents no way to switch reasoning off on a relayed route, so a
    // disable request is refused (reasoning_not_disableable), never forwarded.
    canDisable: false,
    defaultEffort: null,
    alwaysOn: true
  };
}

/**
 * The per-route request shape for a relayed model, derived from the REVIEWED
 * catalog entry (never the live one). Used by the adapter to send only what
 * NEAR documents for the model. Null for anything that is not a relay route.
 */
export interface NearRelayRequestProfile {
  samplingParameters: ReadonlySet<string>;
}

let requestProfiles: ReadonlyMap<string, NearRelayRequestProfile> | null = null;

/** Look up the reviewed request profile for a relay route id. */
export function nearRelayRequestProfile(externalModelId: string): NearRelayRequestProfile | null {
  if (!requestProfiles) {
    const map = new Map<string, NearRelayRequestProfile>();
    for (const [id, reviewed] of Object.entries(NEAR_RELAY_REVIEWED_ROUTES)) {
      if (!NEAR_RELAY_ROUTES[id]) continue;
      map.set(id, { samplingParameters: new Set(reviewed.samplingParameters) });
    }
    requestProfiles = map;
  }
  return requestProfiles.get(externalModelId) ?? null;
}

/** Optional OpenAI sampling fields AnonRouter's chat contract can carry. */
const RELAY_SAMPLING_FIELDS = ["temperature", "top_p", "frequency_penalty", "presence_penalty", "stop", "seed"] as const;

/** Is this native id a NEAR relayed route (reviewed or not)? */
export function isNearRelayRoute(externalModelId: string): boolean {
  return Object.hasOwn(NEAR_RELAY_ROUTES, externalModelId);
}

/**
 * Shape an outbound body for a relayed route. Returns the body unchanged for
 * anything that is not a relay route, so confidential routes (and the request
 * hash their signatures bind) are untouched.
 *
 *  - `user` is always removed. NEAR forwards caller fields it does not model to
 *    OpenAI and OpenRouter upstreams; a client-chosen end-user id must not ride
 *    along on an identity-shielded route.
 *  - Optional sampling fields are forwarded only when NEAR's REVIEWED catalog
 *    entry lists them for the model (for example o3 and the Claude 5 family do
 *    not accept `temperature`). An unreviewed relay route forwards none.
 *  - `max_tokens` / `max_completion_tokens` (the reservation bound) always pass:
 *    review requires `max_tokens`, and NEAR maps the pair to each upstream's
 *    own name, letting `max_completion_tokens` win when both are present.
 *  - Every `cache_control` breakpoint is removed (top level, messages, content
 *    parts, tools). NEAR copies a client breakpoint verbatim to Anthropic,
 *    which then bills a cache WRITE at 1.25x input; NEAR publishes no such
 *    price, so AnonRouter could only bill it at the input price. Without a
 *    breakpoint Anthropic creates no cache entry, so that charge cannot arise.
 *    OpenAI-compatible and Gemini upstreams never received the marker (NEAR
 *    drops it), so stripping it here changes nothing for them.
 */
export function shapeNearRelayBody(externalModelId: string, body: Record<string, unknown>): Record<string, unknown> {
  if (!isNearRelayRoute(externalModelId)) return body;
  const accepted = nearRelayRequestProfile(externalModelId)?.samplingParameters ?? new Set<string>();
  const { user: _user, cache_control: _cacheControl, ...rest } = body;
  for (const field of RELAY_SAMPLING_FIELDS) {
    if (!accepted.has(field)) delete rest[field];
  }
  if (Array.isArray(rest.messages)) {
    rest.messages = rest.messages.map((message) => {
      const clean = withoutCacheControl(message);
      const content = (clean as { content?: unknown } | null)?.content;
      return Array.isArray(content) ? { ...(clean as Record<string, unknown>), content: content.map(withoutCacheControl) } : clean;
    });
  }
  if (Array.isArray(rest.tools)) rest.tools = rest.tools.map(withoutCacheControl);
  return rest;
}

/** A copy of a JSON object without its `cache_control` key; anything else unchanged. */
function withoutCacheControl(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value) || !Object.hasOwn(value, "cache_control")) return value;
  const { cache_control: _marker, ...clean } = value as Record<string, unknown>;
  return clean;
}

/**
 * NEAR /v1/models -> relayed routes (anonymous/private only).
 *
 * `excludedIds` are ids another NEAR route class has claimed; one native id is
 * one route, so a confidential route always wins and the relay never shadows it.
 */
export function normalizeNearRelayCatalog(
  raw: RawNearRelayModel[],
  excludedIds: ReadonlySet<string> = new Set()
): NormalizedModel[] {
  const normalized: NormalizedModel[] = [];
  const seen = new Set<string>();
  for (const candidate of raw) {
    const providerModelId = string(candidate.id);
    if (!providerModelId || excludedIds.has(providerModelId) || seen.has(providerModelId)) continue;
    const route = NEAR_RELAY_ROUTES[providerModelId];
    if (!route) continue;
    // The live owner must still be the reviewed upstream. A route NEAR moves to
    // "nearai" or "attested 3p" is a different route class with different
    // evidence; it is never carried over under a relay label.
    const owner = string(candidate.owned_by)?.toLowerCase() ?? "";
    if (owner !== route.owner || !NEAR_RELAY_OWNERS.has(owner)) continue;
    // Chat routes only: text out, text or text+image in.
    const outputModalities = stringArray(candidate.output_modalities);
    const inputModalities = stringArray(candidate.input_modalities);
    if (outputModalities.length !== 1 || outputModalities[0] !== "text") continue;
    if (!inputModalities.includes("text") || inputModalities.some((modality) => modality !== "text" && modality !== "image")) continue;
    seen.add(providerModelId);

    const family = NEAR_RELAY_FAMILIES[route.family];
    const reviewed = isReviewedNearRelayEntry(candidate);
    const tier = defaultTier(candidate);
    const publishedContext = integer(candidate.context_length);
    // AnonRouter bills the standard tier, so the route's context is capped at
    // the lowest base-tier threshold anyone in the chain prices by: NEAR's own
    // `longContextThreshold`, or the upstream's (see the rule above). Every
    // admitted request then stays in the tier it is billed at.
    const upstreamThreshold = nearRelayUpstreamLongContextThreshold(providerModelId);
    const capThresholds = [tier.longContextThreshold, upstreamThreshold].filter((value): value is number => value !== null);
    const contextTokens = publishedContext === null || tier.longTierWithoutThreshold
      ? null
      : Math.min(publishedContext, ...capThresholds);
    const publishedMaxOutput = integer(candidate.max_output_length);
    // Never invented: a route without a published generation cap stays
    // non-callable (null) rather than receiving a guessed ceiling.
    const maxOutputTokens = publishedMaxOutput === null || contextTokens === null
      ? publishedMaxOutput
      : Math.min(publishedMaxOutput, contextTokens);

    const features = stringArray(candidate.supported_features);
    const supportsTools = features.includes("tools");
    const supportsVision = inputModalities.includes("image");
    const reasoning = features.includes("reasoning");
    const responseSchema = features.includes("structured_outputs") || features.includes("json_mode");
    const reasoningCapabilities = relayReasoningCaps(reasoning, route);

    const pricing = record(candidate.pricing);
    // NEAR's JSON numbers carry binary float noise (qwen3.7-max input is
    // 2.8000000000000003); round to the billing columns' micro-dollar precision.
    const inputPrice = positive(pricing?.input);
    const outputPrice = positive(pricing?.output);
    const inputPerMillionUsd = inputPrice === null ? null : micros(inputPrice);
    const outputPerMillionUsd = outputPrice === null ? null : micros(outputPrice);
    // Cache prices are published only where a cache discount or a cache-write
    // charge can actually reach the bill (NearRelayFamily.promptCaching). On an
    // `unavailable` family a cached or cache-write token, should one ever be
    // reported, falls back to the input price, which is at least NEAR's
    // published cache-read price.
    const automaticCaching = family.promptCaching === "automatic";
    const cacheReadPerToken = automaticCaching ? positive(pricing?.input_cache_read) : null;
    const cacheReadPerMillionUsd = cacheReadPerToken === null ? null : micros(cacheReadPerToken * 1_000_000);
    const cacheWritePerMillionUsd = automaticCaching ? tier.cacheWrite : null;
    const pricingNote = [
      "Standard-tier pricing in USD per 1M tokens.",
      ...(automaticCaching ? [] : ["Prompt caching is not available on this route; every prompt token bills at the input price."]),
      ...(tier.longContextThreshold !== null
        ? [`The provider bills a higher tier above ${tier.longContextThreshold.toLocaleString("en-US")} input tokens, so AnonRouter caps this route's context there.`]
        : []),
      ...(upstreamThreshold !== null && (tier.longContextThreshold === null || upstreamThreshold < tier.longContextThreshold)
        ? [`The model's developer bills prompts above ${upstreamThreshold.toLocaleString("en-US")} tokens at a higher rate, so AnonRouter caps this route's context there.`]
        : []),
      ...(record(record(candidate.textPricing)?.tiers) && Object.keys(record(record(candidate.textPricing)?.tiers) ?? {}).some((name) => name !== "default")
        ? ["The provider's optional flex and priority tiers are not exposed by AnonRouter."]
        : [])
    ].join(" ").slice(0, 400);

    // Presence in NEAR's /v1/models IS availability: NEAR lists only models it
    // serves (`is_active`). `is_ready` is NOT an availability signal. NEAR's own
    // source documents it as OpenRouter listing metadata that "does not affect
    // Cloud API's own listing/filtering" (cloud-api migration V0053), so it is
    // ignored here and excluded from the fingerprint.
    const online = true;
    const deprecation = nearDeprecation(candidate.deprecation_date);
    const publicSlug = providerQualifiedRouteId(INTERNAL_PROVIDER, route.slug);
    const modalities: Array<"text" | "image"> = supportsVision ? ["text", "image"] : ["text"];
    const routing: RoutingProfile = {
      qualityTier: route.qualityTier,
      tasks: supportsVision
        ? ["general", "writing", "math", "coding", "analysis", "vision"]
        : ["general", "writing", "math", "coding", "analysis"],
      supportsWeb: false,
      expectedLatencyMs: null
    };
    const promptCaching = cacheReadPerMillionUsd !== null;
    const featureList = [
      "streaming",
      ...(supportsTools ? ["tool-calling"] : []),
      ...(supportsVision ? ["vision"] : []),
      ...(reasoning ? ["reasoning"] : []),
      ...(route.codeOptimized ? ["code-optimized"] : []),
      ...(promptCaching ? ["prompt-caching"] : [])
    ];
    const statusNote = !reviewed
      ? NEAR_RELAY_REVIEWED_ROUTES[providerModelId]
        ? "The provider changed this route's identity, limits, capabilities or pricing after it was reviewed; re-audit is required."
        : "This relay route is not in the reviewed manifest and cannot be enabled."
      : deprecation
        ? `The provider has scheduled this model for deprecation${deprecation.sunsetAt ? ` on ${deprecation.sunsetAt.slice(0, 10)}` : ""}.`
        : null;

    normalized.push({
      providerModelId,
      publicSlug,
      displayName: route.displayName,
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
        cacheWritePerMillionUsd,
        unitUsd: null,
        unit: null,
        inputLabel: null,
        outputLabel: null,
        note: pricingNote
      },
      online,
      privacyClass: family.privacyClass,
      supportsE2ee: false,
      supportsTee: false,
      capabilities: {
        functionCalling: supportsTools,
        responseSchema,
        reasoning,
        webSearch: false,
        vision: supportsVision,
        optimizedForCode: route.codeOptimized === true,
        promptCaching
      },
      reasoningCapabilities,
      beta: false,
      deprecation,
      regionRestrictions: null,
      traits: ["near-relay", reviewed ? "catalog-reviewed" : "provider-discovered"],
      moderation: "unknown",
      voices: null,
      releasedAt: null,
      supportsStreaming: true,
      supportsTools,
      supportsVision,
      maxImages: supportsVision ? 1 : 0,
      routing,
      publicMetadata: {
        id: route.canonicalId,
        displayName: route.displayName,
        // Stored with the INTERNAL provider id (the catalog schema is keyed on
        // it, and eligibility reads it); the public read boundary presents it as
        // `other` (publicView.ts). Every other field here is already public.
        provider: INTERNAL_PROVIDER,
        providerName: publicProviderName(INTERNAL_PROVIDER, "NEAR AI"),
        providerRouteId: publicSlug,
        routeId: providerModelId,
        shortDescription: `${route.displayName} relayed through a partner gateway to ${family.upstream}. Not a TEE route.`,
        primaryModality: "text",
        modalities: [...modalities],
        contextTokens,
        maxOutputTokens,
        inputPriceUsdPerMillion: inputPerMillionUsd,
        outputPriceUsdPerMillion: outputPerMillionUsd,
        cacheReadPriceUsdPerMillion: cacheReadPerMillionUsd,
        cacheWritePriceUsdPerMillion: cacheWritePerMillionUsd,
        pricingNote,
        privacyLevel: family.privacyClass,
        privacySummary: family.summary,
        privacyNotes: [...family.notes],
        moderation: "unknown",
        ...(reasoning ? { reasoning: reasoningCapabilities } : {}),
        features: featureList,
        routingModes: ["anonrouter-hosted", "provider-direct"],
        availability: deprecation ? "deprecated" : reviewed && online ? "available" : "needs-verification",
        ...(statusNote ? { statusNote } : {}),
        sourceReferences: family.sources.map((source) => ({ ...source }))
      }
    });
  }
  return normalized.sort((a, b) => a.providerModelId.localeCompare(b.providerModelId));
}
