// The pure provider-routing engine.
//
// Given the set of provider routes that serve ONE canonical model, a normalized
// policy, and content-free request facts, it produces a bounded, ordered
// `ProviderRoutingPlan`. It has no DB/Redis/network: health is passed in as a
// resolved state, so the whole engine is deterministic and unit-testable.
//
// Default Auto ordering (docs/PROVIDER_ROUTING.md):
//   1. drop unavailable / disabled / quarantined / incompatible / unpriced
//   2. enforce account/workspace restrictions (only/ignore)
//   3. enforce request privacy / capabilities / price
//   4. find the strongest available privacy class
//   5. exclude routes below that class BY DEFAULT (no silent downgrade)
//   6. prefer healthy routes
//   7. select the lowest-priced route
//   8. break ties by latency, then the explicit provider precedence
//      (PROVIDER_TIE_BREAK_ORDER), then a stable route id
//
// A caller that sets a lower `minimum_privacy` widens step 5 down to that floor;
// fallback may then use routes at or above the floor but never below it.

import { PRIVACY_RANK, type NormalizedProviderRoutingPolicy, type ProviderSort } from "./policy.js";
import { publicProviderSlug } from "../publicIdentity.js";

export type ProviderHealth = "healthy" | "degraded" | "temporarily_unavailable" | "disabled";

/** A single provider route for one canonical model. Derived from a ModelRecord. */
export interface ProviderRoute {
  /** Provider slug, e.g. "aws-bedrock". */
  provider: string;
  canonicalModelId: string;
  publicModelId: string;
  externalModelId: string;
  /** Route effective privacy class (internal ladder). */
  privacyClass: string;
  modelType: "text" | "image" | "tts" | "embedding";
  inputPricePerMillion: number;
  outputPricePerMillion: number;
  /** Discounted cached-prompt and cache-creation prices, when separately reviewed. */
  cacheReadPricePerMillion?: number | null;
  cacheWritePricePerMillion?: number | null;
  unitPriceUsd: number | null;
  /** Whether the route carries a usable reviewed price for its operation. */
  priced: boolean;
  supportsStreaming: boolean;
  supportsTools: boolean;
  supportsVision: boolean;
  supportsReasoning: boolean;
  maxOutputTokens: number | null;
  contextWindow: number;
  expectedLatencyMs: number | null;
  /** Observed p50 latency (ms) from metadata-only uptime, when available. */
  latencyP50Ms: number | null;
  /** Observed median throughput (tokens/sec) from metadata-only uptime, when available. */
  throughputTps: number | null;
  health: ProviderHealth;
  /** Deterministic tiebreak identity, stable across restarts. */
  stableId: string;
}

/** Content-free request facts the engine filters against. */
export interface ProviderRoutingRequest {
  operation: "chat" | "embeddings" | "image" | "speech";
  stream: boolean;
  requiresTools: boolean;
  requiresVision: boolean;
  requiresReasoning: boolean;
  /**
   * Whether this is an E2EE (client-attested ciphertext) request. E2EE is a
   * distinct SERVING MODALITY, not merely the top of the privacy ladder: an E2EE
   * route can only serve ciphertext + attestation, and a plaintext route can only
   * serve plaintext. So a single canonical model may carry both an `e2ee` route
   * and a plaintext route (for example Venice GLM 5.2 with and without caching);
   * they never compete for one request. This flag partitions the candidate pool:
   * an E2EE request sees ONLY `e2ee` routes, and a plaintext request NEVER sees
   * `e2ee` routes.
   */
  e2ee: boolean;
  /** Caller output-token intent; excludes routes whose advertised max is smaller. */
  requestedMaxOutputTokens?: number;
  /**
   * The conservative prompt-size ceiling (tokens) the relay computed for this
   * request: a count, never content. When present, a route whose context window
   * cannot hold it (plus `requestedMaxOutputTokens`, for chat) is not a
   * candidate, so a prompt too large for one provider's cap goes to another
   * provider that can serve it. Absent (ticket issue, before the prompt is
   * measured; whole-body E2EE, which reserves the full window) means no filter.
   * Not part of any digest: the policy digest covers the policy only.
   */
  inputTokenCeiling?: number;
}

export interface ProviderRoutingPlan {
  canonicalModelId: string;
  policy: NormalizedProviderRoutingPolicy;
  /** Ordered attempts, best first, already capped to policy.maxAttempts. */
  attempts: ProviderRoute[];
  /** Strongest privacy class among the chosen attempts (what Auto tries first). */
  effectivePrivacyClass: string;
  /** Weakest privacy class any attempt could select: the honest guarantee floor. */
  minimumPrivacyClass: string;
  /** Whether more than one attempt is planned. */
  fallbackAvailable: boolean;
  /** Worst-case reservation across the plan (see reservationCostUsd). */
  maximumReservationUsd: number;
}

export type ProviderRoutingUnavailableReason =
  | "no_provider_route"
  | "no_provider_route_meets_privacy"
  | "no_provider_route_meets_price"
  /** Routes exist under the policy, but none has the context for this prompt. */
  | "no_provider_route_fits_context";

export type ProviderRoutingResult =
  | { ok: true; plan: ProviderRoutingPlan }
  | { ok: false; reason: ProviderRoutingUnavailableReason };

/** Content-free health inputs. Never carries prompts or provider bodies. */
export interface ProviderHealthSignals {
  emergencyDisabled: boolean;
  killSwitchEngaged: boolean;
  circuitState?: "closed" | "open" | "half_open";
  /** Catalog freshness failed (route metadata is stale). */
  catalogStale?: boolean;
  providerActive?: boolean;
  modelCallable?: boolean;
  /** Recent metadata-only observation counts. */
  recentAttempts?: number;
  recentSuccessRate?: number | null;
}

/**
 * Unify every available health signal into a single state. Purely metadata:
 * emergency controls, provider/model kill switches, process-local circuit state,
 * catalog freshness, and recent success-rate observations. Never inspects any
 * provider response body or prompt.
 */
export function providerHealthFromSignals(signals: ProviderHealthSignals): ProviderHealth {
  if (signals.emergencyDisabled || signals.providerActive === false || signals.modelCallable === false) {
    return "disabled";
  }
  if (signals.killSwitchEngaged || signals.circuitState === "open") {
    return "temporarily_unavailable";
  }
  if (signals.circuitState === "half_open" || signals.catalogStale) {
    return "degraded";
  }
  if (
    signals.recentSuccessRate !== null
    && signals.recentSuccessRate !== undefined
    && (signals.recentAttempts ?? 0) >= 8
    && signals.recentSuccessRate < 0.5
  ) {
    return "degraded";
  }
  return "healthy";
}

function matchesSlug(routeProvider: string, slug: string): boolean {
  // A policy slug is a PUBLIC provider id, so the route is compared in its
  // public form (../publicIdentity.ts): a route served by `near-ai` is `other`,
  // and the internal id matches nothing, like any unknown slug. Every policy is
  // public: request input, workspace defaults and the control plane's implicit
  // pin (which writes the public slug).
  const route = publicProviderSlug(routeProvider);
  // Base-slug matching: "deepinfra" matches "deepinfra" and "deepinfra/turbo".
  return route === slug || route.startsWith(`${slug}/`);
}

function inList(routeProvider: string, list: string[]): boolean {
  return list.some((slug) => matchesSlug(routeProvider, slug));
}

function routeIsAttemptable(route: ProviderRoute): boolean {
  return route.health !== "disabled" && route.health !== "temporarily_unavailable";
}

function operationModelType(operation: ProviderRoutingRequest["operation"]): ProviderRoute["modelType"] {
  if (operation === "embeddings") return "embedding";
  if (operation === "image") return "image";
  if (operation === "speech") return "tts";
  return "text";
}

/**
 * Routes that pass every hard, technical filter EXCEPT the privacy floor and
 * max-price: operation type, health attemptability, reviewed pricing, only/ignore,
 * streaming/tools/vision/reasoning capability, and the output-token limit.
 */
function technicallyEligibleRoutes(
  routes: ProviderRoute[],
  policy: NormalizedProviderRoutingPolicy,
  request: ProviderRoutingRequest
): ProviderRoute[] {
  const wantedType = operationModelType(request.operation);
  return routes.filter((route) => {
    if (route.modelType !== wantedType) return false;
    // E2EE modality partition: an E2EE request sees only e2ee routes; a plaintext
    // request never sees e2ee routes. This runs before privacy ranking so Auto
    // can never select an e2ee route for a plaintext request (it could not serve
    // the ciphertext) and vice versa.
    if (request.e2ee ? route.privacyClass !== "e2ee" : route.privacyClass === "e2ee") return false;
    if (!routeIsAttemptable(route)) return false;
    if (!route.priced) return false;
    if (policy.only && !inList(route.provider, policy.only)) return false;
    if (policy.ignore.length > 0 && inList(route.provider, policy.ignore)) return false;
    if (request.stream && !route.supportsStreaming) return false;
    if (request.requiresTools && !route.supportsTools) return false;
    if (request.requiresVision && !route.supportsVision) return false;
    // require_parameters: only route to providers that support the requested
    // reasoning parameter. Tools/vision are always hard requirements above.
    if (policy.requireParameters && request.requiresReasoning && !route.supportsReasoning) return false;
    if (
      request.requestedMaxOutputTokens !== undefined
      && route.maxOutputTokens !== null
      && request.requestedMaxOutputTokens > route.maxOutputTokens
    ) {
      return false;
    }
    return true;
  });
}

/**
 * Whether a route's context window holds this request: exactly the checks the
 * control plane applies to the serving route (context_too_large), so a route
 * that passes here can never fail them. Chat needs room for the prompt AND the
 * requested output; embeddings need room for the input. No ceiling, no filter.
 */
export function routeFitsRequestContext(route: ProviderRoute, request: ProviderRoutingRequest): boolean {
  const ceiling = request.inputTokenCeiling;
  if (ceiling === undefined) return true;
  if (route.modelType === "text") {
    const remaining = route.contextWindow - ceiling;
    if (remaining <= 0) return false;
    return request.requestedMaxOutputTokens === undefined || request.requestedMaxOutputTokens <= remaining;
  }
  if (route.modelType === "embedding") return ceiling <= route.contextWindow;
  return true;
}

function passesMaxPrice(route: ProviderRoute, policy: NormalizedProviderRoutingPolicy): boolean {
  if (!policy.maxPrice) return true;
  if (policy.maxPrice.input !== null && route.inputPricePerMillion > policy.maxPrice.input) return false;
  if (policy.maxPrice.output !== null && route.outputPricePerMillion > policy.maxPrice.output) return false;
  return true;
}

/**
 * The candidate pool for a request: technically eligible, within the price
 * ceiling, and (when the prompt size is known) able to hold the prompt. This is
 * the input to plan building (before the privacy floor and ordering are
 * applied). Exposed for callers that want the raw pool.
 */
export function listEligibleProviderRoutes(params: {
  routes: ProviderRoute[];
  policy: NormalizedProviderRoutingPolicy;
  request: ProviderRoutingRequest;
}): ProviderRoute[] {
  return technicallyEligibleRoutes(params.routes, params.policy, params.request).filter((route) =>
    passesMaxPrice(route, params.policy) && routeFitsRequestContext(route, params.request)
  );
}

function priceKey(route: ProviderRoute): number {
  // Media routes carry no per-token price, so ordering them by token rates
  // would tie every candidate at zero. Order them by their reviewed unit price.
  if (route.modelType === "image" || route.modelType === "tts") {
    return route.unitPriceUsd ?? Number.POSITIVE_INFINITY;
  }
  return route.inputPricePerMillion + route.outputPricePerMillion;
}
function healthKey(route: ProviderRoute): number {
  // Only "healthy" and "degraded" reach ordering; degraded sinks below healthy.
  return route.health === "healthy" ? 0 : 1;
}
/**
 * Provider precedence for routes that tie on every real criterion (privacy,
 * health, price, latency). Earlier wins.
 *
 * WHY AN EXPLICIT LIST. Ties used to fall to the stable route id, which begins
 * with the INTERNAL provider id, so the winner was whichever id sorted first:
 * enabling `near-ai` would have taken every tie from `venice` because "n" < "v",
 * moving traffic for no reason a customer could see. An internal id's spelling
 * must not decide where traffic goes.
 *
 * The established providers keep exactly the relative order they had under the
 * old rule (it was alphabetical), so no live tie moves. A provider added later
 * goes at the END: an incumbent keeps a tie, and a new provider wins traffic
 * only on privacy, health, price or latency. `near-ai` is last for that reason.
 * A provider missing from the list sorts after every listed one.
 */
export const PROVIDER_TIE_BREAK_ORDER: readonly string[] = Object.freeze([
  "aws-bedrock",
  "chutes",
  "deepinfra",
  "fireworks",
  "mock",
  "phala-ai",
  "tinfoil",
  "venice",
  "near-ai"
]);

/** Position in PROVIDER_TIE_BREAK_ORDER; unlisted providers share the last slot. */
export function providerTieBreakRank(provider: string): number {
  const index = PROVIDER_TIE_BREAK_ORDER.indexOf(provider);
  return index === -1 ? PROVIDER_TIE_BREAK_ORDER.length : index;
}

/**
 * Comparator over internal provider ids for the final tie-break, shared by the
 * engine, the single-route lookup (registry) and the `/v1/models` Auto
 * preview, so all three name the same provider. Only two UNLISTED providers
 * fall back to comparing ids, which keeps the order total.
 */
export function compareProviderTieBreak(left: string, right: string): number {
  const rank = providerTieBreakRank(left) - providerTieBreakRank(right);
  if (rank !== 0) return rank;
  return left < right ? -1 : left > right ? 1 : 0;
}

function latencyKey(route: ProviderRoute): number {
  return route.latencyP50Ms ?? route.expectedLatencyMs ?? Number.POSITIVE_INFINITY;
}
function throughputKey(route: ProviderRoute): number {
  // Higher throughput is better; unknown throughput sorts last.
  return route.throughputTps ?? Number.NEGATIVE_INFINITY;
}
function privacyKeyDesc(route: ProviderRoute): number {
  return -(PRIVACY_RANK[route.privacyClass] ?? 0);
}

/** Ordered comparison keys per sort strategy. Lower tuple sorts earlier. */
function comparisonKeys(route: ProviderRoute, sort: ProviderSort): Array<number | string> {
  switch (sort) {
    case "price":
      return [priceKey(route), healthKey(route), latencyKey(route), providerTieBreakRank(route.provider), route.stableId];
    case "latency":
      // Insufficient latency data → all keys tie at Infinity, so the stable
      // fallback ordering (health, price, id) below decides. Never fabricated.
      return [latencyKey(route), healthKey(route), priceKey(route), providerTieBreakRank(route.provider), route.stableId];
    case "throughput":
      return [-throughputKey(route), healthKey(route), priceKey(route), providerTieBreakRank(route.provider), route.stableId];
    case "privacy":
    default:
      return [privacyKeyDesc(route), healthKey(route), priceKey(route), latencyKey(route), providerTieBreakRank(route.provider), route.stableId];
  }
}

function compareRoutes(a: ProviderRoute, b: ProviderRoute, sort: ProviderSort): number {
  const ka = comparisonKeys(a, sort);
  const kb = comparisonKeys(b, sort);
  for (let i = 0; i < ka.length; i += 1) {
    const va = ka[i];
    const vb = kb[i];
    if (va < vb) return -1;
    if (va > vb) return 1;
  }
  return 0;
}

/**
 * Build the bounded provider routing plan for one canonical model.
 *
 * `reservationCostUsd(route)` returns the worst-case USD a single attempt on
 * that route could cost under the bounded input/output ceilings. The plan's
 * `maximumReservationUsd` is the max across attempts, so a fallback can never
 * exceed the amount reserved before the first attempt.
 */
export function buildProviderRoutingPlan(params: {
  canonicalModelId: string;
  routes: ProviderRoute[];
  policy: NormalizedProviderRoutingPolicy;
  request: ProviderRoutingRequest;
  reservationCostUsd: (route: ProviderRoute) => number;
}): ProviderRoutingResult {
  const { canonicalModelId, routes, policy, request, reservationCostUsd } = params;
  const rankOf = (route: ProviderRoute) => PRIVACY_RANK[route.privacyClass] ?? 0;

  const capable = technicallyEligibleRoutes(routes, policy, request);
  if (capable.length === 0) return { ok: false, reason: "no_provider_route" };

  const withinPrice = capable.filter((route) => passesMaxPrice(route, policy));
  if (withinPrice.length === 0) return { ok: false, reason: "no_provider_route_meets_price" };

  // Hard privacy floor: an explicit `minimum_privacy` always applies; a non-default
  // sort (price/latency/throughput) with no explicit floor falls back to the
  // platform's default routable floor ("private") so an explicit optimize-for-cost
  // request never silently reaches an anonymous route. The default privacy sort
  // uses no hard floor here — the no-downgrade confinement below keeps it at the
  // strongest available class instead.
  const hardFloorRank =
    policy.minimumPrivacy !== null
      ? PRIVACY_RANK[policy.minimumPrivacy]
      : policy.sort === "privacy"
        ? null
        : PRIVACY_RANK.private;
  const withinHardFloor = hardFloorRank === null ? withinPrice : withinPrice.filter((route) => rankOf(route) >= hardFloorRank);
  if (withinHardFloor.length === 0) return { ok: false, reason: "no_provider_route_meets_privacy" };

  // Apply explicit order first (already validated ⊆ only, ∩ ignore = ∅), then fill
  // the remainder by the sort strategy. Explicit `order` entries are explicit
  // choices and beat sorting.
  const sortedPool = withinHardFloor.slice().sort((a, b) => compareRoutes(a, b, policy.sort));
  const explicit: ProviderRoute[] = [];
  const seen = new Set<ProviderRoute>();
  for (const slug of policy.order) {
    for (const route of sortedPool) {
      if (!seen.has(route) && matchesSlug(route.provider, slug)) {
        seen.add(route);
        explicit.push(route);
      }
    }
  }
  const remainder = sortedPool.filter((route) => !seen.has(route));

  // allow_fallbacks:false → only the first eligible route (explicit if named);
  // the context fit below is part of "eligible", so it picks from this head.
  let ordered: ProviderRoute[] = policy.allowFallbacks
    ? [...explicit, ...remainder]
    : explicit.length > 0 ? explicit : remainder;

  // No-downgrade confinement (default privacy sort, no explicit floor). Explicit
  // `order` entries are explicit choices and are exempt: the floor is the WEAKEST
  // explicitly-ordered class if any were named, else the primary route's class.
  // This keeps Auto from silently falling back to a weaker privacy tier while
  // still honoring a caller who explicitly listed a lower-privacy provider.
  //
  // The floor is taken BEFORE the context fit, deliberately: a prompt too large
  // for every route of the strongest class fails closed rather than quietly
  // moving to a weaker class. A caller who set `minimum_privacy` has no
  // confinement and may be served by a weaker route at or above that floor.
  if (policy.minimumPrivacy === null && policy.sort === "privacy" && ordered.length > 0) {
    const confineFloor = explicit.length > 0
      ? Math.min(...explicit.map(rankOf))
      : rankOf(ordered[0]);
    ordered = ordered.filter((route) => seen.has(route) || rankOf(route) >= confineFloor);
  }

  // Context fit: a route that cannot hold this prompt is skipped, so the
  // request goes to the next route in the same order that can serve it. Only
  // when none can does the plan fail (closed, as context_too_large).
  const fitting = ordered.filter((route) => routeFitsRequestContext(route, request));
  if (ordered.length > 0 && fitting.length === 0) return { ok: false, reason: "no_provider_route_fits_context" };
  ordered = policy.allowFallbacks ? fitting : fitting.slice(0, 1);

  const attempts = ordered.slice(0, Math.max(1, policy.maxAttempts));
  if (attempts.length === 0) return { ok: false, reason: "no_provider_route" };

  const ranks = attempts.map((route) => PRIVACY_RANK[route.privacyClass] ?? 0);
  const strongestAttemptRank = Math.max(...ranks);
  const weakestAttemptRank = Math.min(...ranks);
  const effectivePrivacyClass = attempts.find((r) => (PRIVACY_RANK[r.privacyClass] ?? 0) === strongestAttemptRank)!.privacyClass;
  const minimumPrivacyClass = attempts.find((r) => (PRIVACY_RANK[r.privacyClass] ?? 0) === weakestAttemptRank)!.privacyClass;
  const maximumReservationUsd = attempts.reduce((max, route) => Math.max(max, reservationCostUsd(route)), 0);

  return {
    ok: true,
    plan: {
      canonicalModelId,
      policy,
      attempts,
      effectivePrivacyClass,
      minimumPrivacyClass,
      fallbackAvailable: attempts.length > 1,
      maximumReservationUsd
    }
  };
}

/**
 * Whether a single route could be selected under a policy: technically eligible,
 * within the price ceiling, and at or above an explicit privacy floor. Used to
 * constrain /auto model selection to canonical models that HAVE an eligible
 * provider route under the policy.
 */
export function isProviderRouteEligible(
  route: ProviderRoute,
  policy: NormalizedProviderRoutingPolicy,
  request: ProviderRoutingRequest
): boolean {
  const pool = listEligibleProviderRoutes({ routes: [route], policy, request });
  if (pool.length === 0) return false;
  if (policy.minimumPrivacy !== null && (PRIVACY_RANK[route.privacyClass] ?? 0) < PRIVACY_RANK[policy.minimumPrivacy]) {
    return false;
  }
  return true;
}

/** The attempt to make at a given zero-based index, or null when exhausted. */
export function selectNextProviderAttempt(plan: ProviderRoutingPlan, attemptIndex: number): ProviderRoute | null {
  if (attemptIndex < 0 || attemptIndex >= plan.attempts.length) return null;
  return plan.attempts[attemptIndex];
}
