// Provider routing policy: the wire schema, its normalization into a single
// internal `NormalizedProviderRoutingPolicy`, conflict validation, a stable
// digest for ticket binding, and the restrictive workspace merge.
//
// This module is intentionally pure and free of DB/Redis so the same
// normalization runs identically at ticket issuance (control plane) and at
// redemption (relay), which is what lets a bound ticket and a redeemed body
// compare byte-for-byte. See docs/PROVIDER_ROUTING.md.
//
// Design notes vs OpenRouter:
//   - A bare string `provider: "aws-bedrock"` is an EXACT pin: it normalizes to
//     `{ only: ["aws-bedrock"], allow_fallbacks: false }` and never falls back.
//   - Omitting `provider` is Auto (privacy-first, price-tiebroken).
//   - We never carry OpenRouter's `data_collection`/`zdr` toggles: AnonRouter's
//     privacy floor is expressed through `minimum_privacy` over the internal
//     privacy ladder (anonymous < private < tee < e2ee), and Auto never silently
//     downgrades privacy during fallback.

import { z } from "zod";
import { AppError } from "../../security/errors.js";

/** Sort strategies accepted on the wire and used by the routing engine. */
export type ProviderSort = "privacy" | "price" | "latency" | "throughput";
export const PROVIDER_SORTS: readonly ProviderSort[] = ["privacy", "price", "latency", "throughput"];

/** Privacy floor a caller may request. `unknown` is never a valid floor. */
export type ProviderPrivacyFloor = "anonymous" | "private" | "tee" | "e2ee";
export const PROVIDER_PRIVACY_FLOORS: readonly ProviderPrivacyFloor[] = ["anonymous", "private", "tee", "e2ee"];

/** Internal privacy ladder ranking shared by policy + engine. Higher is stronger. */
export const PRIVACY_RANK: Record<string, number> = { anonymous: 0, unknown: 0, private: 1, tee: 2, e2ee: 3 };

/** Hard ceiling on transparent provider attempts. The architecture keeps every
 *  attempt individually single-use and fail-closed, so this stays small. */
export const MAX_PROVIDER_ATTEMPTS = 3;
const MAX_PROVIDER_LIST = 16;
/** Base provider slug shape. Matches "venice", "aws-bedrock", "deepinfra/turbo". */
const PROVIDER_SLUG = /^[a-z0-9][a-z0-9-]{0,63}(\/[a-z0-9][a-z0-9-]{0,63})?$/;
/** A generous upper bound on a per-million price so a fat-fingered ceiling still validates. */
const MAX_PRICE_PER_MILLION = 1_000_000;

const priceSchema = z.number().min(0).max(MAX_PRICE_PER_MILLION);

const providerListSchema = z.array(z.string().min(1).max(64)).min(1).max(MAX_PROVIDER_LIST);

/**
 * The exact provider-routing surface accepted on the wire (snake_case). Either a
 * bare string (exact pin) or a bounded object. `.strict()` rejects unknown keys.
 * Deeper semantic validation (conflicts, slug shape) happens in
 * `normalizeProviderPolicy`, which throws the stable policy error codes.
 */
export const providerRoutingPolicySchema = z.union([
  z.string().min(1).max(64),
  z
    .object({
      order: providerListSchema.optional(),
      only: providerListSchema.optional(),
      ignore: z.array(z.string().min(1).max(64)).max(MAX_PROVIDER_LIST).optional(),
      allow_fallbacks: z.boolean().optional(),
      sort: z.enum(["privacy", "price", "latency", "throughput"]).optional(),
      minimum_privacy: z.enum(["anonymous", "private", "tee", "e2ee"]).optional(),
      max_price: z
        .object({ input: priceSchema.optional(), output: priceSchema.optional() })
        .strict()
        .optional(),
      require_parameters: z.boolean().optional(),
      max_attempts: z.number().int().min(1).max(MAX_PROVIDER_ATTEMPTS).optional()
    })
    .strict()
]);

export type ProviderRoutingPolicyInput = z.infer<typeof providerRoutingPolicySchema>;

/** The one internal policy shape every downstream component consumes. */
export interface NormalizedProviderRoutingPolicy {
  /** Explicit try-order of provider slugs; empty when unset. */
  order: string[];
  /** Restrict the candidate pool to these slugs; null = no restriction. */
  only: string[] | null;
  /** Remove these slugs from the candidate pool. */
  ignore: string[];
  /** Whether more than one attempt may be made. */
  allowFallbacks: boolean;
  /** Ordering strategy. Default "privacy". */
  sort: ProviderSort;
  /** Privacy floor; null means "no explicit floor" (Auto stays at the strongest class). */
  minimumPrivacy: ProviderPrivacyFloor | null;
  /** Per-million price ceilings; null = unbounded. */
  maxPrice: { input: number | null; output: number | null } | null;
  /** Only attempt routes that support every requested parameter (reasoning, tools, …). */
  requireParameters: boolean;
  /** Bounded number of attempts (1..MAX_PROVIDER_ATTEMPTS). */
  maxAttempts: number;
  /** True only for the bare-string exact provider pin. */
  pin: boolean;
}

/** The default Auto policy: privacy-first, price-tiebroken, bounded fallback. */
export const AUTO_PROVIDER_POLICY: NormalizedProviderRoutingPolicy = Object.freeze({
  order: [],
  only: null,
  ignore: [],
  allowFallbacks: true,
  sort: "privacy",
  minimumPrivacy: null,
  maxPrice: null,
  requireParameters: false,
  maxAttempts: MAX_PROVIDER_ATTEMPTS,
  pin: false
});

function invalid(message: string): never {
  throw new AppError(400, "invalid_provider_policy", message);
}

function conflict(message: string): never {
  throw new AppError(400, "provider_policy_conflict", message);
}

function normalizeSlug(raw: string): string {
  const slug = raw.trim().toLowerCase();
  if (!PROVIDER_SLUG.test(slug)) {
    invalid(`Invalid provider slug: ${JSON.stringify(raw)}`);
  }
  return slug;
}

/** Normalize + validate a slug list, preserving first-seen order and de-duping. */
function normalizeSlugList(raw: string[] | undefined): string[] {
  if (!raw) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of raw) {
    const slug = normalizeSlug(value);
    if (!seen.has(slug)) {
      seen.add(slug);
      out.push(slug);
    }
  }
  return out;
}

/**
 * Normalize any accepted `provider` value into the single internal policy.
 * Throws `invalid_provider_policy` (bad slug/shape) or `provider_policy_conflict`
 * (contradictory fields). `undefined` yields the Auto default.
 */
export function normalizeProviderPolicy(
  input: ProviderRoutingPolicyInput | undefined | null
): NormalizedProviderRoutingPolicy {
  if (input === undefined || input === null) {
    return { ...AUTO_PROVIDER_POLICY };
  }

  // Bare string = exact pin. Equivalent to { only:[x], allow_fallbacks:false }.
  if (typeof input === "string") {
    const slug = normalizeSlug(input);
    return {
      order: [slug],
      only: [slug],
      ignore: [],
      allowFallbacks: false,
      sort: "privacy",
      minimumPrivacy: null,
      maxPrice: null,
      requireParameters: false,
      maxAttempts: 1,
      pin: true
    };
  }

  const order = normalizeSlugList(input.order);
  const only = input.only ? normalizeSlugList(input.only) : null;
  const ignore = normalizeSlugList(input.ignore);

  // Conflict rules (documented in docs/PROVIDER_ROUTING.md).
  if (only) {
    const ignoreSet = new Set(ignore);
    const overlap = only.find((slug) => ignoreSet.has(slug));
    if (overlap) conflict(`Provider ${JSON.stringify(overlap)} cannot appear in both only and ignore`);
  }
  if (order.length > 0) {
    const ignoreSet = new Set(ignore);
    const banned = order.find((slug) => ignoreSet.has(slug));
    if (banned) conflict(`order includes ${JSON.stringify(banned)}, which is also in ignore`);
    if (only) {
      const onlySet = new Set(only);
      const excluded = order.find((slug) => !onlySet.has(slug));
      if (excluded) conflict(`order includes ${JSON.stringify(excluded)}, which is excluded by only`);
    }
  }

  const allowFallbacks = input.allow_fallbacks ?? true;
  // allow_fallbacks:false permits only the first eligible route.
  let maxAttempts = allowFallbacks ? input.max_attempts ?? MAX_PROVIDER_ATTEMPTS : 1;
  maxAttempts = Math.max(1, Math.min(MAX_PROVIDER_ATTEMPTS, maxAttempts));

  const maxPrice = input.max_price
    ? {
        input: input.max_price.input ?? null,
        output: input.max_price.output ?? null
      }
    : null;
  // A max_price object that names no ceilings is meaningless; treat as unset.
  const normalizedMaxPrice = maxPrice && (maxPrice.input !== null || maxPrice.output !== null) ? maxPrice : null;

  return {
    order,
    only,
    ignore,
    allowFallbacks,
    sort: input.sort ?? "privacy",
    minimumPrivacy: input.minimum_privacy ?? null,
    maxPrice: normalizedMaxPrice,
    requireParameters: input.require_parameters ?? false,
    maxAttempts,
    pin: false
  };
}

/**
 * A stable, canonical digest of a normalized policy. Bound into an inference
 * ticket and recomputed by the relay from the redeemed body; a mismatch is a
 * `ticket_provider_policy_mismatch`. `order` sequence is meaningful and kept;
 * `only`/`ignore` are order-insensitive and sorted for stability.
 */
export function providerPolicyDigest(policy: NormalizedProviderRoutingPolicy): string {
  return JSON.stringify({
    o: policy.order,
    y: policy.only ? [...policy.only].sort() : null,
    i: [...policy.ignore].sort(),
    f: policy.allowFallbacks,
    s: policy.sort,
    p: policy.minimumPrivacy,
    x: policy.maxPrice ? { i: policy.maxPrice.input, o: policy.maxPrice.output } : null,
    r: policy.requireParameters,
    a: policy.maxAttempts,
    n: policy.pin
  });
}

/** Convenience: digest of a raw wire value (undefined = Auto). */
export function providerPolicyDigestFromInput(input: ProviderRoutingPolicyInput | undefined | null): string {
  return providerPolicyDigest(normalizeProviderPolicy(input));
}

/** Whether a normalized policy is the untouched Auto default. */
export function isAutoProviderPolicy(policy: NormalizedProviderRoutingPolicy): boolean {
  return providerPolicyDigest(policy) === providerPolicyDigest(AUTO_PROVIDER_POLICY);
}

/**
 * Workspace-level provider defaults. Stored per workspace and merged
 * restrictively under every request. Mirrors the safety-bearing fields of a
 * normalized policy plus a default sort.
 */
export interface WorkspaceProviderDefaults {
  sort: ProviderSort;
  only: string[] | null;
  ignore: string[];
  allowFallbacks: boolean;
  maxAttempts: number;
  minimumPrivacy: ProviderPrivacyFloor | null;
  maxPrice: { input: number | null; output: number | null } | null;
  requireParameters: boolean;
}

export const DEFAULT_WORKSPACE_PROVIDER_DEFAULTS: WorkspaceProviderDefaults = Object.freeze({
  sort: "privacy",
  only: null,
  ignore: [],
  allowFallbacks: true,
  maxAttempts: MAX_PROVIDER_ATTEMPTS,
  minimumPrivacy: null,
  maxPrice: null,
  requireParameters: false
});

function strongerFloor(
  a: ProviderPrivacyFloor | null,
  b: ProviderPrivacyFloor | null
): ProviderPrivacyFloor | null {
  if (a === null) return b;
  if (b === null) return a;
  return PRIVACY_RANK[a] >= PRIVACY_RANK[b] ? a : b;
}

function tighterPrice(
  a: { input: number | null; output: number | null } | null,
  b: { input: number | null; output: number | null } | null
): { input: number | null; output: number | null } | null {
  if (!a) return b;
  if (!b) return a;
  const tighter = (x: number | null, y: number | null) => {
    if (x === null) return y;
    if (y === null) return x;
    return Math.min(x, y);
  };
  const merged = { input: tighter(a.input, b.input), output: tighter(a.output, b.output) };
  return merged.input === null && merged.output === null ? null : merged;
}

function intersectOnly(a: string[] | null, b: string[] | null): string[] | null {
  if (a === null) return b === null ? null : [...b];
  if (b === null) return [...a];
  const bSet = new Set(b);
  return a.filter((slug) => bSet.has(slug));
}

/**
 * Merge a request-level policy under a workspace's provider defaults. The merge
 * is strictly restrictive: a request can only make routing MORE constrained.
 *
 *   - `only` intersects (request ∩ workspace).
 *   - `ignore` unions.
 *   - `minimum_privacy` is raised to the stronger of the two (never lowered).
 *   - `max_price` is tightened per-field (never raised).
 *   - fallbacks may only be disabled.
 *   - `max_attempts` is capped at the workspace maximum.
 *   - `require_parameters` is OR-ed.
 *   - `sort`/`order` come from the request when it sends a non-Auto policy;
 *     a pure-Auto request inherits the workspace default sort.
 */
export function mergeWorkspaceProviderPolicy(
  request: NormalizedProviderRoutingPolicy,
  workspace: WorkspaceProviderDefaults
): NormalizedProviderRoutingPolicy {
  const requestIsAuto = isAutoProviderPolicy(request);
  const allowFallbacks = request.allowFallbacks && workspace.allowFallbacks;
  const maxAttempts = Math.max(
    1,
    Math.min(request.maxAttempts, workspace.maxAttempts, allowFallbacks ? MAX_PROVIDER_ATTEMPTS : 1)
  );
  return {
    order: request.order,
    only: intersectOnly(request.only, workspace.only),
    ignore: [...new Set([...request.ignore, ...workspace.ignore])],
    allowFallbacks,
    sort: requestIsAuto ? workspace.sort : request.sort,
    minimumPrivacy: strongerFloor(request.minimumPrivacy, workspace.minimumPrivacy),
    maxPrice: tighterPrice(request.maxPrice, workspace.maxPrice),
    requireParameters: request.requireParameters || workspace.requireParameters,
    maxAttempts,
    pin: request.pin
  };
}
