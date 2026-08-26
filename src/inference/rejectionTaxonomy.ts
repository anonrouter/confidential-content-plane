// Canonical, provider-independent classification for the inference rejection
// ledger. This is the single source of truth for how an inference rejection is
// labeled; the CHECK constraints in migration 075 mirror these enums.
//
// The crucial rule: operational provider failures (429, timeout, 5xx, malformed
// response, credential failure) are kept SEPARATE from user policy violations. A
// provider outage is never a user abuse strike. Only an explicit, documented,
// allowlisted provider moderation result becomes `provider_policy_rejection`; a
// bare provider 400/403 is a neutral `provider_bad_request`/`provider_rejected`.

import { sanitizeProviderMachineCode, sanitizeProviderRequestId } from "../providers/providerErrorMeta.js";

export const REJECTION_ORIGINS = ["local_admission", "router", "provider"] as const;
export type RejectionOrigin = (typeof REJECTION_ORIGINS)[number];

export const REJECTION_CATEGORIES = [
  // Local admission decisions (the control plane, before/at authorization).
  "local_rate_limit",
  "local_concurrency_limit",
  "insufficient_balance",
  "account_restricted",
  // Provider outcomes after an authenticated attempt.
  "provider_rate_limit",
  "provider_policy_rejection",
  "provider_bad_request",
  "provider_authentication_error",
  "provider_quota_exhausted",
  "provider_model_unavailable",
  "provider_timeout",
  "provider_network_error",
  "provider_invalid_response",
  "provider_server_error",
  "provider_rejected",
  // Fallback when no signal is safely classifiable.
  "unknown_rejection"
] as const;
export type RejectionCategory = (typeof REJECTION_CATEGORIES)[number];

export const LOCAL_ADMISSION_CATEGORIES: readonly RejectionCategory[] = [
  "local_rate_limit",
  "local_concurrency_limit",
  "insufficient_balance",
  "account_restricted"
];

/** Categories that represent an operational provider failure, never user abuse. */
export const PROVIDER_OPERATIONAL_CATEGORIES: readonly RejectionCategory[] = [
  "provider_rate_limit",
  "provider_quota_exhausted",
  "provider_model_unavailable",
  "provider_timeout",
  "provider_network_error",
  "provider_invalid_response",
  "provider_server_error"
];

/**
 * A rejection is terminal (must NOT transparently fall back to another provider)
 * only when it is an explicit provider policy/moderation decision. Transient
 * operational failures remain eligible for the existing bounded fallback.
 */
export function isTerminalCategory(category: RejectionCategory): boolean {
  return category === "provider_policy_rejection";
}

/**
 * Whether a category is a candidate for a user-facing abuse signal. Only an
 * explicit provider policy rejection qualifies. Rate limiting, outages, quota
 * failures, timeouts, malformed responses, and credential errors NEVER do.
 * (Repeated LOCAL rate limiting may separately raise a bounded rate_limit_abuse
 * signal at the caller's discretion; that is not driven by this predicate.)
 */
export function isUserAbuseCategory(category: RejectionCategory): boolean {
  return category === "provider_policy_rejection";
}

/**
 * Per-provider allowlist mapping a DOCUMENTED, machine-readable provider result
 * code to a canonical category. This is the ONLY route to
 * `provider_policy_rejection` (and other explicit provider codes). Extend this
 * registry to add a new provider or a newly-documented code; never infer a
 * category from an undocumented field or a bare HTTP status.
 *
 * Venice returns image content-violation as a documented, content-free response
 * header (x-venice-is-content-violation), surfaced as
 * WorkerImageResult.contentViolation and forwarded here as the code
 * `content_violation`. That is the initial concrete policy-rejection signal.
 */
export const PROVIDER_MACHINE_CODE_ALLOWLIST: Record<string, Record<string, RejectionCategory>> = {
  venice: {
    content_violation: "provider_policy_rejection"
  },
  fireworks: {},
  "aws-bedrock": {},
  deepinfra: {},
  default: {}
};

/**
 * Machine codes (any provider) that the bounded body parser is permitted to
 * extract from a never-retained error body. Empty by default: today no adapter
 * feeds the body parser, so this stays unused until a provider's documented code
 * is added here and to the per-provider allowlist above.
 */
export const BODY_MACHINE_CODE_ALLOWLIST: ReadonlySet<string> = new Set<string>();

/**
 * Whether a provider machine code denotes a terminal policy rejection in ANY
 * provider allowlist. Used by the relay to keep a policy rejection from
 * transparently falling back to another provider (a content block for one
 * provider is a content block, period). Operational codes return false.
 */
export function isTerminalProviderCode(code: string | undefined): boolean {
  const sanitized = sanitizeProviderMachineCode(code);
  if (!sanitized) return false;
  for (const map of Object.values(PROVIDER_MACHINE_CODE_ALLOWLIST)) {
    const category = map[sanitized];
    if (category && isTerminalCategory(category)) return true;
  }
  return false;
}

/** Resolve an allowlisted provider machine code to a category, or null. */
export function classifyProviderMachineCode(
  providerName: string | undefined,
  code: string | undefined
): RejectionCategory | null {
  const sanitized = sanitizeProviderMachineCode(code);
  if (!sanitized) return null;
  const providerMap = (providerName && PROVIDER_MACHINE_CODE_ALLOWLIST[providerName]) || undefined;
  return providerMap?.[sanitized] ?? PROVIDER_MACHINE_CODE_ALLOWLIST.default[sanitized] ?? null;
}

interface LocalAdmissionError {
  statusCode?: unknown;
  code?: unknown;
}

/**
 * Classify a local admission failure thrown during authorization. Returns null
 * for failures we intentionally do NOT record per-account (generic validation
 * 400s, plan-config denials, and infrastructure 503s) — recording every such
 * failure would reintroduce write amplification and is not abuse-relevant.
 */
export function classifyLocalAdmission(error: unknown): RejectionCategory | null {
  if (!error || typeof error !== "object") return null;
  const { statusCode, code } = error as LocalAdmissionError;
  const errorCode = typeof code === "string" ? code : "";
  // Balance/budget/free-tier exhaustion all present as 402.
  if (statusCode === 402) return "insufficient_balance";
  if (errorCode === "rate_limited") return "local_rate_limit";
  if (errorCode === "concurrency_limited") return "local_concurrency_limit";
  if (statusCode === 429) return "local_rate_limit";
  // Enforcement restrictions: account_restricted / inference_restricted / etc.
  if (errorCode === "account_restricted" || errorCode.endsWith("_restricted")) return "account_restricted";
  return null;
}

export interface ProviderOutcomeInput {
  providerName?: string;
  /** The provider's own HTTP status, when known (ProviderError.providerStatusCode). */
  providerStatus?: number;
  /** An allowlisted provider machine code, when a provider surfaced one. */
  providerCode?: string;
  /** AnonRouter's sanitized error code (ProviderError.code). */
  anonrouterCode?: string;
  /** The relay's sanitized fallback outcome, when there is no ProviderError. */
  relayOutcome?: string;
}

/**
 * Classify a provider outcome into a canonical category. Precedence:
 *   1. an explicit allowlisted provider machine code (the only policy route),
 *   2. AnonRouter's own error code (timeout / malformed / stream-incomplete),
 *   3. the provider HTTP status,
 *   4. the relay's sanitized fallback outcome,
 *   5. unknown_rejection.
 * A bare 400/403 is NEVER a policy rejection.
 */
export function classifyProviderOutcome(input: ProviderOutcomeInput): RejectionCategory {
  const machine = classifyProviderMachineCode(input.providerName, input.providerCode);
  if (machine) return machine;

  const code = input.anonrouterCode ?? "";
  if (code === "provider_timeout" || code === "control_rpc_timeout") return "provider_timeout";
  if (
    code === "provider_invalid_json"
    || code === "provider_no_stream"
    || code === "provider_invalid_response"
    || code === "provider_stream_incomplete"
    || code === "worker_stream_incomplete"
  ) {
    return "provider_invalid_response";
  }

  const status = input.providerStatus;
  if (typeof status === "number") {
    if (status === 429) return "provider_rate_limit";
    if (status === 401) return "provider_authentication_error";
    if (status === 402) return "provider_quota_exhausted";
    if (status === 404) return "provider_model_unavailable";
    if (status === 400) return "provider_bad_request";
    if (status >= 500) return "provider_server_error";
    if (status >= 400) return "provider_rejected"; // includes 403 — never inferred as policy
  }

  switch (input.relayOutcome) {
    case "rate_limited":
      return "provider_rate_limit";
    case "network_error":
      return "provider_network_error";
    case "invalid_response":
      return "provider_invalid_response";
    case "provider_unavailable":
      return "provider_server_error";
    case "provider_rejected":
      return "provider_rejected";
    default:
      return "unknown_rejection";
  }
}

// Re-export the shared sanitizers so callers doing defense-in-depth validation
// before a DB write have one import surface.
export { sanitizeProviderMachineCode, sanitizeProviderRequestId };
