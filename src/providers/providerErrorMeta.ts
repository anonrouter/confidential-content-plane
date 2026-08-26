// Content-free extraction of sanitized provider-rejection metadata at the
// provider boundary. This module NEVER buffers or returns an upstream error
// body, a human-readable message, prompt/response content, or a credential.
//
// It exposes:
//   - an allowlist of response HEADER names that safely carry a provider request
//     id (opaque per-request correlator, not content),
//   - strict sanitizers that bound charset + length so nothing reflected from a
//     prompt or a secret can survive, and
//   - a strictly-bounded, allowlist-only body machine-code parser that is
//     IMPLEMENTED but DISABLED by default (upstream error bodies keep being
//     cancelled). It exists so a provider with a documented machine-readable
//     rejection code can be added later without re-plumbing, and so its safety
//     can be tested against oversized/reflected/secret-bearing bodies.

/**
 * Allowlisted response header names that carry an opaque provider request id.
 * Confirmed from the provider adapters: Fireworks uses x-request-id then
 * x-fireworks-request-id, DeepInfra x-request-id, Venice cf-ray, Bedrock/Mantle
 * x-request-id, and x-amzn-requestid is AWS's canonical id header. Header NAMES
 * are matched case-insensitively; the VALUE is sanitized before use.
 */
export const PROVIDER_REQUEST_ID_HEADERS = [
  "x-request-id",
  "x-fireworks-request-id",
  "cf-ray",
  "x-amzn-requestid",
  "x-amzn-request-id"
] as const;

const REQUEST_ID_MAX_LENGTH = 128;
const MACHINE_CODE_MAX_LENGTH = 64;
// Hard cap on how many bytes of a (never-retained) body the bounded parser will
// look at. A provider machine code appears at the very top of the JSON error
// envelope; anything larger is treated as absent rather than scanned.
const BODY_SCAN_MAX_BYTES = 2_048;

/**
 * Sanitize a provider request id to a bounded, opaque token. Anything with
 * characters outside the safe correlator grammar (spaces, punctuation, reflected
 * prompt text) is rejected wholesale rather than partially stored.
 */
export function sanitizeProviderRequestId(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const value = raw.trim();
  if (value.length === 0 || value.length > REQUEST_ID_MAX_LENGTH) return undefined;
  if (!/^[A-Za-z0-9._:-]+$/.test(value)) return undefined;
  return value;
}

/**
 * Sanitize a provider machine code to the safe identifier grammar shared with
 * the ledger CHECK constraint. Only lowercase identifier-shaped tokens survive;
 * a human-readable message never matches.
 */
export function sanitizeProviderMachineCode(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const value = raw.trim().toLowerCase();
  if (value.length === 0 || value.length > MACHINE_CODE_MAX_LENGTH) return undefined;
  if (!/^[a-z0-9_.:-]+$/.test(value)) return undefined;
  return value;
}

/**
 * Read the sanitized provider request id from an allowlisted response header.
 * Works on error responses too (the caller invokes this immediately BEFORE
 * cancelling the body). Never reads the body.
 */
export function extractProviderErrorMeta(response: Pick<Response, "headers">): { providerRequestId?: string } {
  for (const name of PROVIDER_REQUEST_ID_HEADERS) {
    const sanitized = sanitizeProviderRequestId(response.headers.get(name));
    if (sanitized) return { providerRequestId: sanitized };
  }
  return {};
}

/**
 * Strictly-bounded, allowlist-only provider machine-code parser. It reads at most
 * BODY_SCAN_MAX_BYTES, accepts ONLY a top-level `code`/`error.code`/`error.type`
 * string that both sanitizes AND is present in `allowlist`, and returns it. Any
 * unrecognized code, oversized body, non-JSON body, or reflected/secret content
 * yields undefined and nothing is retained.
 *
 * DISABLED by default: no adapter feeds it a body today (bodies are cancelled).
 * Exposed for future providers with a documented code and for adversarial tests.
 */
export function parseBoundedProviderMachineCode(
  bodyText: string,
  allowlist: ReadonlySet<string>
): string | undefined {
  if (typeof bodyText !== "string" || bodyText.length === 0) return undefined;
  // Never scan more than the cap; an oversized body is treated as absent.
  if (bodyText.length > BODY_SCAN_MAX_BYTES) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object") return undefined;
  const root = parsed as Record<string, unknown>;
  const error = root.error && typeof root.error === "object" ? (root.error as Record<string, unknown>) : undefined;
  const candidates = [root.code, error?.code, error?.type];
  for (const candidate of candidates) {
    const sanitized = sanitizeProviderMachineCode(candidate);
    // Only an explicitly allowlisted code is accepted; unknown fields are dropped.
    if (sanitized && allowlist.has(sanitized)) return sanitized;
  }
  return undefined;
}
