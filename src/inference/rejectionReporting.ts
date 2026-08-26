// Relay-side helpers that report a provider-attempt rejection to the control
// plane for the inference rejection ledger. Everything here is BEST EFFORT: a
// failure is swallowed and never changes the caller's actual rejection response,
// settlement, or abort. Content is never touched — only sanitized facts derived
// from the ProviderError (or a transport failure) the relay caught.

import { ProviderError } from "../security/errors.js";
import { isAbortError } from "./disconnect.js";
import type { ControlClient, ProviderAttemptOutcome, RecordProviderRejectionRpcRequest } from "./rpc.js";

type ProviderRejectionFacts = Partial<Pick<
  RecordProviderRejectionRpcRequest,
  "anonrouterCode" | "providerStatus" | "providerRequestId" | "relayOutcome"
>>;

/**
 * Extract sanitized rejection facts from a caught error, or null when the error
 * is NOT a provider-origin failure worth recording here (a local AppError such as
 * a router timeout — those are recorded at the control-plane admission path — or
 * anything else). Client cancellation is handled by the caller before this runs.
 */
export function providerRejectionFacts(error: unknown): ProviderRejectionFacts | null {
  if (error instanceof ProviderError) {
    return {
      anonrouterCode: error.code,
      ...(typeof error.providerStatusCode === "number" ? { providerStatus: error.providerStatusCode } : {}),
      ...(error.providerRequestId ? { providerRequestId: error.providerRequestId } : {}),
      // The provider's own policy code (Venice `content_violation` and friends) is
      // prompt-derived and stays here. Control learns only that the provider
      // rejected the attempt, which is all refund conservation needs (O13).
      ...(error.providerCode ? { relayOutcome: "provider_rejected" as const } : {})
    };
  }
  // Transport failures before any provider response (no ProviderError). These are
  // operational, never abuse.
  if (error instanceof TypeError && (error.message === "fetch failed" || error.message === "terminated")) {
    return { anonrouterCode: "provider_network_error", relayOutcome: "network_error" };
  }
  if (error instanceof DOMException && (error.name === "NetworkError" || error.name === "TimeoutError")) {
    return { anonrouterCode: "provider_network_error", relayOutcome: "network_error" };
  }
  return null;
}

/**
 * Report a failed provider attempt. No-op on client cancellation or a non-provider
 * error. Idempotent per (requestId, attemptIndex) at the control plane, so retries
 * and per-attempt fallback records never double count.
 */
export async function reportProviderRejection(
  controlClient: ControlClient,
  params: {
    requestId: string;
    attemptIndex: number;
    automatic: boolean;
    error: unknown;
    signal: AbortSignal;
    startedAt: number;
  }
): Promise<void> {
  if (!controlClient.recordProviderRejection) return;
  // Caller cancellation and downstream disconnect are never recorded as rejections.
  if (params.signal.aborted || isAbortError(params.error)) return;
  const facts = providerRejectionFacts(params.error);
  if (!facts) return;
  await controlClient
    .recordProviderRejection({
      requestId: params.requestId,
      attemptIndex: params.attemptIndex,
      automatic: params.automatic,
      ...facts,
      latencyMs: Date.now() - params.startedAt
    })
    .catch(() => undefined);
}

/**
 * Report a provider result that arrived on a SUCCESSFUL response but produced no
 * usable output (Venice's documented image content-violation header is the one
 * live case). The attempt is non-billable and the ledger needs to know it
 * happened.
 *
 * It reports the GENERIC outcome, not the provider's machine code.
 * `providerCode` used to cross here, and it is the single most content-derived
 * value the old boundary carried: `content_violation` states that a moderation
 * classifier judged this account's prompt. Refund conservation needs only "this
 * attempt produced nothing chargeable", which `relayOutcome` supplies.
 *
 * The consequence is deliberate and is not a silent one: the control plane can
 * no longer classify a provider policy rejection as user abuse, so the
 * deduplicated moderation signal that used to fire for it no longer fires.
 * Abuse response for the confidential path has to be built inside the content
 * plane, where the content already is, or not at all. See
 * docs/architecture/confidential-backend/CONTROL_RPC_CONTRACT.md.
 */
export async function reportProviderNonBillableOutcome(
  controlClient: ControlClient,
  params: {
    requestId: string;
    attemptIndex: number;
    automatic: boolean;
    /** Kept for the caller's local semantics; deliberately not transmitted. */
    providerCode: string;
    providerRequestId?: string;
    startedAt: number;
  }
): Promise<void> {
  if (!controlClient.recordProviderRejection) return;
  if (!params.providerCode) return;
  await controlClient
    .recordProviderRejection({
      requestId: params.requestId,
      attemptIndex: params.attemptIndex,
      automatic: params.automatic,
      relayOutcome: "provider_rejected",
      ...(params.providerRequestId ? { providerRequestId: params.providerRequestId } : {}),
      latencyMs: Date.now() - params.startedAt
    })
    .catch(() => undefined);
}

export type { ProviderAttemptOutcome };
