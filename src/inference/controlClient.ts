// ControlClient implementations. In-process wraps the ControlPlane directly
// (dev monolith); HTTP calls the control-api over an authenticated internal RPC.
// Neither ever returns stable account identity to the relay.

import { AppError } from "../security/errors.js";
import type {
  AbortRpcRequest,
  AttestationRedemption,
  AuthorizeNextAttemptRpcRequest,
  AuthorizeNextAttemptRpcResult,
  AuthorizeRpcRequest,
  AuthorizeRpcResult,
  CaptureRpcRequest,
  ControlClient,
  DeliveryStartedRpcRequest,
  RecordProviderRejectionRpcRequest,
  RedeemResult,
  SettleRpcRequest,
  SettleRpcResponse
} from "./rpc.js";
import type { ModelRecord } from "../providers/types.js";


export class HttpControlClient implements ControlClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly timeoutMs = 5_000
  ) {}

  private async post(path: string, body: unknown, downstreamSignal?: AbortSignal): Promise<Response> {
    const timeoutController = new AbortController();
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      timeoutController.abort(new DOMException("Control RPC timed out", "TimeoutError"));
    }, this.timeoutMs);
    const signal = downstreamSignal
      ? AbortSignal.any([downstreamSignal, timeoutController.signal])
      : timeoutController.signal;
    try {
      return await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${this.token}` },
        body: JSON.stringify(body),
        signal
      });
    } catch (error) {
      // Preserve downstream cancellation so the relay treats a closed client as
      // normal cancellation. Convert only our internal deadline to a stable,
      // non-sensitive service error.
      if (!downstreamSignal?.aborted && timedOut) {
        throw new AppError(503, "control_rpc_timeout", "Control RPC timed out");
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async throwFor(response: Response): Promise<never> {
    let code = "control_rpc_error";
    let message = "Control RPC failed";
    try {
      const parsed = (await response.json()) as { error?: { type?: string; message?: string } };
      if (parsed.error?.type) code = parsed.error.type;
      if (parsed.error?.message) message = parsed.error.message;
    } catch {
      // keep defaults
    }
    throw new AppError(response.status, code, message);
  }

  async redeem(ticketId: string, signal?: AbortSignal): Promise<RedeemResult | null> {
    const response = await this.post("/internal/control/redeem", { ticketId }, signal);
    if (!response.ok) return this.throwFor(response);
    const body = (await response.json()) as { result: RedeemResult | null };
    return body.result;
  }

  async authorize(request: AuthorizeRpcRequest, signal?: AbortSignal): Promise<AuthorizeRpcResult> {
    const response = await this.post("/internal/control/authorize", request, signal);
    if (!response.ok) return this.throwFor(response);
    return (await response.json()) as AuthorizeRpcResult;
  }

  async authorizeNextProviderAttempt(
    request: AuthorizeNextAttemptRpcRequest,
    signal?: AbortSignal
  ): Promise<AuthorizeNextAttemptRpcResult | null> {
    const response = await this.post("/internal/control/authorize-next-attempt", request, signal);
    if (!response.ok) return this.throwFor(response);
    const body = (await response.json()) as { result: AuthorizeNextAttemptRpcResult | null };
    return body.result;
  }

  async settle(request: SettleRpcRequest, signal?: AbortSignal): Promise<SettleRpcResponse> {
    const response = await this.post("/internal/control/settle", request, signal);
    if (!response.ok) return this.throwFor(response);
    const body = (await response.json()) as Partial<SettleRpcResponse>;
    return {
      chargedUsd: typeof body.chargedUsd === "number" ? body.chargedUsd : 0,
      ...(typeof body.receiptRecorded === "boolean" ? { receiptRecorded: body.receiptRecorded } : {})
    };
  }

  async markDeliveryStarted(request: DeliveryStartedRpcRequest, signal?: AbortSignal): Promise<void> {
    const response = await this.post("/internal/control/delivery-started", request, signal);
    if (!response.ok) await this.throwFor(response);
  }

  async recordProviderRejection(request: RecordProviderRejectionRpcRequest, signal?: AbortSignal): Promise<void> {
    // Best-effort observation: never surface a control error to the relay. Cancel
    // the body and return regardless of status; the caller also swallows.
    const response = await this.post("/internal/control/provider-rejection", request, signal);
    await response.body?.cancel().catch(() => undefined);
  }

  async capture(request: CaptureRpcRequest, signal?: AbortSignal): Promise<void> {
    const response = await this.post("/internal/control/capture", request, signal);
    if (!response.ok) await this.throwFor(response);
  }

  async abort(request: AbortRpcRequest, signal?: AbortSignal): Promise<void> {
    const response = await this.post("/internal/control/abort", request, signal);
    if (!response.ok) await this.throwFor(response);
  }

  async redeemAttestation(ticket: string, signal?: AbortSignal): Promise<AttestationRedemption | null> {
    const response = await this.post("/internal/control/attestation-redeem", { ticket }, signal);
    if (!response.ok) return this.throwFor(response);
    const body = (await response.json()) as { result: AttestationRedemption | null };
    return body.result;
  }

  /**
   * Content-free public catalog rows for local automatic selection, carried on
   * the existing `models` route rather than a new one: the route inventory in
   * CONTROL_RPC_CONTRACT.md is fixed, and `models` already takes no request body
   * and returns content-free catalog rows. The contract pins the route as taking
   * no caller body; an empty object is the POST-with-no-fields it accepts.
   *
   * A missing catalog THROWS rather than returning an empty list. RoutingCatalogCache
   * serves its stale copy when this rejects and turns a cold failure into
   * router_unavailable; an empty array instead caches "no models at all" for the
   * full TTL and fails /auto silently.
   */
  async fetchRoutingCandidates(signal?: AbortSignal): Promise<ModelRecord[]> {
    const response = await this.post("/internal/control/models", {}, signal);
    if (!response.ok) return this.throwFor(response);
    const body = (await response.json()) as { routing_catalog?: ModelRecord[] };
    if (!Array.isArray(body.routing_catalog)) {
      throw new AppError(503, "router_unavailable", "Control plane returned no routing catalog");
    }
    return body.routing_catalog;
  }
}
