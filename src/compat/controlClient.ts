// Compat broker → control ticket-mint client. Mirrors HttpControlClient's
// bounded-timeout / abort plumbing. The broker authenticates the CHANNEL with
// the compat service token (Authorization) and passes the caller's ar_ key plus
// TOP-LEVEL ticket metadata in the body — never messages, embeddings input, tool
// arguments, or any prompt/response content. A non-2xx reply is surfaced as an
// AppError carrying control's code so the broker can map it to an OpenAI error.

import { AppError } from "../security/errors.js";

export interface CompatMintRequest {
  apiKey: string;
  operation: "chat" | "embeddings";
  model: unknown;
  max_tokens?: unknown;
  max_completion_tokens?: unknown;
  reasoning_effort?: unknown;
  reasoning?: unknown;
  venice_parameters?: { disable_thinking?: unknown };
}

export interface CompatMintResult {
  ticket: string;
  expires_in: number;
  operation: "chat" | "embeddings";
  model: string;
  automatic: boolean;
  privacy_class: string;
  max_output_tokens: number | null;
  reasoning: string;
}

export class CompatControlClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly timeoutMs = 5_000
  ) {}

  async mint(request: CompatMintRequest, clientIp: string, downstreamSignal?: AbortSignal): Promise<CompatMintResult> {
    const timeoutController = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      timeoutController.abort(new DOMException("Compat mint RPC timed out", "TimeoutError"));
    }, this.timeoutMs);
    const signal = downstreamSignal
      ? AbortSignal.any([downstreamSignal, timeoutController.signal])
      : timeoutController.signal;

    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/internal/compat/mint`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.token}`,
          // Attribute the credential lookup to the real client, not the broker.
          "x-forwarded-for": clientIp
        },
        body: JSON.stringify(request),
        signal
      });
    } catch (error) {
      // Preserve client cancellation; convert only our own deadline into a
      // stable, non-sensitive service error.
      if (!downstreamSignal?.aborted && timedOut) {
        throw new AppError(503, "control_rpc_timeout", "Ticket service timed out");
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      let code = "control_rpc_error";
      let message = "Ticket service failed";
      try {
        const parsed = (await response.json()) as { error?: { type?: string; message?: string } };
        if (parsed.error?.type) code = parsed.error.type;
        if (parsed.error?.message) message = parsed.error.message;
      } catch {
        // keep defaults
      }
      throw new AppError(response.status, code, message);
    }
    return (await response.json()) as CompatMintResult;
  }

  /**
   * Fetch the model catalog for GET /v1/models.
   *
   * TWO credentials, doing two different jobs. The hop is authenticated with the
   * BROKER's service token, as before. The CALLER's key is now sent alongside it
   * so control can decide whether this caller may list at all.
   *
   * This reverses an earlier decision, and the reason is worth keeping. The old
   * comment argued that "a catalog listing needs no user identity, so forwarding
   * the customer credential across this hop would widen its exposure for
   * nothing" -- and the result was that the broker checked only that a Bearer
   * header was PRESENT. Any `ar_`-prefixed string returned the entire catalogue
   * with 200, while the same string was correctly refused 401 on chat.
   *
   * The exposure argument does not hold either: the broker already forwards the
   * raw key over this exact hop on every chat request, because the compat mint
   * takes `apiKey`. Sending it here widens nothing and buys consistent refusal.
   */
  async models(apiKey?: string, downstreamSignal?: AbortSignal): Promise<unknown> {
    const timeoutController = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      timeoutController.abort(new DOMException("Compat models RPC timed out", "TimeoutError"));
    }, this.timeoutMs);
    const signal = downstreamSignal
      ? AbortSignal.any([downstreamSignal, timeoutController.signal])
      : timeoutController.signal;
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/internal/control/models`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${this.token}` },
        body: JSON.stringify(apiKey ? { apiKey } : {}),
        signal
      });
    } catch (error) {
      if (!downstreamSignal?.aborted && timedOut) {
        throw new AppError(503, "control_rpc_timeout", "Model catalog timed out");
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) {
      // An auth verdict is the CALLER's answer and must reach them unchanged.
      // Collapsing 401/403 into control_rpc_error would tell a coding agent the
      // catalogue was unavailable when in fact its key was refused.
      if (response.status === 401) throw new AppError(401, "invalid_api_key", "Invalid API key");
      if (response.status === 403) throw new AppError(403, "insufficient_scope", "API key scope is not permitted");
      throw new AppError(response.status, "control_rpc_error", "Model catalog unavailable");
    }
    return await response.json();
  }
}
