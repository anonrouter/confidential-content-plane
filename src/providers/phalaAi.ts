import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import { estimateInputTokens, estimateTextTokens } from "../metering/tokens.js";
import { ProviderError } from "../security/errors.js";
import { parseJsonResponse, requireStreamBody } from "./http.js";
import { openAiUsageToInternal, proxyOpenAiSse, type SseParseResult } from "./sse.js";
import type {
  ProviderAdapter,
  ProviderChatResult,
  ProviderRequest,
  ProviderStreamResult
} from "./types.js";

const CHAT_TIMEOUT_MS = 10 * 60_000;

async function phalaAiFetch(
  url: string,
  init: RequestInit,
  cancellation?: AbortSignal,
  timeoutMs = CHAT_TIMEOUT_MS
): Promise<Response> {
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = cancellation ? AbortSignal.any([cancellation, timeout]) : timeout;
  try {
    return await fetch(url, { ...init, signal });
  } catch (error) {
    if (cancellation?.aborted) throw cancellation.reason ?? error;
    if (timeout.aborted || (error instanceof DOMException && error.name === "TimeoutError")) {
      throw new ProviderError("provider_timeout", "Provider did not complete within the request deadline", 504);
    }
    throw error;
  }
}

/**
 * Strip AnonRouter-internal and provider-specific fields before forwarding.
 *
 * `routing` and `venice_parameters` are AnonRouter/Venice constructs Phala would
 * reject or ignore; `prompt_cache_*` is an OpenAI-platform control Phala does not
 * document. `reasoning` is deliberately NOT stripped here, unlike the Tinfoil
 * adapter: Phala publishes `reasoning`, `reasoning_effort` and
 * `include_reasoning` in each model's `supported_parameters`, and the catalog
 * normalizer only attests reasoning controls for models that list them, so
 * passing it through is attested rather than hopeful.
 */
function phalaAiBody(request: ProviderRequest, stream: boolean): Record<string, unknown> {
  const {
    routing: _routing,
    venice_parameters: _veniceParameters,
    prompt_cache_key: _promptCacheKey,
    prompt_cache_retention: _promptCacheRetention,
    stream_options: _streamOptions,
    ...body
  } = request.body;
  return {
    ...body,
    model: request.model.externalModelId,
    stream,
    ...(stream ? { stream_options: { include_usage: true } } : {})
  };
}

/**
 * Phala AI via its OpenAI-compatible Chat Completions API
 * (base `https://inference.phala.com/v1`).
 *
 * PRIVACY, AND WHY THERE IS NO ATTESTATION METHOD HERE. Phala AI is an
 * aggregator gateway that decrypts downstream traffic at its frontend before
 * forwarding upstream, and its published TDX evidence attests that gateway — a
 * TD which reports zero GPUs and names no model. So these routes are `private`,
 * and this adapter deliberately implements NO `fetchAttestation`: the verifier
 * registry has no `phala-ai` entry, `providerExposesAttestation("phala-ai")` is
 * false, and the attestation-ticket mint therefore refuses these routes rather
 * than issuing a ticket that could only ever redeem to a gateway-scoped document.
 * That refusal is the intended behaviour and is asserted by
 * `tests/unit/phala-ai-no-attestation.test.ts`.
 *
 * Adding an attestation path here would be a privacy-claim change, not a feature,
 * and belongs with a reviewed measurement pin and an owner decision.
 */
export class PhalaAiProviderAdapter implements ProviderAdapter {
  readonly name = "phala-ai";
  private readonly baseUrl: string;
  private readonly apiKey: string;

  constructor(config: ContentPlaneConfig) {
    this.baseUrl = config.providers.phalaAiBaseUrl;
    this.apiKey = config.providers.phalaAiApiKey;
  }

  private headers(requestId: string) {
    if (!this.apiKey) {
      throw new ProviderError("provider_not_configured", "Phala AI API key is not configured");
    }
    return {
      "content-type": "application/json",
      authorization: `Bearer ${this.apiKey}`,
      "x-request-id": requestId
    };
  }

  /**
   * Phala's per-response receipt id. Recorded as the provider request id so an
   * operator can correlate a settlement with the provider's own transparency
   * record. It is an opaque identifier, never content, and Phala's receipt
   * document is NOT fetched: doing so would be a second authenticated call per
   * request for evidence that cannot lift the privacy class.
   */
  private providerRequestId(response: Response): string | undefined {
    return response.headers.get("x-receipt-id")
      ?? response.headers.get("x-request-id")
      ?? undefined;
  }

  async chat(request: ProviderRequest): Promise<ProviderChatResult> {
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await phalaAiFetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify(phalaAiBody(request, false))
    }, request.signal);
    const json = await parseJsonResponse(response);
    return {
      response: json,
      usage: openAiUsageToInternal((json as { usage?: unknown }).usage),
      providerRequestId: this.providerRequestId(response)
    };
  }

  async stream(request: ProviderRequest): Promise<ProviderStreamResult> {
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await phalaAiFetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify(phalaAiBody(request, true))
    }, request.signal);
    const body = await requireStreamBody(response);
    let resolveUsage!: (result: SseParseResult) => void;
    const usageResult = new Promise<SseParseResult>((resolve) => {
      resolveUsage = resolve;
    });
    return {
      stream: proxyOpenAiSse(body, resolveUsage),
      providerRequestId: this.providerRequestId(response),
      // `stream_options.include_usage` asks Phala for a real usage frame. The
      // estimate is the fallback for a stream that ends without one, and it is
      // deliberately never zero: a settled request that metered nothing would
      // bill nothing.
      usage: usageResult.then((result) => result.usage ?? {
        inputTokens: estimateInputTokens(request.body.messages),
        outputTokens: Math.max(1, result.estimatedOutputTokens || estimateTextTokens("phala-ai")),
        cachedTokens: 0
      })
    };
  }
}
