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

async function deepInfraFetch(url: string, init: RequestInit, cancellation?: AbortSignal): Promise<Response> {
  const timeout = AbortSignal.timeout(CHAT_TIMEOUT_MS);
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
 * Only fields in AnonRouter's OpenAI-compatible chat contract may reach
 * DeepInfra. Relay-only routing/reasoning intent and Venice-specific extensions
 * are removed explicitly, even if a future call site bypasses schema stripping.
 * OpenAI-standard tools/tool_choice, vision `image_url` parts, and
 * `reasoning_effort` are forwarded verbatim (DeepInfra is OpenAI-compatible).
 */
function deepInfraBody(request: ProviderRequest, stream: boolean): Record<string, unknown> {
  const {
    routing: _routing,
    reasoning: _reasoning,
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
 * DeepInfra open-model inference via its OpenAI-compatible Chat Completions API.
 * DeepInfra states it holds request/response content only in memory during
 * inference and deletes it afterward (classified `private`); AnonRouter uses the
 * standard Chat Completions path only and never its bulk/batch endpoints.
 */
export class DeepInfraProviderAdapter implements ProviderAdapter {
  readonly name = "deepinfra";
  private readonly baseUrl: string;
  private readonly apiKey: string;

  constructor(config: ContentPlaneConfig) {
    this.baseUrl = config.providers.deepinfraBaseUrl;
    this.apiKey = config.providers.deepinfraApiKey;
  }

  private headers(requestId: string) {
    if (!this.apiKey) {
      throw new ProviderError("provider_not_configured", "DeepInfra API key is not configured");
    }
    return {
      "content-type": "application/json",
      authorization: `Bearer ${this.apiKey}`,
      "x-request-id": requestId
    };
  }

  async chat(request: ProviderRequest): Promise<ProviderChatResult> {
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await deepInfraFetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify(deepInfraBody(request, false))
    }, request.signal);
    const json = await parseJsonResponse(response);
    return {
      response: json,
      usage: openAiUsageToInternal((json as { usage?: unknown }).usage),
      providerRequestId: response.headers.get("x-request-id") ?? undefined
    };
  }

  async stream(request: ProviderRequest): Promise<ProviderStreamResult> {
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await deepInfraFetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify(deepInfraBody(request, true))
    }, request.signal);
    const body = await requireStreamBody(response);
    let resolveUsage!: (result: SseParseResult) => void;
    const usageResult = new Promise<SseParseResult>((resolve) => {
      resolveUsage = resolve;
    });
    return {
      stream: proxyOpenAiSse(body, resolveUsage),
      providerRequestId: response.headers.get("x-request-id") ?? undefined,
      usage: usageResult.then((result) => result.usage ?? {
        inputTokens: estimateInputTokens(request.body.messages),
        outputTokens: Math.max(1, result.estimatedOutputTokens || estimateTextTokens("deepinfra")),
        cachedTokens: 0
      })
    };
  }
}
