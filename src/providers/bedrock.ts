import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import { estimateInputTokens, estimateTextTokens } from "../metering/tokens.js";
import { ProviderError } from "../security/errors.js";
import { BedrockMantleClient } from "./bedrockMantle.js";
import { parseJsonResponse, requireStreamBody } from "./http.js";
import { openAiUsageToInternal, proxyOpenAiSse, type SseParseResult } from "./sse.js";
import type { ProviderAdapter, ProviderChatResult, ProviderRequest, ProviderStreamResult } from "./types.js";

const CHAT_TIMEOUT_MS = 10 * 60_000;
// The ZDR retention gate runs control-plane GETs on the request critical path.
// Bound them so a hung Mantle endpoint cannot hang the worker and the relay.
const GATE_TIMEOUT_MS = 15_000;

export const BEDROCK_LAUNCH_ROUTES = new Set([
  "openai.gpt-oss-20b",
  "openai.gpt-oss-120b",
  "qwen.qwen3-coder-next",
  "deepseek.v3.2",
  "mistral.mistral-large-3-675b-instruct",
  "google.gemma-3-4b-it",
  "qwen.qwen3-vl-235b-a22b-instruct",
  "xai.grok-4.3"
]);

type MantleModel = {
  id?: unknown;
  model_id?: unknown;
  status?: unknown;
  allowed_modes?: unknown;
  data_retention?: { mode?: unknown; allowed_modes?: unknown } | unknown;
};

function cleanContent(content: unknown): unknown {
  if (!Array.isArray(content)) return content;
  return content.map((part) => {
    if (!part || typeof part !== "object" || Array.isArray(part)) return part;
    const { cache_control: _cacheControl, ...clean } = part as Record<string, unknown>;
    return clean;
  });
}

export function bedrockBody(request: ProviderRequest, stream: boolean): Record<string, unknown> {
  const {
    routing: _routing,
    reasoning: _reasoning,
    venice_parameters: _veniceParameters,
    prompt_cache_key: _promptCacheKey,
    prompt_cache_retention: _promptCacheRetention,
    stream_options: _streamOptions,
    ...body
  } = request.body;
  const messages = Array.isArray(body.messages)
    ? body.messages.map((message) => message && typeof message === "object" && !Array.isArray(message)
      ? { ...message, content: cleanContent((message as { content?: unknown }).content) }
      : message)
    : body.messages;
  return {
    ...body,
    messages,
    model: request.model.externalModelId,
    stream,
    ...(stream ? { stream_options: { include_usage: true } } : {})
  };
}

function effectiveNone(model: MantleModel): boolean {
  const retentionObject = model.data_retention && typeof model.data_retention === "object"
    ? model.data_retention as { mode?: unknown; allowed_modes?: unknown }
    : undefined;
  const allowed = Array.isArray(retentionObject?.allowed_modes)
    ? retentionObject.allowed_modes
    : Array.isArray(model.allowed_modes) ? model.allowed_modes : [];
  const retention = retentionObject?.mode;
  return model.status === "available" && allowed.includes("none") && retention === "none";
}

export class BedrockProviderAdapter implements ProviderAdapter {
  readonly name = "aws-bedrock";
  private readonly enabled: boolean;
  private readonly client: Pick<BedrockMantleClient, "request">;

  constructor(config: ContentPlaneConfig, client?: Pick<BedrockMantleClient, "request">) {
    this.enabled = config.providers.bedrockEnabled;
    this.client = client ?? new BedrockMantleClient({
      baseUrl: config.providers.bedrockBaseUrl,
      region: config.providers.bedrockRegion,
      profile: config.providers.bedrockAwsProfile || undefined
    });
  }

  private async ensurePrivateRoute(modelId: string, signal?: AbortSignal): Promise<void> {
    if (!this.enabled) throw new ProviderError("provider_not_configured", "AWS Bedrock is not enabled");
    if (!BEDROCK_LAUNCH_ROUTES.has(modelId)) {
      throw new ProviderError("provider_model_not_approved", "AWS Bedrock model is not approved");
    }
    // The account-level retention mode is the master ZDR switch. Confirm it on
    // EVERY request: a cached "ok" from seconds ago is not a confirmation, so a
    // caching window would keep serving under the ZDR promise if the account
    // setting ever left `none`.
    const accountResponse = await this.gate("data_retention", signal);
    const retention = await parseJsonResponse(accountResponse) as { mode?: unknown };
    if (retention.mode !== "none") {
      throw new ProviderError("provider_privacy_unavailable", "AWS Bedrock zero-retention mode is not active");
    }
    const modelResponse = await this.gate(`models/${encodeURIComponent(modelId)}`, signal);
    const model = await parseJsonResponse(modelResponse) as MantleModel;
    if (!effectiveNone(model)) {
      throw new ProviderError("provider_privacy_unavailable", "AWS Bedrock model is not available with zero retention");
    }
  }

  private gate(path: string, cancellation?: AbortSignal): Promise<Response> {
    return this.guarded(cancellation, GATE_TIMEOUT_MS, (signal) => this.client.request(path, {}, signal));
  }

  // Bound every Mantle call with a timeout composed with the caller's disconnect
  // signal, and map expiry to a clean provider_timeout (504) like the other
  // adapters, so timeouts drive fallback/circuit-breaker logic instead of
  // surfacing as opaque 500s.
  private async guarded(cancellation: AbortSignal | undefined, timeoutMs: number, perform: (signal: AbortSignal) => Promise<Response>): Promise<Response> {
    const timeout = AbortSignal.timeout(timeoutMs);
    const signal = cancellation ? AbortSignal.any([cancellation, timeout]) : timeout;
    try {
      return await perform(signal);
    } catch (error) {
      if (cancellation?.aborted) throw cancellation.reason ?? error;
      if (timeout.aborted || (error instanceof DOMException && error.name === "TimeoutError")) {
        throw new ProviderError("provider_timeout", "AWS Bedrock did not respond within the request deadline", 504);
      }
      throw error;
    }
  }

  async chat(request: ProviderRequest): Promise<ProviderChatResult> {
    request.signal?.throwIfAborted();
    await this.ensurePrivateRoute(request.model.externalModelId, request.signal);
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await this.guarded(request.signal, CHAT_TIMEOUT_MS, (signal) => this.client.request("chat/completions", {
      method: "POST",
      // Bedrock Mantle assigns/rewrites x-request-id at its edge. Signing a
      // caller-supplied value makes the post-rewrite SigV4 canonical request
      // differ and AWS correctly rejects it with signature mismatch.
      headers: { "content-type": "application/json" },
      body: JSON.stringify(bedrockBody(request, false))
    }, signal));
    const json = await parseJsonResponse(response);
    return {
      response: json,
      usage: openAiUsageToInternal((json as { usage?: unknown }).usage),
      providerRequestId: response.headers.get("x-request-id") ?? undefined
    };
  }

  async stream(request: ProviderRequest): Promise<ProviderStreamResult> {
    request.signal?.throwIfAborted();
    await this.ensurePrivateRoute(request.model.externalModelId, request.signal);
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await this.guarded(request.signal, CHAT_TIMEOUT_MS, (signal) => this.client.request("chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(bedrockBody(request, true))
    }, signal));
    const body = await requireStreamBody(response);
    let resolveUsage!: (result: SseParseResult) => void;
    const usageResult = new Promise<SseParseResult>((resolve) => { resolveUsage = resolve; });
    return {
      // Mantle closes its SSE after the final finish_reason/usage chunk without a
      // `[DONE]` sentinel; accept that clean EOF as a valid terminal (AR bedrock
      // streaming otherwise fails at end-of-stream with provider_stream_incomplete).
      stream: proxyOpenAiSse(body, resolveUsage, { acceptEofAfterFinish: true }),
      providerRequestId: response.headers.get("x-request-id") ?? undefined,
      usage: usageResult.then((result) => result.usage ?? {
        inputTokens: estimateInputTokens(request.body.messages),
        outputTokens: Math.max(1, result.estimatedOutputTokens || estimateTextTokens("bedrock")),
        cachedTokens: 0
      })
    };
  }
}
