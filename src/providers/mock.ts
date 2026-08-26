import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import { estimateInputTokens, estimateTextTokens } from "../metering/tokens.js";
import type {
  ImageProviderRequest,
  ImageProviderResult,
  ProviderAdapter,
  ProviderChatResult,
  ProviderRequest,
  ProviderStreamResult,
  SpeechProviderRequest,
  SpeechProviderResult
} from "./types.js";
import type { EmbeddingProviderRequest, EmbeddingProviderResult } from "./embeddings.js";
import { normalizeEmbeddingResponse } from "./embeddings.js";
import { parseJsonResponse, requireStreamBody } from "./http.js";
import { openAiUsageToInternal, proxyOpenAiSse, type SseParseResult } from "./sse.js";

// 1x1 transparent PNG — a deterministic placeholder for tests and local dev.
const MOCK_IMAGE_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

export class MockProviderAdapter implements ProviderAdapter {
  readonly name = "mock";
  private readonly baseUrl: string;

  constructor(config: ContentPlaneConfig) {
    this.baseUrl = config.providers.mockBaseUrl;
  }

  async chat(request: ProviderRequest): Promise<ProviderChatResult> {
    const url = `${this.baseUrl}/chat/completions`;
    const init: RequestInit = {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-request-id": request.requestId
      },
      body: JSON.stringify({
        ...request.body,
        model: request.model.externalModelId,
        stream: false
      }),
      signal: request.signal
    };
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await fetch(url, init);

    const json = await parseJsonResponse(response);
    return {
      response: json,
      usage: openAiUsageToInternal((json as { usage?: unknown }).usage)
    };
  }

  async stream(request: ProviderRequest): Promise<ProviderStreamResult> {
    const url = `${this.baseUrl}/chat/completions`;
    const init: RequestInit = {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-request-id": request.requestId
      },
      body: JSON.stringify({
        ...request.body,
        model: request.model.externalModelId,
        stream: true,
        stream_options: {
          include_usage: true
        }
      }),
      signal: request.signal
    };
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await fetch(url, init);

    const body = await requireStreamBody(response);
    let resolveUsage!: (usage: SseParseResult) => void;
    const usagePromise = new Promise<SseParseResult>((resolve) => {
      resolveUsage = resolve;
    });
    const stream = proxyOpenAiSse(body, (result) => resolveUsage(result));

    return {
      stream,
      usage: usagePromise.then((result) => {
        return (
          result.usage ?? {
            inputTokens: estimateInputTokens(request.body.messages),
            outputTokens: Math.max(1, result.estimatedOutputTokens || estimateTextTokens("mock")),
            cachedTokens: 0
          }
        );
      })
    };
  }

  async embeddings(request: EmbeddingProviderRequest): Promise<EmbeddingProviderResult> {
    const init: RequestInit = {
      method: "POST",
      headers: { "content-type": "application/json", "x-request-id": request.requestId },
      body: JSON.stringify({ ...request.body, model: request.model.externalModelId }),
      signal: request.signal
    };
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await fetch(`${this.baseUrl}/embeddings`, init);
    return normalizeEmbeddingResponse(await parseJsonResponse(response), request.body, request.model.externalModelId);
  }

  async generateImage(request: ImageProviderRequest): Promise<ImageProviderResult> {
    const init: RequestInit = {
      method: "POST",
      headers: { "content-type": "application/json", "x-request-id": request.requestId },
      body: JSON.stringify({
        model: request.model.externalModelId,
        prompt: request.prompt,
        width: request.width,
        height: request.height
      }),
      signal: request.signal
    };
    // Mirror the real adapter: honor cancellation and commit the durable dispatch
    // fence before the provider call so the split path is faithfully exercised.
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await fetch(`${this.baseUrl}/image/generate`, init);
    const json = (await parseJsonResponse(response)) as {
      images?: unknown;
      blurred?: unknown;
      content_violation?: unknown;
    };
    const base64 = Array.isArray(json.images) && typeof json.images[0] === "string"
      ? json.images[0]
      : MOCK_IMAGE_BASE64;
    return {
      base64,
      mimeType: "image/png",
      blurred: json.blurred === true,
      contentViolation: json.content_violation === true
    };
  }

  async speech(request: SpeechProviderRequest): Promise<SpeechProviderResult> {
    return { audio: Buffer.from(`mock-audio:${request.input.slice(0, 32)}`), mimeType: "audio/mpeg" };
  }
}
