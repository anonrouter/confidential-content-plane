import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import { createHash } from "node:crypto";
import { ProviderError } from "../security/errors.js";
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
import type { VeniceKeysetStore } from "./veniceKeyStore.js";
import { openAiUsageToInternal, proxyOpenAiSse, type SseParseResult } from "./sse.js";
import { sha256Hex } from "./attestation/crypto.js";
import {
  OperationalCircuitBreaker,
  VeniceCircuitBreakerRegistry,
  operationalFailureScope,
  type CircuitPermit,
  type VeniceCircuitOperation
} from "./circuitBreaker.js";


// Media generations can run for tens of seconds (gpt-image ≈ 40s); bound them
// so a hung provider call cannot hold a reservation open forever.
const MEDIA_TIMEOUT_MS = 120_000;
const CHAT_TIMEOUT_MS = 10 * 60_000;
// Defensible bounds on a base64 image response: images are returned inline and
// may be several MB, but a runaway or malicious provider response must never
// exhaust worker memory. The raw JSON envelope is capped, and the decoded image
// is capped independently. Neither the base64 nor any bytes are ever logged.
const MAX_IMAGE_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_IMAGE_DECODED_BYTES = 12 * 1024 * 1024;
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const PROCESS_VENICE_BREAKERS = new VeniceCircuitBreakerRegistry();

function withSha256(body: ReadableStream<Uint8Array>): {
  body: ReadableStream<Uint8Array>;
  digest: Promise<string>;
} {
  const reader = body.getReader();
  const hash = createHash("sha256");
  let resolveDigest!: (value: string) => void;
  const digest = new Promise<string>((resolve) => { resolveDigest = resolve; });
  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    resolveDigest(hash.digest("hex"));
  };
  return {
    body: new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const next = await reader.read();
          if (next.done) {
            finish();
            controller.close();
            return;
          }
          if (next.value) {
            hash.update(next.value);
            controller.enqueue(next.value);
          }
        } catch (error) {
          finish();
          controller.error(error);
        }
      },
      async cancel(reason) {
        finish();
        await reader.cancel(reason).catch(() => undefined);
      }
    }),
    digest
  };
}

interface VeniceCircuitGuard {
  networkBreaker: OperationalCircuitBreaker;
  networkPermit: CircuitPermit;
  scopedBreaker: OperationalCircuitBreaker;
  scopedPermit: CircuitPermit;
}

async function chatFetch(url: string, init: RequestInit, cancellation?: AbortSignal): Promise<Response> {
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

async function mediaFetch(url: string, init: RequestInit, cancellation?: AbortSignal): Promise<Response> {
  const timeout = AbortSignal.timeout(MEDIA_TIMEOUT_MS);
  const signal = cancellation ? AbortSignal.any([cancellation, timeout]) : timeout;
  try {
    return await fetch(url, { ...init, signal });
  } catch (error) {
    if (cancellation?.aborted) throw cancellation.reason ?? error;
    if (timeout.aborted || (error instanceof DOMException && error.name === "TimeoutError")) {
      throw new ProviderError("provider_timeout", "Provider did not respond in time", 504);
    }
    throw error;
  }
}

/**
 * Read a provider response body with a hard byte cap. A response larger than the
 * cap is aborted and rejected rather than buffered, so a malicious or broken
 * upstream cannot exhaust worker memory. The bytes are never logged.
 */
async function readBoundedResponseText(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new ProviderError("provider_response_too_large", "Provider response exceeded the permitted size", 502);
      }
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function providerHttpError(response: Response): Promise<ProviderError> {
  // Drain the response without retaining or exposing provider-controlled text.
  await response.body?.cancel().catch(() => undefined);
  return new ProviderError("provider_http_error", "Provider request failed", response.status);
}

/**
 * Explicit venice_parameters allowlist for the final provider boundary.
 * Only the presentation-only `strip_thinking_response` may pass through, and
 * the provider-owned system prompt stays disabled so admission keeps a local
 * input-token upper bound. The legacy `disable_thinking` flag is deliberately
 * NOT forwarded: disabling reasoning is owned by the canonical reasoning layer
 * (src/inference/reasoning.ts), which translates it to the documented
 * catalog-attested mechanism before the body reaches this adapter.
 */
function sanitizedVeniceParameters(body: Record<string, unknown>): Record<string, unknown> {
  const params =
    body.venice_parameters && typeof body.venice_parameters === "object" && !Array.isArray(body.venice_parameters)
      ? (body.venice_parameters as Record<string, unknown>)
      : {};
  return {
    ...(params.strip_thinking_response === true ? { strip_thinking_response: true } : {}),
    include_venice_system_prompt: false
  };
}

export class VeniceProviderAdapter implements ProviderAdapter {
  readonly name = "venice";
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly keysById: Map<string, string>;
  private readonly keyStore?: VeniceKeysetStore;
  private readonly circuitBreakers: VeniceCircuitBreakerRegistry;

  constructor(config: ContentPlaneConfig, circuitBreakers?: VeniceCircuitBreakerRegistry, keyStore?: VeniceKeysetStore) {
    this.baseUrl = config.providers.veniceBaseUrl;
    this.apiKey = config.providers.veniceInferenceKey;
    // Nullish guard: hand-built partial configs in tests omit the keyset.
    this.keysById = new Map((config.providers.veniceKeys ?? []).map((entry) => [entry.id, entry.key]));
    // When the durable overlay store is wired (the credential worker), key ids
    // resolve against the live effective keyset so operator add/remove actions
    // apply without a restart.
    this.keyStore = keyStore;
    // Production may construct more than one adapter in the credential worker;
    // share process-local, bounded breaker state across them. Tests get isolated
    // state unless they explicitly inject a registry.
    this.circuitBreakers = circuitBreakers
      ?? (config.env === "test" ? new VeniceCircuitBreakerRegistry() : PROCESS_VENICE_BREAKERS);
  }

  private acquireGuard(operation: VeniceCircuitOperation, externalModelId: string): VeniceCircuitGuard {
    // Check the provider-wide transport circuit before creating or touching a
    // model scope. During a network outage this keeps the bounded scope map quiet.
    const networkBreaker = this.circuitBreakers.network;
    const networkPermit = networkBreaker.acquire();
    const scopedBreaker = this.circuitBreakers.scoped(operation, externalModelId);
    try {
      const scopedPermit = scopedBreaker.acquire();
      return { networkBreaker, networkPermit, scopedBreaker, scopedPermit };
    } catch (error) {
      networkBreaker.recordNeutral(networkPermit);
      throw error;
    }
  }

  private recordSuccess(guard: VeniceCircuitGuard): void {
    guard.networkBreaker.recordSuccess(guard.networkPermit);
    guard.scopedBreaker.recordSuccess(guard.scopedPermit);
  }

  private recordNeutral(guard: VeniceCircuitGuard): void {
    guard.networkBreaker.recordNeutral(guard.networkPermit);
    guard.scopedBreaker.recordNeutral(guard.scopedPermit);
  }

  private recordFailure(guard: VeniceCircuitGuard, error: unknown, cancellation?: AbortSignal): void {
    if (cancellation?.aborted) {
      this.recordNeutral(guard);
      return;
    }

    const failureScope = operationalFailureScope(error);
    if (failureScope === "network") {
      guard.networkBreaker.recordOperationalFailure(guard.networkPermit);
      guard.scopedBreaker.recordNeutral(guard.scopedPermit);
      return;
    }
    if (failureScope === "scope") {
      // Receiving a provider HTTP/shape outcome proves connectivity even when
      // this specific model + operation is unhealthy or throttled.
      guard.networkBreaker.recordSuccess(guard.networkPermit);
      guard.scopedBreaker.recordOperationalFailure(guard.scopedPermit);
      return;
    }

    if (error instanceof ProviderError && typeof error.providerStatusCode === "number") {
      // Ordinary provider 4xx is not an outage. It is a completed exchange and
      // can safely clear stale operational failures in this exact scope.
      this.recordSuccess(guard);
      return;
    }
    this.recordNeutral(guard);
  }

  private async guarded<T>(
    operation: VeniceCircuitOperation,
    externalModelId: string,
    cancellation: AbortSignal | undefined,
    execute: () => Promise<T>
  ): Promise<T> {
    const guard = this.acquireGuard(operation, externalModelId);
    try {
      const result = await execute();
      this.recordSuccess(guard);
      return result;
    } catch (error) {
      this.recordFailure(guard, error, cancellation);
      throw error;
    }
  }

  private monitorStream(
    stream: AsyncIterable<string>,
    guard: VeniceCircuitGuard,
    cancellation?: AbortSignal
  ): AsyncIterable<string> {
    const adapter = this;
    return (async function* () {
      let settled = false;
      try {
        for await (const chunk of stream) yield chunk;
        adapter.recordSuccess(guard);
        settled = true;
      } catch (error) {
        adapter.recordFailure(guard, error, cancellation);
        settled = true;
        throw error;
      } finally {
        // A consumer may stop iterating without aborting its request. That says
        // nothing about Venice health and must release a half-open probe without
        // declaring either success or failure.
        if (!settled) adapter.recordNeutral(guard);
      }
    })();
  }

  private headers(requestId: string, e2eeHeaders?: Record<string, string>, providerKeyId?: string | null) {
    // A control-selected key id must resolve against the local keyset; an
    // unknown id fails closed rather than silently using another credential.
    const apiKey = providerKeyId
      ? this.keyStore
        ? this.keyStore.keyById(providerKeyId) ?? undefined
        : this.keysById.get(providerKeyId)
      : this.keyStore
        ? this.keyStore.defaultKey() ?? undefined
        : this.apiKey;
    if (!apiKey) {
      throw new ProviderError("provider_not_configured", "Venice inference key is not configured");
    }

    return {
      "content-type": "application/json",
      authorization: `Bearer ${apiKey}`,
      "x-request-id": requestId,
      // For E2EE, carry the client's TEE headers verbatim to the enclave. The
      // relay never sees plaintext; content stays encrypted end to end.
      ...(e2eeHeaders ?? {})
    };
  }

  /**
   * Fetch a TEE attestation quote for a model + client nonce. Only the
   * credential-isolated worker calls this; the client independently verifies the
   * returned evidence before encrypting. The Venice key never leaves the worker.
   */
  async fetchAttestation(externalModelId: string, nonce: string, signal?: AbortSignal, providerKeyId?: string | null): Promise<unknown> {
    return this.guarded("attestation", externalModelId, signal, async () => {
      const url = `${this.baseUrl}/tee/attestation?model=${encodeURIComponent(externalModelId)}&nonce=${encodeURIComponent(nonce)}`;
      const response = await chatFetch(url, { method: "GET", headers: this.headers("attestation", undefined, providerKeyId) }, signal);
      if (!response.ok) throw await providerHttpError(response);
      return parseJsonResponse(response);
    });
  }

  /** Fetch Venice's enclave response receipt. Venice keys receipts by the chat
   * completion body `id` (not the transport's Cloudflare `cf-ray`). */
  async fetchSignature(
    providerRequestId: string,
    externalModelId: string,
    signal?: AbortSignal,
    providerKeyId?: string | null
  ): Promise<unknown> {
    return this.guarded("attestation", externalModelId, signal, async () => {
      const url = `${this.baseUrl}/tee/signature?model=${encodeURIComponent(externalModelId)}&request_id=${encodeURIComponent(providerRequestId)}`;
      const response = await chatFetch(url, {
        method: "GET",
        headers: this.headers("signature", undefined, providerKeyId)
      }, signal);
      if (!response.ok) throw await providerHttpError(response);
      return parseJsonResponse(response);
    });
  }

  async chat(request: ProviderRequest): Promise<ProviderChatResult> {
    return this.guarded("chat", request.model.externalModelId, request.signal, async () => {
      const url = `${this.baseUrl}/chat/completions`;
      request.signal?.throwIfAborted();
      const dispatchAuth = await request.onProviderAttempt?.();
      request.signal?.throwIfAborted();
      const requestBody = JSON.stringify({
        ...request.body,
        model: request.model.externalModelId,
        // Keep the provider from injecting an unbounded, unmetered system
        // prompt, and drop any non-allowlisted venice_parameters key.
        venice_parameters: sanitizedVeniceParameters(request.body as Record<string, unknown>),
        stream: false
      });
      const init: RequestInit = {
        method: "POST",
        headers: this.headers(request.requestId, request.e2eeHeaders, dispatchAuth?.providerKeyId),
        body: requestBody
      };
      const response = await chatFetch(url, init, request.signal);
      if (!response.ok) throw await providerHttpError(response);
      let responseText: string;
      let json: unknown;
      try {
        responseText = await response.text();
        json = JSON.parse(responseText);
      } catch {
        throw new ProviderError("provider_invalid_json", "Provider returned an invalid response", response.status);
      }
      return {
        response: json,
        usage: openAiUsageToInternal((json as { usage?: unknown }).usage),
        providerRequestId: typeof (json as { id?: unknown }).id === "string"
          ? (json as { id: string }).id
          : undefined,
        exactRequestHash: sha256Hex(requestBody),
        exactResponseHash: sha256Hex(responseText)
      };
    });
  }

  async stream(request: ProviderRequest): Promise<ProviderStreamResult> {
    const guard = this.acquireGuard("stream", request.model.externalModelId);
    let established: {
      body: ReadableStream<Uint8Array>;
      exactRequestHash: string;
      exactResponseHash: Promise<string>;
    };
    try {
      const url = `${this.baseUrl}/chat/completions`;
      request.signal?.throwIfAborted();
      const dispatchAuth = await request.onProviderAttempt?.();
      request.signal?.throwIfAborted();
      const requestBody = JSON.stringify({
        ...request.body,
        model: request.model.externalModelId,
        venice_parameters: sanitizedVeniceParameters(request.body as Record<string, unknown>),
        stream: true,
        stream_options: {
          include_usage: true
        }
      });
      const init: RequestInit = {
        method: "POST",
        headers: this.headers(request.requestId, request.e2eeHeaders, dispatchAuth?.providerKeyId),
        body: requestBody
      };
      const response = await chatFetch(url, init, request.signal);

      const body = await requireStreamBody(response);
      const hashed = withSha256(body);
      established = {
        body: hashed.body,
        exactRequestHash: sha256Hex(requestBody),
        exactResponseHash: hashed.digest
      };
    } catch (error) {
      this.recordFailure(guard, error, request.signal);
      throw error;
    }
    let resolveUsage!: (usage: SseParseResult) => void;
    const usagePromise = new Promise<SseParseResult>((resolve) => {
      resolveUsage = resolve;
    });
    const stream = this.monitorStream(
      proxyOpenAiSse(established.body, (result) => resolveUsage(result)),
      guard,
      request.signal
    );

    return {
      stream,
      usage: usagePromise.then((result) => {
        return (
          result.usage ?? {
            inputTokens: estimateInputTokens(request.body.messages),
            outputTokens: Math.max(1, result.estimatedOutputTokens || estimateTextTokens("venice")),
            cachedTokens: 0
          }
        );
      }),
      signatureBinding: Promise.all([usagePromise, established.exactResponseHash]).then(([result, responseHash]) => {
        if (!result.providerRequestId) return undefined;
        return {
          providerRequestId: result.providerRequestId,
          exactRequestHash: established.exactRequestHash,
          exactResponseHash: responseHash
        };
      })
    };
  }

  async embeddings(request: EmbeddingProviderRequest): Promise<EmbeddingProviderResult> {
    return this.guarded("embeddings", request.model.externalModelId, request.signal, async () => {
      request.signal?.throwIfAborted();
      const dispatchAuth = await request.onProviderAttempt?.();
      request.signal?.throwIfAborted();
      const init: RequestInit = {
        method: "POST",
        headers: this.headers(request.requestId, undefined, dispatchAuth?.providerKeyId),
        body: JSON.stringify({ ...request.body, model: request.model.externalModelId })
      };
      const response = await chatFetch(`${this.baseUrl}/embeddings`, init, request.signal);
      const raw = await parseJsonResponse(response);
      const normalized = normalizeEmbeddingResponse(raw, request.body, request.model.externalModelId);
      return {
        ...normalized,
        providerRequestId: response.headers.get("cf-ray") ?? undefined
      };
    });
  }

  async generateImage(request: ImageProviderRequest): Promise<ImageProviderResult> {
    return this.guarded("image", request.model.externalModelId, request.signal, async () => {
      // The durable provider-attempt fence MUST commit before any upstream fetch
      // (identical discipline to chat/embeddings): a transport failure before
      // this callback stays a zero-cost abort; after it, control captures the
      // authorized flat price. The fence also names the credential to use.
      request.signal?.throwIfAborted();
      const dispatchAuth = await request.onProviderAttempt?.();
      request.signal?.throwIfAborted();
      const response = await mediaFetch(`${this.baseUrl}/image/generate`, {
        method: "POST",
        headers: this.headers(request.requestId, undefined, dispatchAuth?.providerKeyId),
        body: JSON.stringify({
          model: request.model.externalModelId,
          prompt: request.prompt,
          width: request.width,
          height: request.height,
          format: "webp",
          hide_watermark: true,
          // Venice defaults safe_mode to true, which blurs images it classifies as
          // adult content. This gateway routes uncensored models, so opt out.
          safe_mode: false,
          return_binary: false
        })
      }, request.signal);

      if (!response.ok) throw await providerHttpError(response);
      const text = await readBoundedResponseText(response, MAX_IMAGE_RESPONSE_BYTES);
      let json: { images?: unknown };
      try {
        json = JSON.parse(text) as { images?: unknown };
      } catch {
        throw new ProviderError("provider_invalid_json", "Provider returned malformed image data", response.status);
      }
      const base64 = Array.isArray(json.images) && typeof json.images[0] === "string" ? json.images[0] : null;
      // Validate structural facts only; never surface the bytes in an error.
      if (!base64 || !BASE64_PATTERN.test(base64)) {
        throw new ProviderError("provider_invalid_json", "Provider returned no image data", response.status);
      }
      if ((base64.length * 3) / 4 > MAX_IMAGE_DECODED_BYTES) {
        throw new ProviderError("provider_response_too_large", "Provider image exceeded the permitted size", 502);
      }
      return {
        base64,
        mimeType: "image/webp",
        blurred: response.headers.get("x-venice-is-blurred") === "true",
        contentViolation: response.headers.get("x-venice-is-content-violation") === "true"
      };
    });
  }

  async speech(request: SpeechProviderRequest): Promise<SpeechProviderResult> {
    return this.guarded("speech", request.model.externalModelId, undefined, async () => {
      const response = await mediaFetch(`${this.baseUrl}/audio/speech`, {
        method: "POST",
        headers: this.headers(request.requestId),
        body: JSON.stringify({
          model: request.model.externalModelId,
          input: request.input,
          ...(request.voice ? { voice: request.voice } : {}),
          response_format: "mp3"
        })
      });

      if (!response.ok) throw await providerHttpError(response);
      const audio = Buffer.from(await response.arrayBuffer());
      if (audio.byteLength === 0) throw new ProviderError("provider_invalid_json", "Provider returned no audio data", response.status);
      return { audio, mimeType: "audio/mpeg" };
    });
  }
}
