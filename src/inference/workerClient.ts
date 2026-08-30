// WorkerClient implementations. In-process wraps provider adapters directly
// (dev monolith); HTTP calls credential-isolated provider workers over an
// authenticated internal RPC. The relay holds no provider credential.

import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import { VeniceProviderAdapter } from "../providers/venice.js";
import type { VeniceKeysetStore } from "../providers/veniceKeyStore.js";
import { ProviderRegistry } from "../providers/registry.js";
import {
  canonicalOutputTokenLimit,
  type ImageProviderRequest,
  type ModelRecord,
  type ProviderDispatchAuthorization,
  type ProviderRequest,
  type ProviderSignatureBinding,
  type SpeechProviderRequest
} from "../providers/types.js";
import type { EmbeddingProviderRequest } from "../providers/embeddings.js";
import { AppError, ProviderError } from "../security/errors.js";
import { openAiUsageToInternal } from "../providers/sse.js";
import {
  NO_REASONING_CAPABILITIES,
  reasoningSelectionKey,
  resolveReasoningSelection,
  type ReasoningRequestFields
} from "./reasoning.js";
import type { TokenUsage } from "../metering/tokens.js";
import type {
  WorkerAttestationRequest,
  WorkerChatRequest,
  WorkerChatResult,
  WorkerClient,
  WorkerEmbeddingRequest,
  WorkerEmbeddingResult,
  WorkerImageRequest,
  WorkerImageResult,
  WorkerSpeechRequest,
  WorkerSpeechResult,
  WorkerOpaqueE2eeRequest,
  WorkerOpaqueE2eeResult,
  ProviderDispatchAttempt,
  WorkerProbeRequest,
  WorkerProbeResult,
  WorkerStreamResult
} from "./rpc.js";

const USAGE_EVENT = "anonrouter-usage";
const SIGNATURE_BINDING_EVENT = "anonrouter-signature-binding";
const STREAM_ERROR_EVENT = "anonrouter-stream-error";
const TERMINAL_EVENT = "anonrouter-terminal";

export type ProviderAttemptFence = (
  attempt: ProviderDispatchAttempt,
  signal?: AbortSignal
) => Promise<ProviderDispatchAuthorization | void>;
export type AttestationAttemptFence = (
  dispatchToken: string,
  providerName: string,
  externalModelId: string,
  signal?: AbortSignal
) => Promise<ProviderDispatchAuthorization | void>;

function isPublicDoneChunk(chunk: string): boolean {
  return chunk.trim() === "data: [DONE]";
}

/** Minimal model shape the adapters need (they only read externalModelId + name). */
function stubModel(
  request: Pick<WorkerChatRequest, "providerName" | "externalModelId">,
  modelType: ModelRecord["modelType"] = "text"
): ModelRecord {
  return {
    id: "",
    providerId: "",
    providerName: request.providerName,
    providerStatus: "active",
    providerPrivacyClass: "",
    publicModelId: request.externalModelId,
    externalModelId: request.externalModelId,
    displayName: "",
    modelType,
    unitPriceUsd: null,
    contextWindow: 1_000_000,
    maxOutputTokens: modelType === "text" ? 1_000_000 : 0,
    inputPricePerMillion: 0,
    outputPricePerMillion: 0,
    cacheReadPricePerMillion: null,
    cacheWritePricePerMillion: null,
    privacyClass: "",
    supportsStreaming: true,
    supportsTools: false,
    routingEnabled: false,
    qualityTier: 1,
    routingTasks: [],
    supportsWeb: false,
    expectedLatencyMs: null,
    // The relay already translated reasoning into exact provider fields; the
    // worker-side adapter never consults capabilities.
    reasoningCapabilities: NO_REASONING_CAPABILITIES
  };
}

function toEmbeddingProviderRequest(
  request: WorkerEmbeddingRequest,
  providerAttemptFence: ProviderAttemptFence,
  signal?: AbortSignal
): EmbeddingProviderRequest {
  return {
    requestId: request.requestId,
    model: stubModel(request, "embedding"),
    body: request.body,
    signal,
    onProviderAttempt: () => providerAttemptFence({
      dispatchToken: request.dispatchToken,
      requestId: request.requestId,
      operation: "embeddings",
      providerName: request.providerName,
      externalModelId: request.externalModelId,
      stream: false,
      effectiveMaxOutputTokens: 0,
      reasoningKey: "default",
      providerReasoningKey: "default"
    }, signal)
  };
}

/**
 * Build the content-free image dispatch attempt + provider request. Image
 * generation is single-shot and carries no chat token/output semantics: the
 * bound provider-work facts are the size and output format the ticket authorized
 * (and control priced). The worker re-reports them so control can reject any
 * post-authorization size/format tampering at the durable fence.
 */
function toImageProviderRequest(
  request: WorkerImageRequest,
  providerAttemptFence: ProviderAttemptFence,
  signal?: AbortSignal
): ImageProviderRequest {
  return {
    requestId: request.requestId,
    model: stubModel(request, "image"),
    prompt: request.prompt,
    width: request.width,
    height: request.height,
    signal,
    onProviderAttempt: () => providerAttemptFence({
      dispatchToken: request.dispatchToken,
      requestId: request.requestId,
      operation: "image",
      providerName: request.providerName,
      externalModelId: request.externalModelId,
      stream: false,
      effectiveMaxOutputTokens: 0,
      reasoningKey: "default",
      providerReasoningKey: "default",
      imageWidth: request.width,
      imageHeight: request.height,
      imageResponseFormat: request.responseFormat
    }, signal)
  };
}

/**
 * Speech mirrors image: single-shot, no chat token/output semantics, and the
 * bound provider-work facts are the exact character count, voice, and container
 * the ticket authorized (and control priced). The worker re-reports them so
 * control can reject any post-authorization tampering at the durable fence.
 */
function toSpeechProviderRequest(
  request: WorkerSpeechRequest,
  providerAttemptFence: ProviderAttemptFence,
  signal?: AbortSignal
): SpeechProviderRequest {
  return {
    requestId: request.requestId,
    model: stubModel(request, "tts"),
    input: request.input,
    voice: request.voice,
    responseFormat: request.responseFormat,
    signal,
    onProviderAttempt: () => providerAttemptFence({
      dispatchToken: request.dispatchToken,
      requestId: request.requestId,
      operation: "speech",
      providerName: request.providerName,
      externalModelId: request.externalModelId,
      stream: false,
      effectiveMaxOutputTokens: 0,
      reasoningKey: "default",
      providerReasoningKey: "default",
      // The count the worker is actually about to send, not a value it was
      // told: this is what makes the fence a real check on the charge.
      speechCharacterCount: request.input.length,
      speechVoice: request.voice,
      speechResponseFormat: request.responseFormat
    }, signal)
  };
}

function chatDispatchAttempt(request: WorkerChatRequest, stream: boolean): ProviderDispatchAttempt {
  let effectiveMaxOutputTokens = 0;
  try {
    const canonical = canonicalOutputTokenLimit(request.body);
    const legacy = request.body.max_tokens;
    const completion = request.body.max_completion_tokens;
    // Control intentionally sends both aliases with the same value. Requiring
    // both at the worker boundary avoids provider-version precedence changes.
    if (
      Number.isSafeInteger(canonical)
      && (canonical ?? 0) > 0
      && legacy === canonical
      && completion === canonical
    ) effectiveMaxOutputTokens = canonical!;
  } catch {
    // Send a non-matching sentinel through the one-time control callback so a
    // malformed attempt consumes its grant instead of remaining replayable.
  }
  let providerReasoningKey = "invalid";
  try {
    const veniceParameters = request.body.venice_parameters;
    const containsRelayOnlyReasoning = request.body.reasoning !== undefined
      || Boolean(
        veniceParameters
        && typeof veniceParameters === "object"
        && !Array.isArray(veniceParameters)
        && "disable_thinking" in veniceParameters
      );
    if (!containsRelayOnlyReasoning) {
      providerReasoningKey = reasoningSelectionKey(
        resolveReasoningSelection(request.body as ReasoningRequestFields)
      );
    }
  } catch {
    // Same fail-closed consumption rule as malformed token aliases above.
  }
  return {
    dispatchToken: request.dispatchToken,
    requestId: request.requestId,
    operation: "chat",
    providerName: request.providerName,
    externalModelId: request.externalModelId,
    stream,
    effectiveMaxOutputTokens,
    reasoningKey: request.reasoningKey,
    providerReasoningKey
  };
}

function toProviderRequest(
  request: WorkerChatRequest,
  stream: boolean,
  providerAttemptFence: ProviderAttemptFence,
  signal?: AbortSignal
): ProviderRequest {
  return {
    requestId: request.requestId,
    model: stubModel(request),
    body: request.body as ProviderRequest["body"],
    inputTokens: 0,
    e2eeHeaders: request.e2eeHeaders,
    signal,
    onProviderAttempt: () => providerAttemptFence(chatDispatchAttempt(request, stream), signal)
  };
}

/**
 * In-process worker client used by the dev monolith. It routes chat/stream to
 * the right provider adapter (mock or venice) and Venice attestation to the
 * credential-bearing Venice adapter. The real venice-worker container only ever
 * exercises the Venice path.
 */
export class InProcessWorkerClient implements WorkerClient {
  private readonly registry: ProviderRegistry;
  private readonly venice: VeniceProviderAdapter;

  constructor(
    config: ContentPlaneConfig,
    private readonly providerAttemptFence: ProviderAttemptFence,
    private readonly attestationAttemptFence: AttestationAttemptFence,
    veniceKeyStore?: VeniceKeysetStore
  ) {
    this.registry = new ProviderRegistry(config, veniceKeyStore);
    this.venice = new VeniceProviderAdapter(config, undefined, veniceKeyStore);
  }

  async attestation(request: WorkerAttestationRequest, signal?: AbortSignal) {
    signal?.throwIfAborted();
    const authorization = await this.attestationAttemptFence(
      request.dispatchToken,
      request.providerName,
      request.externalModelId,
      signal
    );
    signal?.throwIfAborted();
    const adapter = this.registry.adapterFor(request.providerName);
    if (!adapter.fetchAttestation) {
      throw new ProviderError("attestation_unsupported", "Provider does not expose E2EE attestation", 501);
    }
    return request.providerName === "venice"
      ? this.venice.fetchAttestation(request.externalModelId, request.nonce, signal, authorization?.providerKeyId)
      : adapter.fetchE2eeAttestation
        ? adapter.fetchE2eeAttestation(request.externalModelId, request.nonce, signal, authorization?.providerKeyId)
        : adapter.fetchAttestation(request.externalModelId, request.nonce, signal, authorization?.providerKeyId);
  }

  // Provider-neutral read-only attestation for the public TEE API. Dispatches to
  // the resolved provider's adapter (not hardcoded Venice) so Chutes/Tinfoil/NEAR
  // AI each fetch their own enclave evidence with their own isolated credential.
  async attestationForModel(providerName: string, externalModelId: string, nonce: string, signal?: AbortSignal): Promise<unknown> {
    signal?.throwIfAborted();
    const adapter = this.registry.adapterFor(providerName);
    if (!adapter.fetchAttestation) {
      throw new ProviderError("attestation_unsupported", "Provider does not expose TEE attestation", 501);
    }
    return adapter.fetchAttestation(externalModelId, nonce, signal);
  }

  async signatureForRequest(providerName: string, externalModelId: string, providerRequestId: string, signal?: AbortSignal): Promise<unknown> {
    signal?.throwIfAborted();
    const adapter = this.registry.adapterFor(providerName);
    if (!adapter.fetchSignature) {
      throw new ProviderError("tee_signature_not_supported", "Provider does not expose per-request signatures", 501);
    }
    return adapter.fetchSignature(providerRequestId, externalModelId, signal);
  }

  async chat(request: WorkerChatRequest, signal?: AbortSignal): Promise<WorkerChatResult> {
    const result = await this.registry
      .adapterFor(request.providerName)
      .chat(toProviderRequest(request, false, this.providerAttemptFence, signal));
    return {
      response: result.response,
      usage: result.usage,
      providerRequestId: result.providerRequestId,
      exactRequestHash: result.exactRequestHash,
      exactResponseHash: result.exactResponseHash
    };
  }

  async embeddings(request: WorkerEmbeddingRequest, signal?: AbortSignal): Promise<WorkerEmbeddingResult> {
    const adapter = this.registry.adapterFor(request.providerName);
    if (!adapter.embeddings) throw new AppError(503, "provider_unavailable", "Provider does not support embeddings");
    const result = await adapter.embeddings(toEmbeddingProviderRequest(request, this.providerAttemptFence, signal));
    return { response: result.response, usage: result.usage };
  }

  async generateImage(request: WorkerImageRequest, signal?: AbortSignal): Promise<WorkerImageResult> {
    const adapter = this.registry.adapterFor(request.providerName);
    if (!adapter.generateImage) {
      throw new AppError(503, "provider_unavailable", "Provider does not support image generation");
    }
    const result = await adapter.generateImage(toImageProviderRequest(request, this.providerAttemptFence, signal));
    return {
      base64: result.base64,
      mimeType: result.mimeType,
      blurred: result.blurred,
      contentViolation: result.contentViolation
    };
  }

  async generateSpeech(request: WorkerSpeechRequest, signal?: AbortSignal): Promise<WorkerSpeechResult> {
    const adapter = this.registry.adapterFor(request.providerName);
    if (!adapter.speech) {
      throw new AppError(503, "provider_unavailable", "Provider does not support speech generation");
    }
    const result = await adapter.speech(toSpeechProviderRequest(request, this.providerAttemptFence, signal));
    // Audio crosses the worker -> relay RPC as base64 in JSON, exactly as image
    // bytes do. It is never logged and never reaches the control plane.
    return { audioBase64: result.audio.toString("base64"), mimeType: result.mimeType };
  }

  async stream(request: WorkerChatRequest, signal?: AbortSignal): Promise<WorkerStreamResult> {
    const result = await this.registry
      .adapterFor(request.providerName)
      .stream(toProviderRequest(request, true, this.providerAttemptFence, signal));
    return { stream: result.stream, usage: result.usage, signatureBinding: result.signatureBinding };
  }

  async opaqueE2ee(request: WorkerOpaqueE2eeRequest, signal?: AbortSignal): Promise<WorkerOpaqueE2eeResult> {
    signal?.throwIfAborted();
    const adapter = this.registry.adapterFor(request.providerName);
    if (!adapter.opaqueE2ee) {
      throw new ProviderError("e2ee_transport_not_supported", "Provider does not expose a whole-body E2EE transport", 501);
    }
    const ciphertext = decodeCanonicalBase64(request.ciphertextBase64);
    const result = await adapter.opaqueE2ee({
      requestId: request.requestId,
      model: stubModel(request),
      protocol: request.protocol,
      ciphertext,
      headers: request.headers,
      signal,
      onProviderAttempt: () => this.providerAttemptFence({
        dispatchToken: request.dispatchToken,
        requestId: request.requestId,
        operation: "chat",
        providerName: request.providerName,
        externalModelId: request.externalModelId,
        stream: false,
        effectiveMaxOutputTokens: request.effectiveMaxOutputTokens,
        reasoningKey: request.reasoningKey,
        providerReasoningKey: "default",
        opaqueE2ee: true
      }, signal)
    });
    return {
      statusCode: result.statusCode,
      contentType: result.contentType,
      bodyBase64: Buffer.from(result.body).toString("base64"),
      responseHeaders: result.responseHeaders,
      usage: result.usage
    };
  }

  // Synthetic health probe. Sends a one-token, non-streaming request straight
  // to the adapter with NO onProviderAttempt fence, so it never mints a dispatch
  // ticket, never bills, and never touches the durable single-use ticket flow.
  // It exists only to answer "does this model still respond, and how fast".
  async probe(request: WorkerProbeRequest, signal?: AbortSignal): Promise<WorkerProbeResult> {
    const providerRequest: ProviderRequest = {
      requestId: request.requestId,
      model: stubModel({ providerName: request.providerName, externalModelId: request.externalModelId }, "text"),
      body: {
        model: request.externalModelId,
        messages: [{ role: "user", content: "ping" }],
        max_tokens: 1,
        stream: false
      } as ProviderRequest["body"],
      inputTokens: 1,
      signal
    };
    const started = Date.now();
    try {
      await this.registry.adapterFor(request.providerName).chat(providerRequest);
      return { ok: true, latencyMs: Date.now() - started };
    } catch (error) {
      const latencyMs = Date.now() - started;
      if (error instanceof ProviderError) {
        return { ok: false, latencyMs, statusCode: error.statusCode, errorCode: error.code };
      }
      return { ok: false, latencyMs, errorCode: "provider_probe_failed" };
    }
  }
}

/** Serialize a worker stream plus mandatory usage and success terminal sidebands. */
export async function* serializeWorkerStream(result: WorkerStreamResult): AsyncIterable<string> {
  try {
    for await (const chunk of result.stream) {
      // Defensive compatibility: adapters must consume the provider marker,
      // but never let a legacy adapter turn it into a pre-settlement promise.
      if (!isPublicDoneChunk(chunk)) yield chunk;
    }
  } catch (error) {
    if (!(error instanceof ProviderError) || error.code !== "provider_stream_incomplete") throw error;

    // The relay needs the partial token metadata to settle output already sent
    // to the caller. Carry only the allowlisted error code and usage; never
    // serialize the provider exception text or any stream content as metadata.
    const usage = await result.usage.catch(() => undefined);
    yield `event: ${USAGE_EVENT}\ndata: ${JSON.stringify(usage ?? null)}\n\n`;
    yield `event: ${STREAM_ERROR_EVENT}\ndata: ${JSON.stringify({ code: "provider_stream_incomplete" })}\n\n`;
    return;
  }
  const usage = await result.usage.catch(() => undefined);
  const signatureBinding = await result.signatureBinding?.catch(() => undefined);
  if (signatureBinding
    && typeof signatureBinding.providerRequestId === "string"
    && signatureBinding.providerRequestId.length <= 256
    && /^[0-9a-f]{64}$/.test(signatureBinding.exactRequestHash)
    && /^[0-9a-f]{64}$/.test(signatureBinding.exactResponseHash)) {
    yield `event: ${SIGNATURE_BINDING_EVENT}\ndata: ${JSON.stringify(signatureBinding)}\n\n`;
  }
  yield `event: ${USAGE_EVENT}\ndata: ${JSON.stringify(usage ?? null)}\n\n`;
  yield `event: ${TERMINAL_EVENT}\ndata: {"status":"complete"}\n\n`;
}

/**
 * Narrow worker -> control capability used only at the provider dispatch edge.
 * It carries an opaque single-use token plus content-free dispatch facts and
 * fails closed before any provider fetch.
 */
export class HttpProviderAttemptAcknowledger {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly deploymentId = "primary",
    private readonly timeoutMs = 5_000
  ) {}

  async authorizeDispatch(
    attempt: ProviderDispatchAttempt,
    downstreamSignal?: AbortSignal
  ): Promise<ProviderDispatchAuthorization> {
    return this.post(
      "/internal/control/dispatch-attempt",
      { ...attempt, deploymentId: this.deploymentId },
      "Provider dispatch fence",
      downstreamSignal
    );
  }

  async authorizeAttestation(
    dispatchToken: string,
    providerName: string,
    externalModelId: string,
    downstreamSignal?: AbortSignal
  ): Promise<ProviderDispatchAuthorization> {
    return this.post(
      "/internal/control/attestation-attempt",
      { dispatchToken, providerName, externalModelId, deploymentId: this.deploymentId },
      "Attestation dispatch fence",
      downstreamSignal
    );
  }

  private async post(
    path: string,
    body: unknown,
    label: string,
    downstreamSignal?: AbortSignal
  ): Promise<ProviderDispatchAuthorization> {
    const deadline = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      deadline.abort(new DOMException(`${label} timed out`, "TimeoutError"));
    }, this.timeoutMs);
    const signal = downstreamSignal
      ? AbortSignal.any([downstreamSignal, deadline.signal])
      : deadline.signal;
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${this.token}` },
        body: JSON.stringify(body),
        signal
      });
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        throw new AppError(503, "provider_attempt_fence_failed", "Provider dispatch authorization failed");
      }
      // The fence body carries the control-selected credential id (if any).
      // A malformed body keeps the default-key behavior instead of failing an
      // already-authorized dispatch.
      const parsed = (await response.json().catch(() => null)) as { provider_key_id?: unknown } | null;
      return {
        providerKeyId: typeof parsed?.provider_key_id === "string" ? parsed.provider_key_id : null
      };
    } catch (error) {
      if (!downstreamSignal?.aborted && timedOut) {
        throw new AppError(503, "provider_attempt_fence_timeout", "Provider dispatch authorization timed out");
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * Reconstruct a ProviderError from a worker's internal error response, recovering
 * the sanitized provider status / request-id / machine-code that the worker error
 * handler serialized into the `provider` block (workerErrorHandler in httpBase).
 * Without this the split path would collapse every provider failure into the
 * worker's HTTP status and lose the rejection-ledger metadata. The body is a
 * small sanitized JSON envelope (no prompt/response/credential); a parse failure
 * degrades gracefully to the generic fallback.
 */
async function workerProviderError(response: Response, fallbackCode: string): Promise<ProviderError> {
  let code = fallbackCode;
  let providerStatus: number | undefined = response.status;
  let providerRequestId: string | undefined;
  let providerCode: string | undefined;
  try {
    const parsed = (await response.json()) as {
      error?: { type?: unknown };
      provider?: { status?: unknown; request_id?: unknown; code?: unknown };
    };
    if (typeof parsed.error?.type === "string") code = parsed.error.type;
    const provider = parsed.provider;
    if (provider && typeof provider === "object") {
      if (typeof provider.status === "number") providerStatus = provider.status;
      if (typeof provider.request_id === "string") providerRequestId = provider.request_id;
      if (typeof provider.code === "string") providerCode = provider.code;
    }
  } catch {
    // No JSON body / unexpected shape: keep the generic fallback + worker status.
  }
  return new ProviderError(code, "Worker request failed", providerStatus, { providerRequestId, providerCode });
}

export class HttpWorkerClient implements WorkerClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly provider: "venice" | "fireworks" | "aws-bedrock" | "deepinfra" | "chutes" | "tinfoil" | "near-ai" = "venice",
    /**
     * Deadline for the worker to return RESPONSE HEADERS, not for the whole
     * exchange. There was previously no deadline at all here, which was
     * survivable while the relay and the worker shared a Docker bridge: a hung
     * peer was effectively impossible. Across a WAN it is not, and without a
     * deadline a single black-holed connection holds a relay slot until the
     * client gives up, with the reservation still open.
     *
     * Deliberately generous, because it bounds the worker's own upstream call:
     * the provider dispatch happens inside the worker before it answers.
     */
    private readonly headersTimeoutMs = 120_000
  ) {}

  private endpoint(operation: string) {
    return `${this.baseUrl}/internal/${this.provider}/${operation}`;
  }

  private headers() {
    return { "content-type": "application/json", authorization: `Bearer ${this.token}` };
  }

  /**
   * fetch with a headers-only deadline.
   *
   * The timer is cleared the moment the response resolves, so a long streamed
   * generation is never truncated by it. Only the caller's own signal can end
   * the body. Getting this backwards would cap every generation at the timeout,
   * which is why the distinction is spelled out here rather than assumed.
   */
  private async send(url: string, body: unknown, signal?: AbortSignal): Promise<Response> {
    const deadline = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      deadline.abort(new DOMException("Worker RPC timed out", "TimeoutError"));
    }, this.headersTimeoutMs);
    const combined = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
    try {
      return await fetch(url, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(body),
        signal: combined
      });
    } catch (error) {
      // A client disconnect stays a disconnect, so the relay treats it as
      // ordinary cancellation and runs its normal compensation. Only our own
      // deadline becomes a stable, content-free service error.
      if (!signal?.aborted && timedOut) {
        throw new ProviderError("worker_unavailable", "Worker did not respond in time", 504);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  async attestation(request: WorkerAttestationRequest, signal?: AbortSignal): Promise<unknown> {
    if (request.providerName !== this.provider && !(request.providerName === "mock" && this.provider === "venice")) {
      throw new ProviderError("worker_attestation_failed", "Attestation provider does not match the credential worker", 409);
    }
    const response = await this.send(this.endpoint("attestation"), request, signal);
    if (!response.ok) throw new ProviderError("worker_attestation_failed", "Worker attestation failed", response.status);
    const payload = (await response.json()) as { evidence?: unknown };
    // The internal worker endpoint wraps raw provider evidence for transport;
    // expose exactly that evidence at the public relay (one wrapper, not two).
    return payload.evidence;
  }

  async attestationForModel(providerName: string, externalModelId: string, nonce: string, signal?: AbortSignal): Promise<unknown> {
    if (providerName !== this.provider) {
      throw new ProviderError("worker_attestation_failed", "Attestation provider does not match the credential worker", 409);
    }
    const response = await this.send(this.endpoint("tee-attestation"), { providerName, externalModelId, nonce }, signal);
    if (!response.ok) throw new ProviderError("worker_attestation_failed", "Worker attestation failed", response.status);
    const payload = (await response.json()) as { evidence?: unknown };
    return payload.evidence;
  }

  async signatureForRequest(providerName: string, externalModelId: string, providerRequestId: string, signal?: AbortSignal): Promise<unknown> {
    if (providerName !== this.provider) {
      throw new ProviderError("tee_signature_not_supported", "Signature provider does not match the credential worker", 409);
    }
    const response = await this.send(this.endpoint("tee-signature"), { providerName, externalModelId, providerRequestId }, signal);
    if (!response.ok) throw new ProviderError("tee_signature_not_supported", "Worker signature unavailable", response.status);
    const payload = (await response.json()) as { evidence?: unknown };
    return payload.evidence;
  }

  async chat(request: WorkerChatRequest, signal?: AbortSignal): Promise<WorkerChatResult> {
    const response = await this.send(this.endpoint("chat"), request, signal);
    if (!response.ok) throw await workerProviderError(response, "worker_chat_failed");
    return (await response.json()) as WorkerChatResult;
  }

  async embeddings(request: WorkerEmbeddingRequest, signal?: AbortSignal): Promise<WorkerEmbeddingResult> {
    const response = await this.send(this.endpoint("embeddings"), request, signal);
    if (!response.ok) throw await workerProviderError(response, "worker_embeddings_failed");
    return (await response.json()) as WorkerEmbeddingResult;
  }

  async generateImage(request: WorkerImageRequest, signal?: AbortSignal): Promise<WorkerImageResult> {
    const response = await this.send(this.endpoint("image"), request, signal);
    if (!response.ok) throw await workerProviderError(response, "worker_image_failed");
    return (await response.json()) as WorkerImageResult;
  }

  async generateSpeech(request: WorkerSpeechRequest, signal?: AbortSignal): Promise<WorkerSpeechResult> {
    const response = await fetch(this.endpoint("speech"), {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(request),
      signal
    });
    if (!response.ok) throw await workerProviderError(response, "worker_speech_failed");
    return (await response.json()) as WorkerSpeechResult;
  }

  async stream(request: WorkerChatRequest, signal?: AbortSignal): Promise<WorkerStreamResult> {
    const response = await this.send(this.endpoint("stream"), request, signal);
    if (!response.ok) throw await workerProviderError(response, "worker_stream_failed");
    if (!response.body) throw new ProviderError("worker_stream_failed", "Worker stream failed", response.status);
    let resolveUsage!: (usage: TokenUsage | undefined) => void;
    const usage = new Promise<TokenUsage | undefined>((resolve) => (resolveUsage = resolve));
    let resolveSignatureBinding!: (binding: ProviderSignatureBinding | undefined) => void;
    const signatureBinding = new Promise<ProviderSignatureBinding | undefined>((resolve) => {
      resolveSignatureBinding = resolve;
    });
    const stream = deserializeWorkerStream(request, response.body, resolveUsage, resolveSignatureBinding, signal);
    return { stream, usage, signatureBinding };
  }

  async opaqueE2ee(request: WorkerOpaqueE2eeRequest, signal?: AbortSignal): Promise<WorkerOpaqueE2eeResult> {
    if (request.providerName !== this.provider && !(request.providerName === "mock" && this.provider === "venice")) {
      throw new ProviderError("worker_e2ee_failed", "E2EE provider does not match the credential worker", 409);
    }
    const response = await this.send(this.endpoint("opaque-e2ee"), request, signal);
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new ProviderError("worker_e2ee_failed", "Worker E2EE request failed", response.status);
    }
    return (await response.json()) as WorkerOpaqueE2eeResult;
  }
}

/** Relay-side provider dispatcher; each target is a separate credential worker. */
export class RoutedWorkerClient implements WorkerClient {
  constructor(
    private readonly venice: HttpWorkerClient,
    private readonly fireworks: HttpWorkerClient,
    private readonly bedrock: HttpWorkerClient,
    private readonly deepinfra: HttpWorkerClient,
    private readonly chutes: HttpWorkerClient,
    private readonly tinfoil: HttpWorkerClient,
    private readonly near: HttpWorkerClient
  ) {}

  private forProvider(providerName: string): HttpWorkerClient {
    if (providerName === "venice") return this.venice;
    if (providerName === "fireworks") return this.fireworks;
    if (providerName === "aws-bedrock") return this.bedrock;
    if (providerName === "deepinfra") return this.deepinfra;
    if (providerName === "chutes") return this.chutes;
    if (providerName === "tinfoil") return this.tinfoil;
    if (providerName === "near-ai") return this.near;
    // Test/dev split harnesses intentionally send the mock provider through the
    // existing Venice worker RPC. Production fixture providers are disabled in
    // the database, so control can never authorize this fallback there.
    if (providerName === "mock") return this.venice;
    throw new ProviderError("worker_provider_unavailable", "Provider worker is unavailable", 503);
  }

  attestation(request: WorkerAttestationRequest, signal?: AbortSignal) {
    return this.forProvider(request.providerName).attestation(request, signal);
  }

  attestationForModel(providerName: string, externalModelId: string, nonce: string, signal?: AbortSignal) {
    return this.forProvider(providerName).attestationForModel(providerName, externalModelId, nonce, signal);
  }

  signatureForRequest(providerName: string, externalModelId: string, providerRequestId: string, signal?: AbortSignal) {
    return this.forProvider(providerName).signatureForRequest(providerName, externalModelId, providerRequestId, signal);
  }

  chat(request: WorkerChatRequest, signal?: AbortSignal) {
    return this.forProvider(request.providerName).chat(request, signal);
  }

  embeddings(request: WorkerEmbeddingRequest, signal?: AbortSignal) {
    return this.forProvider(request.providerName).embeddings(request, signal);
  }

  generateImage(request: WorkerImageRequest, signal?: AbortSignal) {
    return this.forProvider(request.providerName).generateImage(request, signal);
  }

  generateSpeech(request: WorkerSpeechRequest, signal?: AbortSignal) {
    return this.forProvider(request.providerName).generateSpeech(request, signal);
  }

  stream(request: WorkerChatRequest, signal?: AbortSignal) {
    return this.forProvider(request.providerName).stream(request, signal);
  }

  opaqueE2ee(request: WorkerOpaqueE2eeRequest, signal?: AbortSignal) {
    return this.forProvider(request.providerName).opaqueE2ee(request, signal);
  }
}

function decodeCanonicalBase64(value: string): Uint8Array {
  if (value.length === 0 || value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new ProviderError("invalid_e2ee_ciphertext", "E2EE ciphertext encoding is invalid", 400);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0 || decoded.toString("base64") !== value) {
    throw new ProviderError("invalid_e2ee_ciphertext", "E2EE ciphertext encoding is invalid", 400);
  }
  return decoded;
}

/** Split the worker's SSE + trailing usage event back into {stream, usage}. */
async function* deserializeWorkerStream(
  request: WorkerChatRequest,
  body: ReadableStream<Uint8Array>,
  resolveUsage: (usage: TokenUsage | undefined) => void,
  resolveSignatureBinding: (binding: Awaited<NonNullable<WorkerStreamResult["signatureBinding"]>>) => void,
  signal?: AbortSignal
): AsyncIterable<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let resolved = false;
  let signatureResolved = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      buffer = buffer.replace(/\r\n/g, "\n");
      let boundary = buffer.indexOf("\n\n");
      while (boundary !== -1) {
        const event = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        if (event.startsWith(`event: ${SIGNATURE_BINDING_EVENT}`)) {
          const dataLine = event.split("\n").find((line) => line.startsWith("data:"));
          const raw = dataLine ? dataLine.slice(5).trim() : "{}";
          let parsed: unknown;
          try { parsed = JSON.parse(raw); } catch { parsed = null; }
          const binding = parsed as { providerRequestId?: unknown; exactRequestHash?: unknown; exactResponseHash?: unknown } | null;
          if (binding
            && typeof binding.providerRequestId === "string"
            && binding.providerRequestId.length <= 256
            && typeof binding.exactRequestHash === "string" && /^[0-9a-f]{64}$/.test(binding.exactRequestHash)
            && typeof binding.exactResponseHash === "string" && /^[0-9a-f]{64}$/.test(binding.exactResponseHash)) {
            resolveSignatureBinding({
              providerRequestId: binding.providerRequestId,
              exactRequestHash: binding.exactRequestHash,
              exactResponseHash: binding.exactResponseHash
            });
            signatureResolved = true;
          } else {
            throw new ProviderError("worker_stream_incomplete", "Worker signature binding was malformed", 502);
          }
        } else if (event.startsWith(`event: ${USAGE_EVENT}`)) {
          const dataLine = event.split("\n").find((line) => line.startsWith("data:"));
          const raw = dataLine ? dataLine.slice(5).trim() : "null";
          resolveUsage(openAiUsageToInternalFromWorker(raw));
          resolved = true;
        } else if (event.startsWith(`event: ${TERMINAL_EVENT}`)) {
          if (!resolved) {
            throw new ProviderError("worker_stream_incomplete", "Worker stream ended unexpectedly", 502);
          }
          return;
        } else if (event.startsWith(`event: ${STREAM_ERROR_EVENT}`)) {
          const dataLine = event.split("\n").find((line) => line.startsWith("data:"));
          const raw = dataLine ? dataLine.slice(5).trim() : "{}";
          let code: unknown;
          try {
            code = (JSON.parse(raw) as { code?: unknown }).code;
          } catch {
            code = undefined;
          }
          if (code === "provider_stream_incomplete") {
            throw new ProviderError(
              "provider_stream_incomplete",
              "Provider stream ended before its terminal marker",
              502
            );
          }
          throw new ProviderError("worker_stream_failed", "Worker stream failed", 502);
        } else {
          yield event + "\n\n";
        }
        boundary = buffer.indexOf("\n\n");
      }
    }
    throw new ProviderError("worker_stream_incomplete", "Worker stream ended unexpectedly", 502);
  } catch (error) {
    if (signal?.aborted) throw signal.reason ?? error;
    if (error instanceof ProviderError) throw error;
    throw new ProviderError("worker_stream_incomplete", "Worker stream ended unexpectedly", 502);
  } finally {
    await reader.cancel().catch(() => undefined);
    // If the worker died before emitting usage, leave it undefined. The provider
    // dispatch fence still makes the control plane conservatively capture any
    // ambiguous upstream attempt rather than granting free provider work.
    if (!resolved) resolveUsage(undefined);
    if (!signatureResolved) resolveSignatureBinding(undefined);
    void request;
  }
}

function openAiUsageToInternalFromWorker(raw: string): TokenUsage | undefined {
  try {
    const parsed = JSON.parse(raw);
    if (parsed === null) return undefined;
    if (typeof parsed === "object" && "inputTokens" in parsed) {
      const usage = parsed as TokenUsage;
      return { ...usage, cacheWriteTokens: usage.cacheWriteTokens ?? 0 };
    }
    return openAiUsageToInternal(parsed);
  } catch {
    return undefined;
  }
}
