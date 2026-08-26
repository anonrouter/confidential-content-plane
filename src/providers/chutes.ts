import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import { estimateInputTokens, estimateTextTokens } from "../metering/tokens.js";
import { ProviderError } from "../security/errors.js";
import { parseJsonResponse, requireStreamBody } from "./http.js";
import { normalizeEmbeddingResponse } from "./embeddings.js";
import type { EmbeddingProviderRequest, EmbeddingProviderResult } from "./embeddings.js";
import { openAiUsageToInternal, proxyOpenAiSse, type SseParseResult } from "./sse.js";
import type {
  ProviderAdapter,
  ProviderChatResult,
  ProviderOpaqueE2eeRequest,
  ProviderOpaqueE2eeResult,
  ProviderRequest,
  ProviderStreamResult
} from "./types.js";

const CHAT_TIMEOUT_MS = 10 * 60_000;
const ATTESTATION_TIMEOUT_MS = 15_000;

async function chutesFetch(url: string, init: RequestInit, cancellation?: AbortSignal, timeoutMs = CHAT_TIMEOUT_MS): Promise<Response> {
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
 * Only fields in AnonRouter's OpenAI-compatible chat contract may reach Chutes.
 * Relay-only routing/reasoning intent and Venice-specific extensions are removed
 * explicitly, even if a future call site bypasses schema stripping.
 */
function chutesBody(request: ProviderRequest, stream: boolean): Record<string, unknown> {
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
 * Chutes decentralized inference via its OpenAI-compatible Chat Completions API
 * (base https://llm.chutes.ai/v1). Confidential-compute (`tee`) routes run inside
 * an attested Intel TDX + NVIDIA CC enclave, but AnonRouter's gateway still sees
 * plaintext for a standard request, so those routes are classified `tee`, not
 * `e2ee`. Attestation evidence is fetched out-of-band from the public evidence
 * host and independently verified by ChutesTeeVerifier; the inference credential
 * is never sent to the evidence endpoint. Chutes exposes no per-request signature.
 */
export class ChutesProviderAdapter implements ProviderAdapter {
  readonly name = "chutes";
  private readonly baseUrl: string;
  private readonly attestationBaseUrl: string;
  private readonly apiKey: string;

  constructor(config: ContentPlaneConfig) {
    this.baseUrl = config.providers.chutesBaseUrl;
    this.attestationBaseUrl = config.providers.chutesAttestationBaseUrl;
    this.apiKey = config.providers.chutesApiKey;
  }

  private headers(requestId: string) {
    if (!this.apiKey) {
      throw new ProviderError("provider_not_configured", "Chutes API key is not configured");
    }
    return {
      "content-type": "application/json",
      authorization: `Bearer ${this.apiKey}`,
      "x-request-id": requestId
    };
  }

  private async resolveConfidentialChuteId(externalModelId: string, signal?: AbortSignal): Promise<string> {
    const modelsResponse = await chutesFetch(
      `${this.baseUrl}/models`,
      { method: "GET", headers: { accept: "application/json" } },
      signal,
      ATTESTATION_TIMEOUT_MS
    );
    const catalog = (await parseJsonResponse(modelsResponse)) as {
      data?: Array<{ id?: unknown; chute_id?: unknown; confidential_compute?: unknown }>;
    };
    const entry = catalog.data?.find((model) => model?.id === externalModelId);
    const chuteId = typeof entry?.chute_id === "string" ? entry.chute_id : null;
    if (!chuteId || entry?.confidential_compute !== true) {
      throw new ProviderError("e2ee_route_unavailable", "No confidential-compute chute is available for this model", 404);
    }
    return chuteId;
  }

  async chat(request: ProviderRequest): Promise<ProviderChatResult> {
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await chutesFetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify(chutesBody(request, false))
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
    const response = await chutesFetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify(chutesBody(request, true))
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
        outputTokens: Math.max(1, result.estimatedOutputTokens || estimateTextTokens("chutes")),
        cachedTokens: 0
      })
    };
  }

  /**
   * Chutes ML-KEM whole-body relay. The client obtains an attested instance key
   * and a single-use nonce from the attestation response, then sends the exact
   * encrypted blob here. The worker supplies only its isolated credential and
   * ticket-bound chute id; it never parses or transforms the ciphertext.
   *
   * Non-streaming is intentional for the launch surface: Chutes exposes exact
   * usage only inside its encrypted non-stream response, so AnonRouter captures
   * the full conservative reservation instead of inventing token counts.
   */
  async opaqueE2ee(request: ProviderOpaqueE2eeRequest): Promise<ProviderOpaqueE2eeResult> {
    if (request.protocol !== "chutes-mlkem-v1") {
      throw new ProviderError("e2ee_protocol_unsupported", "Chutes requires ML-KEM E2EE v1", 400);
    }
    const keys = Object.keys(request.headers).sort();
    if (keys.join(",") !== ["X-E2E-Nonce", "X-Instance-Id"].sort().join(",")) {
      throw new ProviderError("e2ee_headers_invalid", "Chutes E2EE headers are incomplete or unsupported", 400);
    }
    const instanceId = request.headers["X-Instance-Id"];
    const nonce = request.headers["X-E2E-Nonce"];
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(instanceId ?? "")) {
      throw new ProviderError("e2ee_instance_invalid", "Chutes E2EE instance id is invalid", 400);
    }
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce ?? "")) {
      throw new ProviderError("e2ee_nonce_invalid", "Chutes E2EE nonce is invalid", 400);
    }
    if (request.ciphertext.byteLength < 1_116) {
      throw new ProviderError("invalid_e2ee_ciphertext", "Chutes E2EE ciphertext is too short", 400);
    }
    if (!this.apiKey) {
      throw new ProviderError("provider_not_configured", "Chutes API key is not configured");
    }
    const chuteId = await this.resolveConfidentialChuteId(request.model.externalModelId, request.signal);
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await chutesFetch(`${this.attestationBaseUrl}/e2e/invoke`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.apiKey}`,
        "content-type": "application/octet-stream",
        "x-chute-id": chuteId,
        "x-instance-id": instanceId,
        "x-e2e-nonce": nonce,
        "x-e2e-stream": "false",
        "x-e2e-path": "/v1/chat/completions",
        "x-request-id": request.requestId
      },
      body: Buffer.from(request.ciphertext)
    }, request.signal);
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new ProviderError("provider_rejected_e2ee", "Chutes rejected the encrypted request", response.status);
    }
    const body = new Uint8Array(await response.arrayBuffer());
    if (body.byteLength === 0) {
      throw new ProviderError("provider_invalid_e2ee_response", "Chutes returned an empty encrypted response", 502);
    }
    return {
      statusCode: response.status,
      contentType: "application/octet-stream",
      body,
      responseHeaders: {}
    };
  }

  async embeddings(request: EmbeddingProviderRequest): Promise<EmbeddingProviderResult> {
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await chutesFetch(`${this.baseUrl}/embeddings`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify({ ...request.body, model: request.model.externalModelId })
    }, request.signal);
    const raw = await parseJsonResponse(response);
    const normalized = normalizeEmbeddingResponse(raw, request.body, request.model.externalModelId);
    return { ...normalized, providerRequestId: response.headers.get("x-request-id") ?? undefined };
  }

  /**
   * Fetch Chutes' out-of-band TEE evidence for a model + fresh caller nonce: an
   * Intel TDX DCAP quote plus NVIDIA GPU confidential-compute reports. Two steps:
   * resolve the model's chute_id from the public catalog, then fetch that chute's
   * evidence. The evidence host is public; we deliberately do NOT attach the
   * inference credential. Returned raw for ChutesTeeVerifier to verify.
   */
  async fetchAttestation(externalModelId: string, nonce: string, signal?: AbortSignal): Promise<unknown> {
    if (!/^[0-9a-f]{32,128}$/i.test(nonce)) {
      throw new ProviderError("invalid_nonce", "Attestation nonce must be 32-128 hex characters", 400);
    }
    const chuteId = await this.resolveConfidentialChuteId(externalModelId, signal);
    if (!this.apiKey) {
      throw new ProviderError("provider_not_configured", "Chutes API key is not configured");
    }
    const url = `${this.attestationBaseUrl}/chutes/${encodeURIComponent(chuteId)}/evidence?nonce=${encodeURIComponent(nonce)}`;
    // Modern Chutes evidence binds SHA256(nonce + per-instance ML-KEM public
    // key), so the credential-isolated worker must obtain the exact key set from
    // the authenticated discovery endpoint. The public relay never receives the
    // credential; only public keys are attached to the raw evidence.
    const authHeaders = { accept: "application/json", authorization: `Bearer ${this.apiKey}` };
    // Evidence is public. Never attach the inference credential to this URL.
    const response = await chutesFetch(url, { method: "GET", headers: { accept: "application/json" } }, signal, ATTESTATION_TIMEOUT_MS);
    const raw = (await parseJsonResponse(response)) as Record<string, unknown>;
    const evidenceInstanceIds = new Set(
      (Array.isArray(raw.evidence) ? raw.evidence : [])
        .map((item) => item && typeof item === "object" ? (item as { instance_id?: unknown }).instance_id : undefined)
        .filter((id): id is string => typeof id === "string")
    );
    const e2ePubkeys: Record<string, string> = {};
    const e2eInstances = new Map<string, { instance_id: string; e2e_pubkey: string; nonces: string[] }>();
    // Chutes samples at most five instances per discovery response. Accumulate a
    // bounded union until every evidence instance has a key; incomplete discovery
    // is returned as-is and the pure verifier rejects it.
    for (let attempt = 0; attempt < 12 && Object.keys(e2ePubkeys).length < evidenceInstanceIds.size; attempt += 1) {
      const instancesResponse = await chutesFetch(`${this.attestationBaseUrl}/e2e/instances/${encodeURIComponent(chuteId)}`, {
        method: "GET",
        headers: authHeaders
      }, signal, ATTESTATION_TIMEOUT_MS);
      const discovered = (await parseJsonResponse(instancesResponse)) as {
        instances?: Array<{ instance_id?: unknown; e2e_pubkey?: unknown; nonces?: unknown }>;
      };
      for (const instance of discovered.instances ?? []) {
        if (typeof instance.instance_id === "string" && evidenceInstanceIds.has(instance.instance_id)
          && typeof instance.e2e_pubkey === "string") {
          e2ePubkeys[instance.instance_id] = instance.e2e_pubkey;
          const nonces = Array.isArray(instance.nonces)
            ? instance.nonces.filter((value): value is string => typeof value === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(value))
            : [];
          if (nonces.length > 0) {
            e2eInstances.set(instance.instance_id, {
              instance_id: instance.instance_id,
              e2e_pubkey: instance.e2e_pubkey,
              nonces
            });
          }
        }
      }
    }
    return { ...raw, e2e_pubkeys: e2ePubkeys, e2e_instances: [...e2eInstances.values()] };
  }
}
