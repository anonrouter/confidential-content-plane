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
  ProviderRequest,
  ProviderStreamResult
} from "./types.js";
import { APPROVED_NEAR_ROUTES } from "./catalog/nearNormalize.js";
import { sha256Hex } from "./attestation/crypto.js";

const CHAT_TIMEOUT_MS = 10 * 60_000;
const ATTESTATION_TIMEOUT_MS = 15_000;
const ENDPOINTS_TTL_MS = 5 * 60_000;

async function nearFetch(url: string, init: RequestInit, cancellation?: AbortSignal, timeoutMs = CHAT_TIMEOUT_MS): Promise<Response> {
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

function nearBody(request: ProviderRequest, stream: boolean): Record<string, unknown> {
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
 * NEAR AI Cloud inference. NEAR exposes TWO endpoint shapes and AnonRouter binds
 * each route to the CORRECT one (route-specific base URLs, not one hostname):
 *   - direct confidential route `{slug}.completions.near.ai/v1`: TLS terminates
 *     inside the model's Intel TDX enclave and it exposes a per-request signature.
 *     Attestation, inference, and signature all target this exact host so the
 *     attested enclave IS the serving enclave.
 *   - gateway `cloud-api.near.ai/v1`: used for attested-3p routes (served in a
 *     partner TEE) which have no direct host.
 * The direct slug is discovered from NEAR's public /endpoints map (cached), so an
 * upstream-proxy model (not TEE) is never treated as a confidential route.
 */
export class NearProviderAdapter implements ProviderAdapter {
  readonly name = "near-ai";
  private readonly gatewayBaseUrl: string;
  private readonly endpointsUrl: string;
  private readonly apiKey: string;
  private endpointsCache: { at: number; byModel: Map<string, string> } | null = null;

  constructor(config: ContentPlaneConfig) {
    this.gatewayBaseUrl = config.providers.nearBaseUrl;
    this.endpointsUrl = config.providers.nearEndpointsUrl;
    this.apiKey = config.providers.nearApiKey;
  }

  private headers(requestId: string, e2eeHeaders?: Record<string, string>) {
    if (!this.apiKey) {
      throw new ProviderError("provider_not_configured", "NEAR AI API key is not configured");
    }
    const allowedE2eeHeaders: Record<string, string> = {};
    if (e2eeHeaders) {
      const signingAlgo = e2eeHeaders["X-Signing-Algo"];
      const clientKey = e2eeHeaders["X-Client-Pub-Key"];
      const version = e2eeHeaders["X-Encryption-Version"];
      // Defense in depth at the credential boundary: accept only the current
      // documented NEAR v2 protocol. The relay cannot smuggle arbitrary headers
      // to the provider through this metadata map.
      if (
        signingAlgo !== "ed25519"
        || version !== "2"
        || !clientKey
        || !/^[0-9a-f]{64}$/i.test(clientKey)
        || Object.keys(e2eeHeaders).some((name) => ![
          "X-Signing-Algo",
          "X-Client-Pub-Key",
          "X-Encryption-Version"
        ].includes(name))
      ) {
        throw new ProviderError("e2ee_headers_invalid", "NEAR E2EE headers failed validation", 400);
      }
      Object.assign(allowedE2eeHeaders, {
        "X-Signing-Algo": signingAlgo,
        "X-Client-Pub-Key": clientKey,
        "X-Encryption-Version": version
      });
    }
    return {
      "content-type": "application/json",
      authorization: `Bearer ${this.apiKey}`,
      "x-request-id": requestId,
      ...allowedE2eeHeaders
    };
  }

  /** Resolve the direct enclave host for a model, or null when it has no direct
   *  confidential route (attested-3p / gateway-only). Cached with a short TTL. */
  private async directDomain(externalModelId: string, signal?: AbortSignal): Promise<string | null> {
    const now = Date.now();
    if (!this.endpointsCache || now - this.endpointsCache.at > ENDPOINTS_TTL_MS) {
      const byModel = new Map<string, string>();
      try {
        const response = await nearFetch(this.endpointsUrl, { method: "GET", headers: { accept: "application/json" } }, signal, ATTESTATION_TIMEOUT_MS);
        const data = (await parseJsonResponse(response)) as { endpoints?: Array<{ domain?: unknown; models?: unknown }> };
        for (const entry of data.endpoints ?? []) {
          if (typeof entry?.domain !== "string" || !Array.isArray(entry.models)) continue;
          for (const model of entry.models) {
            if (typeof model === "string") byModel.set(model, entry.domain);
          }
        }
      } catch {
        // Treat discovery failure as no direct route. Plaintext TEE may use the
        // provider gateway; e2eeInferenceBase rejects this state fail-closed.
      }
      this.endpointsCache = { at: now, byModel };
    }
    return this.endpointsCache.byModel.get(externalModelId) ?? null;
  }

  private async inferenceBase(externalModelId: string, signal?: AbortSignal): Promise<string> {
    const domain = await this.directDomain(externalModelId, signal);
    return domain ? `https://${domain}/v1` : this.gatewayBaseUrl;
  }

  private async e2eeInferenceBase(externalModelId: string, signal?: AbortSignal): Promise<string> {
    const domain = await this.directDomain(externalModelId, signal);
    const pinned = APPROVED_NEAR_ROUTES[externalModelId]?.endpointDomain;
    if (!domain || !pinned || domain.toLowerCase() !== pinned.toLowerCase()) {
      throw new ProviderError(
        "e2ee_enclave_endpoint_unavailable",
        "The pinned NEAR direct enclave endpoint is unavailable",
        503
      );
    }
    return `https://${domain}/v1`;
  }

  async chat(request: ProviderRequest): Promise<ProviderChatResult> {
    request.signal?.throwIfAborted();
    if (request.e2eeHeaders) this.headers(request.requestId, request.e2eeHeaders);
    const base = request.e2eeHeaders
      ? await this.e2eeInferenceBase(request.model.externalModelId, request.signal)
      : await this.inferenceBase(request.model.externalModelId, request.signal);
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const requestBody = JSON.stringify(nearBody(request, false));
    const response = await nearFetch(`${base}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId, request.e2eeHeaders),
      body: requestBody
    }, request.signal);
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new ProviderError("provider_http_error", "Provider request failed", response.status);
    }
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
      // NEAR returns the completion id (used later to fetch the per-request
      // signature) and an X-Request-Id transport header.
      providerRequestId: (typeof (json as { id?: unknown }).id === "string" ? (json as { id: string }).id : undefined)
        ?? response.headers.get("x-request-id") ?? undefined,
      exactRequestHash: sha256Hex(requestBody),
      exactResponseHash: sha256Hex(responseText)
    };
  }

  async stream(request: ProviderRequest): Promise<ProviderStreamResult> {
    request.signal?.throwIfAborted();
    if (request.e2eeHeaders) this.headers(request.requestId, request.e2eeHeaders);
    const base = request.e2eeHeaders
      ? await this.e2eeInferenceBase(request.model.externalModelId, request.signal)
      : await this.inferenceBase(request.model.externalModelId, request.signal);
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await nearFetch(`${base}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId, request.e2eeHeaders),
      body: JSON.stringify(nearBody(request, true))
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
        outputTokens: Math.max(1, result.estimatedOutputTokens || estimateTextTokens("near")),
        cachedTokens: 0
      })
    };
  }

  async embeddings(request: EmbeddingProviderRequest): Promise<EmbeddingProviderResult> {
    request.signal?.throwIfAborted();
    const base = await this.inferenceBase(request.model.externalModelId, request.signal);
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await nearFetch(`${base}/embeddings`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify({ ...request.body, model: request.model.externalModelId })
    }, request.signal);
    const raw = await parseJsonResponse(response);
    const normalized = normalizeEmbeddingResponse(raw, request.body, request.model.externalModelId);
    return { ...normalized, providerRequestId: response.headers.get("x-request-id") ?? undefined };
  }

  /**
   * Fetch a TLS-in-TEE attestation report for a direct confidential route. The
   * report is served BY the enclave (no credential needed) and binds the enclave's
   * TLS SPKI + the caller nonce into an Intel TDX quote. Returned raw for
   * NearTeeVerifier to verify the bindings.
   */
  async fetchAttestation(externalModelId: string, nonce: string, signal?: AbortSignal): Promise<unknown> {
    return this.fetchAttestationForAlgorithm(externalModelId, nonce, "ecdsa", signal);
  }

  /** NEAR v2 encrypts to the Ed25519 key bound into this same TDX report. */
  async fetchE2eeAttestation(externalModelId: string, nonce: string, signal?: AbortSignal): Promise<unknown> {
    return this.fetchAttestationForAlgorithm(externalModelId, nonce, "ed25519", signal);
  }

  private async fetchAttestationForAlgorithm(
    externalModelId: string,
    nonce: string,
    signingAlgorithm: "ecdsa" | "ed25519",
    signal?: AbortSignal
  ): Promise<unknown> {
    if (!/^[0-9a-f]{32,128}$/i.test(nonce)) {
      throw new ProviderError("invalid_nonce", "Attestation nonce must be 32-128 hex characters", 400);
    }
    const domain = await this.directDomain(externalModelId, signal);
    if (!domain) {
      throw new ProviderError("attestation_unavailable", "No direct confidential route for this model", 404);
    }
    const pinned = APPROVED_NEAR_ROUTES[externalModelId]?.endpointDomain;
    if (!pinned || domain.toLowerCase() !== pinned.toLowerCase()) {
      throw new ProviderError("attestation_unavailable", "The discovered endpoint does not match the pinned enclave", 503);
    }
    const url = `https://${domain}/v1/attestation/report?include_tls_fingerprint=true&signing_algo=${signingAlgorithm}&nonce=${encodeURIComponent(nonce)}`;
    const response = await nearFetch(url, { method: "GET", headers: { accept: "application/json" } }, signal, ATTESTATION_TIMEOUT_MS);
    const report = (await parseJsonResponse(response)) as Record<string, unknown>;
    // The live endpoint serializes tcb_info.app_compose as JSON. Preserve that
    // exact string: mr_config_id hashes the whole serialized document, not a
    // parsed/reserialized object and not only docker_compose_file.
    const tcb = (report.info as { tcb_info?: { app_compose?: unknown; compose_hash?: unknown } } | undefined)?.tcb_info;
    let compose: string | null = null;
    let dockerComposeFile: string | null = null;
    if (typeof tcb?.app_compose === "string") {
      // mr_config_id hashes this exact serialized app_compose JSON string, not a
      // reserialized object and not only docker_compose_file.
      compose = tcb.app_compose;
      try {
        const parsed = JSON.parse(tcb.app_compose) as { docker_compose_file?: unknown };
        if (typeof parsed.docker_compose_file === "string") dockerComposeFile = parsed.docker_compose_file;
      } catch {
        // Pure verifier receives no extracted compose and fails closed.
      }
    } else if (tcb?.app_compose && typeof tcb.app_compose === "object") {
      const candidate = (tcb.app_compose as { docker_compose_file?: unknown }).docker_compose_file;
      if (typeof candidate === "string") dockerComposeFile = candidate;
    }
    return compose
      ? {
          ...report,
          app_compose: compose,
          docker_compose_file: dockerComposeFile,
          compose_hash: typeof tcb?.compose_hash === "string" ? tcb.compose_hash : undefined
        }
      : report;
  }

  /**
   * Fetch the provider-signed per-request signature for a completed request. The
   * signature binds sha256(request) and sha256(response); NearTeeVerifier checks
   * those against AnonRouter's own hashes and the attested signer.
   */
  async fetchSignature(providerRequestId: string, externalModelId: string, signal?: AbortSignal): Promise<unknown> {
    const domain = await this.directDomain(externalModelId, signal);
    const url = domain
      ? `https://${domain}/v1/signature/${encodeURIComponent(providerRequestId)}?signing_algo=ecdsa`
      : `${this.gatewayBaseUrl}/signature/${encodeURIComponent(providerRequestId)}?model=${encodeURIComponent(externalModelId)}&signing_algo=ecdsa`;
    const response = await nearFetch(url, {
      method: "GET",
      // Both current direct and gateway signature endpoints require the worker's
      // provider credential. It never crosses into the relay/public route.
      headers: { accept: "application/json", authorization: `Bearer ${this.apiKey}` }
    }, signal, ATTESTATION_TIMEOUT_MS);
    return parseJsonResponse(response);
  }
}
