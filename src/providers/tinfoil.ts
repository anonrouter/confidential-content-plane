import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import { estimateInputTokens, estimateTextTokens } from "../metering/tokens.js";
import { ProviderError } from "../security/errors.js";
import { parseJsonResponse, requireStreamBody } from "./http.js";
import { normalizeEmbeddingResponse } from "./embeddings.js";
import type { EmbeddingProviderRequest, EmbeddingProviderResult } from "./embeddings.js";
import { openAiUsageToInternal, proxyOpenAiSse, type SseParseResult } from "./sse.js";
import type { TinfoilVerificationDocument } from "./attestation/tinfoil.js";
import type {
  ProviderAdapter,
  ProviderChatResult,
  ProviderRequest,
  ProviderStreamResult
} from "./types.js";

const CHAT_TIMEOUT_MS = 10 * 60_000;
const ATTESTATION_TIMEOUT_MS = 20_000;

async function tinfoilFetch(url: string, init: RequestInit, cancellation?: AbortSignal, timeoutMs = CHAT_TIMEOUT_MS): Promise<Response> {
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

function tinfoilBody(request: ProviderRequest, stream: boolean): Record<string, unknown> {
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

/** The subset of the Tinfoil SDK's `Verifier` we depend on. Loaded via a guarded
 *  dynamic import so the offline build never requires the `tinfoil` npm package. */
interface TinfoilSdkVerifier {
  verify(): Promise<unknown>;
  getVerificationDocument(): TinfoilVerificationDocument | undefined;
}

/**
 * Tinfoil confidential inference via its OpenAI-compatible Chat Completions API
 * (base https://inference.tinfoil.sh/v1). The standard server-side route runs in a
 * verified SEV-SNP + NVIDIA CC enclave, but AnonRouter's gateway still sees
 * plaintext, so it is classified `tee` (not `e2ee`). Attestation is verified by
 * Tinfoil's own SDK (the cryptographic root of trust: hardware + Sigstore code
 * measurement + weights + key binding); we run that SDK on the credential worker
 * and surface its verification document to TinfoilTeeVerifier. Tinfoil exposes no
 * offline-verifiable per-request signature.
 *
 * Tinfoil also documents an EHBP/HPKE transport. AnonRouter does not expose it:
 * the model selector remains inside the ciphertext and the documented outer
 * metadata cannot bind that selection to an AnonRouter ticket/reservation. This
 * adapter handles only standard JSON/TLS and never advertises E2EE merely because
 * the upstream supports it.
 */
export class TinfoilProviderAdapter implements ProviderAdapter {
  readonly name = "tinfoil";
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly configRepo: string;

  constructor(config: ContentPlaneConfig) {
    this.baseUrl = config.providers.tinfoilBaseUrl;
    this.apiKey = config.providers.tinfoilApiKey;
    this.configRepo = config.providers.tinfoilConfigRepo;
  }

  private headers(requestId: string) {
    if (!this.apiKey) {
      throw new ProviderError("provider_not_configured", "Tinfoil API key is not configured");
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
    const response = await tinfoilFetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify(tinfoilBody(request, false))
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
    const response = await tinfoilFetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify(tinfoilBody(request, true))
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
        outputTokens: Math.max(1, result.estimatedOutputTokens || estimateTextTokens("tinfoil")),
        cachedTokens: 0
      })
    };
  }

  async embeddings(request: EmbeddingProviderRequest): Promise<EmbeddingProviderResult> {
    request.signal?.throwIfAborted();
    await request.onProviderAttempt?.();
    request.signal?.throwIfAborted();
    const response = await tinfoilFetch(`${this.baseUrl}/embeddings`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify({ ...request.body, model: request.model.externalModelId })
    }, request.signal);
    const raw = await parseJsonResponse(response);
    const normalized = normalizeEmbeddingResponse(raw, request.body, request.model.externalModelId);
    return { ...normalized, providerRequestId: response.headers.get("x-request-id") ?? undefined };
  }

  /**
   * Verify the enclave via the official Tinfoil SDK and return its verification
   * DOCUMENT (never a homegrown check). The SDK is loaded via a guarded dynamic
   * import so the offline build/CI never require the `tinfoil` npm package; when it
   * is not installed we fail CLOSED (securityVerified:false) rather than pretend.
   */
  async fetchAttestation(externalModelId: string): Promise<TinfoilVerificationDocument> {
    const enclaveHost = new URL(this.baseUrl).host;
    const sdk = await this.loadSdkVerifier(`https://${enclaveHost}`);
    if (!sdk) {
      // No SDK wired: honest fail-closed document. The verifier keeps the route
      // untrusted; an operator must wire the SDK before enabling a tee route.
      return { securityVerified: false, enclaveHost, configRepo: this.configRepo };
    }
    try {
      await sdk.verify();
      const doc = sdk.getVerificationDocument();
      // `verify()` returning is insufficient on its own. Only the SDK's explicit
      // immutable verification document, with every critical step successful,
      // may earn sdk-verified in the pure verifier.
      if (!doc || doc.securityVerified !== true) {
        return { securityVerified: false, enclaveHost, configRepo: this.configRepo };
      }
      return structuredClone(doc);
    } catch {
      return { securityVerified: false, enclaveHost, configRepo: this.configRepo };
    }
  }

  private async loadSdkVerifier(serverURL: string): Promise<TinfoilSdkVerifier | null> {
    // Non-literal specifier so tsc treats this as `any` and does not require the
    // optional package to be present at build time.
    const spec: string = "tinfoil";
    try {
      const mod = (await import(spec)) as { Verifier?: new (opts: { serverURL: string; configRepo: string }) => TinfoilSdkVerifier };
      if (!mod.Verifier) return null;
      return new mod.Verifier({ serverURL, configRepo: this.configRepo });
    } catch {
      return null;
    }
  }
}
