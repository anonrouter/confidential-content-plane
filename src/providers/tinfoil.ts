import { createHash, X509Certificate } from "node:crypto";
import { Agent, request as httpsRequest } from "node:https";
import { Readable } from "node:stream";
import { checkServerIdentity as checkTlsServerIdentity } from "node:tls";
import type { PeerCertificate } from "node:tls";
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
export const TINFOIL_VERIFICATION_TTL_MS = 10 * 60_000;
export const TINFOIL_ENCLAVE_ORIGIN = "https://inference.tinfoil.sh";

export class TinfoilTlsPinError extends Error {
  constructor() {
    super("Tinfoil TLS pinning failed: peer SPKI does not match the attested key");
    this.name = "TinfoilTlsPinError";
  }
}

export interface TinfoilPinnedTlsTransport {
  readonly fetch: typeof fetch;
  observedTlsSpki(): string | null;
  close(): void;
}

/**
 * Build a private-agent HTTPS transport whose sockets are usable only after
 * normal PKI/hostname validation and an exact SPKI match. A private agent is
 * load-bearing: a shared agent could reuse a socket opened by an unrelated
 * unpinned request and skip this transport's checkServerIdentity callback.
 */
export function createTinfoilPinnedTlsTransport(
  origin: string,
  expectedTlsSpki: string,
  options: { ca?: string } = {}
): TinfoilPinnedTlsTransport {
  const pinnedOrigin = new URL(origin).origin;
  if (!/^https:\/\//.test(pinnedOrigin) || !/^[0-9a-f]{64}$/i.test(expectedTlsSpki)) {
    throw new Error("Tinfoil pinned transport requires an HTTPS origin and SHA-256 SPKI");
  }
  const expected = expectedTlsSpki.toLowerCase();
  let observed: string | null = null;
  const agent = new Agent({ keepAlive: true, ...(options.ca ? { ca: options.ca } : {}) });

  const pinnedFetch: typeof fetch = async (input, init) => {
    const target = input instanceof Request
      ? new URL(input.url)
      : new URL(input.toString(), pinnedOrigin);
    if (target.protocol !== "https:" || target.origin !== pinnedOrigin) {
      throw new Error(`Tinfoil pinned transport refused origin ${target.origin}`);
    }
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    const headerObject: Record<string, string> = {};
    headers.forEach((value, name) => { headerObject[name] = value; });
    let body = init?.body;
    if (body == null && input instanceof Request && input.body !== null) {
      body = Buffer.from(await input.clone().arrayBuffer());
    }
    const signal = init?.signal;

    return await new Promise<Response>((resolve, reject) => {
      const request = httpsRequest({
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port ? Number(target.port) : 443,
        path: `${target.pathname}${target.search}`,
        method,
        headers: headerObject,
        agent,
        checkServerIdentity: (host: string, cert: PeerCertificate) => {
          const standardError = checkTlsServerIdentity(host, cert);
          if (standardError) return standardError;
          if (!cert.raw) return new TinfoilTlsPinError();
          const actual = createHash("sha256")
            .update(new X509Certificate(cert.raw).publicKey.export({ type: "spki", format: "der" }))
            .digest("hex");
          if (actual !== expected) return new TinfoilTlsPinError();
          observed = actual;
          return undefined;
        }
      }, (response) => {
        const responseHeaders = new Headers();
        for (const [name, value] of Object.entries(response.headers)) {
          if (Array.isArray(value)) value.forEach((item) => responseHeaders.append(name, item));
          else if (value != null) responseHeaders.set(name, String(value));
        }
        resolve(new Response(Readable.toWeb(response) as ReadableStream<Uint8Array>, {
          status: response.statusCode ?? 500,
          statusText: response.statusMessage ?? "",
          headers: responseHeaders
        }));
      });
      request.once("error", reject);
      if (signal) {
        const abort = () => request.destroy(
          signal.reason instanceof Error ? signal.reason : new Error("Request aborted")
        );
        if (signal.aborted) {
          abort();
          return;
        }
        signal.addEventListener("abort", abort, { once: true });
        request.once("close", () => signal.removeEventListener("abort", abort));
      }
      if (body == null) request.end();
      else if (typeof body === "string" || Buffer.isBuffer(body) || ArrayBuffer.isView(body)) request.end(body);
      else if (body instanceof ArrayBuffer) request.end(Buffer.from(body));
      else if (typeof (body as ReadableStream<Uint8Array>).getReader === "function") {
        Readable.fromWeb(body as never).pipe(request);
      } else request.destroy(new Error("Unsupported Tinfoil request body"));
    });
  };

  return {
    fetch: pinnedFetch,
    observedTlsSpki: () => observed,
    close: () => agent.destroy()
  };
}

export async function tinfoilFetch(
  secureFetch: typeof fetch,
  url: string,
  init: RequestInit,
  cancellation?: AbortSignal,
  timeoutMs = CHAT_TIMEOUT_MS
): Promise<Response> {
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = cancellation ? AbortSignal.any([cancellation, timeout]) : timeout;
  try {
    return await secureFetch(url, { ...init, signal });
  } catch (error) {
    if (cancellation?.aborted) throw cancellation.reason ?? error;
    if (timeout.aborted || (error instanceof DOMException && error.name === "TimeoutError")) {
      throw new ProviderError("provider_timeout", "Provider did not complete within the request deadline", 504);
    }
    throw error;
  }
}

function tinfoilBody(request: ProviderRequest, stream: boolean): Record<string, unknown> {
  const body = { ...request.body } as Record<string, unknown>;
  for (const relayOnly of [
    "routing",
    "reasoning",
    "venice_parameters",
    "prompt_cache_key",
    "prompt_cache_retention",
    "user_cache_secret",
    "stream_options"
  ]) delete body[relayOnly];
  return {
    ...body,
    model: request.model.externalModelId,
    stream,
    ...(stream ? { stream_options: { include_usage: true } } : {})
  };
}

/** The exact official-verifier surface we use. The literal runtime import is
 * load-bearing for the public content-plane dependency exporter. */
export interface TinfoilSdkVerifier {
  verify(): Promise<unknown>;
  getVerificationDocument(): TinfoilVerificationDocument | undefined;
}

export interface TinfoilProviderDependencies {
  verifierFactory?: (options: { serverURL: string; configRepo: string }) => TinfoilSdkVerifier | Promise<TinfoilSdkVerifier>;
  transportFactory?: (origin: string, expectedTlsSpki: string) => TinfoilPinnedTlsTransport;
  now?: () => number;
  verificationTtlMs?: number;
}

interface VerifiedTinfoilTransport {
  document: TinfoilVerificationDocument;
  transport: TinfoilPinnedTlsTransport;
}

/**
 * Tinfoil confidential inference through its OpenAI-compatible API. Tinfoil's
 * official verifier authenticates the signed tagged release, AMD SEV-SNP report,
 * and equality between signed code and the live enclave. AnonRouter then pins
 * every inference connection's observed certificate SPKI to the public-key
 * fingerprint carried in that verified report. This remains a `tee` route:
 * AnonRouter's measured worker sees plaintext, and EHBP is not exposed.
 */
export class TinfoilProviderAdapter implements ProviderAdapter {
  readonly name = "tinfoil";
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly configRepo: string;
  private readonly dependencies: TinfoilProviderDependencies;
  private verifiedTransportPromise: Promise<VerifiedTinfoilTransport | null> | null = null;
  private verifiedTransportExpiresAtMs = 0;

  constructor(config: ContentPlaneConfig, dependencies: TinfoilProviderDependencies = {}) {
    this.baseUrl = config.providers.tinfoilBaseUrl;
    this.apiKey = config.providers.tinfoilApiKey;
    this.configRepo = config.providers.tinfoilConfigRepo;
    this.dependencies = dependencies;
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
    const { response } = await this.requestThroughAttestedTls(`${this.baseUrl}/chat/completions`, {
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
    const { response } = await this.requestThroughAttestedTls(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify(tinfoilBody(request, true))
    }, request.signal);
    const body = await requireStreamBody(response);
    let resolveUsage!: (result: SseParseResult) => void;
    const usageResult = new Promise<SseParseResult>((resolve) => { resolveUsage = resolve; });
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
    const { response } = await this.requestThroughAttestedTls(`${this.baseUrl}/embeddings`, {
      method: "POST",
      headers: this.headers(request.requestId),
      body: JSON.stringify({ ...request.body, model: request.model.externalModelId })
    }, request.signal);
    const raw = await parseJsonResponse(response);
    const normalized = normalizeEmbeddingResponse(raw, request.body, request.model.externalModelId);
    return { ...normalized, providerRequestId: response.headers.get("x-request-id") ?? undefined };
  }

  /** Fetch the provider catalog over the same attested, SPKI-pinned transport as
   * inference. The catalog carries no prompt, but it does carry the provider
   * credential and must not get a weaker network path. */
  async fetchModels(timeoutMs: number): Promise<Response> {
    if (!this.apiKey) {
      throw new ProviderError("provider_not_configured", "Tinfoil API key is not configured");
    }
    const url = new URL(this.baseUrl);
    url.pathname = `${url.pathname.replace(/\/$/, "")}/models`;
    url.search = "";
    return (await this.requestThroughAttestedTls(url.toString(), {
      method: "GET",
      headers: { authorization: `Bearer ${this.apiKey}` }
    }, undefined, timeoutMs)).response;
  }

  async fetchAttestation(_externalModelId: string): Promise<TinfoilVerificationDocument> {
    try {
      const { response, verified } = await this.requestThroughAttestedTls(
        TINFOIL_ENCLAVE_ORIGIN,
        { method: "HEAD" },
        undefined,
        ATTESTATION_TIMEOUT_MS
      );
      await response.body?.cancel();
      const observedTlsSpki = verified.transport.observedTlsSpki();
      if (!observedTlsSpki) throw new Error("pinned TLS request did not expose an observed SPKI");
      return {
        ...structuredClone(verified.document),
        transportBinding: {
          mode: "tls-pinned",
          endpointIdentity: new URL(TINFOIL_ENCLAVE_ORIGIN).host,
          observedTlsSpki,
          verified: true
        }
      };
    } catch {
      this.invalidateVerifiedTransport();
      return {
        securityVerified: false,
        enclaveHost: new URL(TINFOIL_ENCLAVE_ORIGIN).host,
        configRepo: this.configRepo
      };
    }
  }

  private async requestThroughAttestedTls(
    url: string,
    init: RequestInit,
    cancellation?: AbortSignal,
    timeoutMs = CHAT_TIMEOUT_MS,
    allowRotationRetry = true
  ): Promise<{ response: Response; verified: VerifiedTinfoilTransport }> {
    const verified = await this.requireVerifiedTransport();
    try {
      const response = await tinfoilFetch(verified.transport.fetch, url, init, cancellation, timeoutMs);
      return { response, verified };
    } catch (error) {
      if (allowRotationRetry && error instanceof TinfoilTlsPinError) {
        // A certificate-key rotation fails before the request is sent. Refresh
        // the official evidence once, rebuild the private pinned agent, and retry.
        this.invalidateVerifiedTransport();
        return this.requestThroughAttestedTls(url, init, cancellation, timeoutMs, false);
      }
      throw error;
    }
  }

  private async requireVerifiedTransport(): Promise<VerifiedTinfoilTransport> {
    const verified = await this.getVerifiedTransport();
    if (!verified) {
      throw new ProviderError(
        "provider_security_verification_failed",
        "Tinfoil enclave or pinned transport could not be verified"
      );
    }
    return verified;
  }

  private async getVerifiedTransport(): Promise<VerifiedTinfoilTransport | null> {
    if (
      this.verifiedTransportPromise
      && this.verifiedTransportExpiresAtMs > 0
      && (this.dependencies.now?.() ?? Date.now()) >= this.verifiedTransportExpiresAtMs
    ) {
      // Re-run the provider authority periodically even when the TLS key stays
      // stable. Otherwise a long-lived worker could keep accepting a release it
      // verified days ago merely because its keep-alive socket still works.
      this.invalidateVerifiedTransport();
    }
    if (!this.verifiedTransportPromise) {
      const pending = this.loadVerifiedTransport();
      this.verifiedTransportPromise = pending;
      const verified = await pending;
      if (this.verifiedTransportPromise === pending) {
        if (verified) {
          this.verifiedTransportExpiresAtMs = (this.dependencies.now?.() ?? Date.now())
            + (this.dependencies.verificationTtlMs ?? TINFOIL_VERIFICATION_TTL_MS);
        } else {
          // A transient verifier or network failure darks this attempt, not the
          // worker for the rest of its process lifetime. The next request gets a
          // fresh verification attempt and still fails closed until one passes.
          this.verifiedTransportPromise = null;
        }
      }
      return verified;
    }
    return this.verifiedTransportPromise;
  }

  private async loadVerifiedTransport(): Promise<VerifiedTinfoilTransport | null> {
    try {
      // The configurable API path may move, but its origin may not. This keeps
      // endpoint policy independent from a measured-compose configuration edit.
      if (new URL(this.baseUrl).origin !== TINFOIL_ENCLAVE_ORIGIN) return null;
      const options = { serverURL: TINFOIL_ENCLAVE_ORIGIN, configRepo: this.configRepo };
      const verifier = this.dependencies.verifierFactory
        ? await this.dependencies.verifierFactory(options)
        : await this.loadOfficialVerifier(options);
      if (!verifier) return null;
      await verifier.verify();
      const document = verifier.getVerificationDocument();
      const tlsPublicKeyFingerprint = document?.enclaveMeasurement?.tlsPublicKeyFingerprint;
      if (document?.securityVerified !== true || !/^[0-9a-f]{64}$/i.test(tlsPublicKeyFingerprint ?? "")) {
        return null;
      }
      const transport = (this.dependencies.transportFactory ?? createTinfoilPinnedTlsTransport)(
        TINFOIL_ENCLAVE_ORIGIN,
        tlsPublicKeyFingerprint!
      );
      return { document: structuredClone(document), transport };
    } catch {
      return null;
    }
  }

  private async loadOfficialVerifier(
    options: { serverURL: string; configRepo: string }
  ): Promise<TinfoilSdkVerifier | null> {
    try {
      // Keep this specifier literal. scripts/export-content-plane.ts carries its
      // locked dependency closure into the public image.
      const mod = (await import("tinfoil")) as {
        Verifier?: new (value: { serverURL: string; configRepo: string }) => TinfoilSdkVerifier;
      };
      return mod.Verifier ? new mod.Verifier(options) : null;
    } catch {
      return null;
    }
  }

  private invalidateVerifiedTransport(): void {
    void this.verifiedTransportPromise?.then((verified) => verified?.transport.close()).catch(() => undefined);
    this.verifiedTransportPromise = null;
    this.verifiedTransportExpiresAtMs = 0;
  }
}
