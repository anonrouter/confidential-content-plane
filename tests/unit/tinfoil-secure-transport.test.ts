import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ContentPlaneConfig } from "../../src/contentPlaneConfig.js";
import type { EmbeddingProviderRequest } from "../../src/providers/embeddings.js";
import type { TinfoilVerificationDocument } from "../../src/providers/attestation/tinfoil.js";
import {
  TINFOIL_ENCLAVE_ORIGIN,
  TinfoilProviderAdapter,
  TinfoilTlsPinError,
  createTinfoilPinnedTlsTransport,
  tinfoilFetch,
  type TinfoilPinnedTlsTransport,
  type TinfoilProviderDependencies
} from "../../src/providers/tinfoil.js";
import type { ModelRecord, ProviderRequest } from "../../src/providers/types.js";

const TLS_FP = "ab".repeat(32);
const CODE_FP = "cd".repeat(48);

const config = {
  providers: {
    tinfoilBaseUrl: "https://inference.tinfoil.sh/v1",
    tinfoilApiKey: "tinfoil_test_secret",
    tinfoilConfigRepo: "tinfoilsh/confidential-model-router"
  }
} as ContentPlaneConfig;

function document(over: Partial<TinfoilVerificationDocument> = {}): TinfoilVerificationDocument {
  return {
    schemaVersion: 1,
    securityVerified: true,
    enclaveHost: "inference.tinfoil.sh",
    selectedRouterEndpoint: "inference.tinfoil.sh",
    configRepo: "tinfoilsh/confidential-model-router",
    releaseTag: "v99.0.0",
    releaseDigest: "ef".repeat(32),
    codeFingerprint: CODE_FP,
    enclaveFingerprint: CODE_FP,
    enclaveMeasurement: { tlsPublicKeyFingerprint: TLS_FP },
    tlsPublicKey: TLS_FP,
    verifier: { name: "@tinfoilsh/verifier", version: "1.2.1" },
    steps: Object.fromEntries([
      "fetchDigest",
      "verifyCode",
      "verifyEnclave",
      "compareMeasurements",
      "verifyCertificate"
    ].map((name) => [name, { status: "success" }])),
    ...over
  };
}

function model(externalModelId = "deepseek-v4-flash"): ModelRecord {
  return {
    externalModelId,
    providerName: "tinfoil",
    publicModelId: `tinfoil/${externalModelId}`
  } as ModelRecord;
}

function chatRequest(over: Partial<ProviderRequest> = {}): ProviderRequest {
  return {
    requestId: "req_tinfoil_1",
    model: model(),
    inputTokens: 1,
    body: {
      model: "public/model",
      messages: [{ role: "user", content: "hello" }],
      routing: { strategy: "cost" },
      prompt_cache_key: "must-not-leave",
      user_cache_secret: "must-not-leave"
    } as unknown as ProviderRequest["body"],
    ...over
  };
}

function fakeTransport(secureFetch: typeof fetch, observed = TLS_FP): TinfoilPinnedTlsTransport {
  return {
    fetch: secureFetch,
    observedTlsSpki: vi.fn(() => observed),
    close: vi.fn()
  };
}

function dependencies(
  transport: TinfoilPinnedTlsTransport,
  hooks: {
    verifierOptions?: Array<{ serverURL: string; configRepo: string }>;
    transportOptions?: Array<{ origin: string; fingerprint: string }>;
    doc?: TinfoilVerificationDocument;
  } = {}
): TinfoilProviderDependencies {
  return {
    verifierFactory: async (options) => {
      hooks.verifierOptions?.push(options);
      return {
        verify: vi.fn(async () => undefined),
        getVerificationDocument: vi.fn(() => hooks.doc ?? document())
      };
    },
    transportFactory: (origin, fingerprint) => {
      hooks.transportOptions?.push({ origin, fingerprint });
      return transport;
    }
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("TinfoilProviderAdapter attested TLS transport", () => {
  it("binds verifier and transport to the fixed origin, independent of request config", async () => {
    const verifierOptions: Array<{ serverURL: string; configRepo: string }> = [];
    const transportOptions: Array<{ origin: string; fingerprint: string }> = [];
    const transport = fakeTransport(vi.fn(async () => new Response(null, { status: 404 })) as typeof fetch);
    const adapter = new TinfoilProviderAdapter(config, dependencies(transport, { verifierOptions, transportOptions }));

    await adapter.fetchAttestation("deepseek-v4-flash");

    expect(verifierOptions).toEqual([{
      serverURL: TINFOIL_ENCLAVE_ORIGIN,
      configRepo: "tinfoilsh/confidential-model-router"
    }]);
    expect(transportOptions).toEqual([{ origin: TINFOIL_ENCLAVE_ORIGIN, fingerprint: TLS_FP }]);

    const substitutedConfig = {
      providers: { ...config.providers, tinfoilBaseUrl: "https://attacker.example/v1" }
    } as ContentPlaneConfig;
    const substituted = new TinfoilProviderAdapter(substitutedConfig, dependencies(transport));
    await expect(substituted.chat(chatRequest())).rejects.toMatchObject({
      code: "provider_security_verification_failed"
    });
  });

  it("uses only the pinned transport for chat and sends the exact sanitized body", async () => {
    const globalFetch = vi.fn();
    vi.stubGlobal("fetch", globalFetch);
    const secureFetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      expect(String(input)).toBe("https://inference.tinfoil.sh/v1/chat/completions");
      expect((init?.headers as Record<string, string>).authorization).toBe("Bearer tinfoil_test_secret");
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body).toEqual({
        model: "deepseek-v4-flash",
        messages: [{ role: "user", content: "hello" }],
        stream: false
      });
      return new Response(JSON.stringify({ usage: { prompt_tokens: 2, completion_tokens: 3 } }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }) as typeof fetch;
    const adapter = new TinfoilProviderAdapter(config, dependencies(fakeTransport(secureFetch)));

    const result = await adapter.chat(chatRequest());

    expect(result.usage).toMatchObject({ inputTokens: 2, outputTokens: 3 });
    expect(secureFetch).toHaveBeenCalledOnce();
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it("uses the same verified transport for streaming and embeddings", async () => {
    const calls: string[] = [];
    const secureFetch = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/chat/completions")) {
        return new Response(
          'data: {"choices":[{"delta":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}\n\ndata: [DONE]\n\n',
          { status: 200, headers: { "content-type": "text/event-stream" } }
        );
      }
      return new Response(JSON.stringify({ object: "list", data: [{ object: "embedding", index: 0, embedding: [0.1] }], model: "nomic-embed-text", usage: { prompt_tokens: 1, total_tokens: 1 } }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }) as typeof fetch;
    const adapter = new TinfoilProviderAdapter(config, dependencies(fakeTransport(secureFetch)));

    const streamed = await adapter.stream(chatRequest());
    for await (const _chunk of streamed.stream) {
      // Consume the proxied stream so its usage promise settles.
    }
    await streamed.usage;
    await adapter.embeddings!({
      requestId: "req_embedding",
      model: model("nomic-embed-text"),
      body: { model: "public/embed", input: "hello" }
    } as EmbeddingProviderRequest);

    expect(calls).toEqual([
      "https://inference.tinfoil.sh/v1/chat/completions",
      "https://inference.tinfoil.sh/v1/embeddings"
    ]);
  });

  it("records the independently observed peer SPKI only after a pinned request", async () => {
    const secureFetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      expect(String(input)).toBe(TINFOIL_ENCLAVE_ORIGIN);
      expect(init?.method).toBe("HEAD");
      expect(init?.headers).toBeUndefined();
      return new Response(null, { status: 404 });
    }) as typeof fetch;
    const adapter = new TinfoilProviderAdapter(config, dependencies(fakeTransport(secureFetch)));

    const attestation = await adapter.fetchAttestation("deepseek-v4-flash");

    expect(attestation.transportBinding).toEqual({
      mode: "tls-pinned",
      endpointIdentity: "inference.tinfoil.sh",
      observedTlsSpki: TLS_FP,
      verified: true
    });
  });

  it("fails closed rather than falling back when verification or the pin fails", async () => {
    const globalFetch = vi.fn();
    vi.stubGlobal("fetch", globalFetch);
    const verifierFailure: TinfoilProviderDependencies = {
      verifierFactory: async () => ({
        verify: vi.fn(async () => { throw new Error("attestation refused"); }),
        getVerificationDocument: () => undefined
      })
    };
    await expect(new TinfoilProviderAdapter(config, verifierFailure).chat(chatRequest()))
      .rejects.toMatchObject({ code: "provider_security_verification_failed" });

    let attempts = 0;
    const pinFailure: TinfoilProviderDependencies = {
      verifierFactory: async () => ({ verify: async () => undefined, getVerificationDocument: () => document() }),
      transportFactory: () => fakeTransport(vi.fn(async () => {
        attempts += 1;
        throw new TinfoilTlsPinError();
      }) as typeof fetch)
    };
    await expect(new TinfoilProviderAdapter(config, pinFailure).chat(chatRequest()))
      .rejects.toBeInstanceOf(TinfoilTlsPinError);
    expect(attempts).toBe(2);
    expect(globalFetch).not.toHaveBeenCalled();
  });
});

describe("createTinfoilPinnedTlsTransport", () => {
  it("accepts the matching peer and rejects a wrong pin on a real TLS request", async () => {
    const dir = mkdtempSync(join(tmpdir(), "anonrouter-tinfoil-tls-"));
    const keyPath = join(dir, "key.pem");
    const certPath = join(dir, "cert.pem");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", keyPath, "-out", certPath, "-days", "1",
      "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"
    ], { stdio: "ignore" });
    const key = readFileSync(keyPath, "utf8");
    const cert = readFileSync(certPath, "utf8");
    const server = createServer({ key, cert }, (_request, response) => response.end("ok"));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("TLS test server did not bind");
    const origin = `https://localhost:${address.port}`;
    const fingerprint = createHash("sha256")
      .update(new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" }))
      .digest("hex");
    const matching = createTinfoilPinnedTlsTransport(origin, fingerprint, { ca: cert });
    const wrong = createTinfoilPinnedTlsTransport(origin, "00".repeat(32), { ca: cert });

    try {
      const response = await matching.fetch(origin);
      expect(await response.text()).toBe("ok");
      expect(matching.observedTlsSpki()).toBe(fingerprint);
      await expect(wrong.fetch(origin)).rejects.toBeInstanceOf(TinfoilTlsPinError);
      expect(wrong.observedTlsSpki()).toBeNull();
    } finally {
      matching.close();
      wrong.close();
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a request whose origin differs from the pin", async () => {
    const transport = createTinfoilPinnedTlsTransport(TINFOIL_ENCLAVE_ORIGIN, "00".repeat(32));
    try {
      await expect(transport.fetch("https://attacker.example/v1"))
        .rejects.toThrow("refused origin");
    } finally {
      transport.close();
    }
  });
});

describe("tinfoilFetch deadline handling", () => {
  it("preserves caller cancellation on the pinned transport", async () => {
    const controller = new AbortController();
    const reason = new Error("caller cancelled");
    const secureFetch = vi.fn((_input: string | URL | Request, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
    })) as typeof fetch;
    const pending = tinfoilFetch(secureFetch, TINFOIL_ENCLAVE_ORIGIN, {}, controller.signal, 1_000);
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
  });

  it("maps a pinned-transport deadline to provider_timeout", async () => {
    const secureFetch = vi.fn((_input: string | URL | Request, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
    })) as typeof fetch;
    await expect(tinfoilFetch(secureFetch, TINFOIL_ENCLAVE_ORIGIN, {}, undefined, 5))
      .rejects.toMatchObject({ code: "provider_timeout" });
  });
});
