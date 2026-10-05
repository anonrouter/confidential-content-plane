import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../../src/config.js";
import { APPROVED_NEAR_ROUTES } from "../../src/providers/catalog/nearNormalize.js";
import {
  ProviderTransport,
  providerCredentialConfigured,
  staticProviderTransport,
  veniceProviderTransport
} from "../../src/providers/transport.js";
import { VeniceKeysetStore } from "../../src/providers/veniceKeyStore.js";

const BASE = "https://api.provider.example.test/inference/v1";
const KEY = "unit-test-provider-key";

function transport(overrides: Partial<ConstructorParameters<typeof ProviderTransport>[0]> = {}) {
  const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
  const instance = new ProviderTransport({
    provider: "example",
    credentialLabel: "Example API key",
    credentialBaseUrls: [BASE],
    resolveKey: () => KEY,
    fetch: fetchMock as unknown as typeof fetch,
    ...overrides
  });
  return { instance, fetchMock };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("provider transport", () => {
  it("attaches the credential to a request for its own origin and refuses redirects", async () => {
    const { instance, fetchMock } = transport();
    await instance.fetch(`${BASE}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-request-id": "req_1" },
      body: "{}"
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${BASE}/chat/completions`);
    expect(init.headers).toEqual({
      "content-type": "application/json",
      "x-request-id": "req_1",
      authorization: `Bearer ${KEY}`
    });
    expect(init.redirect).toBe("error");
    expect(init.method).toBe("POST");
  });

  it("does not let the caller choose to follow redirects", async () => {
    const { instance, fetchMock } = transport();
    await instance.fetch(`${BASE}/models`, { redirect: "follow" });
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.redirect).toBe("error");
  });

  it.each([
    ["another host", "https://api.other.example.test/inference/v1/chat/completions"],
    ["a subdomain of the bound host", "https://evil.api.provider.example.test/v1"],
    ["a host that only starts with the bound host", "https://api.provider.example.test.evil.example/v1"],
    ["plain http on the bound host", "http://api.provider.example.test/inference/v1"],
    ["another port on the bound host", "https://api.provider.example.test:8443/inference/v1"],
    ["userinfo naming the bound host", "https://api.provider.example.test@evil.example/v1"],
    ["userinfo on the bound host", "https://user:pass@api.provider.example.test/inference/v1"],
    ["a relative url", "/inference/v1/chat/completions"],
    ["a non-http scheme", "file:///etc/passwd"]
  ])("refuses %s without sending anything", async (_label, url) => {
    const { instance, fetchMock } = transport();
    await expect(instance.fetch(url)).rejects.toMatchObject({ code: "provider_destination_forbidden" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not echo the refused destination in the error", async () => {
    const { instance } = transport();
    const secretLooking = "https://attacker.example/leak?k=sk-canary-0123456789";
    const error = await instance.fetch(secretLooking).catch((caught: unknown) => caught as Error);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).not.toContain("attacker.example");
    expect((error as Error).message).not.toContain("sk-canary");
  });

  it.each([
    ["a record", { Authorization: "Bearer caller" }],
    ["a lower-cased record", { authorization: "Bearer caller" }],
    ["a Headers instance", new Headers({ AUTHORIZATION: "Bearer caller" })],
    ["an array of pairs", [["AuThOrIzAtIoN", "Bearer caller"]] as [string, string][]],
    ["a proxy credential", { "Proxy-Authorization": "Basic caller" }],
    ["a host override", { Host: "api.other.example.test" }]
  ])("refuses a caller-supplied credential or host header given as %s", async (_label, headers) => {
    const { instance, fetchMock } = transport();
    await expect(instance.fetch(`${BASE}/models`, { headers })).rejects.toMatchObject({
      code: "provider_header_forbidden"
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends a record's header names exactly as the adapter wrote them", async () => {
    // fetch puts a record's names on the wire as given, and two providers are
    // sent mixed-case E2EE headers. Folding them here would change the request.
    const { instance, fetchMock } = transport();
    await instance.fetch(`${BASE}/chat/completions`, {
      headers: { "content-type": "application/json", "X-Signing-Algo": "ed25519", "X-Venice-TEE-Client-Pub-Key": "ab" }
    });
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.headers).toEqual({
      "content-type": "application/json",
      "X-Signing-Algo": "ed25519",
      "X-Venice-TEE-Client-Pub-Key": "ab",
      authorization: `Bearer ${KEY}`
    });
  });

  it("sends through a caller-owned fetch when given one, under the same policy", async () => {
    const { instance, fetchMock } = transport();
    const pinned = vi.fn(async () => new Response("{}", { status: 200 }));
    await instance.fetch(`${BASE}/models`, { method: "GET" }, { via: pinned as unknown as typeof fetch });

    expect(fetchMock).not.toHaveBeenCalled();
    const [url, init] = pinned.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${BASE}/models`);
    expect(init.headers).toEqual({ authorization: `Bearer ${KEY}` });
    expect(init.redirect).toBe("error");

    // The caller-owned fetch does not widen the destination or header policy.
    await expect(instance.fetch("https://api.other.example.test/v1", {}, { via: pinned as unknown as typeof fetch }))
      .rejects.toMatchObject({ code: "provider_destination_forbidden" });
    await expect(instance.fetch(`${BASE}/models`, { headers: { Authorization: "Bearer caller" } }, { via: pinned as unknown as typeof fetch }))
      .rejects.toMatchObject({ code: "provider_header_forbidden" });
    expect(pinned).toHaveBeenCalledTimes(1);
  });

  it("fails before any request when no credential resolves", async () => {
    const { instance, fetchMock } = transport({ resolveKey: () => undefined });
    expect(instance.hasCredential()).toBe(false);
    expect(() => instance.assertCredential()).toThrow("Example API key is not configured");
    await expect(instance.fetch(`${BASE}/models`)).rejects.toMatchObject({ code: "provider_not_configured" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("resolves the credential per request and passes the selected key id through", async () => {
    const keys: Record<string, string> = { primary: "key-primary", backup: "key-backup" };
    const resolveKey = vi.fn((keyId?: string | null) => (keyId ? keys[keyId] : keys.primary));
    const { instance, fetchMock } = transport({ resolveKey });

    await instance.fetch(`${BASE}/models`, {}, { keyId: "backup" });
    await instance.fetch(`${BASE}/models`);
    // An unknown id must fail rather than fall back to another credential.
    await expect(instance.fetch(`${BASE}/models`, {}, { keyId: "missing" })).rejects.toMatchObject({
      code: "provider_not_configured"
    });

    const sent = fetchMock.mock.calls.map((call) => ((call as unknown as [string, RequestInit])[1].headers as Record<string, string>).authorization);
    expect(sent).toEqual(["Bearer key-backup", "Bearer key-primary"]);
    expect(resolveKey).toHaveBeenCalledTimes(3);
  });

  it("binds nothing when the base url is missing or unparseable", async () => {
    const { instance, fetchMock } = transport({ credentialBaseUrls: [undefined, "not a url"] });
    await expect(instance.fetch(`${BASE}/models`)).rejects.toMatchObject({ code: "provider_destination_forbidden" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses the global fetch at call time, so each provider is bound to its own configured origin", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const config = {
      providers: {
        fireworksBaseUrl: "https://fireworks.example.test/inference/v1",
        fireworksApiKey: "fw-key",
        deepinfraBaseUrl: "https://deepinfra.example.test/v1/openai",
        deepinfraApiKey: "di-key"
      }
    } as AppConfig;

    const fireworks = staticProviderTransport(config, "fireworks");
    const deepinfra = staticProviderTransport(config, "deepinfra");

    await fireworks.fetch("https://fireworks.example.test/inference/v1/chat/completions");
    // The misrouting this module exists to stop: one provider's transport asked
    // to reach another provider's origin.
    await expect(fireworks.fetch("https://deepinfra.example.test/v1/openai/chat/completions"))
      .rejects.toMatchObject({ code: "provider_destination_forbidden" });
    await deepinfra.fetch("https://deepinfra.example.test/v1/openai/chat/completions");

    const sent = fetchMock.mock.calls.map((call) => {
      const [url, init] = call as unknown as [string, RequestInit];
      return [new URL(url).host, (init.headers as Record<string, string>).authorization];
    });
    expect(sent).toEqual([
      ["fireworks.example.test", "Bearer fw-key"],
      ["deepinfra.example.test", "Bearer di-key"]
    ]);
  });
});

/** A loopback origin that answers every request with `respond`, and counts them. */
async function loopback(respond: (path: string) => { status: number; headers?: Record<string, string> }) {
  const seen: Array<{ path: string; authorization: string | undefined }> = [];
  const server: Server = createServer((request, response) => {
    seen.push({ path: request.url ?? "", authorization: request.headers.authorization });
    const answer = respond(request.url ?? "");
    response.writeHead(answer.status, answer.headers ?? {});
    response.end("{}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { origin, seen, close };
}

describe("provider transport redirects, on a real socket", () => {
  it("does not follow a redirect, so neither the key nor the request reaches the redirect target", async () => {
    const target = await loopback(() => ({ status: 200 }));
    const bound = await loopback(() => ({ status: 302, headers: { location: `${target.origin}/collect` } }));
    try {
      const instance = new ProviderTransport({
        provider: "example",
        credentialLabel: "Example API key",
        credentialBaseUrls: [`${bound.origin}/v1`],
        resolveKey: () => KEY
      });
      await expect(instance.fetch(`${bound.origin}/v1/models`)).rejects.toThrow();
      await expect(instance.probeCandidate(`${bound.origin}/v1/api_keys/rate_limits`, "candidate-secret")).rejects.toThrow();

      // Both requests reached the bound origin, and nothing went any further.
      expect(bound.seen).toEqual([
        { path: "/v1/models", authorization: `Bearer ${KEY}` },
        { path: "/v1/api_keys/rate_limits", authorization: "Bearer candidate-secret" }
      ]);
      expect(target.seen).toEqual([]);
    } finally {
      await bound.close();
      await target.close();
    }
  });
});

describe("candidate credential probe", () => {
  it("sends the candidate, not the installed key, to the provider's own origin as a bare GET", async () => {
    const { instance, fetchMock } = transport();
    const signal = AbortSignal.timeout(1_000);
    await instance.probeCandidate(`${BASE}/api_keys/rate_limits`, "candidate-secret", signal);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${BASE}/api_keys/rate_limits`);
    // Exactly this and nothing else: no method override, no body, no caller headers.
    expect(init).toEqual({
      signal,
      headers: { authorization: "Bearer candidate-secret" },
      redirect: "error"
    });
  });

  it("works before any key is installed", async () => {
    const { instance, fetchMock } = transport({ resolveKey: () => undefined });
    await instance.probeCandidate(`${BASE}/api_keys/rate_limits`, "candidate-secret");
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer candidate-secret");
  });

  it.each([
    ["another provider's origin", "https://api.other.example.test/api_keys/rate_limits"],
    ["plain http on the bound host", "http://api.provider.example.test/inference/v1/api_keys/rate_limits"],
    ["another port on the bound host", "https://api.provider.example.test:8443/inference/v1/api_keys/rate_limits"],
    ["userinfo naming the bound host", "https://api.provider.example.test@evil.example/api_keys/rate_limits"],
    ["a relative url", "/api_keys/rate_limits"]
  ])("refuses %s without sending the candidate anywhere", async (_label, url) => {
    const { instance, fetchMock } = transport();
    await expect(instance.probeCandidate(url, "candidate-secret")).rejects.toMatchObject({
      code: "provider_destination_forbidden"
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses an empty candidate rather than sending an empty bearer", async () => {
    const { instance, fetchMock } = transport();
    await expect(instance.probeCandidate(`${BASE}/api_keys/rate_limits`, "")).rejects.toMatchObject({
      code: "provider_not_configured"
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("venice key resolution", () => {
  const VENICE = "https://venice.example.test/api/v1";
  const bootKeys = [
    { id: "primary", label: null, key: "sk-boot-primary" },
    { id: "backup", label: null, key: "sk-boot-backup" }
  ];
  const config = {
    providers: { veniceBaseUrl: VENICE, veniceInferenceKey: "sk-boot-primary", veniceKeys: bootKeys }
  } as unknown as AppConfig;
  let dir: string | undefined;

  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
  });

  function store() {
    dir = mkdtempSync(join(tmpdir(), "venice-transport-"));
    return new VeniceKeysetStore(bootKeys, join(dir, "overlay.json"));
  }

  async function sentKey(instance: ProviderTransport, keyId?: string | null): Promise<string> {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await instance.fetch(`${VENICE}/models`, {}, { keyId });
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    return (init.headers as Record<string, string>).authorization;
  }

  it("without a store: an id resolves against the configured keyset, no id means the boot key", async () => {
    const instance = veniceProviderTransport(config);
    expect(await sentKey(instance, "backup")).toBe("Bearer sk-boot-backup");
    expect(await sentKey(instance)).toBe("Bearer sk-boot-primary");
    expect(await sentKey(instance, null)).toBe("Bearer sk-boot-primary");
  });

  it("with a store: ids and the default follow the live keyset, including a retired boot key", async () => {
    const live = store();
    const instance = veniceProviderTransport(config, live);
    expect(await sentKey(instance, "backup")).toBe("Bearer sk-boot-backup");

    live.addKey({ id: "rotated", label: null, key: "sk-added-rotated" });
    live.removeKey("primary");
    // The transport was built before the change and still sees it: per request.
    expect(await sentKey(instance, "rotated")).toBe("Bearer sk-added-rotated");
    expect(await sentKey(instance)).toBe("Bearer sk-boot-backup");
    expect(instance.hasCredential({ keyId: "primary" })).toBe(false);
  });

  it.each([
    ["without a store", false],
    ["with a store", true]
  ])("an unknown key id fails with no request and never falls back to another key (%s)", async (_label, withStore) => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const instance = veniceProviderTransport(config, withStore ? store() : undefined);

    expect(instance.hasCredential({ keyId: "missing" })).toBe(false);
    expect(() => instance.assertCredential({ keyId: "missing" })).toThrow("Venice inference key is not configured");
    await expect(instance.fetch(`${VENICE}/models`, {}, { keyId: "missing" })).rejects.toMatchObject({
      code: "provider_not_configured"
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("with a store, the boot key in config is not a fallback once the store has retired it", async () => {
    // One boot key, removed after an operator added its replacement.
    dir = mkdtempSync(join(tmpdir(), "venice-transport-"));
    const single = [{ id: "primary", label: null, key: "sk-boot-primary" }];
    const live = new VeniceKeysetStore(single, join(dir, "overlay.json"));
    live.addKey({ id: "replacement", label: null, key: "sk-added-replacement" });
    live.removeKey("primary");
    const instance = veniceProviderTransport(
      { providers: { veniceBaseUrl: VENICE, veniceInferenceKey: "sk-boot-primary", veniceKeys: single } } as unknown as AppConfig,
      live
    );
    expect(await sentKey(instance)).toBe("Bearer sk-added-replacement");
  });

  it("is bound to the configured Venice origin only", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(veniceProviderTransport(config).fetch("https://api.venice.ai/api/v1/models"))
      .rejects.toMatchObject({ code: "provider_destination_forbidden" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("static provider bindings", () => {
  const config = {
    providers: {
      veniceBaseUrl: "https://api.venice.ai/api/v1",
      veniceInferenceKey: "",
      chutesBaseUrl: "https://llm.chutes.ai/v1",
      chutesAttestationBaseUrl: "https://api.chutes.ai",
      chutesApiKey: "cpk-key",
      tinfoilBaseUrl: "https://inference.tinfoil.sh/v1",
      tinfoilApiKey: "tf-key",
      nearBaseUrl: "https://cloud-api.near.ai/v1",
      nearEndpointsUrl: "https://completions.near.ai/endpoints",
      nearApiKey: "near-key",
      fireworksBaseUrl: "https://api.fireworks.ai/inference/v1",
      fireworksApiKey: ""
    }
  } as unknown as AppConfig;

  async function outcome(instance: ProviderTransport, url: string): Promise<string> {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await instance.fetch(url);
    } catch (error) {
      expect(fetchMock).not.toHaveBeenCalled();
      return (error as { code?: string }).code ?? "threw";
    }
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    return (init.headers as Record<string, string>).authorization;
  }

  it("chutes: the key may go to its inference host and its API host, and nowhere else", async () => {
    const chutes = staticProviderTransport(config, "chutes");
    expect(await outcome(chutes, "https://llm.chutes.ai/v1/chat/completions")).toBe("Bearer cpk-key");
    expect(await outcome(chutes, "https://api.chutes.ai/e2e/invoke")).toBe("Bearer cpk-key");
    expect(await outcome(chutes, "https://chutes.ai/v1/models")).toBe("provider_destination_forbidden");
    expect(await outcome(chutes, "https://raw.githubusercontent.com/chutesai/sek8s/main/x")).toBe("provider_destination_forbidden");
  });

  it("tinfoil: the key leaves only through a caller-supplied pinned fetch, never through global fetch", async () => {
    const globalFetch = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", globalFetch);
    const pinned = vi.fn(async () => new Response("{}", { status: 200 }));
    const via = pinned as unknown as typeof fetch;
    const tinfoil = staticProviderTransport(config, "tinfoil");

    await tinfoil.fetch("https://inference.tinfoil.sh/v1/models", {}, { via });
    const [, init] = pinned.mock.calls[0] as unknown as [string, RequestInit];
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer tf-key");

    // Without the pinned agent there is no sender at all.
    await expect(tinfoil.fetch("https://inference.tinfoil.sh/v1/models")).rejects.toMatchObject({
      code: "provider_security_verification_failed"
    });
    // The verifier's collateral proxies are reachable hosts, not key recipients.
    for (const url of ["https://github-proxy.tinfoil.sh/repos/x", "https://kds-proxy.tinfoil.sh/vcek/v1/x"]) {
      await expect(tinfoil.fetch(url, {}, { via })).rejects.toMatchObject({ code: "provider_destination_forbidden" });
    }
    expect(pinned).toHaveBeenCalledTimes(1);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it("near: the key may go to the gateway and to the pinned enclave hosts, never to a host discovery merely named", async () => {
    const near = staticProviderTransport(config, "near-ai");
    expect(await outcome(near, "https://cloud-api.near.ai/v1/chat/completions")).toBe("Bearer near-key");

    const pinned = Object.values(APPROVED_NEAR_ROUTES).flatMap((route) => route.endpointDomain ? [route.endpointDomain] : []);
    // The table is the source: an empty one would make this loop prove nothing.
    expect(pinned).toContain("glm-5-3-flash.completions.near.ai");
    for (const host of pinned) {
      expect(await outcome(near, `https://${host}/v1/chat/completions`), host).toBe("Bearer near-key");
    }

    // The discovery host itself, and a plausible-looking sibling that is not pinned.
    expect(await outcome(near, "https://completions.near.ai/endpoints")).toBe("provider_destination_forbidden");
    expect(await outcome(near, "https://not-reviewed.completions.near.ai/v1/chat/completions")).toBe("provider_destination_forbidden");
    expect(await outcome(near, "https://attacker.example/v1/chat/completions")).toBe("provider_destination_forbidden");
    expect(await outcome(near, "http://glm-5-3-flash.completions.near.ai/v1/chat/completions")).toBe("provider_destination_forbidden");
  });

  it("names the provider generically in near's not-configured error", () => {
    const unconfigured = staticProviderTransport({ providers: { nearBaseUrl: "https://cloud-api.near.ai/v1", nearApiKey: "" } } as unknown as AppConfig, "near-ai");
    expect(() => unconfigured.assertCredential()).toThrow("Provider API key is not configured");
  });

  it("reports whether a credential is configured without handing it out", () => {
    expect(providerCredentialConfigured(config, "chutes")).toBe(true);
    expect(providerCredentialConfigured(config, "near-ai")).toBe(true);
    expect(providerCredentialConfigured(config, "fireworks")).toBe(false);
    expect(providerCredentialConfigured(config, "venice")).toBe(false);
    expect(providerCredentialConfigured({ providers: { veniceInferenceKey: "k" } } as unknown as AppConfig, "venice")).toBe(true);
  });
});
