// The one place a provider credential is attached to an outbound request.
//
// WHAT THIS IS. Every adapter used to read its own key out of config, build its
// own `authorization` header and call global `fetch` with no redirect policy.
// That is survivable while each worker holds one provider's credential set and
// can reach one provider's hosts. It is not survivable in a process that holds
// several: a mis-selected adapter, a followed redirect or a URL taken from
// provider output would carry one provider's key to another provider's host.
//
// So adapters no longer hold a key. They hand a URL and their own headers to a
// transport that is bound to ONE provider, and the transport:
//
//   - refuses any URL whose origin is not one of that provider's configured
//     credential-bearing origins (exact scheme, host and port);
//   - refuses a URL carrying userinfo;
//   - refuses a caller-supplied `authorization`, `proxy-authorization` or
//     `host` header, in whatever form the headers arrive;
//   - attaches the credential itself, resolved per request;
//   - refuses redirects.
//
// WHAT THIS IS NOT. It is a guard against bugs in otherwise honest code. It is
// not a boundary against a compromised process: code running in the same
// process can read the same keys and open its own socket. See
// docs/architecture/confidential-backend/PROVIDER_POOL_PLAN.md section 2.
//
// WHICH ORIGINS. The transport binds to the origins of the provider's
// CONFIGURED base URLs. Whether those are the pinned production origins is a
// boot-time configuration check, not a per-request one, so a test or a local
// stack that points a provider at a loopback mock still gets the same binding:
// the key goes to the configured origin and nowhere else. The one addition is
// NEAR, whose direct enclave hosts are not configuration: they come from the
// reviewed route table, never from what NEAR's discovery endpoint returns. They
// are real provider hosts, so the synthetic profile (providerOrigins.ts), whose
// only credential-bearing origin is the in-CVM mock, leaves them out.

import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import { ProviderError } from "../security/errors.js";
import { APPROVED_NEAR_ROUTES } from "./catalog/nearNormalize.js";
import type { VeniceKeysetStore } from "./veniceKeyStore.js";

/** Resolve the credential for one request. `keyId` is a control-selected id. */
export type ProviderKeyResolver = (keyId?: string | null) => string | undefined;

export interface ProviderTransportOptions {
  /** Canonical provider name. */
  readonly provider: string;
  /** Names the credential in the not-configured error, e.g. "Fireworks API key". */
  readonly credentialLabel: string;
  /** URLs whose origins may receive this provider's credential. */
  readonly credentialBaseUrls: readonly (string | undefined)[];
  readonly resolveKey: ProviderKeyResolver;
  /** Injected for tests; the global is read at call time so a stub applies. */
  readonly fetch?: typeof fetch;
}

export interface ProviderKeySelection {
  /** A control-selected key id. An unknown id fails; it never falls back. */
  readonly keyId?: string | null;
}

export interface ProviderRequestOptions extends ProviderKeySelection {
  /**
   * Send through this fetch instead of the transport's own. Tinfoil passes its
   * SPKI-pinned agent here, so the credential still leaves only on the attested
   * socket. The destination, header and redirect policy apply either way.
   */
  readonly via?: typeof fetch;
}

// Headers an adapter must never set. `host` is here because it would let a
// request reach one origin while naming another to anything that routes on it.
const CALLER_FORBIDDEN_HEADERS = ["authorization", "proxy-authorization", "host"];

// Spelled through `RequestInit` because the global `HeadersInit` alias exists
// only where DOM types happen to be loaded, which the API build does not do.
type CallerHeaders = RequestInit["headers"];

function originOf(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.origin === "null" ? null : parsed.origin;
  } catch {
    return null;
  }
}

function destinationForbidden(): ProviderError {
  // Deliberately says nothing about the URL. A rejected destination is
  // attacker-influenced data, and an error message is a logging channel.
  return new ProviderError("provider_destination_forbidden", "Provider request destination is not permitted");
}

/**
 * Whether the caller set a header only the transport may set. `Headers` does
 * the case folding and the tuple/record/instance handling, so a forbidden name
 * cannot hide behind a capital letter or an array of pairs.
 */
function carriesForbiddenHeader(input: CallerHeaders): boolean {
  const named = new Headers(input);
  return CALLER_FORBIDDEN_HEADERS.some((name) => named.has(name));
}

/**
 * The caller's headers as a plain record. A record keeps its names exactly as
 * written: fetch sends them as given, and NEAR's and Venice's E2EE headers are
 * mixed-case today, so folding them here would change the wire. Any other form
 * is flattened through `Headers`.
 */
function callerHeaders(input: CallerHeaders): Record<string, string | ReadonlyArray<string>> {
  if (input && !(input instanceof Headers) && !Array.isArray(input)) return { ...input };
  const flattened: Record<string, string> = {};
  new Headers(input).forEach((value, name) => {
    flattened[name] = value;
  });
  return flattened;
}

export class ProviderTransport {
  private readonly origins: ReadonlySet<string>;

  constructor(private readonly options: ProviderTransportOptions) {
    this.origins = new Set(
      options.credentialBaseUrls.map(originOf).filter((origin): origin is string => origin !== null)
    );
  }

  get provider(): string {
    return this.options.provider;
  }

  /** Whether a credential resolves, without making a request. */
  hasCredential(selection: ProviderKeySelection = {}): boolean {
    return Boolean(this.options.resolveKey(selection.keyId));
  }

  /**
   * Fail now if no credential resolves. Adapters call this where they used to
   * build their own header, so the not-configured error is raised at the same
   * point in a dispatch as before.
   */
  assertCredential(selection: ProviderKeySelection = {}): void {
    this.credential(selection);
  }

  private credential(selection: ProviderKeySelection): string {
    const key = this.options.resolveKey(selection.keyId);
    if (!key) {
      throw new ProviderError("provider_not_configured", `${this.options.credentialLabel} is not configured`);
    }
    return key;
  }

  /** An authenticated request to one of this provider's credential-bearing origins. */
  async fetch(url: string, init: RequestInit = {}, options: ProviderRequestOptions = {}): Promise<Response> {
    return this.send(url, init, () => this.credential(options), options.via);
  }

  /**
   * Check a credential that is NOT YET INSTALLED against this provider's own
   * origin, before a key store accepts it. The candidate rides this one request
   * under the same destination and redirect policy as `fetch` and is not kept.
   *
   * Deliberately narrow: a bodiless GET with no caller headers. It is the only
   * way to send a key the resolver did not produce, and it cannot be pointed at
   * another origin or made to carry anything else.
   */
  async probeCandidate(url: string, candidate: string, signal?: AbortSignal): Promise<Response> {
    return this.send(url, { signal }, () => {
      if (!candidate) {
        throw new ProviderError("provider_not_configured", `${this.options.credentialLabel} is not configured`);
      }
      return candidate;
    });
  }

  private async send(
    url: string,
    init: RequestInit,
    credential: () => string,
    via?: typeof fetch
  ): Promise<Response> {
    let destination: URL;
    try {
      destination = new URL(url);
    } catch {
      throw destinationForbidden();
    }
    if (destination.username || destination.password) throw destinationForbidden();
    if (!this.origins.has(destination.origin)) throw destinationForbidden();

    if (carriesForbiddenHeader(init.headers)) {
      throw new ProviderError("provider_header_forbidden", "Provider request carries a header only the transport may set");
    }
    const headers = { ...callerHeaders(init.headers), authorization: `Bearer ${credential()}` };

    const dispatch = via ?? this.options.fetch ?? globalThis.fetch;
    // `redirect: "error"` last, so a caller cannot ask for "follow".
    return dispatch(destination.toString(), { ...init, headers, redirect: "error" });
  }
}

interface StaticProviderBinding {
  readonly credentialLabel: string;
  readonly credentialBaseUrls: (config: ContentPlaneConfig) => readonly (string | undefined)[];
  readonly key: (config: ContentPlaneConfig) => string | undefined;
  /** Replaces the default sender, for a provider that must not use global fetch. */
  readonly fetch?: typeof fetch;
}

/**
 * The direct enclave origins that may receive the NEAR credential: exactly the
 * hosts pinned in the reviewed route table, which is the set the adapter
 * already checks a discovered endpoint against. NEAR's discovery response is
 * provider output and never widens this.
 */
function approvedNearEnclaveOrigins(): string[] {
  return Object.values(APPROVED_NEAR_ROUTES).flatMap((route) =>
    route.endpointDomain ? [`https://${route.endpointDomain}`] : []
  );
}

// Providers with one static credential. Venice is absent on purpose: it holds a
// keyset with control-selected ids and a live overlay, so it has its own
// resolver.
//
// These are the origins that may RECEIVE the key, not every host the provider's
// adapter talks to. Keyless calls (NEAR endpoint discovery, the enclave's own
// attestation report, Chutes' public evidence, Tinfoil's verifier collateral)
// do not go through a transport at all.
const STATIC_PROVIDERS = {
  fireworks: {
    credentialLabel: "Fireworks API key",
    credentialBaseUrls: (config) => [config.providers.fireworksBaseUrl],
    key: (config) => config.providers.fireworksApiKey
  },
  deepinfra: {
    credentialLabel: "DeepInfra API key",
    credentialBaseUrls: (config) => [config.providers.deepinfraBaseUrl],
    key: (config) => config.providers.deepinfraApiKey
  },
  "phala-ai": {
    credentialLabel: "Phala AI API key",
    credentialBaseUrls: (config) => [config.providers.phalaAiBaseUrl],
    key: (config) => config.providers.phalaAiApiKey
  },
  chutes: {
    credentialLabel: "Chutes API key",
    // Inference on one host; the E2EE invoke and instance discovery on the other.
    credentialBaseUrls: (config) => [config.providers.chutesBaseUrl, config.providers.chutesAttestationBaseUrl],
    key: (config) => config.providers.chutesApiKey
  },
  tinfoil: {
    credentialLabel: "Tinfoil API key",
    credentialBaseUrls: (config) => [config.providers.tinfoilBaseUrl],
    key: (config) => config.providers.tinfoilApiKey,
    // No default sender. The Tinfoil credential may leave only through the
    // adapter's SPKI-pinned agent, passed per request as `via`; that agent also
    // refuses any origin but the attested enclave. A request without it is a bug.
    fetch: async () => {
      throw new ProviderError(
        "provider_security_verification_failed",
        "Tinfoil enclave or pinned transport could not be verified"
      );
    }
  },
  "near-ai": {
    // Never names the provider: this message can reach a customer (near.ts).
    credentialLabel: "Provider API key",
    // The enclave hosts are not configuration, so the boot check on base URLs
    // cannot remove them. A synthetic deployment must not reach a real origin
    // with a key, so it drops them here.
    credentialBaseUrls: (config) => [
      config.providers.nearBaseUrl,
      ...(config.providers.transportProfile === "synthetic" ? [] : approvedNearEnclaveOrigins())
    ],
    key: (config) => config.providers.nearApiKey
  }
} satisfies Record<string, StaticProviderBinding>;

export type StaticTransportProvider = keyof typeof STATIC_PROVIDERS;

/** The transport for a provider that holds a single static credential. */
export function staticProviderTransport(
  config: ContentPlaneConfig,
  provider: StaticTransportProvider
): ProviderTransport {
  const binding: StaticProviderBinding = STATIC_PROVIDERS[provider];
  return new ProviderTransport({
    provider,
    credentialLabel: binding.credentialLabel,
    credentialBaseUrls: binding.credentialBaseUrls(config),
    // Read at request time, not captured, so the binding never holds a copy.
    resolveKey: () => binding.key(config) || undefined,
    fetch: binding.fetch
  });
}

/**
 * Venice's transport. Venice holds a keyset and control names the key for each
 * dispatch, so the credential is resolved per request:
 *
 *   - a key id resolves against the live overlay store when one is wired (the
 *     credential worker), otherwise against the configured keyset. An unknown
 *     id resolves to nothing, so the request fails; it never falls back to
 *     another key.
 *   - no key id means the store's default key, or the boot key with no store.
 *
 * Every Venice caller in a process must be handed the same store, so inference,
 * attestation, catalog and rate limits all follow an operator's add or remove.
 */
export function veniceProviderTransport(config: ContentPlaneConfig, keyStore?: VeniceKeysetStore): ProviderTransport {
  return new ProviderTransport({
    provider: "venice",
    credentialLabel: "Venice inference key",
    credentialBaseUrls: [config.providers.veniceBaseUrl],
    resolveKey: (keyId) => {
      if (keyId) {
        if (keyStore) return keyStore.keyById(keyId) ?? undefined;
        // Nullish guard: hand-built partial configs in tests omit the keyset.
        return new Map((config.providers.veniceKeys ?? []).map((entry) => [entry.id, entry.key])).get(keyId);
      }
      return keyStore ? keyStore.defaultKey() ?? undefined : config.providers.veniceInferenceKey || undefined;
    }
  });
}

/**
 * Whether this process was configured with a provider's credential. For code
 * that only decides where work runs (here, or on the worker that holds the key)
 * and has no business touching the value.
 */
export function providerCredentialConfigured(
  config: ContentPlaneConfig,
  provider: StaticTransportProvider | "venice"
): boolean {
  if (provider === "venice") return Boolean(config.providers.veniceInferenceKey);
  const binding: StaticProviderBinding = STATIC_PROVIDERS[provider];
  return Boolean(binding.key(config));
}
