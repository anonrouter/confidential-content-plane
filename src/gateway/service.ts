// The in-TEE producer for GET /v1/gateway/attestation.
//
// This is the only component that talks to the dstack guest agent, and the only
// one whose container mounts /var/run/dstack.sock. It reads immutable CVM
// identity once, derives a stable application key, and mints a fresh TDX quote
// per caller nonce.
//
// It never sees, logs, or stores request content. It exists specifically so the
// process that DOES hold content can point a caller at cryptographic evidence of
// what that process is.

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { x25519 } from "@noble/curves/ed25519";
import {
  gatewayBindingDigest,
  normalizeGatewayBinding,
  GATEWAY_BINDING_VERSION,
  type GatewayAttestationBinding,
  type GatewayTransportBinding
} from "./binding.js";
import { createDstackGateway, type DstackGateway } from "./dstackClient.js";
import { TlsIdentityObserver, type TlsObservation } from "./tlsObservation.js";

/**
 * HKDF info string for the published application key. Versioned in the info
 * string, not in the dstack key path: the dstack seed should stay stable across
 * application key rotations so a rotation does not require a new app id.
 */
const APP_KEY_INFO = "anonrouter/gateway/x25519/v1";

/** Immutable CVM facts. Read once; they cannot change without a reboot. */
export interface GatewayIdentity {
  appId: string;
  instanceId: string;
  composeHash: string;
  /** The exact measured app-compose manifest string. */
  appCompose: string;
  /** VM configuration blob. Absent on the simulator; required by dstack-verifier. */
  vmConfig: string | null;
  osImageHash: string | null;
  deviceId: string | null;
  keyProviderInfo: string | null;
}

export interface GatewayAttestationDocument {
  binding: GatewayAttestationBinding;
  /** Lowercase hex SHA-512 of the canonical binding; equals the quote's report_data. */
  binding_hash: string;
  quote: string;
  event_log: string;
  app_compose: string;
  vm_config: string | null;
  issued_at_ms: number;
  /** Non-authoritative context. A verifier reads identity from the quote. */
  info: {
    app_name: string | null;
    os_image_hash: string | null;
    device_id: string | null;
    key_provider_info: string | null;
  };
  /** Honest statement of what this document does and does not establish. */
  note: string;
}

export interface GatewayAttestationConfig {
  /**
   * Every public origin this workload serves, canonical scheme://host[:port],
   * CANONICAL FIRST.
   *
   * A LIST RATHER THAN ONE VALUE, and the reason is a certificate fact rather
   * than a preference. The content plane serves the restored
   * `https://api.anonrouter.ai` base URL and keeps
   * `https://api.private.anonrouter.ai` as the verification alias.
   * `dstack-ingress` issues a SEPARATE certificate per name and selects it by
   * SNI, so the two names have different SPKIs. The binding carries exactly one
   * origin and one SPKI, so a document must describe the connection the caller
   * actually made -- otherwise a verifier on the alias observes one key while
   * the quote names another, and fails closed on a correctly configured
   * deployment.
   *
   * NOTHING HERE WIDENS WHAT A CLIENT WILL ACCEPT. The verifier compares
   * `binding.origin` against its OWN connection and against a policy that is
   * distributed with the client, never fetched from this server. This list only
   * decides which of several true statements the TD makes.
   */
  origins: readonly string[];
  /** Reviewed release identifier for this build. */
  releaseId: string;
  /** Whether the TD owns the TLS session the caller is using. */
  transport: GatewayTransportBinding;
  /**
   * Where OUR in-CVM TLS terminator listens, so the SPKI can be OBSERVED from a
   * completed handshake rather than supplied.
   *
   * There is deliberately no way to pass the fingerprint in. It used to be an
   * environment value, which meant a deployer could claim `in-tee-tls` and name
   * a certificate whose private key lived on another machine entirely: the
   * client would observe that SPKI, the quote would repeat it, the comparison
   * would pass, and the TD would have attested to owning a key it had never
   * seen. Required whenever transport is `in-tee-tls`.
   *
   * NO `servername` FIELD. The SNI is derived from the origin being bound, so
   * the observed certificate is always the one that origin is served with. A
   * configurable servername would be a second place for the name to live and
   * the two would drift, which on this path means attesting to the wrong key.
   */
  tlsTerminator: { host: string; port: number } | null;
  /** Optional explicit guest-agent endpoint (socket path or simulator URL). */
  dstackEndpoint?: string;
}

/**
 * A caller's `Host` header resolved to one of the origins this TD serves.
 *
 * WHY THE HOST HEADER IS SAFE TO READ HERE, given a client controls it. It
 * SELECTS among origins that are already approved; it cannot introduce one. An
 * unrecognised value falls back to the canonical origin rather than being
 * echoed, so nothing a caller writes reaches the binding.
 *
 * And a forged selection does not help the forger: the verifier supplies the
 * origin IT connected to as `expectations.origin` and requires equality with
 * `binding.origin`, so a document naming the wrong one fails at the client. The
 * Host header decides which true statement to make, and the client checks that
 * the statement is about its own connection.
 */
export function selectAttestedOrigin(origins: readonly string[], host: string | undefined): string {
  const canonical = origins[0];
  if (!canonical) {
    throw new GatewayAttestationUnavailable("no public origin is configured for attestation");
  }
  const requested = host?.trim().toLowerCase();
  if (!requested) return canonical;
  // Compare on host[:port], which is exactly what a Host header carries and what
  // `URL.host` yields. Comparing hostname alone would let :8443 match :443.
  for (const origin of origins) {
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      continue;
    }
    if (parsed.host.toLowerCase() === requested) return origin;
  }
  return canonical;
}

const NOTE = [
  "This attests the AnonRouter gateway itself, not the upstream model provider.",
  "It proves that the exact measured build named by compose_hash is running inside",
  "an Intel TDX trust domain and that this response is bound to your nonce, the",
  "connection origin, and the published application key. It does not prove that",
  "build behaves well: verify the reviewed source that produces this compose hash.",
  "The upstream provider you select may still process or retain content under its",
  "own policy. See /v1/tee/attestation for provider attestation."
].join(" ");

export class GatewayAttestationUnavailable extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "GatewayAttestationUnavailable";
  }
}

export class GatewayAttestationService {
  private identity: GatewayIdentity | null = null;
  private appPublicKeyHex: string | null = null;
  private identityLoad: Promise<GatewayIdentity> | null = null;
  /**
   * One observer per attested origin, keyed by origin.
   *
   * PER ORIGIN, because each name is served its own certificate. A single
   * shared observer would cache one SPKI and report it for every name, which is
   * the exact failure this split exists to prevent: the alias would attest to
   * the canonical name's key and every verifier that observes its own
   * connection would fail closed against a correctly configured deployment.
   */
  private readonly tlsObservers = new Map<string, TlsIdentityObserver>();

  constructor(
    private readonly gateway: DstackGateway,
    private readonly config: GatewayAttestationConfig,
    /**
     * Test seam: the handshake itself, not a prebuilt observer.
     *
     * IT MOVED DOWN A LEVEL ON PURPOSE. The seam used to be a whole
     * `TlsIdentityObserver`, which was fine while there was one certificate.
     * With one certificate per name, a single injected observer would answer
     * for every origin, so a test could not tell a per-origin SNI from a baked
     * one -- and the defect this split exists to prevent is exactly a baked
     * SNI. Injecting the observation function keeps the per-origin observers,
     * and their SNI, on the tested path.
     *
     * A caller supplying one still cannot express anything a real handshake
     * could not: an observation has to produce an SPKI from somewhere.
     */
    private readonly observe?: TlsObservation
  ) {}

  /** The observer for one origin, built once and reused. */
  private observerFor(origin: string): TlsIdentityObserver | null {
    if (!this.config.tlsTerminator) return null;
    const existing = this.tlsObservers.get(origin);
    if (existing) return existing;
    // SNI IS THE ORIGIN'S OWN HOSTNAME, never a configured constant. This is
    // what makes the observed key the key that name is actually served with.
    const created = new TlsIdentityObserver(
      {
        host: this.config.tlsTerminator.host,
        port: this.config.tlsTerminator.port,
        servername: new URL(origin).hostname
      },
      undefined,
      this.observe
    );
    this.tlsObservers.set(origin, created);
    return created;
  }

  /**
   * The SPKI to bind for ONE origin, or null when this deployment does not
   * claim to own the transport.
   *
   * Fails closed. If transport is `in-tee-tls` and the terminator cannot be
   * observed, attestation fails rather than emitting a document with a missing
   * or stale fingerprint: a verifier that requires in-TEE TLS must not be able
   * to pass against a deployment whose TLS endpoint is not answering.
   */
  private async observedTlsSpki(origin: string): Promise<string | null> {
    if (this.config.transport !== "in-tee-tls") return null;
    const observer = this.observerFor(origin);
    if (!observer) {
      throw new GatewayAttestationUnavailable(
        "transport is in-tee-tls but no TLS terminator address is configured to observe"
      );
    }
    const observed = await observer.current();
    return observed.spkiSha256;
  }

  /**
   * Build a service, or null when this process is not inside a dstack CVM. The
   * caller registers a fail-closed 503 route in that case rather than omitting
   * the endpoint, so a missing enclave is visible instead of looking like a
   * routing error.
   */
  static async create(config: GatewayAttestationConfig): Promise<GatewayAttestationService | null> {
    const gateway = await createDstackGateway(config.dstackEndpoint);
    return gateway ? new GatewayAttestationService(gateway, config) : null;
  }

  /** Immutable CVM identity, read once and memoized (single-flight). */
  async loadIdentity(): Promise<GatewayIdentity> {
    if (this.identity) return this.identity;
    if (!this.identityLoad) {
      this.identityLoad = (async () => {
        const info = await this.gateway.info();
        const appCompose = info.tcb_info?.app_compose;
        if (typeof appCompose !== "string" || appCompose.length === 0) {
          throw new GatewayAttestationUnavailable("guest agent returned no app_compose");
        }
        const identity: GatewayIdentity = {
          appId: normalizeHex(info.app_id),
          instanceId: normalizeHex(info.instance_id),
          composeHash: normalizeHex(info.compose_hash ?? info.tcb_info.compose_hash),
          appCompose,
          vmConfig: typeof info.vm_config === "string" && info.vm_config.length > 0 ? info.vm_config : null,
          osImageHash: nullableString(info.os_image_hash ?? info.tcb_info.os_image_hash),
          deviceId: nullableString(info.device_id ?? info.tcb_info.device_id),
          keyProviderInfo: nullableString(info.key_provider_info)
        };
        this.identity = identity;
        return identity;
      })().catch((error) => {
        // Do not memoize a failure: a transient guest-agent fault must not
        // permanently disable attestation for the life of the process.
        this.identityLoad = null;
        throw error;
      });
    }
    return this.identityLoad;
  }

  /**
   * The published application public key.
   *
   * dstack's getKey is application-scoped and replica-stable, so every replica
   * of this app derives the identical key with no distribution step. The seed is
   * used only as HKDF input: deriving the X25519 keypair here rather than asking
   * the guest agent for `ed25519` keeps the derivation under our control and
   * avoids the guest-agent 0.5.7 floor that the local simulator cannot satisfy.
   */
  async appPublicKey(): Promise<string> {
    if (this.appPublicKeyHex) return this.appPublicKeyHex;
    const seed = await this.gateway.getAppKey();
    const privateKey = hkdf(sha256, seed, undefined, APP_KEY_INFO, 32);
    this.appPublicKeyHex = Buffer.from(x25519.getPublicKey(privateKey)).toString("hex");
    return this.appPublicKeyHex;
  }

  /**
   * Mint a fresh, nonce-bound attestation document.
   *
   * `requestedHost` is the caller's `Host` header. It selects which of the
   * origins this TD serves the document describes, and which name's certificate
   * is observed for the bound SPKI. An unrecognised value falls back to the
   * canonical origin; see `selectAttestedOrigin` for why that is safe.
   */
  async attest(
    nonce: string,
    options: { requestedHost?: string; now?: number } = {}
  ): Promise<GatewayAttestationDocument> {
    const now = options.now ?? Date.now();
    const origin = selectAttestedOrigin(this.config.origins, options.requestedHost);
    const [identity, publicKey, tlsSpkiSha256] = await Promise.all([
      this.loadIdentity(),
      this.appPublicKey(),
      this.observedTlsSpki(origin)
    ]);

    const binding = normalizeGatewayBinding({
      v: GATEWAY_BINDING_VERSION,
      nonce,
      app_id: identity.appId,
      instance_id: identity.instanceId,
      compose_hash: identity.composeHash,
      release_id: this.config.releaseId,
      origin,
      key_alg: "x25519",
      public_key: publicKey,
      transport: this.config.transport,
      // Observed, never supplied. See observedTlsSpki().
      tls_spki_sha256: tlsSpkiSha256
    } satisfies GatewayAttestationBinding);

    // Exactly 64 bytes, so the guest agent's right-zero-padding never applies
    // and there is no ambiguity about which end of report_data was filled.
    const reportData = gatewayBindingDigest(binding);
    const quote = await this.gateway.getQuote(reportData);

    return {
      binding,
      binding_hash: reportData.toString("hex"),
      quote: quote.quote,
      event_log: quote.event_log,
      app_compose: identity.appCompose,
      // Prefer the quote's own vm_config; fall back to /Info. dstack-verifier
      // cannot check platform measurements without it.
      vm_config: (typeof quote.vm_config === "string" && quote.vm_config.length > 0
        ? quote.vm_config
        : identity.vmConfig) ?? null,
      issued_at_ms: now,
      info: {
        app_name: null,
        os_image_hash: identity.osImageHash,
        device_id: identity.deviceId,
        key_provider_info: identity.keyProviderInfo
      },
      note: NOTE
    };
  }
}

function normalizeHex(value: unknown): string {
  if (typeof value !== "string") throw new GatewayAttestationUnavailable("guest agent returned a non-string identity");
  return value.trim().toLowerCase().replace(/^0x/, "");
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}
