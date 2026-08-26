import { createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AttestationRedemption, RedeemResult } from "../inference/rpc.js";
import { abortOnClientDisconnect } from "../inference/disconnect.js";
import { networkAddressScopes } from "../routes/helpers.js";
import { AppError } from "../security/errors.js";

const TICKET_HEADER = "x-anonrouter-ticket";
const CHAT_PATH = "/v1/chat/completions";
const OPAQUE_E2EE_CHAT_PATH = "/v1/e2ee/chat/completions";
const EMBEDDINGS_PATH = "/v1/embeddings";
const ATTESTATION_PATH = "/v1/tee/attestation";
const IMAGE_PATH = "/v1/images/generations";
/**
 * Gateway self-attestation is deliberately credential-free: a client verifies
 * the enclave BEFORE trusting it with anything, so requiring a ticket would
 * invert the trust order. It still needs the flood guard, because each call
 * makes the guest agent mint a fresh TDX quote and the guest agent is a single
 * serialized socket. Admitted here, but never ticket-redeemed.
 */
const GATEWAY_ATTESTATION_PATH = "/v1/gateway/attestation";

interface RelayIngressContext {
  signal: AbortSignal;
  chatRedemption?: RedeemResult;
  embeddingRedemption?: RedeemResult;
  imageRedemption?: RedeemResult;
  attestationRedemption?: AttestationRedemption;
}

const ingressContexts = new WeakMap<FastifyRequest, RelayIngressContext>();

export function relayIngressContext(request: FastifyRequest): RelayIngressContext | undefined {
  return ingressContexts.get(request);
}

export interface RelayIngressLimits {
  windowMs: number;
  globalRequests: number;
  subnetRequests: number;
  exactRequests: number;
  globalConcurrent: number;
  subnetConcurrent: number;
  exactConcurrent: number;
  classifierGlobalRequests: number;
  classifierSubnetRequests: number;
  classifierExactRequests: number;
  classifierGlobalConcurrent: number;
  classifierSubnetConcurrent: number;
  classifierExactConcurrent: number;
  maxBucketEntries: number;
  maxConnections: number;
}

const DEFAULT_LIMITS: RelayIngressLimits = {
  // This is deliberately a generous availability/flood guard. Account, key,
  // token, model, and provider limits remain authoritative at control.
  windowMs: 60_000,
  globalRequests: 3_000,
  subnetRequests: 600,
  exactRequests: 120,
  globalConcurrent: 256,
  subnetConcurrent: 64,
  exactConcurrent: 8,
  // /auto uses one local, serialized classifier. Preserve the paid plan's
  // four-request concurrency for one caller while bounding aggregate queues.
  classifierGlobalRequests: 240,
  classifierSubnetRequests: 90,
  classifierExactRequests: 30,
  classifierGlobalConcurrent: 8,
  classifierSubnetConcurrent: 6,
  classifierExactConcurrent: 4,
  maxBucketEntries: 8_192,
  maxConnections: 512
};

interface Bucket {
  count: number;
  resetAt: number;
}

class RelayLimitError extends AppError {
  readonly retryAfterSeconds: number;

  constructor(code: "rate_limited" | "concurrency_limited", retryAfterMs: number) {
    super(429, code, code === "rate_limited" ? "Too many requests" : "Too many concurrent requests");
    this.retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1_000));
  }
}

function canonicalForwardedAddress(value: string | string[] | undefined): string | null {
  if (typeof value !== "string" || value.includes(",")) return null;
  const candidate = value.trim().split("%", 1)[0];
  return isIP(candidate) ? networkAddressScopes(candidate).exact : null;
}

function canonicalSocketAddress(value: string | undefined): string {
  return networkAddressScopes(value ?? "unknown").exact;
}

/**
 * Only Docker/private-network peers may supply Caddy's overwritten XFF value.
 * Loopback is intentionally excluded so a directly exposed local relay cannot
 * be tricked by a caller-provided header during development or diagnostics.
 */
export function isPrivateProxyAddress(rawAddress: string | undefined): boolean {
  const address = canonicalSocketAddress(rawAddress);
  if (isIP(address) === 4) {
    const parts = address.split(".").map(Number);
    return parts[0] === 10
      || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
      || (parts[0] === 192 && parts[1] === 168);
  }
  if (isIP(address) === 6) {
    const first = Number.parseInt(address.split(":", 1)[0], 16);
    return (first & 0xfe00) === 0xfc00; // RFC 4193 fc00::/7 (Docker ULA).
  }
  return false;
}

export function relayClientAddress(request: FastifyRequest): string {
  const socketAddress = canonicalSocketAddress(request.raw.socket.remoteAddress);
  if (
    request.server.config.server.trustProxyHops === 1
    && isPrivateProxyAddress(request.raw.socket.remoteAddress)
  ) {
    return canonicalForwardedAddress(request.headers["x-forwarded-for"]) ?? socketAddress;
  }
  return socketAddress;
}

/**
 * Dependency-free, process-local relay flood guard.
 *
 * Keys are HMACs under an ephemeral process key: raw addresses are discarded
 * immediately, never logged, and never persisted. The global bucket is charged
 * first so a saturated attack cannot allocate unbounded address keys. State is
 * hard-capped and every counter expires.
 */
export class RelayIngressGuard {
  private readonly limits: RelayIngressLimits;
  private readonly secret = randomBytes(32);
  private readonly buckets = new Map<string, Bucket>();
  private readonly active = {
    ingress: {
      exact: new Map<string, number>(),
      subnet: new Map<string, number>(),
      global: 0
    },
    classifier: {
      exact: new Map<string, number>(),
      subnet: new Map<string, number>(),
      global: 0
    }
  };

  constructor(limits: Partial<RelayIngressLimits> = {}) {
    this.limits = { ...DEFAULT_LIMITS, ...limits };
  }

  private digest(scope: string, value: string): string {
    return createHmac("sha256", this.secret).update(`${scope}:${value}`).digest("hex");
  }

  private sweep(now: number) {
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAt <= now) this.buckets.delete(key);
    }
  }

  private activeBucket(key: string, now: number): Bucket | undefined {
    const bucket = this.buckets.get(key);
    if (bucket && bucket.resetAt <= now) {
      this.buckets.delete(key);
      return undefined;
    }
    return bucket;
  }

  private admitScoped(
    namespace: "ingress" | "classifier",
    rawAddress: string,
    policy: {
      globalRequests: number;
      subnetRequests: number;
      exactRequests: number;
      globalConcurrent: number;
      subnetConcurrent: number;
      exactConcurrent: number;
    },
    now: number
  ): () => void {
    const scopes = networkAddressScopes(rawAddress);
    const exact = this.digest(`${namespace}:exact`, scopes.exact);
    const subnet = this.digest(`${namespace}:subnet`, scopes.subnet);
    const active = this.active[namespace];

    const requestedBuckets = [
      { key: `${namespace}:global`, limit: policy.globalRequests },
      { key: `${namespace}:subnet:${subnet}`, limit: policy.subnetRequests },
      { key: `${namespace}:exact:${exact}`, limit: policy.exactRequests }
    ];

    // Read every scope before mutating any. A rejected exact-address request
    // must not drain the shared subnet/global budget, and a saturated global
    // scope must not allocate rotating address keys.
    let existing = requestedBuckets.map(({ key }) => this.activeBucket(key, now));
    const rejected = existing.findIndex((bucket, index) => Boolean(bucket && bucket.count >= requestedBuckets[index].limit));
    if (rejected >= 0) {
      throw new RelayLimitError("rate_limited", existing[rejected]!.resetAt - now);
    }

    if (
      active.global >= policy.globalConcurrent
      || (active.subnet.get(subnet) ?? 0) >= policy.subnetConcurrent
      || (active.exact.get(exact) ?? 0) >= policy.exactConcurrent
    ) {
      throw new RelayLimitError("concurrency_limited", 1_000);
    }

    let missing = existing.filter((bucket) => !bucket).length;
    if (this.buckets.size + missing > this.limits.maxBucketEntries) {
      this.sweep(now);
      existing = requestedBuckets.map(({ key }) => this.activeBucket(key, now));
      missing = existing.filter((bucket) => !bucket).length;
      if (this.buckets.size + missing > this.limits.maxBucketEntries) {
        throw new RelayLimitError("rate_limited", this.limits.windowMs);
      }
    }

    // Commit the three rate scopes only after every rate, concurrency, and
    // memory-cap check succeeds.
    requestedBuckets.forEach(({ key }, index) => {
      const bucket = existing[index];
      if (bucket) bucket.count += 1;
      else this.buckets.set(key, { count: 1, resetAt: now + this.limits.windowMs });
    });

    active.global += 1;
    active.subnet.set(subnet, (active.subnet.get(subnet) ?? 0) + 1);
    active.exact.set(exact, (active.exact.get(exact) ?? 0) + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      active.global = Math.max(0, active.global - 1);
      const subnetCount = (active.subnet.get(subnet) ?? 1) - 1;
      const exactCount = (active.exact.get(exact) ?? 1) - 1;
      if (subnetCount <= 0) active.subnet.delete(subnet);
      else active.subnet.set(subnet, subnetCount);
      if (exactCount <= 0) active.exact.delete(exact);
      else active.exact.set(exact, exactCount);
    };
  }

  admit(rawAddress: string, now = Date.now()): () => void {
    return this.admitScoped("ingress", rawAddress, {
      globalRequests: this.limits.globalRequests,
      subnetRequests: this.limits.subnetRequests,
      exactRequests: this.limits.exactRequests,
      globalConcurrent: this.limits.globalConcurrent,
      subnetConcurrent: this.limits.subnetConcurrent,
      exactConcurrent: this.limits.exactConcurrent
    }, now);
  }

  /** Additional admission for the shared serialized /auto classifier only. */
  admitAutomaticClassification(rawAddress: string, now = Date.now()): () => void {
    return this.admitScoped("classifier", rawAddress, {
      globalRequests: this.limits.classifierGlobalRequests,
      subnetRequests: this.limits.classifierSubnetRequests,
      exactRequests: this.limits.classifierExactRequests,
      globalConcurrent: this.limits.classifierGlobalConcurrent,
      subnetConcurrent: this.limits.classifierSubnetConcurrent,
      exactConcurrent: this.limits.classifierExactConcurrent
    }, now);
  }

  /** Test/operationally-safe counts only; never exposes address-derived keys. */
  stateCounts() {
    return {
      buckets: this.buckets.size,
      globalActive: this.active.ingress.global,
      exactActive: this.active.ingress.exact.size,
      subnetActive: this.active.ingress.subnet.size,
      classifierGlobalActive: this.active.classifier.global,
      classifierExactActive: this.active.classifier.exact.size,
      classifierSubnetActive: this.active.classifier.subnet.size
    };
  }
}

function pathOf(request: FastifyRequest) {
  return request.url.split("?", 1)[0];
}

function isNoncanonicalProtectedPath(path: string): boolean {
  const lower = path.toLowerCase();
  return lower.startsWith(`${CHAT_PATH}/`)
    || lower.startsWith(`${CHAT_PATH}%2f`)
    || lower.startsWith(`${EMBEDDINGS_PATH}/`)
    || lower.startsWith(`${EMBEDDINGS_PATH}%2f`)
    || lower.startsWith(`${ATTESTATION_PATH}/`)
    || lower.startsWith(`${ATTESTATION_PATH}%2f`)
    || lower.startsWith(`${IMAGE_PATH}/`)
    || lower.startsWith(`${IMAGE_PATH}%2f`)
    || lower.startsWith(`${OPAQUE_E2EE_CHAT_PATH}/`)
    || lower.startsWith(`${OPAQUE_E2EE_CHAT_PATH}%2f`);
}

function ticketHeader(request: FastifyRequest): string | null {
  const raw = request.headers[TICKET_HEADER];
  const value = Array.isArray(raw) ? null : raw?.trim();
  return value && value.length <= 256 ? value : null;
}

export function registerRelayIngressGuard(
  server: FastifyInstance,
  options: Partial<RelayIngressLimits> = {}
): RelayIngressGuard {
  const guard = new RelayIngressGuard(options);
  server.server.maxConnections = (options.maxConnections ?? DEFAULT_LIMITS.maxConnections);

  const releases = new WeakMap<FastifyRequest, () => void>();
  const release = (request: FastifyRequest) => {
    releases.get(request)?.();
    releases.delete(request);
  };

  server.addHook("onRequest", async (request, reply) => {
    const path = pathOf(request);
    // Image generation is a protected ticket path only when the split image flag
    // is on. With the flag off the relay serves a 503 stub at that path, so the
    // ingress must NOT intercept it (a flag-off request has no image ticket).
    const imageProtected = server.config.internal?.imageGenerationEnabled === true && path === IMAGE_PATH;
    const exactProtectedPath = path === CHAT_PATH
      || path === OPAQUE_E2EE_CHAT_PATH
      || path === EMBEDDINGS_PATH
      || path === ATTESTATION_PATH
      || imageProtected;
    const noncanonicalProtectedPath = isNoncanonicalProtectedPath(path);
    const gatewayAttestationPath = path === GATEWAY_ATTESTATION_PATH;
    if (!exactProtectedPath && !noncanonicalProtectedPath && !gatewayAttestationPath) return;

    const requestLeases: Array<() => void> = [];
    let requestReleased = false;
    const addLease = (lease: () => void) => {
      if (requestReleased) lease();
      else requestLeases.push(lease);
    };
    const releaseLeases = () => {
      if (requestReleased) return;
      requestReleased = true;
      for (const lease of requestLeases.splice(0)) lease();
    };
    addLease(guard.admit(relayClientAddress(request)));
    releases.set(request, releaseLeases);
    request.raw.once("aborted", releaseLeases);
    reply.raw.once("close", releaseLeases);

    // Fastify route matching is exact, but a proxy wildcard can still send a
    // trailing-slash/suffix variant to this process. Reject it in onRequest,
    // after the cheap flood/concurrency gate and before ticket redemption or
    // JSON parsing, so a large malformed body cannot bypass ingress controls.
    if (noncanonicalProtectedPath) {
      throw new AppError(404, "route_not_found", "Route not found");
    }

    // Gateway attestation is admitted by the flood guard above and stops here:
    // it is credential-free by design and has no ticket to redeem.
    if (gatewayAttestationPath) return;

    const ticket = ticketHeader(request);
    if (!ticket) {
      throw new AppError(401, "ticket_required", "A single-use ticket is required");
    }

    // This runs in onRequest: after the dependency-free limiter, but before
    // Fastify parses JSON. A malformed/oversized body cannot reach control or
    // consume relay parser work without first presenting a redeemable ticket.
    const signal = abortOnClientDisconnect(request, reply);
    if (path === CHAT_PATH || path === OPAQUE_E2EE_CHAT_PATH) {
      const chatRedemption = await server.controlClient.redeem(ticket, signal);
      if (!chatRedemption) throw new AppError(401, "invalid_ticket", "Inference ticket is invalid or expired");
      if ((chatRedemption.constraints.operation ?? "chat") !== "chat") {
        throw new AppError(409, "ticket_operation_mismatch", "Ticket is not valid for chat");
      }
      if (chatRedemption.constraints.automatic) {
        addLease(guard.admitAutomaticClassification(relayClientAddress(request)));
      }
      ingressContexts.set(request, { signal, chatRedemption });
    } else if (path === EMBEDDINGS_PATH) {
      const embeddingRedemption = await server.controlClient.redeem(ticket, signal);
      if (!embeddingRedemption) throw new AppError(401, "invalid_ticket", "Inference ticket is invalid or expired");
      if (embeddingRedemption.constraints.operation !== "embeddings") {
        throw new AppError(409, "ticket_operation_mismatch", "Ticket is not valid for embeddings");
      }
      ingressContexts.set(request, { signal, embeddingRedemption });
    } else if (path === IMAGE_PATH) {
      const imageRedemption = await server.controlClient.redeem(ticket, signal);
      if (!imageRedemption) throw new AppError(401, "invalid_ticket", "Inference ticket is invalid or expired");
      if ((imageRedemption.constraints.operation ?? "chat") !== "image") {
        throw new AppError(409, "ticket_operation_mismatch", "Ticket is not valid for image generation");
      }
      ingressContexts.set(request, { signal, imageRedemption });
    } else {
      const attestationRedemption = await server.controlClient.redeemAttestation(ticket, signal);
      if (!attestationRedemption) {
        throw new AppError(401, "invalid_attestation_ticket", "Attestation ticket is invalid, expired, or already used");
      }
      ingressContexts.set(request, { signal, attestationRedemption });
    }
  });

  server.addHook("onResponse", async (request) => release(request));
  server.addHook("onError", async (request) => release(request));
  server.addHook("onClose", async () => {
    // No persisted state exists; dropping the server drops all counters.
  });

  return guard;
}
