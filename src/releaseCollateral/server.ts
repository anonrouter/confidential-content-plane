// The release-collateral role: release-authority lookups for a process that must not
// make them itself (PROVIDER_POOL_PLAN.md, W3). The contract, and why it has the
// shape it has, is src/releaseCollateral/contract.ts. This file enforces it.
//
// THE LOOKUPS ARE THE EXISTING FETCHERS, unchanged: GithubPublicationFetcher,
// GithubReleasesFetcher and DstackOnchainFetcher, with their caches, per-host
// budgets, negative caching, single flight, byte caps, deadlines and refused
// redirects (src/providers/attestation/authority/fetchLayer.ts). Nothing here
// builds a URL or a JSON-RPC body. A request selects a fetcher that was
// constructed at boot for one fixed repository or registry and hands it
// validated fields.
//
// WHAT THIS FILE ADDS is the part a fetcher never needed while it ran inside the
// process that owned the evidence: a caller that may be hostile. So, in order,
// and every step before any outbound request:
//
//   1. the service token, before the body is read;
//   2. a request rate limit, and no query string;
//   3. the strict schema of the operation;
//   4. a bound on lookups in flight;
//   5. an allowance for VALUES NOT SEEN BEFORE. A repeated value tells an
//      upstream nothing new; a new one is the channel the contract cannot
//      close. This is what makes the residual a rate.
//
// A request refused at any step has caused no outbound request.

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { z } from "zod";
import { abortOnClientDisconnect } from "../inference/disconnect.js";
import {
  BASE_PUBLIC_RPC_URLS,
  type OnchainAuthorizationSource,
  type PublicationSource,
  type ReleaseImagesSource
} from "../providers/attestation/authority/collateral.js";
import { DSTACK_IMAGE_MEASUREMENTS } from "../providers/attestation/authority/dstackImages.generated.js";
import { DstackOnchainFetcher } from "../providers/attestation/authority/dstackOnchain.js";
import {
  DEFAULT_HOST_BUDGETS,
  RequestBudget,
  type FetchLike,
  type HostBudget
} from "../providers/attestation/authority/fetchLayer.js";
import { GithubPublicationFetcher } from "../providers/attestation/authority/githubFetcher.js";
import { GithubReleasesFetcher } from "../providers/attestation/authority/githubReleases.js";
import { requireServiceToken } from "../routes/internal/serviceAuth.js";
import { AppError, publicErrorBody } from "../security/errors.js";
import {
  canonicalClaims,
  RELEASE_COLLATERAL_BODY_LIMIT_BYTES,
  RELEASE_COLLATERAL_OPERATIONS,
  RELEASE_COLLATERAL_RPC_PREFIX,
  releaseCollateralPath,
  ONCHAIN_REGISTRIES,
  onchainRequestSchema,
  PUBLICATION_REPOSITORIES,
  publicationRequestSchema,
  RELEASE_REPOSITORIES,
  releaseImagesRequestSchema,
  type ReleaseCollateralErrorCode,
  type ReleaseCollateralOperation,
  type OnchainRegistryName
} from "./contract.js";

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

export interface SubjectLimits {
  /** Most values remembered as already admitted, and most the fetcher caches. */
  maxSubjects: number;
  /** Values not seen before that may be admitted at once. */
  novelBurst: number;
  /** Sustained allowance for values not seen before. */
  novelPerHour: number;
}

export interface ReleaseCollateralLimits {
  /** Lookups in flight across every operation. */
  maxConcurrent: number;
  requestBurst: number;
  requestsPerMinute: number;
  /**
   * How long one request waits on its lookup before answering "unavailable".
   * Shorter than the pool's own deadline (RELEASE_COLLATERAL_RPC_TIMEOUT_MS, 20 s by
   * default), so the pool is told why instead of timing out.
   */
  lookupDeadlineMs: number;
  /** A (repository, commit, path) of a publication request. */
  publication: SubjectLimits;
  /** A (registry, app, compose hash, image) of an on-chain request. */
  onchain: SubjectLimits;
}

/**
 * The role's bounds. Code, not configuration: they are part of the measured
 * image, and a deployment cannot widen them with an environment value.
 *
 * Sized from the captured evidence (tests/fixtures/hw-evidence). The four live
 * TDs behind NEAR's and Venice's NEAR-format routes name 147 distinct files
 * and four on-chain subjects between them. A cold start therefore fits inside
 * the bursts about three times over, and steady state is a handful of new
 * values a day, when NEAR deploys. The allowances are what turn the residual
 * channel (contract.ts) into a rate:
 *
 *   publication  512 new (commit, path) at once, then 60 an hour
 *   on chain      32 new subjects at once, then 30 an hour
 *
 * A burst that is too small does not fail open: the request is refused, the
 * pool attaches no record, and that TD fails verification until the allowance
 * refills. Raise a burst only against a measured fleet.
 *
 * The request limit is far above anything the pool sends. It is there so one
 * caller cannot keep the role busy refusing.
 */
export const RELEASE_COLLATERAL_LIMITS: ReleaseCollateralLimits = Object.freeze({
  maxConcurrent: 16,
  requestBurst: 240,
  requestsPerMinute: 480,
  lookupDeadlineMs: 15_000,
  publication: Object.freeze({ maxSubjects: 8192, novelBurst: 512, novelPerHour: 60 }),
  onchain: Object.freeze({ maxSubjects: 256, novelBurst: 32, novelPerHour: 30 })
});

/**
 * The fetchers' per-host request budget, for this role. The workers' own
 * budgets (fetchLayer.ts) with one change: raw.githubusercontent.com keeps its
 * burst and drops from 3000 to 300 requests an hour.
 *
 * A worker's file budget is sized to re-read several providers' logs. Here new
 * files arrive at most as fast as the publication allowance above admits them,
 * so the rest of that budget would only ever be spent re-asking for files that
 * were absent, which is the one request a caller can repeat at will (an absent
 * file is cached for minutes, a present one for good). Which admitted value is
 * re-asked, and when, is a channel too; this is what bounds it.
 */
export const RELEASE_COLLATERAL_HOST_BUDGETS: Readonly<Record<string, HostBudget>> = Object.freeze({
  ...DEFAULT_HOST_BUDGETS,
  "raw.githubusercontent.com": Object.freeze({ burst: 600, perHour: 300 })
});

/** One budget for the role's process, as the workers have one for theirs. */
const RELEASE_COLLATERAL_BUDGET = new RequestBudget(RELEASE_COLLATERAL_HOST_BUDGETS);

/**
 * `perInterval` tokens every `intervalMs`, up to `burst`.
 *
 * Held as whole units of (token x millisecond) rather than as a fractional
 * token count, so on a millisecond clock every refill is exact integer
 * arithmetic: a token is available at the millisecond it is due, not one
 * rounding error either side of it.
 */
class TokenBucket {
  private credit: number;
  private at: number;

  constructor(
    private readonly burst: number,
    private readonly perInterval: number,
    private readonly intervalMs: number,
    private readonly now: () => number
  ) {
    this.credit = burst * intervalMs;
    this.at = now();
  }

  private refill() {
    const now = this.now();
    this.credit = Math.min(this.burst * this.intervalMs, this.credit + Math.max(0, now - this.at) * this.perInterval);
    this.at = now;
  }

  /** Spend `count`, all or none. */
  take(count = 1): boolean {
    this.refill();
    const cost = count * this.intervalMs;
    if (this.credit < cost) return false;
    this.credit -= cost;
    return true;
  }

  /** Whole seconds until `count` could be spent. */
  retryAfterSeconds(count = 1): number {
    this.refill();
    const missing = Math.min(count, this.burst) * this.intervalMs - this.credit;
    return missing <= 0 ? 1 : Math.max(1, Math.ceil(missing / this.perInterval / 1000));
  }
}

/**
 * The values one operation has already admitted, and the allowance for new
 * ones. Bounded: past `maxSubjects` the least recently used is forgotten, and
 * asking for it again spends from the allowance again.
 */
class SubjectLedger {
  private readonly admitted = new Map<string, true>();
  private readonly allowance: TokenBucket;

  constructor(private readonly limits: SubjectLimits, now: () => number) {
    this.allowance = new TokenBucket(limits.novelBurst, limits.novelPerHour, 3_600_000, now);
  }

  /** Admit every key or none. Nothing is recorded or spent on a refusal. */
  admit(keys: readonly string[]): { admitted: true } | { admitted: false; retryAfterSeconds: number } {
    const distinct = [...new Set(keys)];
    const novel = distinct.filter((key) => !this.admitted.has(key)).length;
    if (novel > 0 && !this.allowance.take(novel)) {
      return { admitted: false, retryAfterSeconds: this.allowance.retryAfterSeconds(novel) };
    }
    for (const key of distinct) {
      // Re-inserted, so insertion order is recency.
      this.admitted.delete(key);
      this.admitted.set(key, true);
    }
    while (this.admitted.size > this.limits.maxSubjects) {
      this.admitted.delete(this.admitted.keys().next().value as string);
    }
    return { admitted: true };
  }

  get size(): number {
    return this.admitted.size;
  }
}

/** Every bound the role holds between requests. One per server. */
export class ReleaseCollateralAdmission {
  readonly limits: ReleaseCollateralLimits;
  private readonly requests: TokenBucket;
  private readonly ledgers: { publication: SubjectLedger; onchain: SubjectLedger };
  private active = 0;

  /**
   * `now` and `deadline` are the role's only two readings of time, and both are
   * injected so a test can drive them. The role itself takes the defaults.
   */
  constructor(
    limits: Partial<ReleaseCollateralLimits> = {},
    now: () => number = Date.now,
    private readonly deadline: (ms: number) => AbortSignal = (ms) => AbortSignal.timeout(ms)
  ) {
    this.limits = { ...RELEASE_COLLATERAL_LIMITS, ...limits };
    this.requests = new TokenBucket(this.limits.requestBurst, this.limits.requestsPerMinute, 60_000, now);
    this.ledgers = {
      publication: new SubjectLedger(this.limits.publication, now),
      onchain: new SubjectLedger(this.limits.onchain, now)
    };
  }

  takeRequest(): boolean {
    return this.requests.take();
  }

  requestRetryAfterSeconds(): number {
    return this.requests.retryAfterSeconds();
  }

  /** Claim a lookup slot. False when every slot is taken. */
  enter(): boolean {
    if (this.active >= this.limits.maxConcurrent) return false;
    this.active += 1;
    return true;
  }

  leave(): void {
    this.active -= 1;
  }

  admitSubjects(kind: "publication" | "onchain", keys: readonly string[]) {
    return this.ledgers[kind].admit(keys);
  }

  /** Aborts when one lookup has waited `lookupDeadlineMs`. */
  lookupDeadline(): AbortSignal {
    return this.deadline(this.limits.lookupDeadlineMs);
  }

  /** Counts only (tests and diagnostics). */
  stats(): { inFlight: number; publicationSubjects: number; onchainSubjects: number } {
    return {
      inFlight: this.active,
      publicationSubjects: this.ledgers.publication.size,
      onchainSubjects: this.ledgers.onchain.size
    };
  }
}

// ---------------------------------------------------------------------------
// The lookups
// ---------------------------------------------------------------------------

type PublicationRepository = (typeof PUBLICATION_REPOSITORIES)[number];
type ReleaseRepository = (typeof RELEASE_REPOSITORIES)[number];

/** One source per entry of the contract's allowlists, built once at boot. */
export interface ReleaseCollateralSources {
  publication: Readonly<Record<PublicationRepository, PublicationSource>>;
  releaseImages: Readonly<Record<ReleaseRepository, ReleaseImagesSource>>;
  onchain: Readonly<Record<OnchainRegistryName, OnchainAuthorizationSource>>;
  /** The OS image hashes dstack published. An on-chain subject naming another is refused. */
  osImages: ReadonlySet<string>;
}

export interface ReleaseCollateralUpstreamOptions {
  /** Injected for tests. The role itself always uses the global. */
  fetch?: FetchLike;
  /** The per-host budget. Unset, it is the role's own (RELEASE_COLLATERAL_HOST_BUDGETS). */
  budget?: RequestBudget;
  /** Injected for tests: the clock of the fetchers and of the role's budget. */
  now?: () => number;
  limits?: Partial<ReleaseCollateralLimits>;
}

/** Where each registry's chain is read. Public, keyless, tried in order. */
const REGISTRY_RPC_URLS: Readonly<Record<OnchainRegistryName, readonly string[]>> = {
  "near-base-mainnet": BASE_PUBLIC_RPC_URLS
};

/** The real fetchers, for exactly the repositories and registries the contract names. */
export function releaseCollateralSources(options: ReleaseCollateralUpstreamOptions = {}): ReleaseCollateralSources {
  const limits = { ...RELEASE_COLLATERAL_LIMITS, ...options.limits };
  // The role's budget on the role's clock. With an injected clock it is a
  // budget of its own on that clock, never the process-wide one on real time.
  const budget = options.budget
    ?? (options.now ? new RequestBudget(RELEASE_COLLATERAL_HOST_BUDGETS, options.now) : RELEASE_COLLATERAL_BUDGET);
  const shared = { fetch: options.fetch, budget, now: options.now };
  const publication = {} as Record<PublicationRepository, PublicationSource>;
  for (const repository of PUBLICATION_REPOSITORIES) {
    publication[repository] = new GithubPublicationFetcher({
      repository, ...shared, maxCachedFiles: limits.publication.maxSubjects
    });
  }
  const releaseImages = {} as Record<ReleaseRepository, ReleaseImagesSource>;
  for (const repository of RELEASE_REPOSITORIES) {
    releaseImages[repository] = new GithubReleasesFetcher(repository, shared);
  }
  const onchain = {} as Record<OnchainRegistryName, OnchainAuthorizationSource>;
  for (const registry of Object.keys(ONCHAIN_REGISTRIES) as OnchainRegistryName[]) {
    onchain[registry] = new DstackOnchainFetcher({
      kms: ONCHAIN_REGISTRIES[registry],
      rpcUrls: [...REGISTRY_RPC_URLS[registry]],
      ...shared,
      maxCachedSubjects: limits.onchain.maxSubjects,
      // The subject comes from another process: never call an address as a
      // contract, or hand it a compose hash, unless the KMS registers it.
      requireRegisteredApp: true
    });
  }
  return {
    publication,
    releaseImages,
    onchain,
    osImages: new Set(DSTACK_IMAGE_MEASUREMENTS.map((image) => image.osImageHash))
  };
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/** A refusal or failure of this role. `reason` is one of a fixed set, never caller data. */
export class ReleaseCollateralError extends AppError {
  constructor(
    statusCode: number,
    code: ReleaseCollateralErrorCode,
    message: string,
    readonly reason?: string,
    readonly retryAfterSeconds?: number
  ) {
    super(statusCode, code, message, true, reason ? { reason } : undefined);
  }
}

const refused = () => new ReleaseCollateralError(400, "release_collateral_request_refused", "Release-collateral request refused");
const rateLimited = (retryAfterSeconds: number) =>
  new ReleaseCollateralError(429, "release_collateral_rate_limited", "Release-collateral request rate exceeded", undefined, retryAfterSeconds);

// The fetchers' own failure codes. Anything else is reported as `lookup_failed`:
// an upstream's words are not this role's to repeat.
const LOOKUP_FAILURE_CODES: ReadonlySet<string> = new Set([
  "timeout", "network", "rate_limited", "budget_exhausted", "upstream_status", "response_too_large",
  "github_unavailable", "repository_not_found", "no_default_branch", "too_many_files"
]);

function lookupFailure(error: unknown): string {
  if (error instanceof DOMException) return error.name === "TimeoutError" ? "deadline" : "aborted";
  const code = (error as { code?: unknown } | null)?.code;
  if (typeof code === "string" && LOOKUP_FAILURE_CODES.has(code)) return code;
  const message = error instanceof Error ? error.message : "";
  if (message === "onchain_wrong_chain") return message;
  if (/^onchain_rpc_(?:\d{3}|error)$/.test(message)) return "onchain_rpc_error";
  if (error instanceof SyntaxError || /^git_refs_/.test(message)) return "upstream_malformed";
  return "lookup_failed";
}

function operationOf(request: FastifyRequest): string {
  const route = request.routeOptions?.url ?? "";
  const name = route.startsWith(`${RELEASE_COLLATERAL_RPC_PREFIX}/`) ? route.slice(RELEASE_COLLATERAL_RPC_PREFIX.length + 1) : "";
  return (RELEASE_COLLATERAL_OPERATIONS as readonly string[]).includes(name) ? name : "unknown";
}

/**
 * The role's error handler. One line per refusal or failure, under a static
 * event name, carrying the operation (from the route template), a status and a
 * code from a fixed vocabulary. Never a parameter: every one is caller data.
 */
export function releaseCollateralErrorHandler(error: unknown, request: FastifyRequest, reply: FastifyReply) {
  const raised = error as { statusCode?: unknown; code?: unknown };
  const statusCode = typeof raised.statusCode === "number" ? raised.statusCode : 500;
  // A 4xx this role did not raise is the framework refusing the request before
  // a handler ran: a body that is not JSON, too large, or of another type. The
  // caller gets the same fixed refusal, under the framework's status.
  const answered = !(error instanceof AppError) && statusCode >= 400 && statusCode < 500
    ? new ReleaseCollateralError(statusCode, "release_collateral_request_refused", "Release-collateral request refused")
    : error;
  const code = (answered as { code?: unknown }).code;
  // A fixed reason: this role's own, or the framework's error code.
  const detail = answered instanceof ReleaseCollateralError && answered.reason
    ? answered.reason
    : answered !== error && typeof raised.code === "string" && /^FST_[A-Z_]{1,60}$/.test(raised.code) ? raised.code : undefined;
  request.log.warn(
    {
      request_id: request.id,
      operation: operationOf(request),
      error_type: answered instanceof AppError && typeof code === "string" ? code : "internal_error",
      ...(detail ? { error_code: detail } : {}),
      status_code: statusCode
    },
    statusCode >= 500 ? "release_collateral_lookup_failed" : "release_collateral_request_refused"
  );
  const retryAfterSeconds = (answered as { retryAfterSeconds?: unknown }).retryAfterSeconds;
  if (typeof retryAfterSeconds === "number" && retryAfterSeconds > 0) {
    reply.header("retry-after", String(Math.ceil(retryAfterSeconds)));
  }
  reply.status(statusCode).send(publicErrorBody(answered, request.id));
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

export interface ReleaseCollateralRouteOptions {
  /** RELEASE_COLLATERAL_RPC_TOKEN. An empty token admits no one. */
  token: string;
  sources: ReleaseCollateralSources;
  admission: ReleaseCollateralAdmission;
}

interface Prepared {
  /** The values this request would send upstream, for the allowance. */
  subjects?: { kind: "publication" | "onchain"; keys: string[] };
  run: (signal: AbortSignal) => Promise<Record<string, unknown>>;
}

export async function registerReleaseCollateralRoutes(server: FastifyInstance, options: ReleaseCollateralRouteOptions) {
  const { sources, admission } = options;
  // The sources must be the contract's allowlists exactly: a request that picks
  // an allowed name must find a fetcher built for that name and no other.
  const covers = (held: object, names: readonly string[]) =>
    names.every((name) => Object.hasOwn(held, name)) && Object.keys(held).length === names.length;
  if (!covers(sources.publication, PUBLICATION_REPOSITORIES)
    || !covers(sources.releaseImages, RELEASE_REPOSITORIES)
    || !covers(sources.onchain, Object.keys(ONCHAIN_REGISTRIES))) {
    throw new Error("release-collateral sources do not match the contract's allowlists");
  }

  const guard = requireServiceToken(options.token);
  // Both run before the body is read, so a caller without the token costs one
  // header comparison, and one past the rate costs nothing more.
  const admitRequest = async (request: FastifyRequest) => {
    if (!admission.takeRequest()) throw rateLimited(admission.requestRetryAfterSeconds());
    // Nothing in a URL is read, so nothing may be put in one.
    if (request.raw.url?.includes("?")) throw refused();
  };

  const operation = <S extends z.ZodTypeAny>(
    name: ReleaseCollateralOperation,
    schema: S,
    prepare: (body: z.output<S>) => Prepared
  ) => {
    server.post(releaseCollateralPath(name), {
      bodyLimit: RELEASE_COLLATERAL_BODY_LIMIT_BYTES[name],
      onRequest: [guard, admitRequest]
    }, async (request, reply) => {
      const parsed = schema.safeParse(request.body);
      if (!parsed.success) throw refused();
      const prepared = prepare(parsed.data);
      if (!admission.enter()) {
        throw new ReleaseCollateralError(429, "release_collateral_busy", "Release-collateral lookups are at capacity", undefined, 1);
      }
      try {
        if (prepared.subjects) {
          const verdict = admission.admitSubjects(prepared.subjects.kind, prepared.subjects.keys);
          if (!verdict.admitted) throw rateLimited(verdict.retryAfterSeconds);
        }
        // Ends this request's wait, not the fetcher's shared request, which
        // has its own deadline and still fills the cache.
        const signal = AbortSignal.any([abortOnClientDisconnect(request, reply), admission.lookupDeadline()]);
        try {
          return await prepared.run(signal);
        } catch (error) {
          throw new ReleaseCollateralError(503, "release_collateral_unavailable", "Release-collateral lookup produced no answer", lookupFailure(error));
        }
      } finally {
        admission.leave();
      }
    });
  };

  operation("github-publication", publicationRequestSchema, (body) => {
    // The server's order, not the caller's (see canonicalClaims).
    const claims = canonicalClaims(body.claims);
    return {
      subjects: {
        kind: "publication",
        // The tag is not part of the key: it is looked up locally and never sent.
        keys: claims.map((claim) => `${body.repository}\n${claim.commit}\n${claim.path}`)
      },
      run: async (signal) => ({ publication: await sources.publication[body.repository].collect(claims, signal) })
    };
  });

  operation("github-release-images", releaseImagesRequestSchema, (body) => ({
    // No variable field, so nothing to admit: the listing is one fixed request.
    run: async (signal) => ({ releases: await sources.releaseImages[body.repository].collect(signal) })
  }));

  operation("dstack-onchain-authorization", onchainRequestSchema, (body) => {
    // Only an image dstack published. A TD on any other image fails its base
    // image check whatever the registry says, so the answer could not change a
    // verdict, and 256 caller-chosen bits stay off the wire.
    if (!sources.osImages.has(body.osImageHash)) {
      throw new ReleaseCollateralError(400, "release_collateral_os_image_unknown", "Release-collateral request refused");
    }
    const { registry, ...subject } = body;
    return {
      subjects: {
        kind: "onchain",
        keys: [`${registry}\n${subject.appId}\n${subject.composeHash}\n${subject.osImageHash}`]
      },
      run: async (signal) => ({ authorization: await sources.onchain[registry].authorize(subject, signal) })
    };
  });

  // An authenticated caller naming anything else gets a fixed answer. The
  // default handler would repeat the requested path back.
  server.setNotFoundHandler({ preHandler: guard }, async () => {
    throw new ReleaseCollateralError(404, "release_collateral_request_refused", "Release-collateral request refused");
  });
}
