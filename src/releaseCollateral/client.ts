// The pool's side of the release-collateral contract (src/releaseCollateral/contract.ts): the
// same source interface the release-authority fetchers implement, answered by
// the release-collateral role instead of by a request from this process.
//
// A pooled worker holds several providers' keys and every pooled prompt. With
// this client in place its release-authority lookups leave as a few fixed-shape
// fields to one internal service, and it opens no session to GitHub or Base.
//
// FAIL CLOSED. Every call has a deadline. Anything but a well-formed answer to
// the question asked is thrown, the caller attaches no record
// (NearReleaseCollateralSource), and the verifier fails that authority layer.
// There is no fallback to a direct lookup: an unreachable release-collateral role must
// not be what sends this process to GitHub.

import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import {
  defaultNearReleaseSources,
  NearReleaseCollateralSource,
  type NearReleaseSources
} from "../providers/attestation/authority/collateral.js";
import { validOnchainAuthorization, type DstackOnchainAuthorization } from "../providers/attestation/authority/dstackOnchain.js";
import { readBounded } from "../providers/attestation/authority/fetchLayer.js";
import { validGithubPublication, type GithubPublication, type PublicationClaim } from "../providers/attestation/authority/github.js";
import type { GithubReleaseImages } from "../providers/attestation/authority/githubReleases.js";
import { NEAR_COMPOSE_MANAGER_REPOSITORY, NEAR_OFFICIAL_COMPOSE_REPOSITORY } from "../providers/attestation/authority/near.js";
import {
  RELEASE_COLLATERAL_ERROR_CODES,
  releaseCollateralPath,
  contractClaims,
  contractOnchainSubject,
  MAX_PUBLICATION_CLAIMS,
  PUBLICATION_REPOSITORIES,
  RELEASE_REPOSITORIES,
  type ReleaseCollateralOperation,
  type OnchainRegistryName
} from "./contract.js";

/** A release-collateral call that produced no usable answer. `code` is from a fixed set. */
export class ReleaseCollateralRpcError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "ReleaseCollateralRpcError";
  }
}

export type ReleaseCollateralFailureObserver = (operation: ReleaseCollateralOperation, code: string) => void;

export interface ReleaseCollateralRpcClientOptions {
  /** RELEASE_COLLATERAL_RPC_URL: the release-collateral role's origin. */
  baseUrl: string;
  /** RELEASE_COLLATERAL_RPC_TOKEN. */
  token: string;
  timeoutMs: number;
  /** Injected for tests; the global is read at call time so a stub applies. */
  fetch?: typeof fetch;
  /** Calls in flight at once from this process. The rest wait their turn. */
  maxConcurrent?: number;
  /** Injected for tests: the signal that aborts when one call has taken `timeoutMs`. */
  deadline?: (ms: number) => AbortSignal;
}

// The largest honest answer is a publication record for 512 files, well under this.
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_ERROR_BYTES = 4 * 1024;
// Half the role's own bound, so an honest pool is never the caller it refuses.
const DEFAULT_MAX_CONCURRENT = 8;

// What the role may say went wrong. Anything else is reported as an HTTP error.
const SERVER_ERROR_CODES: ReadonlySet<string> = new Set([...RELEASE_COLLATERAL_ERROR_CODES, "service_unauthorized"]);

function validReleaseImages(value: unknown): value is GithubReleaseImages {
  if (!value || typeof value !== "object") return false;
  const record = value as Partial<GithubReleaseImages>;
  return record.v === 1
    && typeof record.repository === "string"
    && typeof record.fetchedAtMs === "number" && Number.isFinite(record.fetchedAtMs)
    && Array.isArray(record.images)
    && record.images.every((image) => image
      && typeof image.release === "string"
      && typeof image.component === "string"
      && typeof image.digest === "string" && /^sha256:[0-9a-f]{64}$/.test(image.digest));
}

export class ReleaseCollateralRpcClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl?: typeof fetch;
  private readonly maxConcurrent: number;
  private readonly deadline: (ms: number) => AbortSignal;
  private active = 0;
  private readonly waiting: Array<() => void> = [];
  private observer: ReleaseCollateralFailureObserver | null = null;

  constructor(options: ReleaseCollateralRpcClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.token = options.token;
    this.timeoutMs = options.timeoutMs;
    this.fetchImpl = options.fetch;
    this.maxConcurrent = Math.max(1, options.maxConcurrent ?? DEFAULT_MAX_CONCURRENT);
    this.deadline = options.deadline ?? ((ms) => AbortSignal.timeout(ms));
  }

  /** Told of every failed call, with the operation and a code. Never a parameter. */
  observeFailures(observer: ReleaseCollateralFailureObserver): void {
    this.observer = observer;
  }

  /** `repository`'s publication record for `claims`, as GithubPublicationFetcher.collect returns it. */
  async publication(repository: (typeof PUBLICATION_REPOSITORIES)[number], claims: PublicationClaim[], signal?: AbortSignal): Promise<GithubPublication> {
    const contract = contractClaims(claims);
    // The fetcher refuses a log naming more files than this; so does this.
    if (contract.length > MAX_PUBLICATION_CLAIMS) throw this.failed("github-publication", "release_collateral_claims_exceeded");
    return this.call("github-publication", { repository, claims: contract }, signal, (answer) => {
      const record = answer.publication;
      return validGithubPublication(record) && record.repository === repository ? record : null;
    });
  }

  /** `repository`'s released image digests, as GithubReleasesFetcher.collect returns them. */
  async releaseImages(repository: (typeof RELEASE_REPOSITORIES)[number], signal?: AbortSignal): Promise<GithubReleaseImages> {
    return this.call("github-release-images", { repository }, signal, (answer) => {
      const record = answer.releases;
      return validReleaseImages(record) && record.repository === repository ? record : null;
    });
  }

  /** What `registry` says about a subject, as DstackOnchainFetcher.authorize returns it. */
  async onchainAuthorization(
    registry: OnchainRegistryName,
    subject: { appId: string; composeHash: string; osImageHash: string },
    signal?: AbortSignal
  ): Promise<DstackOnchainAuthorization> {
    const contract = contractOnchainSubject(subject);
    // The fetcher's own error for the same input.
    if (!contract) throw new Error("onchain_subject_malformed");
    return this.call("dstack-onchain-authorization", { registry, ...contract }, signal, (answer) => {
      const record = answer.authorization;
      // An answer about another subject is not an answer to this question.
      return validOnchainAuthorization(record)
        && record.appId === `0x${contract.appId}`
        && record.composeHash === contract.composeHash
        && record.osImageHash === contract.osImageHash ? record : null;
    });
  }

  private failed(operation: ReleaseCollateralOperation, code: string): ReleaseCollateralRpcError {
    this.observer?.(operation, code);
    return new ReleaseCollateralRpcError(code);
  }

  /** At most `maxConcurrent` at once, first come first served. */
  private async gated<T>(task: () => Promise<T>): Promise<T> {
    // A released slot is handed straight to the next waiter.
    if (this.active >= this.maxConcurrent) await new Promise<void>((resolve) => this.waiting.push(resolve));
    else this.active += 1;
    try {
      return await task();
    } finally {
      const next = this.waiting.shift();
      if (next) next();
      else this.active -= 1;
    }
  }

  private call<T>(
    operation: ReleaseCollateralOperation,
    body: Record<string, unknown>,
    signal: AbortSignal | undefined,
    read: (answer: Record<string, unknown>) => T | null
  ): Promise<T> {
    return this.gated(async () => {
      signal?.throwIfAborted();
      // Starts when the call does, not while it waited for a slot.
      const timeout = this.deadline(this.timeoutMs);
      const failure = (fallback: string) => {
        // The caller gave up (its own request was cancelled): not a failure of the role.
        if (signal?.aborted) return signal.reason ?? new DOMException("Aborted", "AbortError");
        return this.failed(operation, timeout.aborted ? "release_collateral_timeout" : fallback);
      };
      let response: Response;
      try {
        response = await (this.fetchImpl ?? globalThis.fetch)(`${this.baseUrl}${releaseCollateralPath(operation)}`, {
          method: "POST",
          // The role never redirects. Following one would take the token elsewhere.
          redirect: "error",
          headers: { "content-type": "application/json", authorization: `Bearer ${this.token}` },
          body: JSON.stringify(body),
          signal: signal ? AbortSignal.any([signal, timeout]) : timeout
        });
      } catch {
        throw failure("release_collateral_unreachable");
      }
      if (response.status !== 200) {
        let code = "release_collateral_http_error";
        try {
          const parsed = JSON.parse(new TextDecoder().decode(await readBounded(response, MAX_ERROR_BYTES, "release-collateral"))) as {
            error?: { type?: unknown };
          };
          if (typeof parsed.error?.type === "string" && SERVER_ERROR_CODES.has(parsed.error.type)) code = parsed.error.type;
        } catch {
          // An unreadable error body is still a failed call.
        }
        throw failure(code);
      }
      let answer: unknown;
      try {
        answer = JSON.parse(new TextDecoder().decode(await readBounded(response, MAX_RESPONSE_BYTES, "release-collateral")));
      } catch {
        throw failure("release_collateral_response_invalid");
      }
      const record = answer && typeof answer === "object" && !Array.isArray(answer)
        ? read(answer as Record<string, unknown>)
        : null;
      if (record === null) throw failure("release_collateral_response_invalid");
      return record;
    });
  }
}

/** NEAR's release sources, each answered by the release-collateral role. */
export function rpcNearReleaseSources(client: ReleaseCollateralRpcClient): NearReleaseSources {
  return {
    composeRepository: {
      collect: (claims, signal) => client.publication(NEAR_OFFICIAL_COMPOSE_REPOSITORY, claims, signal)
    },
    composeManagerReleases: {
      collect: (signal) => client.releaseImages(NEAR_COMPOSE_MANAGER_REPOSITORY, signal)
    },
    onchain: {
      authorize: (subject, signal) => client.onchainAuthorization("near-base-mainnet", subject, signal)
    }
  };
}

// One client per loaded configuration, so every adapter in a process shares its
// concurrency bound and its failure observer. Keyed by the config object, not
// by its values: nothing here keeps a second copy of the token.
const CLIENTS = new WeakMap<object, ReleaseCollateralRpcClient>();

/** The release-collateral client this process is configured to use, or null when it makes its own lookups. */
export function releaseCollateralClientFor(config: ContentPlaneConfig): ReleaseCollateralRpcClient | null {
  // Nullish guard: hand-built partial configs in tests omit `internal`.
  const internal = config.internal as ContentPlaneConfig["internal"] | undefined;
  if (!internal?.releaseCollateralRpcUrl) return null;
  let client = CLIENTS.get(internal);
  if (!client) {
    client = new ReleaseCollateralRpcClient({
      baseUrl: internal.releaseCollateralRpcUrl,
      token: internal.releaseCollateralRpcToken,
      timeoutMs: internal.releaseCollateralRpcTimeoutMs
    });
    CLIENTS.set(internal, client);
  }
  return client;
}

/**
 * The NEAR release-authority fetch layer for this process: through the
 * release-collateral role where one is configured (the pool), by direct lookup
 * everywhere else, exactly as before.
 */
export function nearReleaseCollateralSourceFor(config: ContentPlaneConfig): NearReleaseCollateralSource {
  const client = releaseCollateralClientFor(config);
  return new NearReleaseCollateralSource(client ? rpcNearReleaseSources(client) : defaultNearReleaseSources());
}
