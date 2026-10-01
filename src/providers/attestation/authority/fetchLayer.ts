// The fetch discipline every release-authority fetcher shares.
//
// WHY THIS EXISTS. A verdict that depends on what a provider PUBLISHES depends
// on a few public endpoints answering: GitHub (60 unauthenticated REST calls
// per hour per IP, and every worker in the CVM leaves through the same IP),
// Base JSON-RPC, and Chutes' measurement list. Without discipline, a burst of
// attestations becomes a burst of identical requests, one rate limit turns
// every verdict to "failed" for up to an hour, and a transient error is retried
// by every caller at once. So each fetcher gets, from here:
//
//   - SINGLE FLIGHT per key: concurrent callers share one request. A caller's
//     own abort signal ends only that caller's wait, never the shared request
//     (which has its own deadline).
//   - A POSITIVE CACHE with a TTL chosen per answer by the fetcher.
//   - A NEGATIVE CACHE: after a failure the key is not retried before a
//     backoff that doubles per consecutive failure, and never before the
//     upstream's own Retry-After / rate-limit reset.
//   - BOUNDED STALENESS. Past its TTL an answer may still be served while a
//     refresh runs (stale-while-revalidate, where a fetcher opts in) or when a
//     refresh failed (stale-if-error), but NEVER once it is older than
//     `AUTHORITY_MAX_STALE_MS` (90 minutes, measured from the original fetch).
//     Beyond that the caller gets the error and the verifier fails closed. A
//     served answer keeps its ORIGINAL fetch time, so the verifier, which
//     refuses publication data older than its policy's maxPublicationAgeMs
//     (2 hours for NEAR and Chutes), sees the true age; the 30 minutes between
//     the two bounds is margin for the browser, which re-checks the same record
//     against its own clock after transport.
//   - A PROCESS-WIDE REQUEST BUDGET per host (a token bucket), so no input,
//     however hostile, fans out into unbounded traffic, and a host that said
//     "rate limited until T" is not asked again before T, for any key.
//   - BOUNDED RESPONSES (streamed, cut off at a byte cap whether or not a
//     Content-Length was sent) and a deadline on every request. Redirects are
//     refused, nothing but the request line, a fixed User-Agent and (for a
//     conditional request) If-None-Match is sent, and no credential ever is.
//
// WHAT A CACHE HERE MAY NEVER DO: turn a failure into a pass for DIFFERENT
// inputs. Every fetcher keys an answer by every input that determines it (the
// exact head AND commit of an ancestry question, the commit and path of a file,
// the full app/compose/image subject on chain, the repository of a ref
// advertisement). An answer is never reused under another key, and staleness
// only ever substitutes an OLDER answer to the SAME question, which still has
// to pass the verifier on its own merits.

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** The oldest answer any fetcher may serve, stale-while-revalidate or stale-if-error. */
export const AUTHORITY_MAX_STALE_MS = 90 * 60_000;

/** First negative-cache interval after a failure; doubles per consecutive failure. */
export const AUTHORITY_ERROR_BACKOFF_MS = 30_000;
export const AUTHORITY_MAX_ERROR_BACKOFF_MS = 10 * 60_000;
/** A Retry-After or rate-limit reset further out than this is clamped to it. */
export const AUTHORITY_MAX_RETRY_AFTER_MS = 60 * 60_000;

const USER_AGENT = "anonrouter-attestation/1";
/** Clock skew tolerated before a cached answer from "the future" is distrusted. */
const SKEW_MS = 30_000;

export class AuthorityFetchError extends Error {
  constructor(readonly code: string, message: string, readonly retryAtMs?: number) {
    super(message);
    this.name = "AuthorityFetchError";
  }
}

// ---------------------------------------------------------------------------
// Request budget
// ---------------------------------------------------------------------------

export interface HostBudget {
  /** Requests available at once (bucket size). */
  burst: number;
  /** Sustained refill rate. */
  perHour: number;
}

/**
 * Per-host budgets for ONE worker process.
 *
 * api.github.com is the binding one: GitHub allows 60 unauthenticated REST
 * calls per hour per IP, and the Venice and NEAR workers share the CVM's egress
 * IP, so each gets 25 an hour (10 at once). Conditional requests are counted
 * here even though GitHub does not count a 304 against its limit: this budget
 * is ours, and simpler to reason about if every request costs one.
 * raw.githubusercontent.com serves immutable file bytes that are cached by
 * commit, so its burst covers a cold start of several providers' logs.
 */
export const DEFAULT_HOST_BUDGETS: Readonly<Record<string, HostBudget>> = Object.freeze({
  "api.github.com": Object.freeze({ burst: 10, perHour: 25 }),
  "github.com": Object.freeze({ burst: 30, perHour: 300 }),
  "raw.githubusercontent.com": Object.freeze({ burst: 600, perHour: 3000 }),
  "mainnet.base.org": Object.freeze({ burst: 60, perHour: 1200 }),
  "base-rpc.publicnode.com": Object.freeze({ burst: 60, perHour: 1200 }),
  "api.chutes.ai": Object.freeze({ burst: 10, perHour: 60 })
});
const FALLBACK_HOST_BUDGET: HostBudget = Object.freeze({ burst: 30, perHour: 300 });

export class RequestBudget {
  private readonly buckets = new Map<string, { tokens: number; at: number; blockedUntil: number }>();

  constructor(
    private readonly budgets: Readonly<Record<string, HostBudget>> = DEFAULT_HOST_BUDGETS,
    private readonly now: () => number = Date.now,
    private readonly fallback: HostBudget = FALLBACK_HOST_BUDGET
  ) {}

  private bucket(host: string) {
    const budget = this.budgets[host] ?? this.fallback;
    const now = this.now();
    let bucket = this.buckets.get(host);
    if (!bucket) {
      bucket = { tokens: budget.burst, at: now, blockedUntil: 0 };
      this.buckets.set(host, bucket);
    }
    const elapsed = Math.max(0, now - bucket.at);
    bucket.tokens = Math.min(budget.burst, bucket.tokens + (elapsed * budget.perHour) / 3_600_000);
    bucket.at = now;
    return bucket;
  }

  /** Spend one request on `host`, or throw WITHOUT touching the network. */
  take(host: string): void {
    const bucket = this.bucket(host);
    const now = this.now();
    if (bucket.blockedUntil > now) {
      throw new AuthorityFetchError("rate_limited", `${host} asked not to be contacted before ${new Date(bucket.blockedUntil).toISOString()}`, bucket.blockedUntil);
    }
    if (bucket.tokens < 1) {
      const budget = this.budgets[host] ?? this.fallback;
      const retryAtMs = now + Math.ceil(((1 - bucket.tokens) * 3_600_000) / budget.perHour);
      throw new AuthorityFetchError("budget_exhausted", `the request budget for ${host} is spent`, retryAtMs);
    }
    bucket.tokens -= 1;
  }

  /** The host said it will not answer before `untilMs`: stop asking it, for every key. */
  block(host: string, untilMs: number): void {
    const bucket = this.bucket(host);
    bucket.blockedUntil = Math.max(bucket.blockedUntil, untilMs);
  }

  /** Whole requests currently available for `host` (tests and diagnostics). */
  available(host: string): number {
    const bucket = this.bucket(host);
    return bucket.blockedUntil > this.now() ? 0 : Math.floor(bucket.tokens);
  }
}

/** One budget per process: every fetcher that is not handed another shares it. */
export const DEFAULT_AUTHORITY_BUDGET = new RequestBudget();

// ---------------------------------------------------------------------------
// One bounded request
// ---------------------------------------------------------------------------

export interface AuthorityRequest {
  url: string;
  method?: "GET" | "POST";
  accept: string;
  contentType?: string;
  body?: string;
  maxBytes: number;
  timeoutMs: number;
  fetch: FetchLike;
  budget: RequestBudget;
  now?: () => number;
  /** Sent as If-None-Match; a 304 then means "unchanged since that answer". */
  etag?: string;
}

export type AuthorityResponse =
  | { status: 200; body: Uint8Array; etag?: string }
  | { status: 304 }
  | { status: 404 };

/** When a response says "rate limited", the instant it says to come back; else null. */
export function rateLimitRetryAt(response: Response, now: number): number | null {
  const headers = response.headers;
  const retryAfter = headers.get("retry-after");
  const remaining = headers.get("x-ratelimit-remaining");
  const reset = headers.get("x-ratelimit-reset");
  const limited = response.status === 429
    || (response.status === 403 && (remaining === "0" || retryAfter !== null));
  if (!limited) return null;
  let at: number | null = null;
  if (retryAfter !== null) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) at = now + seconds * 1000;
    else {
      const date = Date.parse(retryAfter);
      if (Number.isFinite(date)) at = date;
    }
  }
  if (at === null && reset !== null && Number.isFinite(Number(reset))) at = Number(reset) * 1000;
  if (at === null) at = now + 60_000;
  return Math.min(Math.max(at, now + 1000), now + AUTHORITY_MAX_RETRY_AFTER_MS);
}

/** Read a body to at most `maxBytes`, cancelling the stream as soon as it is exceeded. */
export async function readBounded(response: Response, maxBytes: number, label: string): Promise<Uint8Array> {
  const declared = Number(response.headers.get("content-length") ?? "NaN");
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel().catch(() => undefined);
    throw new AuthorityFetchError("response_too_large", `${label} response exceeds the size limit`);
  }
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new AuthorityFetchError("response_too_large", `${label} response exceeds the size limit`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/**
 * One request under the budget, with a deadline, no redirects and a byte cap.
 * 200 and 404 are answers, 304 is "unchanged" (only when an ETag was sent),
 * a rate-limit answer blocks the host in the budget, anything else throws.
 */
export async function authorityFetch(request: AuthorityRequest): Promise<AuthorityResponse> {
  const now = request.now ?? Date.now;
  const host = new URL(request.url).host;
  request.budget.take(host);
  const timeout = AbortSignal.timeout(request.timeoutMs);
  const headers: Record<string, string> = { accept: request.accept, "user-agent": USER_AGENT };
  if (request.contentType) headers["content-type"] = request.contentType;
  if (request.etag) headers["if-none-match"] = request.etag;
  let response: Response;
  try {
    response = await request.fetch(request.url, {
      method: request.method ?? "GET",
      redirect: "error",
      headers,
      ...(request.body !== undefined ? { body: request.body } : {}),
      signal: timeout
    });
  } catch (error) {
    if (timeout.aborted) throw new AuthorityFetchError("timeout", `${host} did not answer within ${request.timeoutMs} ms`);
    throw new AuthorityFetchError("network", `${host} could not be reached (${error instanceof Error ? error.message : String(error)})`);
  }
  if (response.status === 304 && request.etag) {
    await response.body?.cancel().catch(() => undefined);
    return { status: 304 };
  }
  if (response.status === 404) {
    await response.body?.cancel().catch(() => undefined);
    return { status: 404 };
  }
  const retryAt = rateLimitRetryAt(response, now());
  if (retryAt !== null) {
    await response.body?.cancel().catch(() => undefined);
    request.budget.block(host, retryAt);
    throw new AuthorityFetchError("rate_limited", `${host} answered ${response.status} (rate limited)`, retryAt);
  }
  if (response.status !== 200) {
    await response.body?.cancel().catch(() => undefined);
    throw new AuthorityFetchError("upstream_status", `${host} answered ${response.status}`);
  }
  let body: Uint8Array;
  try {
    body = await readBounded(response, request.maxBytes, host);
  } catch (error) {
    if (error instanceof AuthorityFetchError) throw error;
    if (timeout.aborted) throw new AuthorityFetchError("timeout", `${host} did not finish within ${request.timeoutMs} ms`);
    throw new AuthorityFetchError("network", `${host} response could not be read`);
  }
  const etag = response.headers.get("etag") ?? undefined;
  return { status: 200, body, ...(etag ? { etag } : {}) };
}

// ---------------------------------------------------------------------------
// The cache
// ---------------------------------------------------------------------------

export interface CacheTiming<V> {
  /** How long an answer is served without contacting the source. Per answer. */
  freshMs: (value: V) => number;
  /** Past fresh, serve the old answer immediately while ONE refresh runs, for this long. 0 disables. */
  staleWhileRevalidateMs?: number;
  /** Never serve an answer older than this, by any path. */
  maxStaleMs?: number;
  errorBackoffMs?: number;
  maxErrorBackoffMs?: number;
}

export interface CachedAnswer<V> {
  value: V;
  /** When the source produced this answer (the request's start). Never re-stamped by the cache. */
  fetchedAtMs: number;
  /** True when served past its freshness (revalidating, or the refresh failed). */
  stale: boolean;
}

/** What a loader returns: the answer and, when the source sent one, its ETag. */
export interface Loaded<V> {
  value: V;
  etag?: string;
}

type Loader<V> = (previous: { value: V; etag?: string } | undefined) => Promise<Loaded<V>>;

interface Entry<V> {
  answer?: { value: V; at: number; etag?: string };
  failure?: { error: unknown; retryAtMs: number; consecutive: number };
  inFlight?: Promise<CachedAnswer<V>>;
}

/** Wait for `promise`, but let THIS caller's signal end the wait (not the work). */
function raceSignal<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => { signal.removeEventListener("abort", onAbort); resolve(value); },
      (error) => { signal.removeEventListener("abort", onAbort); reject(error); }
    );
  });
}

export class AuthorityCache<V> {
  private readonly entries = new Map<string, Entry<V>>();
  private readonly maxEntries: number;
  private readonly now: () => number;
  private readonly maxStaleMs: number;
  private readonly swrMs: number;
  private readonly errorBackoffMs: number;
  private readonly maxErrorBackoffMs: number;

  constructor(private readonly timing: CacheTiming<V>, options: { maxEntries?: number; now?: () => number } = {}) {
    this.maxEntries = Math.max(1, options.maxEntries ?? 1024);
    this.now = options.now ?? Date.now;
    this.maxStaleMs = Math.min(timing.maxStaleMs ?? AUTHORITY_MAX_STALE_MS, AUTHORITY_MAX_STALE_MS);
    this.swrMs = Math.max(0, timing.staleWhileRevalidateMs ?? 0);
    this.errorBackoffMs = timing.errorBackoffMs ?? AUTHORITY_ERROR_BACKOFF_MS;
    this.maxErrorBackoffMs = timing.maxErrorBackoffMs ?? AUTHORITY_MAX_ERROR_BACKOFF_MS;
  }

  /**
   * The answer for `key`: fresh from cache, shared with a request already in
   * flight, stale within bounds, or fetched now with `load`. Throws when no
   * answer within bounds exists, so the caller attaches nothing and the
   * verifier fails closed.
   */
  get(key: string, load: Loader<V>, signal?: AbortSignal): Promise<CachedAnswer<V>> {
    const now = this.now();
    const entry = this.entries.get(key);
    const answer = entry?.answer;
    const age = answer ? now - answer.at : Number.POSITIVE_INFINITY;
    const sane = answer !== undefined && answer.at - now <= SKEW_MS;
    if (answer && sane && age < this.timing.freshMs(answer.value)) {
      return Promise.resolve({ value: answer.value, fetchedAtMs: answer.at, stale: false });
    }
    const usableStale = answer && sane && age <= this.maxStaleMs
      ? { value: answer.value, fetchedAtMs: answer.at, stale: true }
      : undefined;
    const withinSwr = usableStale !== undefined
      && this.swrMs > 0
      && age < this.timing.freshMs(answer!.value) + this.swrMs;

    if (entry?.inFlight) {
      if (withinSwr) return Promise.resolve(usableStale!);
      return raceSignal(entry.inFlight, signal);
    }
    if (entry?.failure && now < entry.failure.retryAtMs) {
      // Negative cache: no network until the backoff (or the upstream's own
      // retry time) passes. A bounded stale answer is still an answer.
      if (usableStale) return Promise.resolve(usableStale);
      return Promise.reject(entry.failure.error);
    }
    const flight = this.refresh(key, load);
    if (withinSwr) return Promise.resolve(usableStale!);
    return raceSignal(flight, signal);
  }

  /** Drop every entry (tests, and an operator-forced refresh). */
  clear(): void {
    this.entries.clear();
  }

  private entryFor(key: string): Entry<V> {
    let entry = this.entries.get(key);
    if (entry) return entry;
    while (this.entries.size >= this.maxEntries) {
      // Oldest first (insertion order), never an entry with a request in flight.
      let evicted = false;
      for (const [candidate, value] of this.entries) {
        if (!value.inFlight) {
          this.entries.delete(candidate);
          evicted = true;
          break;
        }
      }
      if (!evicted) break;
    }
    entry = {};
    this.entries.set(key, entry);
    return entry;
  }

  private refresh(key: string, load: Loader<V>): Promise<CachedAnswer<V>> {
    const entry = this.entryFor(key);
    const startedAt = this.now();
    const previous = entry.answer ? { value: entry.answer.value, etag: entry.answer.etag } : undefined;
    // Chained (not an async IIFE) so `flight` exists before any callback runs,
    // even if `load` throws synchronously: the in-flight marker can then never
    // outlive the request it marks.
    const flight: Promise<CachedAnswer<V>> = Promise.resolve()
      .then(() => load(previous))
      .then(
        (loaded) => {
          entry.answer = { value: loaded.value, at: startedAt, ...(loaded.etag ? { etag: loaded.etag } : {}) };
          entry.failure = undefined;
          return { value: loaded.value, fetchedAtMs: startedAt, stale: false };
        },
        (error: unknown) => {
          const consecutive = (entry.failure?.consecutive ?? 0) + 1;
          const backoff = Math.min(this.errorBackoffMs * 2 ** (consecutive - 1), this.maxErrorBackoffMs);
          const upstreamRetry = error instanceof AuthorityFetchError && typeof error.retryAtMs === "number"
            ? Math.min(error.retryAtMs, startedAt + AUTHORITY_MAX_RETRY_AFTER_MS)
            : 0;
          entry.failure = { error, retryAtMs: Math.max(startedAt + backoff, upstreamRetry), consecutive };
          // Stale-if-error, still bounded by the ORIGINAL fetch time.
          const answer = entry.answer;
          const now = this.now();
          if (answer && now - answer.at <= this.maxStaleMs && answer.at - now <= SKEW_MS) {
            return { value: answer.value, fetchedAtMs: answer.at, stale: true };
          }
          throw error;
        }
      )
      .finally(() => {
        if (entry.inFlight === flight) entry.inFlight = undefined;
      });
    // Marks the rejection handled for the case where every waiter has already
    // gone (its own signal aborted); each waiter still sees the error.
    flight.catch(() => undefined);
    entry.inFlight = flight;
    return flight;
  }
}
