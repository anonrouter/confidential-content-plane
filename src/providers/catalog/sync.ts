// Worker-side catalog synchronization: fetch the authenticated Venice models
// endpoint resiliently, normalize + hash it into a versioned payload, and hand it
// to a delivery function (apply directly in the dev monolith, or push to control
// in the split topology). Only ONE sync runs at a time; polling is jittered and
// gated so a single designated worker owns it when the service is scaled.
//
// The Venice API key, authorization header, and raw provider responses are never
// logged or returned — only sanitized counts, status codes, and error names.

import type { FastifyBaseLogger } from "fastify";
import type { ContentPlaneConfig } from "../../contentPlaneConfig.js";
import { computeSourceHash } from "./hash.js";
import { normalizeVeniceCatalog, type RawVeniceModel } from "./normalize.js";
import { CATALOG_SCHEMA_VERSION, type NormalizedCatalogPayload } from "./normalized.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_RETRIES = 3;
const BACKOFF_BASE_MS = 500;
const BACKOFF_CAP_MS = 8_000;
const JITTER_FRACTION = 0.15;

class NonRetryableHttpError extends Error {
  constructor(readonly status: number) {
    super(`non_retryable_http_${status}`);
    this.name = "NonRetryableHttpError";
  }
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    if (signal) {
      const onAbort = () => {
        clearTimeout(timer);
        reject(new Error("aborted"));
      };
      if (signal.aborted) onAbort();
      else signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

/** Parse a Retry-After header (delta-seconds or HTTP-date) into milliseconds. */
export function parseRetryAfterMs(header: string | null, now = Date.now()): number | null {
  if (!header) return null;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 60_000);
  const date = new Date(header);
  if (!Number.isNaN(date.getTime())) return Math.max(0, Math.min(date.getTime() - now, 60_000));
  return null;
}

/** Full jitter exponential backoff, honoring a server-supplied Retry-After floor. */
export function backoffDelayMs(attempt: number, retryAfterMs: number | null, random = Math.random): number {
  const capped = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** attempt);
  const jittered = capped / 2 + random() * (capped / 2);
  return retryAfterMs !== null ? Math.max(jittered, retryAfterMs) : jittered;
}

export interface FetchOptions {
  timeoutMs?: number;
  maxRetries?: number;
  random?: () => number;
  log?: FastifyBaseLogger;
}

/**
 * Fetch and decode the raw Venice model list. Retries network errors, HTTP 429,
 * and HTTP 5xx up to three times with exponential backoff + jitter (honoring
 * Retry-After); ordinary 4xx failures are NOT retried. Throws on final failure.
 */
export async function fetchRawVeniceModels(config: ContentPlaneConfig, opts: FetchOptions = {}): Promise<RawVeniceModel[]> {
  const key = config.providers.veniceInferenceKey;
  if (!key) throw new Error("venice_credential_missing");
  const url = `${config.providers.veniceBaseUrl}/models?type=all`;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRetries = opts.maxRetries ?? MAX_RETRIES;
  const random = opts.random ?? Math.random;

  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    let retryAfterMs: number | null = null;
    try {
      const response = await fetch(url, {
        headers: { authorization: `Bearer ${key}` },
        signal: AbortSignal.timeout(timeoutMs)
      });
      if (response.ok) {
        const body = (await response.json()) as { data?: unknown };
        return Array.isArray(body.data) ? (body.data as RawVeniceModel[]) : [];
      }
      // 4xx (except 429) are client/config errors: do not retry.
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        throw new NonRetryableHttpError(response.status);
      }
      retryAfterMs = parseRetryAfterMs(response.headers.get("retry-after"));
      lastError = new Error(`http_${response.status}`);
    } catch (error) {
      if (error instanceof NonRetryableHttpError) throw error;
      lastError = error; // network/timeout/abort: retryable
    }
    if (attempt === maxRetries) break;
    const delay = backoffDelayMs(attempt, retryAfterMs, random);
    opts.log?.warn(
      { provider: "venice", attempt: attempt + 1, retry_in_ms: Math.round(delay), error_type: errorName(lastError) },
      "catalog_fetch_retry"
    );
    await sleep(delay);
  }
  throw lastError instanceof Error ? lastError : new Error("catalog_fetch_failed");
}

function errorName(error: unknown): string {
  if (error instanceof NonRetryableHttpError) return `http_${error.status}`;
  return error instanceof Error ? error.name : "unknown";
}

/**
 * Build the versioned normalized payload from the live Venice catalog. Returns
 * null (with a sanitized log) on fetch failure so a transient outage never
 * clobbers the last-known-good catalog.
 */
export async function buildVeniceCatalogPayload(
  config: ContentPlaneConfig,
  opts: FetchOptions = {}
): Promise<NormalizedCatalogPayload | null> {
  try {
    const raw = await fetchRawVeniceModels(config, opts);
    const models = normalizeVeniceCatalog(raw);
    return {
      schema_version: CATALOG_SCHEMA_VERSION,
      provider: "venice",
      fetched_at: new Date().toISOString(),
      source_hash: computeSourceHash(models),
      models
    };
  } catch (error) {
    opts.log?.warn({ provider: "venice", error_type: errorName(error) }, "catalog_fetch_failed");
    return null;
  }
}

// --- scheduler ---------------------------------------------------------------

export interface CatalogSynchronizerDeps {
  /** Build the versioned payload (fetch + normalize + hash). */
  buildPayload: () => Promise<NormalizedCatalogPayload | null>;
  /** Deliver a payload: apply in-process, or push to the control plane. */
  deliver: (payload: NormalizedCatalogPayload) => Promise<void>;
  intervalSeconds: number;
  /** CATALOG_SYNC_ENABLED: only the designated poller runs the timer. */
  enabled: boolean;
  jitterFraction?: number;
  log?: FastifyBaseLogger;
  random?: () => number;
  provider?: "venice" | "fireworks" | "aws-bedrock" | "deepinfra" | "chutes" | "tinfoil" | "near-ai" | "phala-ai";
}

/**
 * A single-flight, jittered catalog poller. `runOnce()` coalesces concurrent
 * callers onto one in-flight sync; `start()` runs once immediately then reschedules
 * every `intervalSeconds` ± jitter. Timers are unref'd so they never hold the
 * process open.
 */
export function createCatalogSynchronizer(deps: CatalogSynchronizerDeps) {
  const jitterFraction = deps.jitterFraction ?? JITTER_FRACTION;
  const random = deps.random ?? Math.random;
  const provider = deps.provider ?? "venice";
  let inFlight: Promise<void> | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let stopped = false;

  async function doRun(): Promise<void> {
    const payload = await deps.buildPayload();
    if (!payload) return;
    await deps.deliver(payload);
  }

  function runOnce(): Promise<void> {
    if (inFlight) return inFlight; // coalesce concurrent syncs
    inFlight = doRun()
      .catch((error) => {
        deps.log?.warn(
          { provider, error_type: error instanceof Error ? error.name : "sync_error" },
          "catalog_sync_failed"
        );
      })
      .finally(() => {
        inFlight = null;
      });
    return inFlight;
  }

  function nextDelayMs(): number {
    const base = deps.intervalSeconds * 1000;
    const jitter = base * jitterFraction * (random() * 2 - 1); // ±jitterFraction
    return Math.max(1_000, base + jitter);
  }

  function schedule(): void {
    if (stopped) return;
    timer = setTimeout(() => {
      void runOnce().finally(() => schedule());
    }, nextDelayMs());
    timer.unref?.();
  }

  async function start(): Promise<void> {
    if (!deps.enabled) {
      deps.log?.info({ provider }, "catalog_sync_disabled");
      return;
    }
    await runOnce();
    schedule();
  }

  function stop(): void {
    stopped = true;
    if (timer) clearTimeout(timer);
    timer = null;
  }

  return { runOnce, start, stop };
}

declare module "fastify" {
  interface FastifyInstance {
    /**
     * Worker-only: on-demand catalog fetch + push to control. Unlike the
     * scheduled poller, failures propagate to the caller. Absent on roles
     * that do not run the synchronizer.
     */
    catalogSyncNow?: () => Promise<void>;
  }
}
