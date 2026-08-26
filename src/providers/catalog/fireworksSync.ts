import type { FastifyBaseLogger } from "fastify";
import type { ContentPlaneConfig } from "../../contentPlaneConfig.js";
import { computeSourceHash } from "./hash.js";
import { normalizeFireworksCatalog, type RawFireworksModel } from "./fireworksNormalize.js";
import { CATALOG_SCHEMA_VERSION, type NormalizedCatalogPayload } from "./normalized.js";
import { backoffDelayMs, parseRetryAfterMs, type FetchOptions } from "./sync.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_RETRIES = 3;

class NonRetryableHttpError extends Error {
  constructor(readonly status: number) {
    super(`non_retryable_http_${status}`);
    this.name = "NonRetryableHttpError";
  }
}

function errorName(error: unknown): string {
  if (error instanceof NonRetryableHttpError) return `http_${error.status}`;
  return error instanceof Error ? error.name : "unknown";
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function fireworksCatalogUrl(inferenceBaseUrl: string): string {
  const url = new URL(inferenceBaseUrl);
  url.pathname = "/v1/accounts/fireworks/models";
  url.search = new URLSearchParams({ filter: "supports_serverless=true", pageSize: "200" }).toString();
  return url.toString();
}

export async function fetchRawFireworksModels(config: ContentPlaneConfig, opts: FetchOptions = {}): Promise<RawFireworksModel[]> {
  const key = config.providers.fireworksApiKey;
  if (!key) throw new Error("fireworks_credential_missing");
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRetries = opts.maxRetries ?? MAX_RETRIES;
  const random = opts.random ?? Math.random;
  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    let retryAfterMs: number | null = null;
    try {
      const response = await fetch(fireworksCatalogUrl(config.providers.fireworksBaseUrl), {
        headers: { authorization: `Bearer ${key}` },
        signal: AbortSignal.timeout(timeoutMs)
      });
      if (response.ok) {
        const body = (await response.json()) as { models?: unknown };
        return Array.isArray(body.models) ? body.models as RawFireworksModel[] : [];
      }
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        throw new NonRetryableHttpError(response.status);
      }
      retryAfterMs = parseRetryAfterMs(response.headers.get("retry-after"));
      lastError = new Error(`http_${response.status}`);
    } catch (error) {
      if (error instanceof NonRetryableHttpError) throw error;
      lastError = error;
    }
    if (attempt === maxRetries) break;
    const delay = backoffDelayMs(attempt, retryAfterMs, random);
    opts.log?.warn(
      { provider: "fireworks", attempt: attempt + 1, retry_in_ms: Math.round(delay), error_type: errorName(lastError) },
      "catalog_fetch_retry"
    );
    await sleep(delay);
  }
  throw lastError instanceof Error ? lastError : new Error("catalog_fetch_failed");
}

export async function buildFireworksCatalogPayload(
  config: ContentPlaneConfig,
  opts: FetchOptions & { log?: FastifyBaseLogger } = {}
): Promise<NormalizedCatalogPayload | null> {
  try {
    const raw = await fetchRawFireworksModels(config, opts);
    const models = normalizeFireworksCatalog(raw);
    return {
      schema_version: CATALOG_SCHEMA_VERSION,
      provider: "fireworks",
      fetched_at: new Date().toISOString(),
      source_hash: computeSourceHash(models),
      models
    };
  } catch (error) {
    opts.log?.warn({ provider: "fireworks", error_type: errorName(error) }, "catalog_fetch_failed");
    return null;
  }
}
