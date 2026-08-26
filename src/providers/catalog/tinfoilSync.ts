import type { FastifyBaseLogger } from "fastify";
import type { ContentPlaneConfig } from "../../contentPlaneConfig.js";
import { computeSourceHash } from "./hash.js";
import { normalizeTinfoilCatalog, type RawTinfoilModel } from "./tinfoilNormalize.js";
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

/** Tinfoil exposes its OpenAI-compatible model list at `<base>/models`. */
export function tinfoilCatalogUrl(baseUrl: string): string {
  const url = new URL(baseUrl);
  url.pathname = `${url.pathname.replace(/\/$/, "")}/models`;
  return url.toString();
}

export async function fetchRawTinfoilModels(config: ContentPlaneConfig, opts: FetchOptions = {}): Promise<RawTinfoilModel[]> {
  const key = config.providers.tinfoilApiKey;
  // Fail closed: without the credential the provider stays un-synced (and thus
  // never callable), even though /v1/models is itself publicly readable.
  if (!key) throw new Error("tinfoil_credential_missing");
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRetries = opts.maxRetries ?? MAX_RETRIES;
  const random = opts.random ?? Math.random;
  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    let retryAfterMs: number | null = null;
    try {
      const response = await fetch(tinfoilCatalogUrl(config.providers.tinfoilBaseUrl), {
        headers: { authorization: `Bearer ${key}` },
        signal: AbortSignal.timeout(timeoutMs)
      });
      if (response.ok) {
        const body = (await response.json()) as unknown;
        if (Array.isArray(body)) return body as RawTinfoilModel[];
        const data = (body as { data?: unknown })?.data;
        return Array.isArray(data) ? (data as RawTinfoilModel[]) : [];
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
      { provider: "tinfoil", attempt: attempt + 1, retry_in_ms: Math.round(delay), error_type: errorName(lastError) },
      "catalog_fetch_retry"
    );
    await sleep(delay);
  }
  throw lastError instanceof Error ? lastError : new Error("catalog_fetch_failed");
}

export async function buildTinfoilCatalogPayload(
  config: ContentPlaneConfig,
  opts: FetchOptions & { log?: FastifyBaseLogger } = {}
): Promise<NormalizedCatalogPayload | null> {
  try {
    const raw = await fetchRawTinfoilModels(config, opts);
    const models = normalizeTinfoilCatalog(raw);
    return {
      schema_version: CATALOG_SCHEMA_VERSION,
      provider: "tinfoil",
      fetched_at: new Date().toISOString(),
      source_hash: computeSourceHash(models),
      models
    };
  } catch (error) {
    opts.log?.warn({ provider: "tinfoil", error_type: errorName(error) }, "catalog_fetch_failed");
    return null;
  }
}
