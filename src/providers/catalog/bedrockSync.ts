import type { FastifyBaseLogger } from "fastify";
import type { ContentPlaneConfig } from "../../contentPlaneConfig.js";
import { BedrockMantleClient } from "../bedrockMantle.js";
import { computeSourceHash } from "./hash.js";
import { normalizeBedrockCatalog, type RawBedrockMantleModel } from "./bedrockNormalize.js";
import { CATALOG_SCHEMA_VERSION, type NormalizedCatalogPayload } from "./normalized.js";

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "unknown";
}

export async function buildBedrockCatalogPayload(
  config: ContentPlaneConfig,
  opts: { log?: FastifyBaseLogger; client?: BedrockMantleClient } = {}
): Promise<NormalizedCatalogPayload | null> {
  if (!config.providers.bedrockEnabled) return null;
  const client = opts.client ?? new BedrockMantleClient({
    baseUrl: config.providers.bedrockBaseUrl,
    region: config.providers.bedrockRegion,
    profile: config.providers.bedrockAwsProfile || undefined
  });
  try {
    // Account mode is a hard privacy gate. Do not publish even a static approved
    // route while the effective Mantle account mode is inherit or provider_data_share.
    const retentionResponse = await client.request("data_retention", {}, AbortSignal.timeout(10_000));
    if (!retentionResponse.ok) throw new Error(`http_${retentionResponse.status}`);
    const retention = await retentionResponse.json() as { mode?: unknown };
    if (retention.mode !== "none") throw new Error("bedrock_retention_not_none");

    const response = await client.request("models", {}, AbortSignal.timeout(10_000));
    if (!response.ok) throw new Error(`http_${response.status}`);
    const body = await response.json() as { data?: unknown; models?: unknown } | unknown[];
    const raw = Array.isArray(body)
      ? body
      : Array.isArray(body.data)
        ? body.data
        : Array.isArray(body.models) ? body.models : [];
    const models = normalizeBedrockCatalog(raw as RawBedrockMantleModel[]);
    return {
      schema_version: CATALOG_SCHEMA_VERSION,
      provider: "aws-bedrock",
      fetched_at: new Date().toISOString(),
      source_hash: computeSourceHash(models),
      models
    };
  } catch (error) {
    opts.log?.warn({ provider: "aws-bedrock", error_type: errorName(error) }, "catalog_fetch_failed");
    return null;
  }
}
