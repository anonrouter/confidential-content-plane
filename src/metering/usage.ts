import type { DbPool } from "../db/pool.js";
import { newId } from "../ids.js";
import type { TokenUsage } from "./tokens.js";

export type UsageStatus = "succeeded" | "failed" | "rate_limited" | "insufficient_balance";
export type UsageOperation = "chat" | "embeddings" | "image" | "speech";

export async function recordUsageEvent(
  db: DbPool,
  params: {
    accountId: string;
    requestId: string;
    providerId: string;
    modelId: string;
    apiKeyId?: string;
    operation: UsageOperation;
    usage: TokenUsage;
    costUsd: number;
    providerCostUsd?: number;
    status: UsageStatus;
    firstTokenLatencyMs?: number;
    latencyMs: number;
  }
) {
  await db.query(
    `
      INSERT INTO metering.usage_events (
        id,
        account_id,
        request_id,
        provider_id,
        model_id,
        api_key_id,
        operation,
        input_tokens,
        output_tokens,
        cached_tokens,
        cache_write_tokens,
        cost_usd,
        provider_cost_usd,
        status,
        first_token_latency_ms,
        latency_ms
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
      ON CONFLICT (request_id) DO NOTHING
    `,
    [
      newId("use"),
      params.accountId,
      params.requestId,
      params.providerId,
      params.modelId,
      params.apiKeyId ?? null,
      params.operation,
      params.usage.inputTokens,
      params.usage.outputTokens,
      params.usage.cachedTokens,
      params.usage.cacheWriteTokens ?? 0,
      params.costUsd,
      params.providerCostUsd ?? params.costUsd,
      params.status,
      params.firstTokenLatencyMs ?? null,
      params.latencyMs
    ]
  );
}
