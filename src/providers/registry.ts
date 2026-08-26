import type { ContentPlaneConfig } from "../contentPlaneConfig.js";
import type { DbPool } from "../db/pool.js";
import { AppError } from "../security/errors.js";
import { decodeReasoningCapabilities } from "../inference/reasoning.js";
import { MockProviderAdapter } from "./mock.js";
import { FireworksProviderAdapter } from "./fireworks.js";
import { BedrockProviderAdapter } from "./bedrock.js";
import { DeepInfraProviderAdapter } from "./deepinfra.js";
import { ChutesProviderAdapter } from "./chutes.js";
import { TinfoilProviderAdapter } from "./tinfoil.js";
import { NearProviderAdapter } from "./near.js";
import { VeniceProviderAdapter } from "./venice.js";
import type { VeniceKeysetStore } from "./veniceKeyStore.js";
import { evaluateStoredModelEligibility } from "./catalog/enablement.js";
import type { ModelRecord, ProviderAdapter } from "./types.js";

type RuntimeModelRecord = ModelRecord & {
  providerAvailability: string;
  availabilityStatus: string;
  listed: boolean;
  missingSyncCount: number;
  reviewStatus: string;
  quarantineReason: string | null;
  catalogLastSuccessAt: Date | null;
  catalogStatePresent: boolean;
};

function runtimeEligible(model: RuntimeModelRecord) {
  return evaluateStoredModelEligibility({
    modelType: model.modelType,
    providerAvailability: model.providerAvailability,
    availabilityStatus: model.availabilityStatus,
    listed: model.listed,
    missingSyncCount: model.missingSyncCount,
    reviewStatus: model.reviewStatus,
    quarantineReason: model.quarantineReason,
    privacyClass: model.privacyClass,
    contextWindow: model.contextWindow,
    maxOutputTokens: model.maxOutputTokens,
    inputPricePerMillion: model.inputPricePerMillion,
    outputPricePerMillion: model.outputPricePerMillion,
    unitPriceUsd: model.unitPriceUsd,
    catalogLastSuccessAt: model.catalogLastSuccessAt,
    catalogStatePresent: model.catalogStatePresent
  }).eligible;
}

export class ProviderRegistry {
  private readonly adapters: Map<string, ProviderAdapter>;

  constructor(config: ContentPlaneConfig, veniceKeyStore?: VeniceKeysetStore) {
    // The dev monolith can route all configured providers in-process. Split
    // production workers still enforce credential isolation at their RPC
    // boundary; registering an adapter here never makes a database model
    // callable by itself.
    this.adapters = new Map<string, ProviderAdapter>([
      ["mock", new MockProviderAdapter(config)],
      ["venice", new VeniceProviderAdapter(config, undefined, veniceKeyStore)],
      ["fireworks", new FireworksProviderAdapter(config)],
      ["aws-bedrock", new BedrockProviderAdapter(config)],
      ["deepinfra", new DeepInfraProviderAdapter(config)],
      ["chutes", new ChutesProviderAdapter(config)],
      ["tinfoil", new TinfoilProviderAdapter(config)],
      ["near-ai", new NearProviderAdapter(config)]
    ]);
  }

  adapterFor(providerName: string) {
    const adapter = this.adapters.get(providerName);
    if (!adapter) {
      throw new AppError(503, "provider_unavailable", "Provider is not configured");
    }
    return adapter;
  }
}

const privacyRank: Record<string, number> = { anonymous: 0, private: 1, tee: 2, e2ee: 3 };

/**
 * Resolve one callable provider route.
 *
 * A canonical creator/model slug intentionally matches every provider serving
 * that model. Without an explicit provider, prefer the strongest privacy
 * guarantee and use total token price as the tie-breaker. Supplying a provider
 * pins the request to that provider while keeping the canonical model slug on
 * the public request/response surface.
 */
export async function getEnabledModel(
  db: DbPool,
  publicModelId: string,
  includeTestFixtures = false,
  providerName?: string
): Promise<ModelRecord | null> {
  const result = await db.query<RuntimeModelRecord>(
    `
      SELECT
        m.id,
        m.provider_id AS "providerId",
        p.name AS "providerName",
        p.status AS "providerStatus",
        p.privacy_class AS "providerPrivacyClass",
        m.public_model_id AS "publicModelId",
        COALESCE(NULLIF(m.public_metadata->>'id', ''), m.public_model_id) AS "canonicalModelId",
        m.external_model_id AS "externalModelId",
        m.display_name AS "displayName",
        m.model_type AS "modelType",
        m.unit_price_usd::float8 AS "unitPriceUsd",
        m.context_window AS "contextWindow",
        m.max_output_tokens AS "maxOutputTokens",
        m.input_price_per_million::float8 AS "inputPricePerMillion",
        m.output_price_per_million::float8 AS "outputPricePerMillion",
        m.cache_read_price_per_million::float8 AS "cacheReadPricePerMillion",
        m.cache_write_price_per_million::float8 AS "cacheWritePricePerMillion",
        m.privacy_class AS "privacyClass",
        m.supports_streaming AS "supportsStreaming",
        m.supports_tools AS "supportsTools",
        m.supports_vision AS "supportsVision",
        m.max_images AS "maxImages",
        m.routing_enabled AS "routingEnabled",
        m.quality_tier AS "qualityTier",
        m.routing_tasks AS "routingTasks",
        COALESCE(m.public_metadata->>'moderation', 'unknown') AS "moderation",
        m.supports_web AS "supportsWeb",
        m.expected_latency_ms AS "expectedLatencyMs",
        m.reasoning_capabilities AS "reasoningCapabilities"
        ,m.provider_availability AS "providerAvailability"
        ,m.availability_status AS "availabilityStatus"
        ,m.listed
        ,m.missing_sync_count AS "missingSyncCount"
        ,m.review_status AS "reviewStatus"
        ,m.quarantine_reason AS "quarantineReason"
        ,cs.last_success_at AS "catalogLastSuccessAt"
        ,(cs.provider_id IS NOT NULL) AS "catalogStatePresent"
      FROM providers.models m
      JOIN providers.providers p ON p.id = m.provider_id
      LEFT JOIN providers.catalog_state cs ON cs.provider_id = m.provider_id
      WHERE (
          m.public_model_id = $1
          OR m.external_model_id = $1
          OR m.public_metadata->>'id' = $1
        )
        AND ($3::text IS NULL OR p.name = $3)
        AND m.enabled = true
        AND p.status = 'active'
        AND NOT EXISTS (
          SELECT 1 FROM providers.provider_emergency_controls pec
          WHERE pec.provider_id = p.id AND pec.disabled = true
        )
        AND (p.is_test_fixture = false OR $2 = true)
      ORDER BY p.name, m.public_model_id
    `,
    [publicModelId, includeTestFixtures, providerName ?? null]
  );

  const eligible = result.rows.filter(runtimeEligible);
  const canonicalRequest = eligible.some((model) => model.canonicalModelId === publicModelId);
  const candidates = canonicalRequest
    ? eligible.filter((model) => model.canonicalModelId === publicModelId)
    : eligible;
  candidates.sort((left, right) => {
    if (!canonicalRequest) {
      const leftExact = left.publicModelId === publicModelId ? 2 : left.externalModelId === publicModelId ? 1 : 0;
      const rightExact = right.publicModelId === publicModelId ? 2 : right.externalModelId === publicModelId ? 1 : 0;
      if (leftExact !== rightExact) return rightExact - leftExact;
    }
    const privacy = (privacyRank[right.privacyClass] ?? -1) - (privacyRank[left.privacyClass] ?? -1);
    if (privacy !== 0) return privacy;
    const price = (left.inputPricePerMillion + left.outputPricePerMillion)
      - (right.inputPricePerMillion + right.outputPricePerMillion);
    if (price !== 0) return price;
    return left.providerName.localeCompare(right.providerName);
  });
  const model = candidates[0] ?? null;
  // Defense-in-depth: re-run the same provider/catalog/privacy/pricing decision
  // used by operator enablement so a tampered or stale row cannot become callable.
  if (!model) return null;
  // Fail closed on a malformed capability blob: withhold controls, never invent them.
  return { ...model, reasoningCapabilities: decodeReasoningCapabilities(model.reasoningCapabilities) };
}

/**
 * Every callable provider route that serves the SAME canonical model as the
 * requested id (a canonical creator/model slug, a provider-qualified public id,
 * or a raw route id). This is the candidate set the provider-routing engine
 * ranks. Unlike getEnabledModel it returns every eligible route, not just the
 * single best one, so provider selection (pin / order / sort / fallback) can be
 * computed over the whole group while the public model id stays canonical.
 */
export async function listProviderRoutesForModel(
  db: DbPool,
  requestedModelId: string,
  includeTestFixtures = false
): Promise<ModelRecord[]> {
  const result = await db.query<RuntimeModelRecord>(
    `
      WITH requested AS (
        SELECT COALESCE(NULLIF(m.public_metadata->>'id', ''), m.public_model_id) AS canonical
        FROM providers.models m
        JOIN providers.providers p ON p.id = m.provider_id
        WHERE (
            m.public_model_id = $1
            OR m.external_model_id = $1
            OR m.public_metadata->>'id' = $1
          )
          AND m.enabled = true
          AND p.status = 'active'
          AND (p.is_test_fixture = false OR $2 = true)
        LIMIT 1
      )
      SELECT
        m.id,
        m.provider_id AS "providerId",
        p.name AS "providerName",
        p.status AS "providerStatus",
        p.privacy_class AS "providerPrivacyClass",
        m.public_model_id AS "publicModelId",
        COALESCE(NULLIF(m.public_metadata->>'id', ''), m.public_model_id) AS "canonicalModelId",
        m.external_model_id AS "externalModelId",
        m.display_name AS "displayName",
        m.model_type AS "modelType",
        m.unit_price_usd::float8 AS "unitPriceUsd",
        m.context_window AS "contextWindow",
        m.max_output_tokens AS "maxOutputTokens",
        m.input_price_per_million::float8 AS "inputPricePerMillion",
        m.output_price_per_million::float8 AS "outputPricePerMillion",
        m.cache_read_price_per_million::float8 AS "cacheReadPricePerMillion",
        m.cache_write_price_per_million::float8 AS "cacheWritePricePerMillion",
        m.privacy_class AS "privacyClass",
        m.supports_streaming AS "supportsStreaming",
        m.supports_tools AS "supportsTools",
        m.supports_vision AS "supportsVision",
        m.max_images AS "maxImages",
        m.routing_enabled AS "routingEnabled",
        m.quality_tier AS "qualityTier",
        m.routing_tasks AS "routingTasks",
        COALESCE(m.public_metadata->>'moderation', 'unknown') AS "moderation",
        m.supports_web AS "supportsWeb",
        m.expected_latency_ms AS "expectedLatencyMs",
        m.reasoning_capabilities AS "reasoningCapabilities"
        ,m.provider_availability AS "providerAvailability"
        ,m.availability_status AS "availabilityStatus"
        ,m.listed
        ,m.missing_sync_count AS "missingSyncCount"
        ,m.review_status AS "reviewStatus"
        ,m.quarantine_reason AS "quarantineReason"
        ,cs.last_success_at AS "catalogLastSuccessAt"
        ,(cs.provider_id IS NOT NULL) AS "catalogStatePresent"
      FROM providers.models m
      JOIN providers.providers p ON p.id = m.provider_id
      LEFT JOIN providers.catalog_state cs ON cs.provider_id = m.provider_id
      WHERE COALESCE(NULLIF(m.public_metadata->>'id', ''), m.public_model_id) = (SELECT canonical FROM requested)
        AND m.enabled = true
        AND p.status = 'active'
        AND NOT EXISTS (
          SELECT 1 FROM providers.provider_emergency_controls pec
          WHERE pec.provider_id = p.id AND pec.disabled = true
        )
        AND (p.is_test_fixture = false OR $2 = true)
      ORDER BY p.name, m.public_model_id
    `,
    [requestedModelId, includeTestFixtures]
  );
  return result.rows
    .filter(runtimeEligible)
    .map((model) => ({ ...model, reasoningCapabilities: decodeReasoningCapabilities(model.reasoningCapabilities) }));
}

export async function listEnabledModels(db: DbPool, includeTestFixtures = false): Promise<ModelRecord[]> {
  const result = await db.query<RuntimeModelRecord>(
    `
      SELECT
        m.id,
        m.provider_id AS "providerId",
        p.name AS "providerName",
        p.status AS "providerStatus",
        p.privacy_class AS "providerPrivacyClass",
        m.public_model_id AS "publicModelId",
        COALESCE(NULLIF(m.public_metadata->>'id', ''), m.public_model_id) AS "canonicalModelId",
        m.external_model_id AS "externalModelId",
        m.display_name AS "displayName",
        m.model_type AS "modelType",
        m.unit_price_usd::float8 AS "unitPriceUsd",
        m.context_window AS "contextWindow",
        m.max_output_tokens AS "maxOutputTokens",
        m.input_price_per_million::float8 AS "inputPricePerMillion",
        m.output_price_per_million::float8 AS "outputPricePerMillion",
        m.cache_read_price_per_million::float8 AS "cacheReadPricePerMillion",
        m.cache_write_price_per_million::float8 AS "cacheWritePricePerMillion",
        m.privacy_class AS "privacyClass",
        m.supports_streaming AS "supportsStreaming",
        m.supports_tools AS "supportsTools",
        m.supports_vision AS "supportsVision",
        m.max_images AS "maxImages",
        m.routing_enabled AS "routingEnabled",
        m.quality_tier AS "qualityTier",
        m.routing_tasks AS "routingTasks",
        COALESCE(m.public_metadata->>'moderation', 'unknown') AS "moderation",
        m.supports_web AS "supportsWeb",
        m.expected_latency_ms AS "expectedLatencyMs",
        m.reasoning_capabilities AS "reasoningCapabilities"
        ,m.provider_availability AS "providerAvailability"
        ,m.availability_status AS "availabilityStatus"
        ,m.listed
        ,m.missing_sync_count AS "missingSyncCount"
        ,m.review_status AS "reviewStatus"
        ,m.quarantine_reason AS "quarantineReason"
        ,cs.last_success_at AS "catalogLastSuccessAt"
        ,(cs.provider_id IS NOT NULL) AS "catalogStatePresent"
      FROM providers.models m
      JOIN providers.providers p ON p.id = m.provider_id
      LEFT JOIN providers.catalog_state cs ON cs.provider_id = m.provider_id
      WHERE m.enabled = true
        AND p.status = 'active'
        AND NOT EXISTS (
          SELECT 1 FROM providers.provider_emergency_controls pec
          WHERE pec.provider_id = p.id AND pec.disabled = true
        )
        AND (p.is_test_fixture = false OR $1 = true)
      ORDER BY p.name, m.public_model_id
    `,
    [includeTestFixtures]
  );
  return result.rows
    .filter(runtimeEligible)
    .map((model) => ({ ...model, reasoningCapabilities: decodeReasoningCapabilities(model.reasoningCapabilities) }));
}
