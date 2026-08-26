import type { DbPool } from "../db/pool.js";
import type { ChatCompletionRequestBody } from "../providers/types.js";
import {
  DEFAULT_WORKSPACE_PROVIDER_DEFAULTS,
  type ProviderPrivacyFloor,
  type ProviderSort,
  type WorkspaceProviderDefaults
} from "../providers/routing/policy.js";

export type RoutingPoolMode = "all" | "include" | "exclude";
export type RoutingStrategy = "cost" | "balanced" | "quality";
export type RoutingPrivacyLevel = "open" | "balanced" | "maximum";
export type RoutingPrivacyClass = "anonymous" | "private" | "tee" | "e2ee";

export interface RoutingPreferences {
  pool_mode: RoutingPoolMode;
  model_patterns: string[];
  strategy: RoutingStrategy;
  privacy_level: RoutingPrivacyLevel;
  /**
   * Provider routing defaults, merged restrictively under every request (see
   * mergeWorkspaceProviderPolicy). Optional so tickets/rows written before the
   * provider-routing migration parse as the Auto default. `provider_only` uses
   * null for "no restriction" and [] for "explicitly none".
   */
  provider_sort?: ProviderSort;
  provider_only?: string[] | null;
  provider_ignore?: string[];
  provider_allow_fallbacks?: boolean;
  provider_max_attempts?: number;
  provider_minimum_privacy?: ProviderPrivacyFloor | null;
  provider_max_price_input?: number | null;
  provider_max_price_output?: number | null;
  provider_require_parameters?: boolean;
}

interface RoutingPreferenceRow {
  pool_mode: RoutingPoolMode;
  model_patterns: string[];
  strategy: RoutingStrategy;
  privacy_level: RoutingPrivacyLevel;
  provider_sort?: ProviderSort | null;
  provider_only?: string[] | null;
  provider_ignore?: string[] | null;
  provider_allow_fallbacks?: boolean | null;
  provider_max_attempts?: number | null;
  provider_minimum_privacy?: ProviderPrivacyFloor | null;
  provider_max_price_input?: string | number | null;
  provider_max_price_output?: string | number | null;
  provider_require_parameters?: boolean | null;
}

export const defaultRoutingPreferences: RoutingPreferences = {
  pool_mode: "all",
  model_patterns: [],
  strategy: "balanced",
  privacy_level: "balanced"
};

/** Derive the provider-routing defaults from a preferences row (missing = Auto). */
export function providerDefaultsFromRoutingPreferences(preferences: RoutingPreferences): WorkspaceProviderDefaults {
  const input = preferences.provider_max_price_input ?? null;
  const output = preferences.provider_max_price_output ?? null;
  const maxPrice = input !== null || output !== null ? { input, output } : null;
  return {
    sort: preferences.provider_sort ?? DEFAULT_WORKSPACE_PROVIDER_DEFAULTS.sort,
    only: preferences.provider_only ?? DEFAULT_WORKSPACE_PROVIDER_DEFAULTS.only,
    ignore: preferences.provider_ignore ?? DEFAULT_WORKSPACE_PROVIDER_DEFAULTS.ignore,
    allowFallbacks: preferences.provider_allow_fallbacks ?? DEFAULT_WORKSPACE_PROVIDER_DEFAULTS.allowFallbacks,
    maxAttempts: preferences.provider_max_attempts ?? DEFAULT_WORKSPACE_PROVIDER_DEFAULTS.maxAttempts,
    minimumPrivacy: preferences.provider_minimum_privacy ?? DEFAULT_WORKSPACE_PROVIDER_DEFAULTS.minimumPrivacy,
    maxPrice,
    requireParameters: preferences.provider_require_parameters ?? DEFAULT_WORKSPACE_PROVIDER_DEFAULTS.requireParameters
  };
}

export const privacyClassesByLevel: Record<RoutingPrivacyLevel, RoutingPrivacyClass[]> = {
  open: ["anonymous", "private", "tee", "e2ee"],
  balanced: ["private", "tee", "e2ee"],
  maximum: ["tee", "e2ee"]
};

/**
 * Loads the routing preferences for one of the account's workspaces.
 * A null workspaceId means the account's default workspace, which keeps
 * the pre-workspace account-wide semantics.
 */
function coercePrice(value: string | number | null | undefined): number | null {
  return value === null || value === undefined ? null : Number(value);
}

/** Normalize a preferences row (nullable provider columns) into RoutingPreferences. */
function rowToPreferences(row: RoutingPreferenceRow): RoutingPreferences {
  return {
    pool_mode: row.pool_mode,
    model_patterns: row.model_patterns,
    strategy: row.strategy,
    privacy_level: row.privacy_level,
    provider_sort: row.provider_sort ?? undefined,
    provider_only: row.provider_only ?? undefined,
    provider_ignore: row.provider_ignore ?? undefined,
    provider_allow_fallbacks: row.provider_allow_fallbacks ?? undefined,
    provider_max_attempts: row.provider_max_attempts ?? undefined,
    provider_minimum_privacy: row.provider_minimum_privacy ?? undefined,
    provider_max_price_input: coercePrice(row.provider_max_price_input),
    provider_max_price_output: coercePrice(row.provider_max_price_output),
    provider_require_parameters: row.provider_require_parameters ?? undefined
  };
}

export async function loadRoutingPreferences(db: DbPool, accountId: string, workspaceId: string | null = null): Promise<RoutingPreferences> {
  // Through a SECURITY DEFINER function so the bridge-facing role needs no
  // SELECT on auth.routing_preferences or auth.workspaces. Read-only by
  // construction: the content plane may act on a preference, never change one.
  // See migrations/099_bridge_role_definer_functions.sql.
  const result = await db.query<RoutingPreferenceRow>(
    "SELECT * FROM security.resolve_routing_preferences($1, $2)",
    [accountId, workspaceId]
  );
  return result.rows[0] ? rowToPreferences(result.rows[0]) : { ...defaultRoutingPreferences };
}

export async function saveRoutingPreferences(db: DbPool, accountId: string, workspaceId: string, preferences: RoutingPreferences) {
  const result = await db.query<RoutingPreferenceRow>(
    `
      INSERT INTO auth.routing_preferences (
        account_id, workspace_id, pool_mode, model_patterns, strategy, privacy_level,
        provider_sort, provider_only, provider_ignore, provider_allow_fallbacks, provider_max_attempts,
        provider_minimum_privacy, provider_max_price_input, provider_max_price_output, provider_require_parameters
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      ON CONFLICT (workspace_id) DO UPDATE SET
        pool_mode = EXCLUDED.pool_mode,
        model_patterns = EXCLUDED.model_patterns,
        strategy = EXCLUDED.strategy,
        privacy_level = EXCLUDED.privacy_level,
        provider_sort = EXCLUDED.provider_sort,
        provider_only = EXCLUDED.provider_only,
        provider_ignore = EXCLUDED.provider_ignore,
        provider_allow_fallbacks = EXCLUDED.provider_allow_fallbacks,
        provider_max_attempts = EXCLUDED.provider_max_attempts,
        provider_minimum_privacy = EXCLUDED.provider_minimum_privacy,
        provider_max_price_input = EXCLUDED.provider_max_price_input,
        provider_max_price_output = EXCLUDED.provider_max_price_output,
        provider_require_parameters = EXCLUDED.provider_require_parameters,
        updated_at = now()
      RETURNING pool_mode, model_patterns, strategy, privacy_level,
        provider_sort, provider_only, provider_ignore, provider_allow_fallbacks, provider_max_attempts,
        provider_minimum_privacy, provider_max_price_input, provider_max_price_output, provider_require_parameters
    `,
    [
      accountId,
      workspaceId,
      preferences.pool_mode,
      preferences.model_patterns,
      preferences.strategy,
      preferences.privacy_level,
      preferences.provider_sort ?? null,
      preferences.provider_only ?? null,
      preferences.provider_ignore ?? [],
      preferences.provider_allow_fallbacks ?? true,
      preferences.provider_max_attempts ?? 3,
      preferences.provider_minimum_privacy ?? null,
      preferences.provider_max_price_input ?? null,
      preferences.provider_max_price_output ?? null,
      preferences.provider_require_parameters ?? false
    ]
  );
  return result.rows[0] ? rowToPreferences(result.rows[0]) : preferences;
}

export function routingConfigFromPreferences(preferences: RoutingPreferences): NonNullable<ChatCompletionRequestBody["routing"]> {
  const routing: NonNullable<ChatCompletionRequestBody["routing"]> = {
    strategy: preferences.strategy,
    privacy_classes: [...privacyClassesByLevel[preferences.privacy_level]]
  };
  if (preferences.pool_mode === "include") routing.allow = [...preferences.model_patterns];
  if (preferences.pool_mode === "exclude" && preferences.model_patterns.length > 0) routing.exclude = [...preferences.model_patterns];
  return routing;
}

export function applyRoutingPreferences(body: ChatCompletionRequestBody, preferences: RoutingPreferences): ChatCompletionRequestBody {
  const saved = routingConfigFromPreferences(preferences);
  const requested = body.routing;
  const requestDefinesModelPool = body.model.includes("*") || requested?.allow !== undefined || requested?.exclude !== undefined;
  const routing: NonNullable<ChatCompletionRequestBody["routing"]> = {
    ...saved,
    ...requested
  };

  if (requestDefinesModelPool) {
    delete routing.allow;
    delete routing.exclude;
    if (requested?.allow !== undefined) routing.allow = requested.allow;
    if (requested?.exclude !== undefined) routing.exclude = requested.exclude;
  }

  return { ...body, routing };
}
