import type { DbPool } from "../db/pool.js";
import { AppError } from "../security/errors.js";

export interface UsagePlan {
  code: "payg" | "custom";
  source: "default" | "admin";
  name: string;
  requestsPerMinute: number;
  tokensPerMinute: number;
  concurrentGenerations: number;
  dailyBudgetUsd: number | null;
  maxRequestCostUsd: number | null;
  modelAllowlist: string[] | null;
}

export const defaultUsagePlans = {
  payg: {
    code: "payg",
    source: "default",
    name: "Pay as you go",
    // Agent workloads carry 40K+ token contexts per call: the TPM bucket is
    // debited at input-estimate + 8K, so 250K/min starved coding agents to
    // ~4 requests/min. Balance, the shared provider bucket, and upstream 429s
    // remain the aggregate backstops.
    requestsPerMinute: 120,
    tokensPerMinute: 2_000_000,
    concurrentGenerations: 8,
    dailyBudgetUsd: null,
    // Paid prepaid users are bounded by their balance, API-key/custom budgets,
    // and rate limits. Do not impose a hidden product-wide per-request cap.
    maxRequestCostUsd: null,
    modelAllowlist: null
  }
} as const satisfies Record<string, UsagePlan>;

/**
 * Bound local automatic-routing work before final model selection is possible.
 * Exact-model tickets do not invoke the classifier and keep the existing
 * short-lived ticket prefetch allowance.
 */
export function ticketIssuanceRequestsPerMinute(plan: UsagePlan, automatic: boolean) {
  return automatic
    ? Math.max(1, Math.min(60, plan.requestsPerMinute))
    : 60;
}

interface PlanRow {
  plan_name: string | null;
  requests_per_minute: number | null;
  tokens_per_minute: number | null;
  concurrent_generations: number | null;
  daily_budget_usd: string | null;
  max_request_cost_usd: string | null;
  model_allowlist: string[] | null;
}

export async function resolveUsagePlan(db: DbPool, accountId: string): Promise<UsagePlan> {
  const result = await db.query<PlanRow>(
    `
      -- No join to auth.accounts. It only tested existence, and both outcomes
      -- it distinguished (account absent, or present with no plan) already
      -- resolve to the default plan below, so the join changed nothing except
      -- to make this query require a privilege the bridge-facing role must not
      -- have. Reading the plan table directly is identical in behaviour.
      SELECT p.plan_name, p.requests_per_minute, p.tokens_per_minute,
             p.concurrent_generations, p.daily_budget_usd,
             p.max_request_cost_usd, p.model_allowlist
      FROM billing.account_usage_plans p
      WHERE p.account_id = $1
    `,
    [accountId]
  );
  const row = result.rows[0];
  if (!row?.plan_name) {
    return { ...defaultUsagePlans.payg };
  }
  return {
    code: "custom",
    source: "admin",
    name: row.plan_name,
    requestsPerMinute: Number(row.requests_per_minute),
    tokensPerMinute: Number(row.tokens_per_minute),
    concurrentGenerations: Number(row.concurrent_generations),
    dailyBudgetUsd: row.daily_budget_usd === null ? null : Number(row.daily_budget_usd),
    maxRequestCostUsd: row.max_request_cost_usd === null ? null : Number(row.max_request_cost_usd),
    modelAllowlist: row.model_allowlist
  };
}

function patternMatches(pattern: string, modelId: string) {
  if (pattern === "*") return true;
  if (pattern.endsWith("*")) return modelId.startsWith(pattern.slice(0, -1));
  return pattern === modelId;
}

export function enforcePlanRequest(plan: UsagePlan, modelId: string, estimatedCostUsd: number) {
  if (plan.modelAllowlist?.length && !plan.modelAllowlist.some((pattern) => patternMatches(pattern, modelId))) {
    throw new AppError(403, "model_not_allowed_by_plan", "Model is not allowed by this account's usage plan");
  }
  if (plan.maxRequestCostUsd !== null && estimatedCostUsd > plan.maxRequestCostUsd + Number.EPSILON) {
    throw new AppError(
      402,
      "request_cost_limit_exceeded",
      `Estimated request cost exceeds the ${plan.name} plan limit of $${plan.maxRequestCostUsd.toFixed(6)}`
    );
  }
}

export async function reserveDailyBudget(db: DbPool, accountId: string, dailyBudgetUsd: number | null, estimatedCostUsd: number) {
  if (dailyBudgetUsd === null || estimatedCostUsd <= 0) return 0;
  const amount = Number(estimatedCostUsd.toFixed(6));
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `
        INSERT INTO billing.account_daily_budget_usage (account_id, usage_date)
        VALUES ($1, (now() AT TIME ZONE 'UTC')::date)
        ON CONFLICT (account_id, usage_date) DO NOTHING
      `,
      [accountId]
    );
    const result = await client.query<{ spent_usd: string; reserved_usd: string }>(
      `
        SELECT spent_usd, reserved_usd
        FROM billing.account_daily_budget_usage
        WHERE account_id = $1 AND usage_date = (now() AT TIME ZONE 'UTC')::date
        FOR UPDATE
      `,
      [accountId]
    );
    const used = Number(result.rows[0]?.spent_usd ?? 0) + Number(result.rows[0]?.reserved_usd ?? 0);
    if (used + amount > dailyBudgetUsd + Number.EPSILON) {
      await client.query("ROLLBACK");
      throw new AppError(402, "daily_budget_exhausted", `Daily usage budget exhausted for the ${dailyBudgetUsd.toFixed(2)} USD plan limit`);
    }
    await client.query(
      `
        UPDATE billing.account_daily_budget_usage
        SET reserved_usd = reserved_usd + $2, updated_at = now()
        WHERE account_id = $1 AND usage_date = (now() AT TIME ZONE 'UTC')::date
      `,
      [accountId, amount]
    );
    await client.query("COMMIT");
    return amount;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export async function reconcileDailyBudget(db: DbPool, accountId: string, reservedUsd: number, finalCostUsd: number) {
  if (reservedUsd <= 0 && finalCostUsd <= 0) return;
  await db.query(
    `
      UPDATE billing.account_daily_budget_usage
      SET reserved_usd = GREATEST(0, reserved_usd - $2),
          spent_usd = spent_usd + $3,
          updated_at = now()
      WHERE account_id = $1 AND usage_date = (now() AT TIME ZONE 'UTC')::date
    `,
    [accountId, Math.max(0, reservedUsd), Math.max(0, finalCostUsd)]
  );
}

export function publicUsagePlan(plan: UsagePlan) {
  return {
    code: plan.code,
    source: plan.source,
    name: plan.name,
    requests_per_minute: plan.requestsPerMinute,
    tokens_per_minute: plan.tokensPerMinute,
    concurrent_generations: plan.concurrentGenerations,
    daily_budget_usd: plan.dailyBudgetUsd,
    max_request_cost_usd: plan.maxRequestCostUsd,
    model_allowlist: plan.modelAllowlist
  };
}
