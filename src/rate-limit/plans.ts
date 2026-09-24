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

/**
 * The outcome of taking a daily-budget hold: how much, and against WHICH DAY.
 *
 * The day is returned, not implied. Settlement has to release the hold against
 * the row it was written to, and every other way of working out which row that
 * was is a second guess at a fact this function already knew. See F-9 in
 * docs/TRIAL_POOL_V2_SECURITY_REVIEW.md and migration 111.
 */
export interface DailyBudgetHold {
  /** Dollars held. Zero when the plan has no daily budget or the request is free. */
  reservedUsd: number;
  /**
   * The `billing.account_daily_budget_usage.usage_date` this hold was written
   * to, as a `YYYY-MM-DD` string. Null exactly when `reservedUsd` is 0, because
   * no row was touched.
   */
  usageDate: string | null;
}

export async function reserveDailyBudget(
  db: DbPool,
  accountId: string,
  dailyBudgetUsd: number | null,
  estimatedCostUsd: number
): Promise<DailyBudgetHold> {
  if (dailyBudgetUsd === null || estimatedCostUsd <= 0) return { reservedUsd: 0, usageDate: null };
  const amount = Number(estimatedCostUsd.toFixed(6));
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    // ONE CLOCK READ, TAKEN ONCE AND REUSED.
    //
    // `now()` is fixed for a transaction, so the four statements below already
    // agreed with each other. Reading it into a variable makes that an explicit
    // fact rather than a property of PostgreSQL the next editor has to know,
    // and it is the value the caller stores on the reservation row so that
    // settlement releases against this exact day instead of re-deriving it.
    //
    // As text, not as a `date`: node-postgres parses a `date` into a JS Date at
    // LOCAL midnight, and handing that back as a parameter re-serializes it
    // through the local zone. A `YYYY-MM-DD` string has no zone to lose.
    const day = await client.query<{ usage_date: string }>(
      `SELECT to_char((now() AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD') AS usage_date`
    );
    const usageDate = day.rows[0]!.usage_date;
    await client.query(
      `
        INSERT INTO billing.account_daily_budget_usage (account_id, usage_date)
        VALUES ($1, $2::date)
        ON CONFLICT (account_id, usage_date) DO NOTHING
      `,
      [accountId, usageDate]
    );
    const result = await client.query<{ spent_usd: string; reserved_usd: string }>(
      `
        SELECT spent_usd, reserved_usd
        FROM billing.account_daily_budget_usage
        WHERE account_id = $1 AND usage_date = $2::date
        FOR UPDATE
      `,
      [accountId, usageDate]
    );
    const used = Number(result.rows[0]?.spent_usd ?? 0) + Number(result.rows[0]?.reserved_usd ?? 0);
    if (used + amount > dailyBudgetUsd + Number.EPSILON) {
      await client.query("ROLLBACK");
      throw new AppError(402, "daily_budget_exhausted", `Daily usage budget exhausted for the ${dailyBudgetUsd.toFixed(2)} USD plan limit`);
    }
    await client.query(
      `
        UPDATE billing.account_daily_budget_usage
        SET reserved_usd = reserved_usd + $3, updated_at = now()
        WHERE account_id = $1 AND usage_date = $2::date
      `,
      [accountId, usageDate, amount]
    );
    await client.query("COMMIT");
    return { reservedUsd: amount, usageDate };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Return a daily-budget hold that no reservation row will ever settle.
 *
 * `usageDate` is the day `reserveDailyBudget` reported, and it is required for
 * the same reason settlement stores it (F-9): this runs on the compensating
 * path after a failed reservation, which is exactly when a request has been
 * alive long enough to have crossed UTC midnight. Keying on the current date
 * here would leave the hold outstanding on the previous day forever.
 *
 * Null is accepted so a caller with no recorded day still returns SOMETHING
 * rather than nothing, falling back to today -- the behaviour before the day
 * was tracked, and never worse than it.
 */
export async function reconcileDailyBudget(
  db: DbPool,
  accountId: string,
  reservedUsd: number,
  finalCostUsd: number,
  usageDate?: string | null
) {
  if (reservedUsd <= 0 && finalCostUsd <= 0) return;
  await db.query(
    `
      UPDATE billing.account_daily_budget_usage
      SET reserved_usd = GREATEST(0, reserved_usd - $2),
          spent_usd = spent_usd + $3,
          updated_at = now()
      WHERE account_id = $1
        AND usage_date = COALESCE($4::date, (now() AT TIME ZONE 'UTC')::date)
    `,
    [accountId, Math.max(0, reservedUsd), Math.max(0, finalCostUsd), usageDate ?? null]
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
