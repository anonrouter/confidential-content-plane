import type { DbPool } from "../db/pool.js";
import { newId } from "../ids.js";
import { AppError } from "../security/errors.js";
import { isOpaqueReceiptId } from "../inference/opaqueReceipt.js";
import type { TokenUsage } from "./tokens.js";

export interface ModelPricing {
  inputPricePerMillion: number;
  outputPricePerMillion: number;
  cacheReadPricePerMillion?: number | null;
  cacheWritePricePerMillion?: number | null;
}

export interface BalanceReservationOptions {
  apiKeyId?: string | null;
  apiKeyCreditLimitUsd?: number | null;
  /** OAuth grant bound to the hidden attribution key, revalidated under lock. */
  connectedGrantId?: string | null;
  /**
   * Funding source for this reservation. "balance" (default) reserves prepaid
   * wallet funds. "trial" reserves against the account's model-locked trial
   * entitlement instead: no wallet movement, no balance events, and the
   * entitlement's reply/prompt-token/spend counters are the admission gate.
   */
  funding?: "balance" | "trial";
  /** Durable settlement context so settle/abort need no in-flight state. */
  context?: {
    providerId: string;
    modelId: string;
    inputPricePerMillion: number;
    outputPricePerMillion: number;
    cacheReadPricePerMillion?: number | null;
    cacheWritePricePerMillion?: number | null;
    dailyReservedUsd: number;
    estInputTokens: number;
    estOutputTokens: number;
    operation?: "chat" | "embeddings" | "image" | "speech";
  };
}

export interface BalanceSettlement {
  chargedUsd: number;
  providerCostUsd: number;
  overageUsd: number;
}

/** Highest valid per-token prompt rate that a provider usage report can apply. */
export function maximumPromptPricePerMillion(pricing: ModelPricing): number {
  const optionalPrices = [
    pricing.cacheReadPricePerMillion,
    pricing.cacheWritePricePerMillion
  ].filter((value): value is number =>
    value !== null && value !== undefined && Number.isFinite(value) && value >= 0
  );
  return Math.max(pricing.inputPricePerMillion, ...optionalPrices);
}

function moneyUsd(value: number) {
  if (!Number.isFinite(value)) throw new Error("Billing amount must be finite");
  return Number(Math.max(0, value).toFixed(6));
}

export function calculateCostUsd(usage: TokenUsage, pricing: ModelPricing) {
  // OpenAI-style usage reports cache reads and cache creation as disjoint
  // subsets of prompt_tokens. Clamp malformed totals to the input-token count,
  // assigning cache writes first because their published rate may exceed normal
  // input. Missing cache prices fall back to the ordinary input price.
  const inputTokens = Math.max(0, usage.inputTokens);
  const cacheWriteTokens = Math.min(inputTokens, Math.max(0, usage.cacheWriteTokens ?? 0));
  const cachedTokens = Math.min(
    inputTokens - cacheWriteTokens,
    Math.max(0, usage.cachedTokens)
  );
  const uncachedInputTokens = inputTokens - cacheWriteTokens - cachedTokens;
  const priceOrInput = (value: number | null | undefined) =>
    value !== null && value !== undefined && Number.isFinite(value) && value >= 0
      ? value
      : pricing.inputPricePerMillion;
  const cacheReadPrice = priceOrInput(pricing.cacheReadPricePerMillion);
  const cacheWritePrice = priceOrInput(pricing.cacheWritePricePerMillion);
  const inputCost =
    (uncachedInputTokens * pricing.inputPricePerMillion) / 1_000_000
    + (cachedTokens * cacheReadPrice) / 1_000_000
    + (cacheWriteTokens * cacheWritePrice) / 1_000_000;
  const outputCost = (usage.outputTokens * pricing.outputPricePerMillion) / 1_000_000;
  return Number((inputCost + outputCost).toFixed(6));
}

export async function ensureBalanceRow(db: DbPool, accountId: string) {
  await db.query(
    `
      INSERT INTO billing.balances (account_id, available_usd, reserved_usd)
      VALUES ($1, 0, 0)
      ON CONFLICT (account_id) DO NOTHING
    `,
    [accountId]
  );
}

/**
 * Cheap preflight for work that must happen before the selected model and its
 * maximum reservation are known (currently automatic-routing classification).
 * This is not an authorization or a reservation: reserveBalance remains the
 * authoritative, atomic billing gate once model pricing is available.
 */
export async function assertPositiveAvailableBalance(db: DbPool, accountId: string) {
  const result = await db.query<{ funded: boolean }>(
    `SELECT available_usd > 0 AS funded
       FROM billing.balances
      WHERE account_id = $1`,
    [accountId]
  );
  if (result.rows[0]?.funded !== true) {
    throw new AppError(402, "insufficient_balance", "Insufficient balance");
  }
}

export async function creditBalance(db: DbPool, accountId: string, amountUsd: number, type: "credit" | "adjustment" = "credit") {
  if (amountUsd <= 0) {
    await ensureBalanceRow(db, accountId);
    return;
  }

  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `
        INSERT INTO billing.balances (account_id, available_usd, reserved_usd)
        VALUES ($1, $2, 0)
        ON CONFLICT (account_id)
        DO UPDATE SET available_usd = billing.balances.available_usd + EXCLUDED.available_usd,
          updated_at = now()
      `,
      [accountId, amountUsd]
    );
    await client.query(
      `
        INSERT INTO billing.balance_events (id, account_id, type, amount_usd)
        VALUES ($1, $2, $3, $4)
      `,
      [newId("bev"), accountId, type, amountUsd]
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Repoint a still-reserved inference reservation at the provider route that a
 * transparent fallback selected. The reserved amount is NOT changed: it already
 * covers the plan's worst-case attempt, so settlement (Math.min(cost, reserved))
 * remains bounded and any difference is released. Only the durable settlement
 * context (serving provider/model + prices + estimated tokens) moves so the final
 * charge and metering event attribute to the ACTUAL serving route. A no-op unless
 * the reservation is still 'reserved'.
 */
export async function updateInferenceReservationRoute(
  db: DbPool,
  requestId: string,
  route: {
    providerId: string;
    modelId: string;
    inputPricePerMillion: number;
    outputPricePerMillion: number;
    cacheReadPricePerMillion?: number | null;
    cacheWritePricePerMillion?: number | null;
    estInputTokens: number;
    estOutputTokens: number;
  }
): Promise<boolean> {
  const result = await db.query(
    `UPDATE billing.inference_reservations
        SET provider_id = $2,
            model_id = $3,
            input_price_per_million = $4,
            output_price_per_million = $5,
            cache_read_price_per_million = $6,
            cache_write_price_per_million = $7,
            est_input_tokens = $8,
            est_output_tokens = $9
      WHERE request_id = $1 AND status = 'reserved'`,
    [
      requestId,
      route.providerId,
      route.modelId,
      route.inputPricePerMillion,
      route.outputPricePerMillion,
      route.cacheReadPricePerMillion ?? null,
      route.cacheWritePricePerMillion ?? null,
      route.estInputTokens,
      route.estOutputTokens
    ]
  );
  return (result.rowCount ?? 0) > 0;
}

/** Settled spend attributed to one API key, from the metering ledger. */
export async function apiKeySpentUsd(db: DbPool, apiKeyId: string) {
  const result = await db.query<{ spent_usd: string | null }>(
    `
      SELECT SUM(cost_usd) AS spent_usd
      FROM metering.usage_events
      WHERE api_key_id = $1
        AND status = 'succeeded'
    `,
    [apiKeyId]
  );
  const raw = result.rows[0]?.spent_usd;
  return raw === null || raw === undefined ? 0 : Number(raw);
}

export async function reserveBalance(
  db: DbPool,
  accountId: string,
  amountUsd: number,
  requestId: string,
  options: BalanceReservationOptions = {}
) {
  await ensureBalanceRow(db, accountId);
  // Zero-cost (free/priced-0) requests still create a durable reservation row so
  // settlement and the metadata-only usage event have a single source of truth.
  let amount = moneyUsd(amountUsd);
  const funding = options.funding ?? "balance";

  const client = await db.connect();
  try {
    await client.query("BEGIN");

    const result = await client.query<{ available_usd: string }>(
      "SELECT available_usd FROM billing.balances WHERE account_id = $1 FOR UPDATE",
      [accountId]
    );
    const existing = await client.query<{
      account_id: string;
      api_key_id: string | null;
      reserved_usd: string;
      status: "reserved" | "settled" | "released";
    }>(
      `SELECT account_id, api_key_id, reserved_usd, status FROM billing.inference_reservations WHERE request_id = $1`,
      [requestId]
    );
    if (existing.rows[0]) {
      if (existing.rows[0].account_id !== accountId || (existing.rows[0].api_key_id ?? null) !== (options.apiKeyId ?? null)) {
        throw new Error("Inference reservation id was reused for different billing credentials");
      }
      if (existing.rows[0].status !== "reserved") {
        throw new AppError(409, "request_already_finalized", "Inference request was already finalized");
      }
      await client.query("COMMIT");
      return Number(existing.rows[0].reserved_usd);
    }
    if (funding === "trial") {
      // Trial funding: the entitlement's counters are the admission gate; the
      // wallet is untouched. The row lock serializes concurrent trial sends
      // (the control plane additionally holds account concurrency at 1).
      const entitlement = await client.query<{
        replies_total: number;
        replies_used: number;
        input_token_budget: number;
        input_tokens_used: number;
        spend_ceiling_usd: string;
        spend_used_usd: string;
        reserved_usd: string;
        expires_at: string;
      }>(
        `
          SELECT replies_total, replies_used, input_token_budget, input_tokens_used,
                 spend_ceiling_usd, spend_used_usd, reserved_usd, expires_at
          FROM billing.trial_entitlements
          WHERE account_id = $1
          FOR UPDATE
        `,
        [accountId]
      );
      const trialRow = entitlement.rows[0];
      if (!trialRow) {
        throw new AppError(402, "trial_not_available", "No trial entitlement is available for this account");
      }
      if (new Date(trialRow.expires_at).getTime() <= Date.now()) {
        throw new AppError(402, "trial_expired", "The trial period has ended");
      }
      if (trialRow.replies_used >= trialRow.replies_total) {
        throw new AppError(402, "trial_exhausted", "All trial responses have been used");
      }
      const estInputTokens = options.context?.estInputTokens ?? 0;
      if (trialRow.input_tokens_used + estInputTokens > trialRow.input_token_budget) {
        throw new AppError(402, "trial_exhausted", "The trial conversation has reached its size limit");
      }
      const remainingUsd = moneyUsd(
        Number(trialRow.spend_ceiling_usd) - Number(trialRow.spend_used_usd) - Number(trialRow.reserved_usd)
      );
      if (remainingUsd <= 0) {
        throw new AppError(402, "trial_exhausted", "The trial spending allowance has been used");
      }
      // Clamp the worst-case reservation to what the ceiling can still fund;
      // settlement charges at most the reserved amount, so the ceiling is hard.
      amount = Math.min(amount, remainingUsd);
      await client.query(
        `
          UPDATE billing.trial_entitlements
          SET reserved_usd = reserved_usd + $2
          WHERE account_id = $1
        `,
        [accountId, amount]
      );
    } else {
      const available = Number(result.rows[0]?.available_usd ?? 0);
      if (amount > 0 && available < amount) {
        throw new AppError(402, "insufficient_balance", "Insufficient balance");
      }
    }

    const apiKeyId = options.apiKeyId ?? null;
    let apiKeyLimit = options.apiKeyCreditLimitUsd;
    if (options.connectedGrantId) {
      if (!apiKeyId) throw new Error("Connected grant is missing its attribution key");
      const connected = await client.query<{ lifetime_cap_usd: string | null }>(
        `
          SELECT g.lifetime_cap_usd
          FROM auth.connected_app_grants g
          JOIN auth.connected_app_clients c ON c.id = g.client_id
          JOIN auth.accounts a ON a.id = g.account_id
          JOIN auth.workspaces w ON w.id = g.workspace_id
          JOIN auth.api_keys k ON k.id = g.api_key_id
          WHERE g.id = $1 AND g.account_id = $2 AND g.api_key_id = $3
            AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > now())
            AND c.status = 'enabled' AND a.status = 'active'
            AND w.deleted_at IS NULL
            AND k.revoked_at IS NULL AND k.credential_kind = 'connected_app'
          FOR UPDATE OF g, c, a, w, k
        `,
        [options.connectedGrantId, accountId, apiKeyId]
      );
      const activeGrant = connected.rows[0];
      if (!activeGrant) {
        throw new AppError(401, "connected_grant_inactive", "Connected-app authorization is no longer active");
      }
      // A null cap means the app is uncapped; leave enforcement to the balance
      // check above. Number(null) would be 0, which would wrongly reject spend.
      apiKeyLimit = activeGrant.lifetime_cap_usd === null ? null : Number(activeGrant.lifetime_cap_usd);
    }
    if (amount > 0 && apiKeyId && apiKeyLimit !== null && apiKeyLimit !== undefined) {
      // Definer function: takes the row lock and reports only whether the key
        // exists for this account. The lock is held by THIS transaction, so the
        // serialisation is unchanged, and the bridge-facing role needs no
        // privilege on auth.api_keys. The account check is preserved: it is what
        // refuses a key that does not belong to the spending account.
        const key = await client.query<{ lock_api_key: boolean }>(
          "SELECT security.lock_api_key($1, $2)",
          [apiKeyId, accountId]
        );
        if (!key.rows[0]?.lock_api_key) throw new Error("API key disappeared while reserving inference funds");

      const usage = await client.query<{ committed_usd: string; unsettled_usd: string }>(
        `
          SELECT
            COALESCE((
              SELECT SUM(cost_usd)
              FROM metering.usage_events
              WHERE api_key_id = $1 AND status = 'succeeded'
            ), 0) AS committed_usd,
            COALESCE((
              SELECT SUM(CASE WHEN r.status = 'reserved' THEN r.reserved_usd ELSE r.charged_usd END)
              FROM billing.inference_reservations r
              WHERE r.api_key_id = $1
                AND (
                  r.status = 'reserved'
                  OR (
                    r.status = 'settled'
                    AND NOT EXISTS (
                      SELECT 1 FROM metering.usage_events u WHERE u.request_id = r.request_id
                    )
                  )
                )
            ), 0) AS unsettled_usd
        `,
        [apiKeyId]
      );
      const alreadyAuthorized = Number(usage.rows[0]?.committed_usd ?? 0) + Number(usage.rows[0]?.unsettled_usd ?? 0);
      if (alreadyAuthorized + amount > moneyUsd(apiKeyLimit)) {
        throw new AppError(
          402,
          options.connectedGrantId ? "connected_grant_cap_exceeded" : "api_key_credit_limit_exceeded",
          options.connectedGrantId
            ? `Connected-app spending cap reached ($${alreadyAuthorized.toFixed(6)} authorized of $${moneyUsd(apiKeyLimit).toFixed(6)} limit)`
            : `API key credit limit reached ($${alreadyAuthorized.toFixed(6)} authorized of $${moneyUsd(apiKeyLimit).toFixed(6)} limit)`
        );
      }
    }

    const context = options.context;
    await client.query(
      `
        INSERT INTO billing.inference_reservations (
          request_id, account_id, api_key_id, reserved_usd,
          provider_id, model_id, input_price_per_million, output_price_per_million,
          cache_read_price_per_million, cache_write_price_per_million,
          daily_reserved_usd, est_input_tokens, est_output_tokens, operation,
          funding_source
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      `,
      [
        requestId,
        accountId,
        apiKeyId,
        amount,
        context?.providerId ?? null,
        context?.modelId ?? null,
        context?.inputPricePerMillion ?? 0,
        context?.outputPricePerMillion ?? 0,
        context?.cacheReadPricePerMillion ?? null,
        context?.cacheWritePricePerMillion ?? null,
        context?.dailyReservedUsd ?? 0,
        context?.estInputTokens ?? 0,
        context?.estOutputTokens ?? 0,
        context?.operation ?? "chat",
        funding
      ]
    );

    if (amount > 0 && funding === "balance") {
      await client.query(
        `
          UPDATE billing.balances
          SET available_usd = available_usd - $2,
              reserved_usd = reserved_usd + $2,
              updated_at = now()
          WHERE account_id = $1
        `,
        [accountId, amount]
      );
      await client.query(
        `
          INSERT INTO billing.balance_events (id, account_id, type, amount_usd, request_id)
          VALUES ($1, $2, 'reserve', $3, $4)
        `,
        [newId("bev"), accountId, amount, requestId]
      );
    }
    await client.query("COMMIT");
    return amount;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // Ignore rollback failures; the original error is more useful.
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function reconcileReservedBalance(
  db: DbPool,
  accountId: string,
  reservedUsd: number,
  finalCostUsd: number,
  requestId: string
) {
  const expectedReservation = moneyUsd(reservedUsd);
  const providerCostUsd = moneyUsd(finalCostUsd);

  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const reservationResult = await client.query<{
      account_id: string;
      api_key_id: string | null;
      reserved_usd: string;
      charged_usd: string;
      status: "reserved" | "settled" | "released";
    }>(
      `SELECT account_id, api_key_id, reserved_usd, charged_usd, status
       FROM billing.inference_reservations
       WHERE request_id = $1
       FOR UPDATE`,
      [requestId]
    );
    const reservation = reservationResult.rows[0];
    if (!reservation) {
      if (expectedReservation <= 0 && providerCostUsd <= 0) {
        await client.query("COMMIT");
        return { chargedUsd: 0, providerCostUsd: 0, overageUsd: 0 } satisfies BalanceSettlement;
      }
      throw new Error("Inference settlement has no durable reservation");
    }
    if (reservation.account_id !== accountId) throw new Error("Inference settlement account mismatch");

    const releaseUsd = Number(reservation.reserved_usd);
    if (expectedReservation > 0 && Math.abs(releaseUsd - expectedReservation) >= 0.000001) {
      throw new Error("Inference settlement amount does not match its durable reservation");
    }
    if (reservation.status !== "reserved") {
      const chargedUsd = Number(reservation.charged_usd);
      await client.query("COMMIT");
      return {
        chargedUsd,
        providerCostUsd,
        overageUsd: moneyUsd(Math.max(0, providerCostUsd - chargedUsd))
      } satisfies BalanceSettlement;
    }

    await client.query("SELECT available_usd FROM billing.balances WHERE account_id = $1 FOR UPDATE", [accountId]);
    if (reservation.api_key_id) {
      // Definer function: the lock, not the row. Held by THIS transaction.
      await client.query("SELECT security.lock_api_key($1, NULL)", [reservation.api_key_id]);
    }

    // Prepaid inference is a hard ceiling: capture no more than was authorized.
    // Any provider-side estimation discrepancy is tracked as platform overage;
    // it never creates customer debt.
    const chargeUsd = Math.min(providerCostUsd, releaseUsd);
    const availableDelta = moneyUsd(releaseUsd - chargeUsd);
    await client.query(
      `
        UPDATE billing.balances
        SET reserved_usd = reserved_usd - $2,
            available_usd = available_usd + $3,
            updated_at = now()
        WHERE account_id = $1
      `,
      [accountId, releaseUsd, availableDelta]
    );

    if (releaseUsd > 0) {
      await client.query(
        `
          INSERT INTO billing.balance_events (id, account_id, type, amount_usd, request_id)
          VALUES ($1, $2, 'release', $3, $4)
        `,
        [newId("bev"), accountId, releaseUsd, requestId]
      );
    }

    if (chargeUsd > 0) {
      await client.query(
        `
          INSERT INTO billing.balance_events (id, account_id, type, amount_usd, request_id)
          VALUES ($1, $2, 'charge', $3, $4)
        `,
        [newId("bev"), accountId, -chargeUsd, requestId]
      );
    }

    await client.query(
      `
        UPDATE billing.inference_reservations
        SET charged_usd = $2,
            status = $3,
            finalized_at = now()
        WHERE request_id = $1
      `,
      [requestId, chargeUsd, chargeUsd > 0 ? "settled" : "released"]
    );

    await client.query("COMMIT");
    return {
      chargedUsd: chargeUsd,
      providerCostUsd,
      overageUsd: moneyUsd(Math.max(0, providerCostUsd - chargeUsd))
    } satisfies BalanceSettlement;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

interface ReservationRow {
  account_id: string;
  api_key_id: string | null;
  reserved_usd: string;
  charged_usd: string;
  status: "reserved" | "settled" | "released";
  provider_id: string | null;
  model_id: string | null;
  input_price_per_million: string;
  output_price_per_million: string;
  cache_read_price_per_million: string | null;
  cache_write_price_per_million: string | null;
  daily_reserved_usd: string;
  est_input_tokens: number;
  est_output_tokens: number;
  delivery_started_at: string | null;
  provider_attempt_started_at: string | null;
  operation: "chat" | "embeddings" | "image" | "speech";
  funding_source: "balance" | "trial";
}

/**
 * Durably fence the moment immediately before the credential worker can send
 * an inference request upstream. This is distinct from response delivery:
 * provider billing may begin even when no response byte reaches the caller.
 */
export async function markInferenceProviderAttemptStarted(
  db: DbPool,
  requestId: string,
  runtimeProviderDisabled?: (providerName: string) => Promise<boolean>
) {
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    // The provider row is the serialization point shared with the emergency
    // operator action. If disable wins the lock, this dispatch observes it and
    // fails. If this fence wins first, the request is already classified as an
    // in-flight provider attempt before disable can commit.
    const existing = await client.query<{
      status: "reserved" | "settled" | "released";
      provider_attempt_started_at: string | null;
      provider_id: string;
    }>(
      `SELECT r.status, r.provider_attempt_started_at, p.id AS provider_id
         FROM billing.inference_reservations r
         JOIN providers.models m ON m.id = r.model_id
         JOIN providers.providers p ON p.id = m.provider_id
        WHERE r.request_id = $1
        FOR SHARE OF p`,
      [requestId]
    );
    const row = existing.rows[0];
    if (!row) {
      throw new AppError(409, "reservation_not_found", "Inference reservation is not available for provider dispatch");
    }

    // This MUST be a second READ COMMITTED statement. If the first statement
    // waited behind emergency disable's provider lock, its original statement
    // snapshot predates the newly committed emergency row. A fresh statement
    // after acquiring the shared lock observes the winning mutation.
    const providerState = await client.query<{
      provider_status: string;
      provider_name: string;
      emergency_disabled: boolean;
    }>(
      `SELECT p.status AS provider_status,
              p.name AS provider_name,
              COALESCE(pec.disabled, false) AS emergency_disabled
         FROM providers.providers p
         LEFT JOIN providers.provider_emergency_controls pec ON pec.provider_id = p.id
        WHERE p.id = $1`,
      [row.provider_id]
    );
    const provider = providerState.rows[0];
    if (
      !provider
      || provider.provider_status !== "active"
      || provider.emergency_disabled
      || (runtimeProviderDisabled && await runtimeProviderDisabled(provider.provider_name))
    ) {
      throw new AppError(503, "provider_unavailable", "Provider is temporarily unavailable");
    }
    if (row.status !== "reserved") {
      if (row.provider_attempt_started_at) {
        await client.query("COMMIT");
        return row.provider_attempt_started_at;
      }
      throw new AppError(409, "request_already_finalized", "Inference request was already finalized");
    }
    const updated = await client.query<{ provider_attempt_started_at: string }>(
      `UPDATE billing.inference_reservations
          SET provider_attempt_started_at = COALESCE(provider_attempt_started_at, now())
        WHERE request_id = $1 AND status = 'reserved'
        RETURNING provider_attempt_started_at`,
      [requestId]
    );
    if (!updated.rows[0]) {
      throw new AppError(409, "request_already_finalized", "Inference request was already finalized");
    }
    await client.query("COMMIT");
    return updated.rows[0].provider_attempt_started_at;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Durably fence a streamed response immediately before the relay writes its
 * first byte to the caller. From this point onward an abort/stale sweep must
 * never release the request for zero: measured usage is preferred, otherwise
 * the authorized ceiling is captured conservatively.
 */
export async function markInferenceDeliveryStarted(db: DbPool, requestId: string) {
  const updated = await db.query<{ delivery_started_at: string }>(
    `UPDATE billing.inference_reservations
     SET provider_attempt_started_at = COALESCE(provider_attempt_started_at, now()),
         delivery_started_at = COALESCE(delivery_started_at, now())
     WHERE request_id = $1 AND status = 'reserved'
     RETURNING delivery_started_at`,
    [requestId]
  );
  if (updated.rows[0]) return updated.rows[0].delivery_started_at;

  const existing = await db.query<{ status: "reserved" | "settled" | "released"; delivery_started_at: string | null }>(
    `SELECT status, delivery_started_at FROM billing.inference_reservations WHERE request_id = $1`,
    [requestId]
  );
  if (!existing.rows[0]) {
    throw new AppError(409, "reservation_not_found", "Inference reservation is not available for delivery");
  }
  if (existing.rows[0].delivery_started_at) return existing.rows[0].delivery_started_at;
  throw new AppError(409, "request_already_finalized", "Inference request was already finalized");
}

async function insertUsageEventTx(
  client: import("pg").PoolClient,
  params: {
    requestId: string;
    row: ReservationRow;
    usage: TokenUsage;
    costUsd: number;
    providerCostUsd: number;
    status: string;
    firstTokenLatencyMs?: number;
    latencyMs: number;
  }
) {
  await client.query(
    `
      INSERT INTO metering.usage_events (
        id, account_id, request_id, provider_id, model_id, api_key_id,
        operation, input_tokens, output_tokens, cached_tokens, cache_write_tokens,
        cost_usd, provider_cost_usd, status, first_token_latency_ms, latency_ms
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
      ON CONFLICT (request_id) DO NOTHING
    `,
    [
      newId("use"),
      params.row.account_id,
      params.requestId,
      params.row.provider_id,
      params.row.model_id,
      params.row.api_key_id,
      params.row.operation,
      params.usage.inputTokens,
      params.usage.outputTokens,
      params.usage.cachedTokens,
      params.usage.cacheWriteTokens ?? 0,
      params.costUsd,
      params.providerCostUsd,
      params.status,
      params.firstTokenLatencyMs ?? null,
      params.latencyMs
    ]
  );
}

/**
 * Record that a provider receipt exists for a settlement.
 *
 * This is the whole cross-boundary commitment now. The row holds an opaque
 * 128-bit identifier minted in the content plane and the request it settles:
 * no hash, no provider, no model, no route. `billing.settlement_receipts` has
 * no column that could hold a hash, which is what makes "the control plane
 * cannot persist an exact content hash" a schema property rather than a
 * promise about application code.
 *
 * ONE TABLE, AND IT IS THIS ONE. Migration 096 created
 * `billing.settlement_receipts` and migration 098 created
 * `providers.settlement_receipts` for the same purpose, on two branches that
 * could not see each other. Both tables still exist because dropping a table
 * the other plane already applied is a separate, deliberate migration; only
 * this one is written or read, and it is the one that can verify a receipt
 * belongs to a real reservation, because it lives beside
 * `billing.inference_reservations`.
 *
 * NON-FATAL BUT NOT SILENT, AND NOT UNCONDITIONAL. Failing a paid settlement
 * because a transparency row would not write is the wrong trade, so this
 * returns a boolean the caller (which has a logger, unlike this module) reports.
 * It returns false rather than true for the three cases that matter:
 *
 *   - the value is not a well-formed opaque receipt. Defence in depth against a
 *     compromised content plane: the route schema pins the shape and the column
 *     CHECK pins it again, but a caller reaching this function directly must not
 *     be able to store a digest, so a bad value is never written at all;
 *   - no reservation exists for the request id, so there is nothing to settle;
 *   - a DIFFERENT receipt was already recorded for this settlement, which is a
 *     second receipt for one generation and must not quietly overwrite the first.
 *
 * The previous implementation returned true for all three and swallowed every
 * error, so the boolean it returned could not distinguish "recorded" from
 * "silently discarded".
 */
export async function recordSettlementReceipt(
  db: DbPool,
  requestId: string,
  opaqueReceiptId: string
): Promise<boolean> {
  if (!isOpaqueReceiptId(opaqueReceiptId)) return false;
  try {
    const persisted = await db.query(
      `
        INSERT INTO billing.settlement_receipts (request_id, opaque_receipt_id, expires_at)
        SELECT r.request_id, $2, now() + interval '15 minutes'
        FROM billing.inference_reservations r
        WHERE r.request_id = $1
        ON CONFLICT (request_id) DO UPDATE
        SET expires_at = GREATEST(billing.settlement_receipts.expires_at, EXCLUDED.expires_at)
        WHERE billing.settlement_receipts.opaque_receipt_id = EXCLUDED.opaque_receipt_id
        RETURNING request_id
      `,
      [requestId, opaqueReceiptId]
    );
    return (persisted.rowCount ?? 0) === 1;
  } catch {
    return false;
  }
}

/**
 * Settle or abort a reservation in ONE atomic transaction that also reconciles
 * the daily budget and records the metadata-only usage event. Crash-safe and
 * idempotent: a crash before COMMIT rolls everything back (the reservation stays
 * 'reserved' — never released, never free); a second call after a completed
 * settle is a no-op. All context comes from the durable reservation row, so no
 * in-flight process/Redis state is required.
 */
export async function finalizeInferenceReservation(
  db: DbPool,
  params: {
    requestId: string;
    outcome: "settle" | "abort" | "capture";
    usage?: TokenUsage;
    /** Terminal status for the usage event on abort (a valid usage status). */
    abortStatus?: "failed" | "rate_limited" | "insufficient_balance";
    /** Abort only: the relay attests the provider rejected the request before
     *  any delivery, so a fenced reservation may release at zero. */
    providerRejected?: boolean;
    /** Null/omitted when no streamed output chunk was observed. */
    firstTokenLatencyMs?: number;
    latencyMs?: number;
    /** False for pre-provider admission compensation to avoid rejection DB amplification. */
    recordUsage?: boolean;
  }
): Promise<BalanceSettlement> {
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const reservationResult = await client.query<ReservationRow>(
      `SELECT account_id, api_key_id, reserved_usd, charged_usd, status,
              provider_id, model_id, input_price_per_million, output_price_per_million,
              cache_read_price_per_million, cache_write_price_per_million,
              daily_reserved_usd, est_input_tokens, est_output_tokens,
              delivery_started_at, provider_attempt_started_at, operation,
              funding_source
       FROM billing.inference_reservations WHERE request_id = $1 FOR UPDATE`,
      [params.requestId]
    );
    const row = reservationResult.rows[0];
    if (!row) {
      await client.query("COMMIT");
      return { chargedUsd: 0, providerCostUsd: 0, overageUsd: 0 };
    }
    const reserved = Number(row.reserved_usd);
    // An abort converts to a conservative ceiling capture when output already
    // started flowing to the caller (a delivered stream never releases for
    // zero) or when the provider-attempt fence committed WITHOUT the relay
    // attesting a provider-side rejection. The attested case (providerRejected:
    // an upstream HTTP rejection with zero delivery) releases in full: the
    // aborting relay is the same authenticated caller trusted to report
    // measured usage on settle. A fenced abort without that attestation (e.g.
    // a client disconnect after dispatch) still captures, so disconnecting
    // early never yields free provider work. Crash paths keep the fence's
    // conservatism: the stale sweeper finalizes with outcome "capture".
    const captureAuthorizedCeiling = params.outcome === "capture"
      || (params.outcome === "abort"
        && (row.delivery_started_at !== null
          || (row.provider_attempt_started_at !== null && params.providerRejected !== true)));
    const providerCostUsd = params.usage
      ? calculateCostUsd(params.usage, {
          inputPricePerMillion: Number(row.input_price_per_million),
          outputPricePerMillion: Number(row.output_price_per_million),
          cacheReadPricePerMillion: row.cache_read_price_per_million === null
            ? null
            : Number(row.cache_read_price_per_million),
          cacheWritePricePerMillion: row.cache_write_price_per_million === null
            ? null
            : Number(row.cache_write_price_per_million)
        })
      : captureAuthorizedCeiling
        ? reserved
        : 0;
    if (row.status !== "reserved") {
      // Idempotent: already finalized. Do not re-charge or re-release.
      await client.query("COMMIT");
      const chargedUsd = Number(row.charged_usd);
      return { chargedUsd, providerCostUsd, overageUsd: moneyUsd(Math.max(0, providerCostUsd - chargedUsd)) };
    }

    const charge = captureAuthorizedCeiling
      ? reserved
      : params.outcome === "settle"
        ? Math.min(providerCostUsd, reserved)
        : 0;
    const usage: TokenUsage = params.usage ?? {
      inputTokens: row.est_input_tokens,
      outputTokens: row.est_output_tokens,
      cachedTokens: 0,
      cacheWriteTokens: 0
    };
    const latencyMs = params.latencyMs ?? 0;

    const trialFunded = row.funding_source === "trial";
    if (trialFunded) {
      // Trial settlement moves no wallet money: release the entitlement's
      // in-flight reservation, charge its spend counter, accumulate the actual
      // prompt tokens, and count a reply only for delivered (billable) work so
      // provider-side failures never consume one of the trial's responses.
      const succeeded = params.outcome === "settle" || captureAuthorizedCeiling;
      await client.query(
        `
          UPDATE billing.trial_entitlements
          SET reserved_usd = GREATEST(0, reserved_usd - $2),
              spend_used_usd = spend_used_usd + $3,
              input_tokens_used = input_tokens_used + $4,
              replies_used = LEAST(replies_total, replies_used + $5)
          WHERE account_id = $1
        `,
        [
          row.account_id,
          reserved,
          charge,
          succeeded ? Math.max(0, usage.inputTokens) : 0,
          succeeded ? 1 : 0
        ]
      );
    } else {
      await client.query("SELECT available_usd FROM billing.balances WHERE account_id = $1 FOR UPDATE", [row.account_id]);
      if (row.api_key_id) {
        await client.query("SELECT security.lock_api_key($1, NULL)", [row.api_key_id]);
      }
      const availableDelta = moneyUsd(reserved - charge);
      await client.query(
        `UPDATE billing.balances SET reserved_usd = reserved_usd - $2, available_usd = available_usd + $3, updated_at = now()
         WHERE account_id = $1`,
        [row.account_id, reserved, availableDelta]
      );
    }

    const dailyReserved = Number(row.daily_reserved_usd);
    if (dailyReserved > 0 || charge > 0) {
      await client.query(
        `UPDATE billing.account_daily_budget_usage
         SET reserved_usd = GREATEST(0, reserved_usd - $2), spent_usd = spent_usd + $3, updated_at = now()
         WHERE account_id = $1 AND usage_date = (now() AT TIME ZONE 'UTC')::date`,
        [row.account_id, Math.max(0, dailyReserved), Math.max(0, charge)]
      );
    }

    if (reserved > 0 && !trialFunded) {
      await client.query(
        `INSERT INTO billing.balance_events (id, account_id, type, amount_usd, request_id) VALUES ($1, $2, 'release', $3, $4)`,
        [newId("bev"), row.account_id, reserved, params.requestId]
      );
    }
    if (charge > 0 && !trialFunded) {
      await client.query(
        `INSERT INTO billing.balance_events (id, account_id, type, amount_usd, request_id) VALUES ($1, $2, 'charge', $3, $4)`,
        [newId("bev"), row.account_id, -charge, params.requestId]
      );
    }

    await client.query(
      `UPDATE billing.inference_reservations
       SET charged_usd = $2, status = $3, latency_ms = $4,
           first_token_latency_ms = $5, finalized_at = now()
       WHERE request_id = $1`,
      [params.requestId, charge, charge > 0 ? "settled" : "released", latencyMs, params.firstTokenLatencyMs ?? null]
    );

    if (params.recordUsage !== false) {
      await insertUsageEventTx(client, {
        requestId: params.requestId,
        row,
        usage,
        // Trial-funded work charges no wallet: keep revenue-side accounting at
        // zero while provider_cost_usd still records the real upstream cost.
        costUsd: trialFunded ? 0 : charge,
        providerCostUsd,
        // Captured ceilings are billable delivered work. Recording them as
        // succeeded is also required for API-key spend limits to include them.
        status: params.outcome === "settle" || captureAuthorizedCeiling ? "succeeded" : params.abortStatus ?? "failed",
        firstTokenLatencyMs: params.firstTokenLatencyMs,
        latencyMs
      });
    }

    await client.query("COMMIT");
    return { chargedUsd: charge, providerCostUsd, overageUsd: moneyUsd(Math.max(0, providerCostUsd - charge)) };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

/** Release holds whose provider request has exceeded the hard request timeout.
 * The row lock makes this safe against a settlement racing the sweep. */
export async function releaseStaleBalanceReservations(db: DbPool, olderThanMinutes = 15) {
  const stale = await db.query<{
    request_id: string;
    account_id: string;
    reserved_usd: string;
    provider_id: string | null;
    model_id: string | null;
    delivery_started_at: string | null;
    provider_attempt_started_at: string | null;
  }>(
    `
      SELECT request_id, account_id, reserved_usd, provider_id, model_id,
             delivery_started_at, provider_attempt_started_at
      FROM billing.inference_reservations
      WHERE status = 'reserved'
        AND created_at < now() - ($1::text || ' minutes')::interval
      ORDER BY created_at
      LIMIT 100
    `,
    [Math.max(1, Math.floor(olderThanMinutes))]
  );
  let released = 0;
  for (const row of stale.rows) {
    const result = await finalizeInferenceReservation(db, {
      requestId: row.request_id,
      outcome: row.provider_attempt_started_at || row.delivery_started_at ? "capture" : "abort",
      abortStatus: "failed",
      // Connected-app cap checks may use the reservation primitive without an
      // inference model. Releasing such an abandoned hold must not fabricate a
      // metering row whose provider/model columns are necessarily null.
      recordUsage: Boolean(row.provider_id && row.model_id)
    });
    if (result.chargedUsd === 0) released += 1;
  }
  return released;
}
