// Multiple Venice inference credentials with operator-controlled routing.
//
// Key material lives ONLY where the single key lived before: in the process
// that dispatches to Venice (the venice-worker in the split topology, the api
// monolith in dev). The control plane stores just key ids, labels, and
// fingerprints (providers.venice_keys) and picks which key each dispatch uses:
// round-robin across enabled keys, so enabling exactly one key pins all
// traffic to it and disabling every key fails inference closed.
//
// The selected id travels to the credential holder through the existing
// single-use provider-dispatch fence response; the secret never moves.

import { createHash } from "node:crypto";
import type { Redis } from "ioredis";
import type { DbPool } from "../db/pool.js";
import { AppError } from "../security/errors.js";

export interface VeniceKey {
  id: string;
  label: string | null;
  key: string;
}

/** Content-free descriptor safe to publish to the control plane. */
export interface VeniceKeyManifestEntry {
  id: string;
  label: string | null;
  fingerprint: string;
}

export interface VeniceKeyControlRow {
  key_id: string;
  label: string | null;
  fingerprint: string;
  enabled: boolean;
  priority: number;
  first_seen_at: Date;
  last_seen_at: Date;
  updated_at: Date;
}

export const VENICE_DISPATCH_STRATEGIES = ["round_robin", "priority", "random"] as const;
export type VeniceDispatchStrategy = (typeof VENICE_DISPATCH_STRATEGIES)[number];

export const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export function veniceKeyFingerprint(secret: string): string {
  return createHash("sha256").update(secret).digest("hex").slice(0, 12);
}

/**
 * Parse a JSON keyset: [{"id":"primary","label":"Primary","key":"..."}].
 * Throws on duplicate/invalid ids or empty secrets so a misconfigured keyset
 * fails at boot instead of at dispatch time.
 */
export function parseVeniceKeyset(raw: string, source: string): VeniceKey[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${source} is not valid JSON`);
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error(`${source} must be a non-empty JSON array of {id, key} entries`);
  }
  const seen = new Set<string>();
  return parsed.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${source}[${index}] must be an object`);
    }
    const candidate = entry as { id?: unknown; label?: unknown; key?: unknown };
    if (typeof candidate.id !== "string" || !KEY_ID_PATTERN.test(candidate.id)) {
      throw new Error(`${source}[${index}].id must match ${KEY_ID_PATTERN}`);
    }
    if (seen.has(candidate.id)) throw new Error(`${source} contains duplicate id "${candidate.id}"`);
    seen.add(candidate.id);
    if (typeof candidate.key !== "string" || candidate.key.trim().length === 0) {
      throw new Error(`${source}[${index}].key must be a non-empty string`);
    }
    if (candidate.label !== undefined && typeof candidate.label !== "string") {
      throw new Error(`${source}[${index}].label must be a string when present`);
    }
    return { id: candidate.id, label: candidate.label?.trim() || null, key: candidate.key.trim() };
  });
}

export function veniceKeyManifest(keys: VeniceKey[]): VeniceKeyManifestEntry[] {
  return keys.map((entry) => ({ id: entry.id, label: entry.label, fingerprint: veniceKeyFingerprint(entry.key) }));
}

/**
 * Register the credential holder's current keyset descriptors. Upsert-only:
 * a key that disappears from the manifest keeps its row (its stale
 * last_seen_at makes that visible to operators) and a re-appearing key keeps
 * its operator-chosen enabled state.
 */
export async function upsertVeniceKeyManifest(
  db: DbPool,
  manifest: VeniceKeyManifestEntry[],
  deploymentId = "primary"
): Promise<void> {
  if (deploymentId !== "primary") {
    const valid = manifest.filter((entry) => KEY_ID_PATTERN.test(entry.id));
    for (const entry of valid) {
      await db.query(
        `
          INSERT INTO providers.venice_deployment_keys (deployment_id, key_id, label, fingerprint)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (deployment_id, key_id) DO UPDATE
          SET label = EXCLUDED.label,
              fingerprint = EXCLUDED.fingerprint,
              last_seen_at = now(),
              updated_at = now()
        `,
        [deploymentId, entry.id, entry.label, entry.fingerprint]
      );
    }
    // The worker manifest is authoritative for this deployment. Keeping a
    // disappeared id selectable would authorize a key the worker cannot use.
    await db.query(
      "DELETE FROM providers.venice_deployment_keys WHERE deployment_id=$1 AND NOT (key_id = ANY($2::text[]))",
      [deploymentId, valid.map((entry) => entry.id)]
    );
    return;
  }
  if (manifest.length === 0) return;
  for (const entry of manifest) {
    if (!KEY_ID_PATTERN.test(entry.id)) continue;
    await db.query(
      `
        INSERT INTO providers.venice_keys (key_id, label, fingerprint)
        VALUES ($1, $2, $3)
        ON CONFLICT (key_id) DO UPDATE
        SET label = EXCLUDED.label,
            fingerprint = EXCLUDED.fingerprint,
            last_seen_at = now()
      `,
      [entry.id, entry.label, entry.fingerprint]
    );
  }
}

export async function listVeniceKeys(db: DbPool): Promise<VeniceKeyControlRow[]> {
  const result = await db.query<VeniceKeyControlRow>(
    "SELECT key_id, label, fingerprint, enabled, priority, first_seen_at, last_seen_at, updated_at FROM providers.venice_keys ORDER BY key_id"
  );
  return result.rows;
}

/** The operator-selected dispatch strategy; defaults before the first write. */
export async function getVeniceDispatchStrategy(db: DbPool): Promise<VeniceDispatchStrategy> {
  const result = await db.query<{ strategy: string }>(
    "SELECT strategy FROM providers.venice_dispatch_settings WHERE id"
  );
  const strategy = result.rows[0]?.strategy;
  return (VENICE_DISPATCH_STRATEGIES as readonly string[]).includes(strategy ?? "")
    ? (strategy as VeniceDispatchStrategy)
    : "round_robin";
}

const ROUND_ROBIN_COUNTER = "venice:key-rr";
const SELECTION_CACHE_TTL_MS = 5_000;

interface SelectionCache {
  expiresAt: number;
  registered: boolean;
  strategy: VeniceDispatchStrategy;
  enabled: Array<{ keyId: string; priority: number }>;
}

/**
 * Per-dispatch key selection, evaluated at the worker's final pre-fetch fence.
 *
 * - No rows registered yet (fresh deploy before the first manifest push):
 *   return null so the credential holder uses its default key. Multi-key
 *   control begins once the manifest lands.
 * - Rows exist but none enabled: fail closed. This is the operator kill
 *   switch for "every credential is compromised/exhausted".
 * - Otherwise the operator-selected strategy picks among enabled keys:
 *   round_robin rotates via a shared Valkey counter so the rotation stays
 *   fair across control replicas, priority pins all traffic to the lowest
 *   priority number (key id breaks ties), random draws uniformly.
 */
export class VeniceKeySelector {
  private readonly cache = new Map<string, SelectionCache>();

  constructor(private readonly db: DbPool, private readonly redis: Redis) {}

  private async loadEnabled(deploymentId: string): Promise<SelectionCache> {
    const now = Date.now();
    const cached = this.cache.get(deploymentId);
    if (cached && cached.expiresAt > now) return cached;
    // One cached query carries the keys and the singleton strategy row.
    const result = await this.db.query<{ key_id: string; enabled: boolean; priority: number | null; strategy: string | null }>(
      deploymentId === "primary" ? `
        SELECT k.key_id, k.enabled, k.priority, s.strategy
        FROM providers.venice_keys k
        LEFT JOIN providers.venice_dispatch_settings s ON s.id
        ORDER BY k.key_id
      ` : `
        SELECT k.key_id, k.enabled, k.priority, s.strategy
        FROM providers.venice_deployment_keys k
        LEFT JOIN providers.venice_dispatch_settings s ON s.id
        WHERE k.deployment_id = $1
        ORDER BY k.key_id
      `,
      deploymentId === "primary" ? [] : [deploymentId]
    );
    const strategy = result.rows[0]?.strategy;
    const state = {
      expiresAt: now + SELECTION_CACHE_TTL_MS,
      registered: result.rows.length > 0,
      strategy: (VENICE_DISPATCH_STRATEGIES as readonly string[]).includes(strategy ?? "")
        ? (strategy as VeniceDispatchStrategy)
        : "round_robin",
      enabled: result.rows
        .filter((row) => row.enabled)
        .map((row) => ({ keyId: row.key_id, priority: row.priority ?? 100 }))
    };
    this.cache.set(deploymentId, state);
    return state;
  }

  /** Drop the short selection cache so operator toggles apply immediately. */
  invalidate(): void {
    this.cache.clear();
  }

  async selectKeyId(deploymentId = "primary"): Promise<string | null> {
    const state = await this.loadEnabled(deploymentId);
    if (!state.registered) return null;
    if (state.enabled.length === 0) {
      throw new AppError(503, "provider_key_unavailable", "No Venice inference credential is enabled");
    }
    if (state.enabled.length === 1) return state.enabled[0]!.keyId;
    if (state.strategy === "priority") {
      return [...state.enabled].sort(
        (a, b) => a.priority - b.priority || a.keyId.localeCompare(b.keyId)
      )[0]!.keyId;
    }
    if (state.strategy === "random") {
      return state.enabled[Math.floor(Math.random() * state.enabled.length)]!.keyId;
    }
    let counter: number;
    try {
      counter = await this.redis.incr(`${ROUND_ROBIN_COUNTER}:${deploymentId}`);
    } catch {
      // Valkey trouble must not take inference down: rotation degrades to a
      // process-local pseudo-rotation rather than failing the dispatch.
      counter = Math.floor(Math.random() * state.enabled.length);
    }
    return state.enabled[Math.abs(counter) % state.enabled.length]!.keyId;
  }
}
