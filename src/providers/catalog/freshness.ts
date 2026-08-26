// Catalog freshness policy. The catalog is considered stale after 15 minutes
// without a successful sync, and critically stale after 60 minutes. While stale
// the last-known-good catalog keeps serving; while critically stale, newly
// changed routes are not automatically enabled until a healthy sync resumes.

export const STALE_AFTER_MS = 15 * 60 * 1000;
export const CRITICAL_AFTER_MS = 60 * 60 * 1000;

export type FreshnessLevel = "healthy" | "warning" | "critical";

export interface Freshness {
  /** ms since last successful sync, or null if the catalog has never synced. */
  ageMs: number | null;
  stale: boolean;
  level: FreshnessLevel;
}

export function computeFreshness(lastSuccessAt: Date | null, now: Date): Freshness {
  if (lastSuccessAt === null) {
    // Never successfully synced: treat as stale + critical for observability, but
    // this state does not "freeze" enablement (there is no catalog to protect).
    return { ageMs: null, stale: true, level: "critical" };
  }
  const ageMs = Math.max(0, now.getTime() - lastSuccessAt.getTime());
  const level: FreshnessLevel = ageMs > CRITICAL_AFTER_MS ? "critical" : ageMs > STALE_AFTER_MS ? "warning" : "healthy";
  return { ageMs, stale: ageMs > STALE_AFTER_MS, level };
}

/**
 * Whether a NEW snapshot apply must withhold newly-changed enablement because the
 * catalog was critically stale (> 60m since the previous success) when it arrived.
 * A never-synced catalog (null) is NOT frozen: the first successful sync enables
 * normally. Once this apply records a fresh success, subsequent timely syncs
 * evaluate as healthy and enablement resumes.
 */
export function enablementFrozen(previousSuccessAt: Date | null, now: Date): boolean {
  if (previousSuccessAt === null) return false;
  return now.getTime() - previousSuccessAt.getTime() > CRITICAL_AFTER_MS;
}
