import type { ContentPlaneConfig } from "../contentPlaneConfig.js";

/**
 * Worker-side Venice rate-limit lookup.
 *
 * SPLIT OUT OF `veniceCatalog.ts` FOR D-22.
 *
 * `roles.ts` needs exactly this one function, to attach per-model rate limits to
 * the catalog payload a worker PUSHES to control. It does not need, and must not
 * carry, the catalog APPLY machinery that lives beside it: `veniceCatalog.ts`
 * imports `./catalog/apply.js`, which imports `../admin/signals.js`, which
 * dragged the admin graph into the content plane's module closure.
 *
 * The asymmetry is the point. A worker BUILDS a catalog payload and hands it to
 * control over the content-free metadata RPC; control is what APPLIES it to
 * PostgreSQL. Only the building half belongs on the content tier, and only the
 * building half is here.
 *
 * This is worker-only in another sense too: it is the one call that uses the
 * provider credential, which exists solely inside the one worker container that
 * holds it.
 */
export type VeniceRateLimits = Record<string, { rpm?: number; tpm?: number }>;

/** Worker-side: fetch provider per-model rate limits (needs the Venice key). */
export async function fetchVeniceRateLimits(config: ContentPlaneConfig): Promise<VeniceRateLimits | null> {
  if (!config.providers.veniceInferenceKey) return null;
  try {
    const response = await fetch(`${config.providers.veniceBaseUrl}/api_keys/rate_limits`, {
      headers: { authorization: `Bearer ${config.providers.veniceInferenceKey}` },
      signal: AbortSignal.timeout(5_000)
    });
    if (!response.ok) return null;
    const payload = (await response.json()) as {
      data?: { rateLimits?: Array<{ apiModelId?: string; rateLimits?: Array<{ amount?: number; type?: string }> }> };
    };
    const out: VeniceRateLimits = {};
    for (const model of payload.data?.rateLimits ?? []) {
      if (!model.apiModelId) continue;
      const limits: { rpm?: number; tpm?: number } = {};
      for (const limit of model.rateLimits ?? []) {
        if (limit.type === "RPM" && Number.isFinite(limit.amount)) limits.rpm = limit.amount;
        if (limit.type === "TPM" && Number.isFinite(limit.amount)) limits.tpm = limit.amount;
      }
      out[model.apiModelId] = limits;
    }
    return out;
  } catch {
    return null;
  }
}
