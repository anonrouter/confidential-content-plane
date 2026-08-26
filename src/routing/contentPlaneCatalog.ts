import type { ModelRecord } from "../providers/types.js";

/**
 * The content plane's read-only view of the routing catalog.
 *
 * Automatic model selection moved into the content plane when
 * CONTROL_RPC_CONTRACT.md removed `classification` from the control boundary.
 * Selection needs the catalog — prices, quality tiers, context windows,
 * capability flags — and the content plane has no database, so it reads the
 * catalog over the existing content-free `/internal/control/models` RPC.
 *
 * The direction matters. This is control → content: published catalog facts,
 * the same ones GET /v1/models already serves to anyone. Nothing about a
 * request travels with the fetch; the route takes no body at all.
 *
 * Cached with a short TTL and single-flighted. Selection sits on the hot path of
 * every /auto request, and re-fetching a hundred-odd catalog rows per request
 * would spend the WAN round trip the placement work spent months minimising.
 */

export interface RoutingCatalogSource {
  /** Fetch the current auto-routing candidate pool. */
  fetchRoutingCandidates(signal?: AbortSignal): Promise<ModelRecord[]>;
}

export interface RoutingCatalogCacheOptions {
  ttlMs?: number;
  now?: () => number;
}

const DEFAULT_TTL_MS = 60_000;

/**
 * A stale entry is served while a refresh is in flight rather than blocking the
 * request behind it. A minute-old price is a routing input, not a billing one:
 * the control plane prices the settlement from its own catalog regardless of
 * what was used to choose, so a stale row can only ever pick a slightly
 * different model, never charge a wrong amount.
 */
export class RoutingCatalogCache {
  private cached: { models: ModelRecord[]; fetchedAtMs: number } | null = null;
  private inFlight: Promise<ModelRecord[]> | null = null;
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(
    private readonly source: RoutingCatalogSource,
    options: RoutingCatalogCacheOptions = {}
  ) {
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.now = options.now ?? Date.now;
  }

  async candidates(signal?: AbortSignal): Promise<ModelRecord[]> {
    const fresh = this.cached && this.now() - this.cached.fetchedAtMs < this.ttlMs;
    if (fresh) return this.cached!.models;

    if (!this.inFlight) {
      this.inFlight = this.source
        .fetchRoutingCandidates(signal)
        .then((models) => {
          this.cached = { models, fetchedAtMs: this.now() };
          return models;
        })
        .finally(() => {
          this.inFlight = null;
        });
    }
    try {
      return await this.inFlight;
    } catch (error) {
      // Serve the stale copy rather than failing /auto on a transient control
      // hiccup. With nothing cached there is no honest answer and the caller
      // turns this into router_unavailable.
      if (this.cached) return this.cached.models;
      throw error;
    }
  }
}
