// Fetch layer for the Chutes release authority: a cached snapshot of Chutes'
// published measurement list plus the release tags of its public image
// repository. The verifier never fetches; this does, then hands the record over.
//
// Refresh is hourly (Chutes caches the list for an hour itself), as a
// conditional request when Chutes sent an ETag. Concurrent callers share one
// request (./fetchLayer.ts). A failed refresh keeps the last good snapshot
// until it is AUTHORITY_MAX_STALE_MS old, with its ORIGINAL fetch time, so the
// verifier's own window (maxPublicationAgeMs) still applies to it; after that
// collect() throws, nothing is attached, and verification fails closed. It
// never widens to "accept anything". The sek8s tags come from the repository's
// git ref advertisement (github.com), which spends no GitHub API quota.

import { createHash } from "node:crypto";
import {
  CHUTES_IMAGE_REPOSITORY,
  CHUTES_MEASUREMENTS_SOURCE,
  normalizeChutesMeasurements,
  type ChutesPublishedMeasurement,
  type ChutesReleaseCollateral
} from "./chutes.js";
import {
  AUTHORITY_MAX_STALE_MS,
  AuthorityCache,
  AuthorityFetchError,
  DEFAULT_AUTHORITY_BUDGET,
  authorityFetch,
  type FetchLike,
  type RequestBudget
} from "./fetchLayer.js";
import { GithubPublicationFetcher } from "./githubFetcher.js";

export interface ChutesPublicationFetcherOptions {
  fetch?: FetchLike;
  source?: string;
  refreshMs?: number;
  /** Oldest snapshot served when a refresh fails (capped at AUTHORITY_MAX_STALE_MS). */
  maxStaleMs?: number;
  timeoutMs?: number;
  github?: GithubPublicationFetcher;
  budget?: RequestBudget;
  now?: () => number;
}

const MAX_LIST_BYTES = 4 * 1024 * 1024;

interface ChutesListSnapshot {
  bodySha256: string;
  measurements: ChutesPublishedMeasurement[];
}

export class ChutesPublicationFetcher {
  private readonly fetchImpl: FetchLike;
  private readonly source: string;
  private readonly timeoutMs: number;
  private readonly github: GithubPublicationFetcher;
  private readonly budget: RequestBudget;
  private readonly now: () => number;
  private readonly cache: AuthorityCache<ChutesListSnapshot>;

  constructor(options: ChutesPublicationFetcherOptions = {}) {
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
    this.source = options.source ?? CHUTES_MEASUREMENTS_SOURCE;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.budget = options.budget ?? DEFAULT_AUTHORITY_BUDGET;
    this.now = options.now ?? Date.now;
    this.github = options.github ?? new GithubPublicationFetcher({
      repository: CHUTES_IMAGE_REPOSITORY, fetch: options.fetch, now: options.now, budget: this.budget
    });
    const refreshMs = options.refreshMs ?? 60 * 60_000;
    this.cache = new AuthorityCache<ChutesListSnapshot>({
      freshMs: () => refreshMs,
      maxStaleMs: options.maxStaleMs ?? AUTHORITY_MAX_STALE_MS
    }, { maxEntries: 1, now: this.now });
  }

  async collect(signal?: AbortSignal): Promise<ChutesReleaseCollateral> {
    const { value: snapshot, fetchedAtMs } = await this.cache.get("list", async (previous) => {
      const answer = await authorityFetch({
        url: this.source,
        accept: "application/json",
        maxBytes: MAX_LIST_BYTES,
        timeoutMs: this.timeoutMs,
        fetch: this.fetchImpl,
        budget: this.budget,
        now: this.now,
        etag: previous?.etag
      });
      if (answer.status === 304 && previous) return { value: previous.value, etag: previous.etag };
      if (answer.status !== 200) throw new AuthorityFetchError("chutes_measurements_unavailable", `Chutes' measurement list answered ${answer.status}`);
      const measurements = normalizeChutesMeasurements(JSON.parse(new TextDecoder().decode(answer.body)));
      if (measurements.length === 0) throw new AuthorityFetchError("chutes_measurements_empty", "Chutes' measurement list had no usable entry");
      return {
        value: { bodySha256: createHash("sha256").update(answer.body).digest("hex"), measurements },
        etag: answer.etag
      };
    }, signal);
    const versions = [...new Set(snapshot.measurements.map((entry) => `v${entry.version}`))];
    const tags = await this.github.tags(versions, signal);
    return {
      v: 1,
      source: this.source,
      fetchedAtMs,
      bodySha256: snapshot.bodySha256,
      measurements: snapshot.measurements,
      imageRepository: { repository: this.github.repository, fetchedAtMs: tags.fetchedAtMs, tags: tags.tags }
    };
  }
}
