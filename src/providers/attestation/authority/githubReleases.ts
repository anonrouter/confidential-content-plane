// Container images a provider PUBLISHES through a GitHub release workflow.
//
// NEAR's compose-manager (the in-TD process that runs model composes and
// writes the TD-signed action log) and its launcher are promoted to
// production by nearai/compose-manager's `promote.yml`, which creates a
// `prod-<date>-<sha>` GitHub release as github-actions[bot] listing each
// component's exact image digest (build.yml also signs every image keylessly
// with cosign and attaches SLSA provenance). The launcher inside the TD may
// swap compose-manager images at runtime (cosign-verified against any
// nearai/compose-manager workflow, any ref); every image that started is in
// the TD-signed log as `compose_manager_started`. The check here: every such
// image, and the launcher and default compose-manager the measured boot
// compose names, is a digest a production release published.
//
// Residual trust: release notes are GitHub-served text, editable after the
// fact; the cosign signatures and SLSA provenance are not re-verified here.

import { check } from "../checks.js";
import type { AttestationCheck } from "../types.js";
import {
  AUTHORITY_MAX_STALE_MS,
  AuthorityCache,
  AuthorityFetchError,
  DEFAULT_AUTHORITY_BUDGET,
  authorityFetch,
  type FetchLike,
  type RequestBudget
} from "./fetchLayer.js";
import { normalizeRepository } from "./github.js";

export interface GithubReleaseImage {
  /** Release tag, e.g. "prod-20260702-8e07c35". */
  release: string;
  /** Section heading, e.g. "compose-manager" or "compose-manager-launcher". */
  component: string;
  /** "sha256:<64 hex>". */
  digest: string;
}

export interface GithubReleaseImages {
  v: 1;
  repository: string;
  fetchedAtMs: number;
  images: GithubReleaseImage[];
}

interface RawRelease {
  tag_name?: unknown;
  draft?: unknown;
  prerelease?: unknown;
  body?: unknown;
  author?: { login?: unknown };
}

/**
 * Read the digests out of production releases. Only non-draft, non-prerelease
 * releases tagged `prod-` and authored by the release workflow count; inside a
 * body, a digest belongs to the nearest preceding `### <component>` heading.
 */
export function parseReleaseImages(releases: unknown, tagPrefix = "prod-"): GithubReleaseImage[] {
  if (!Array.isArray(releases)) return [];
  const out: GithubReleaseImage[] = [];
  for (const raw of releases as RawRelease[]) {
    if (raw?.draft !== false || raw.prerelease !== false) continue;
    if (typeof raw.tag_name !== "string" || !raw.tag_name.startsWith(tagPrefix)) continue;
    if (raw.author?.login !== "github-actions[bot]" || typeof raw.body !== "string") continue;
    let component: string | null = null;
    for (const line of raw.body.split(/\r?\n/)) {
      const heading = /^###\s+([A-Za-z0-9._-]+)\s*$/.exec(line);
      if (heading) {
        component = heading[1];
        continue;
      }
      const digest = /^\s*-\s+\*\*Digest\*\*:\s*`(sha256:[0-9a-f]{64})`\s*$/.exec(line);
      if (digest && component) out.push({ release: raw.tag_name, component, digest: digest[1] });
    }
  }
  return out;
}

/** `authority_compose_manager_released`. */
export function composeManagerImagesCheck(input: {
  document: unknown;
  dockerComposeFile: string | null;
  record: GithubReleaseImages | undefined;
  repository: string;
  maxAgeMs: number;
  now: number;
}): AttestationCheck {
  const name = "authority_compose_manager_released";
  const { record } = input;
  if (!record || record.v !== 1 || record.repository !== normalizeRepository(input.repository) || !Array.isArray(record.images)) {
    return check(name, false, true, `no release record for ${input.repository} was supplied`);
  }
  const age = input.now - record.fetchedAtMs;
  if (!(age <= input.maxAgeMs && age >= -30_000)) {
    return check(name, false, true, `the releases of ${input.repository} were not read recently enough`);
  }
  const released = (component: string, digest: string) =>
    record.images.find((image) => image.component === component && image.digest === digest);

  const needed: Array<{ component: string; digest: string; why: string }> = [];
  const actions = (input.document as { compose_manager_attestation?: { actions?: unknown } } | undefined)
    ?.compose_manager_attestation?.actions;
  for (const action of Array.isArray(actions) ? actions as Array<{ action?: unknown; image?: unknown }> : []) {
    if (action?.action !== "compose_manager_started") continue;
    const match = typeof action.image === "string" ? /^nearaidev\/compose-manager@(sha256:[0-9a-f]{64})$/.exec(action.image) : null;
    if (!match) return check(name, false, true, "a compose_manager_started entry names an image outside nearaidev/compose-manager by digest");
    needed.push({ component: "compose-manager", digest: match[1], why: "started" });
  }
  if (needed.length === 0) return check(name, false, true, "the action log records no compose-manager start");
  if (input.dockerComposeFile) {
    for (const [component, repo] of [["compose-manager", "nearaidev/compose-manager"], ["compose-manager-launcher", "nearaidev/compose-manager-launcher"]] as const) {
      const pattern = new RegExp(`${repo.replace("/", "\\/")}@(sha256:[0-9a-f]{64})`, "g");
      for (const match of input.dockerComposeFile.matchAll(pattern)) {
        needed.push({ component, digest: match[1], why: "named by the boot compose" });
      }
    }
  }
  const unreleased = needed.filter((item) => !released(item.component, item.digest));
  if (unreleased.length > 0) {
    const first = unreleased[0];
    return check(name, false, true,
      `${unreleased.length} compose-manager image(s) are not in a production release of ${record.repository}, e.g. ${first.component} ${first.digest.slice(0, 19)}.. (${first.why})`);
  }
  const releases = [...new Set(needed.map((item) => released(item.component, item.digest)!.release))];
  return check(name, true, true,
    `every compose-manager and launcher image the TD ran or booted with is a ${record.repository} production release (${releases.join(", ")})`);
}

export interface GithubReleasesFetcherOptions {
  fetch?: FetchLike;
  apiBase?: string;
  /** Served without asking GitHub while younger than this. */
  ttlMs?: number;
  /** Past the TTL, the previous listing is served while ONE refresh runs, for this long. */
  staleWhileRevalidateMs?: number;
  /** Oldest listing served when a refresh fails (capped at AUTHORITY_MAX_STALE_MS). */
  maxStaleMs?: number;
  timeoutMs?: number;
  budget?: RequestBudget;
  now?: () => number;
}

const MAX_RELEASES_BYTES = 4 * 1024 * 1024;

/**
 * Fetch layer: one unauthenticated releases listing per TTL.
 *
 * The listing is only on GitHub's REST API (the release body, its author and
 * the draft/prerelease flags are what the check reads, and no non-API endpoint
 * carries all of them), so it is the one request here that spends the 60 per
 * hour unauthenticated quota. It is therefore a CONDITIONAL request: the
 * previous answer's ETag goes out as If-None-Match, and a 304 (which GitHub
 * does not count against the quota) re-confirms the cached listing as of now.
 * Releases change rarely, so past the TTL the previous listing is served while
 * one refresh runs; after a failed refresh it is served until it is
 * AUTHORITY_MAX_STALE_MS old, never longer.
 */
export class GithubReleasesFetcher {
  readonly repository: string;
  private readonly cache: AuthorityCache<GithubReleaseImage[]>;
  private readonly budget: RequestBudget;

  constructor(repository: string, private readonly options: GithubReleasesFetcherOptions = {}) {
    const normalized = normalizeRepository(repository);
    if (!normalized) throw new Error("invalid_repository");
    this.repository = normalized;
    this.budget = options.budget ?? DEFAULT_AUTHORITY_BUDGET;
    const ttlMs = options.ttlMs ?? 30 * 60_000;
    this.cache = new AuthorityCache<GithubReleaseImage[]>({
      freshMs: () => ttlMs,
      staleWhileRevalidateMs: options.staleWhileRevalidateMs ?? 15 * 60_000,
      maxStaleMs: options.maxStaleMs ?? AUTHORITY_MAX_STALE_MS
    }, { maxEntries: 1, now: options.now });
  }

  async collect(signal?: AbortSignal): Promise<GithubReleaseImages> {
    const { value: images, fetchedAtMs } = await this.cache.get("releases", async (previous) => {
      const answer = await authorityFetch({
        url: `${(this.options.apiBase ?? "https://api.github.com").replace(/\/$/, "")}/repos/${this.repository}/releases?per_page=100`,
        accept: "application/vnd.github+json",
        maxBytes: MAX_RELEASES_BYTES,
        timeoutMs: this.options.timeoutMs ?? 10_000,
        fetch: this.options.fetch ?? ((input: string, init?: RequestInit) => fetch(input, init)),
        budget: this.budget,
        now: this.options.now,
        etag: previous?.etag
      });
      if (answer.status === 304 && previous) return { value: previous.value, etag: previous.etag };
      if (answer.status !== 200) throw new AuthorityFetchError("upstream_status", `the releases of ${this.repository} answered ${answer.status}`);
      return { value: parseReleaseImages(JSON.parse(new TextDecoder().decode(answer.body))), etag: answer.etag };
    }, signal);
    return { v: 1, repository: this.repository, fetchedAtMs, images };
  }
}
