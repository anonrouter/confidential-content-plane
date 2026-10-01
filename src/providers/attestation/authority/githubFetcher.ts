// The fetch layer for GitHub publication collateral. Network lives HERE and
// nowhere in the verifiers: this reads a provider's official repository and
// returns a `GithubPublication` record for the pure verifier to check.
//
// Three read-only, unauthenticated requests, nothing else:
//   1. the git ref advertisement (`github.com/<repo>.git/info/refs?service=git-upload-pack`):
//      default branch head and every tag, peeled. One request, no API quota.
//   2. only for a logged commit that no named tag peels to: the compare API
//      (`api.github.com/repos/<repo>/compare/<head>...<commit>`), accepted only
//      as `behind`/`identical` with the commit as merge base, i.e. an ancestor
//      of the default branch head.
//   3. the file bytes at a published commit (`raw.githubusercontent.com/<repo>/<commit>/<path>`),
//      hashed here; only the SHA-256 travels.
//
// Caching follows what each answer can change, and every key carries every
// input that determines the answer (./fetchLayer.ts has the shared rules):
//   - files are keyed by commit SHA AND path, so their bytes are immutable:
//     cached until evicted (bounded); a 404 only briefly;
//   - "is <commit> an ancestor of <head>" is keyed by BOTH SHAs, so it is
//     immutable too: a new default-branch head is a new question, never the
//     old answer reused. Cached a day (bounded); a 404 only briefly;
//   - the ref advertisement can change at any push: 5 minute TTL, then a
//     refresh; if that refresh fails the last advertisement may be served
//     until it is AUTHORITY_MAX_STALE_MS old, never longer, and the record
//     carries its original fetch time.
// Why these endpoints: the ref advertisement (github.com) and file bytes
// (raw.githubusercontent.com) are not REST API calls and do not spend the 60
// per hour unauthenticated API quota. Only ancestry needs the REST API (no
// other public endpoint answers it with the same trust property), and only
// for a commit no advertised tag peels to.
// Nothing is sent but the request line and a fixed User-Agent. No credential is
// ever attached: a 401/403/429 is a failure, never a reason to add a token.

import { createHash } from "node:crypto";
import {
  GITHUB_PUBLICATION_VERSION,
  isCommitSha,
  isSafeRepositoryPath,
  isSafeTag,
  normalizeRepository,
  parseGitRefAdvertisement,
  type GitRefAdvertisement,
  type GithubPublication,
  type GithubPublishedFile,
  type PublicationClaim
} from "./github.js";
import {
  AUTHORITY_MAX_STALE_MS,
  AuthorityCache,
  DEFAULT_AUTHORITY_BUDGET,
  authorityFetch,
  type FetchLike,
  type RequestBudget
} from "./fetchLayer.js";

export interface GithubPublicationFetcherOptions {
  /** "owner/name" of the provider's official repository. */
  repository: string;
  fetch?: FetchLike;
  gitBase?: string;
  rawBase?: string;
  apiBase?: string;
  refsTtlMs?: number;
  ancestorTtlMs?: number;
  negativeTtlMs?: number;
  /** Oldest ref advertisement served when a refresh fails (capped at AUTHORITY_MAX_STALE_MS). */
  maxStaleMs?: number;
  timeoutMs?: number;
  concurrency?: number;
  /** Most distinct files one record may need (a hostile log cannot fan out). */
  maxFiles?: number;
  maxFileBytes?: number;
  maxCachedFiles?: number;
  /** Per-host request budget; the process-wide one unless a test supplies its own. */
  budget?: RequestBudget;
  now?: () => number;
}

const MAX_REFS_BYTES = 8 * 1024 * 1024;
const MAX_COMPARE_BYTES = 4 * 1024 * 1024;

export class GithubPublicationError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "GithubPublicationError";
  }
}

export class GithubPublicationFetcher {
  readonly repository: string;
  private readonly fetchImpl: FetchLike;
  private readonly gitBase: string;
  private readonly rawBase: string;
  private readonly apiBase: string;
  private readonly timeoutMs: number;
  private readonly concurrency: number;
  private readonly maxFiles: number;
  private readonly maxFileBytes: number;
  private readonly budget: RequestBudget;
  private readonly now: () => number;
  private readonly refsCache: AuthorityCache<GitRefAdvertisement>;
  private readonly ancestors: AuthorityCache<{ ancestor: boolean; answered: boolean }>;
  private readonly files: AuthorityCache<string | null>;

  constructor(options: GithubPublicationFetcherOptions) {
    const repository = normalizeRepository(options.repository);
    if (!repository) throw new GithubPublicationError("invalid_repository", "repository must be owner/name");
    this.repository = repository;
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
    this.gitBase = (options.gitBase ?? "https://github.com").replace(/\/$/, "");
    this.rawBase = (options.rawBase ?? "https://raw.githubusercontent.com").replace(/\/$/, "");
    this.apiBase = (options.apiBase ?? "https://api.github.com").replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.concurrency = Math.max(1, Math.min(options.concurrency ?? 6, 16));
    this.maxFiles = options.maxFiles ?? 512;
    this.maxFileBytes = options.maxFileBytes ?? 2 * 1024 * 1024;
    this.budget = options.budget ?? DEFAULT_AUTHORITY_BUDGET;
    this.now = options.now ?? Date.now;
    const refsTtlMs = options.refsTtlMs ?? 5 * 60_000;
    const ancestorTtlMs = options.ancestorTtlMs ?? 24 * 60 * 60_000;
    const negativeTtlMs = options.negativeTtlMs ?? 5 * 60_000;
    const cacheOptions = { now: this.now };
    this.refsCache = new AuthorityCache<GitRefAdvertisement>({
      freshMs: () => refsTtlMs,
      maxStaleMs: options.maxStaleMs ?? AUTHORITY_MAX_STALE_MS
    }, { ...cacheOptions, maxEntries: 1 });
    this.ancestors = new AuthorityCache<{ ancestor: boolean; answered: boolean }>({
      // A 200 answers a question about two fixed SHAs, so it cannot change;
      // a 404 (unknown commit) might, so it is held only briefly.
      freshMs: (value) => (value.answered ? ancestorTtlMs : negativeTtlMs),
      maxStaleMs: 0
    }, { ...cacheOptions, maxEntries: 4096 });
    this.files = new AuthorityCache<string | null>({
      freshMs: (sha256) => (sha256 === null ? negativeTtlMs : Number.POSITIVE_INFINITY),
      maxStaleMs: 0
    }, { ...cacheOptions, maxEntries: options.maxCachedFiles ?? 8192 });
  }

  /** Build the publication record for every claim a provider log makes. */
  async collect(claims: PublicationClaim[], signal?: AbortSignal): Promise<GithubPublication> {
    const valid = claims.filter((claim) => isCommitSha(claim.commit.toLowerCase()) && isSafeRepositoryPath(claim.path));
    const { value: refs, fetchedAtMs } = await this.refs(signal);
    const headTarget = refs.headTarget;
    const head = headTarget ? refs.refs.get(headTarget) : undefined;
    if (!headTarget?.startsWith("refs/heads/") || !head) {
      throw new GithubPublicationError("no_default_branch", "the repository advertises no default branch");
    }
    const defaultBranch = headTarget.slice("refs/heads/".length);

    const tags: Record<string, string> = {};
    for (const claim of valid) {
      if (isSafeTag(claim.tag) && refs.tags.has(claim.tag)) tags[claim.tag] = refs.tags.get(claim.tag)!;
    }

    // A commit needs the (rate-limited) ancestry question only when no tag the
    // log names peels to it.
    const needsAncestry = new Set<string>();
    for (const claim of valid) {
      const commit = claim.commit.toLowerCase();
      if (!(isSafeTag(claim.tag) && tags[claim.tag] === commit)) needsAncestry.add(commit);
    }
    const ancestors: string[] = [];
    await this.pool([...needsAncestry], async (commit) => {
      if (await this.isAncestor(head, commit, signal)) ancestors.push(commit);
    });

    const published = new Set<string>([...Object.values(tags), ...ancestors]);
    const wanted = new Map<string, PublicationClaim>();
    for (const claim of valid) {
      const commit = claim.commit.toLowerCase();
      // Never read a file at a commit the repository does not publish: a fork's
      // commit is served under the parent's name, and need not be fetched to fail.
      if (published.has(commit)) wanted.set(`${commit}:${claim.path}`, { commit, path: claim.path });
    }
    if (wanted.size > this.maxFiles) {
      throw new GithubPublicationError("too_many_files", `the log names ${wanted.size} files; the limit is ${this.maxFiles}`);
    }
    const files: GithubPublishedFile[] = [];
    await this.pool([...wanted.values()], async ({ commit, path }) => {
      files.push({ commit, path, sha256: await this.fileSha256(commit, path, signal) });
    });
    files.sort((a, b) => (a.commit + a.path).localeCompare(b.commit + b.path));
    ancestors.sort();

    return {
      v: GITHUB_PUBLICATION_VERSION,
      repository: this.repository,
      // The time of the ref advertisement this record was built from: tags and
      // head come from it, so its age is the record's age.
      fetchedAtMs,
      defaultBranch,
      defaultBranchHead: head,
      tags,
      defaultBranchAncestors: ancestors,
      files
    };
  }

  /** The repository's advertised tags (peeled), for release-tag anchoring. */
  async tags(names: string[], signal?: AbortSignal): Promise<{ fetchedAtMs: number; tags: Record<string, string> }> {
    const { value: refs, fetchedAtMs } = await this.refs(signal);
    const tags: Record<string, string> = {};
    for (const name of names) {
      if (isSafeTag(name) && refs.tags.has(name)) tags[name] = refs.tags.get(name)!;
    }
    return { fetchedAtMs, tags };
  }

  private refs(signal?: AbortSignal) {
    return this.refsCache.get("refs", async () => {
      const url = `${this.gitBase}/${this.repository}.git/info/refs?service=git-upload-pack`;
      const answer = await this.get(url, MAX_REFS_BYTES, "application/x-git-upload-pack-advertisement");
      if (answer === null) throw new GithubPublicationError("repository_not_found", "the repository was not found");
      return { value: parseGitRefAdvertisement(answer) };
    }, signal);
  }

  private async isAncestor(head: string, commit: string, signal?: AbortSignal): Promise<boolean> {
    if (commit === head) return true;
    const { value } = await this.ancestors.get(`${head}...${commit}`, async () => {
      const url = `${this.apiBase}/repos/${this.repository}/compare/${head}...${commit}?per_page=1`;
      const body = await this.get(url, MAX_COMPARE_BYTES, "application/vnd.github+json");
      if (body === null) return { value: { ancestor: false, answered: false } };
      const parsed = JSON.parse(new TextDecoder().decode(body)) as {
        status?: unknown;
        merge_base_commit?: { sha?: unknown };
      };
      const ancestor = (parsed.status === "behind" || parsed.status === "identical")
        && parsed.merge_base_commit?.sha === commit;
      return { value: { ancestor, answered: true } };
    }, signal);
    return value.ancestor;
  }

  private async fileSha256(commit: string, path: string, signal?: AbortSignal): Promise<string | null> {
    const { value } = await this.files.get(`${commit}:${path}`, async () => {
      const encoded = path.split("/").map(encodeURIComponent).join("/");
      const body = await this.get(`${this.rawBase}/${this.repository}/${commit}/${encoded}`, this.maxFileBytes, "*/*");
      return { value: body === null ? null : createHash("sha256").update(body).digest("hex") };
    }, signal);
    return value;
  }

  /** GET under the budget with a deadline, no redirects and a byte cap. 404 -> null; any other non-200 throws. */
  private async get(url: string, maxBytes: number, accept: string): Promise<Uint8Array | null> {
    const answer = await authorityFetch({
      url,
      accept,
      maxBytes,
      timeoutMs: this.timeoutMs,
      fetch: this.fetchImpl,
      budget: this.budget,
      now: this.now
    });
    if (answer.status === 404) return null;
    if (answer.status !== 200) throw new GithubPublicationError("github_unavailable", `GitHub answered ${answer.status}`);
    return answer.body;
  }

  private async pool<T>(items: T[], worker: (item: T) => Promise<void>): Promise<void> {
    let next = 0;
    const run = async () => {
      while (next < items.length) {
        const item = items[next];
        next += 1;
        await worker(item);
      }
    };
    await Promise.all(Array.from({ length: Math.min(this.concurrency, items.length) }, run));
  }
}
