// GitHub publication collateral: what a provider PUBLISHES in its official
// public repository, in a shape a pure verifier can check.
//
// The verifier never fetches. A separate layer (`GithubPublicationFetcher`,
// below) reads the repository and hands the verifier this record, exactly as the
// other vendor collateral (Intel PCS, NVIDIA RIM/OCSP, AMD KDS) is fetched by a
// layer and passed in. What each field proves, and what it does not:
//
// - `files[].sha256` is SHA-256 of the bytes GitHub served for `path` at
//   `commit`. The provider's TD-signed log names the same (commit, path) and the
//   SHA-256 it actually ran, so the comparison is what binds "ran" to
//   "published"; the bytes themselves need not travel.
// - `tags` and `defaultBranchHead` come from the repository's git ref
//   advertisement (`/info/refs?service=git-upload-pack`). A tag the repository
//   does not advertise is absent, and an absent tag is never a publication.
// - `defaultBranchAncestors` are commits GitHub reported (compare API) as
//   ancestors of, or equal to, the default branch head.
//
// Residual trust, stated once: GitHub's answers are not signed. The record is
// as honest as GitHub and the layer that relays it. Git history is mutable (a
// force-push or tag deletion changes the answer), which fails closed. A commit
// that exists only in a fork is served by GitHub under the parent's name; that
// is why a bare commit counts only when it is reachable from the official
// default branch or an advertised tag peels to it.

export const GITHUB_PUBLICATION_VERSION = 1 as const;

export interface GithubPublishedFile {
  /** 40 hex, lowercase. */
  commit: string;
  /** Repository-relative path, exactly as the provider's log names it. */
  path: string;
  /** SHA-256 of the served bytes, lowercase hex; null when GitHub has no such file. */
  sha256: string | null;
}

export interface GithubPublication {
  v: typeof GITHUB_PUBLICATION_VERSION;
  /** "owner/name", lowercase. */
  repository: string;
  /** When the layer read the repository (ms since the epoch). */
  fetchedAtMs: number;
  defaultBranch: string;
  defaultBranchHead: string;
  /** tag name -> the commit it peels to, for the tags the evidence names. */
  tags: Record<string, string>;
  /** Commits GitHub reported as ancestors of (or equal to) the default branch head. */
  defaultBranchAncestors: string[];
  files: GithubPublishedFile[];
}

/** A provider log's claim that it ran `path` at `commit` (optionally released as `tag`). */
export interface PublicationClaim {
  commit: string;
  path: string;
  tag?: string | null;
}

const COMMIT = /^[0-9a-f]{40}$/;
const REPOSITORY = /^[a-z0-9](?:[a-z0-9-]{0,38})\/[a-z0-9._-]{1,100}$/;
// Refuse anything that could escape the repository root or confuse a URL.
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9._\-/+@]{1,512}$/;
// git check-ref-format, conservatively: no "..", no control characters, no
// spaces, no "~^:?*[\\", not ending in ".lock" or "/".
const SAFE_TAG = /^(?!.*\.\.)(?!.*\/\/)(?!.*@\{)(?!.*\.lock$)(?!\/)(?!.*\/$)[A-Za-z0-9._\-/+]{1,200}$/;

export function isCommitSha(value: unknown): value is string {
  return typeof value === "string" && COMMIT.test(value);
}

export function normalizeRepository(value: string): string | null {
  const trimmed = value.trim().toLowerCase()
    .replace(/^https:\/\/github\.com\//, "")
    .replace(/\.git$/, "")
    .replace(/\/$/, "");
  return REPOSITORY.test(trimmed) ? trimmed : null;
}

export function isSafeRepositoryPath(value: unknown): value is string {
  return typeof value === "string" && SAFE_PATH.test(value);
}

export function isSafeTag(value: unknown): value is string {
  return typeof value === "string" && SAFE_TAG.test(value);
}

export interface GitRefAdvertisement {
  /** The ref HEAD points to (symref), e.g. "refs/heads/main"; null if not advertised. */
  headTarget: string | null;
  /** Every advertised ref -> object id. */
  refs: Map<string, string>;
  /** tag name -> peeled commit (annotated tags peel through `^{}`; lightweight tags are the commit). */
  tags: Map<string, string>;
}

/**
 * Parse a git smart-HTTP v0 ref advertisement
 * (`GET <repo>.git/info/refs?service=git-upload-pack`). pkt-line framing: four
 * hex digits of length (including themselves), "0000" flush. The first ref line
 * carries capabilities after a NUL, including `symref=HEAD:<target>`.
 * Malformed framing throws: the caller treats that as "no publication".
 */
export function parseGitRefAdvertisement(body: Uint8Array): GitRefAdvertisement {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  const refs = new Map<string, string>();
  const peeled = new Map<string, string>();
  let headTarget: string | null = null;
  let offset = 0;
  let sawService = false;
  while (offset < text.length) {
    const lengthHex = text.slice(offset, offset + 4);
    if (!/^[0-9a-f]{4}$/.test(lengthHex)) throw new Error("git_refs_malformed");
    const length = Number.parseInt(lengthHex, 16);
    if (length === 0) {
      offset += 4;
      continue;
    }
    if (length < 4 || offset + length > text.length) throw new Error("git_refs_malformed");
    let line = text.slice(offset + 4, offset + length);
    offset += length;
    if (line.endsWith("\n")) line = line.slice(0, -1);
    if (line.startsWith("# service=")) {
      if (line !== "# service=git-upload-pack") throw new Error("git_refs_wrong_service");
      sawService = true;
      continue;
    }
    const nul = line.indexOf("\0");
    const capabilities = nul >= 0 ? line.slice(nul + 1) : "";
    const refLine = nul >= 0 ? line.slice(0, nul) : line;
    const match = /^([0-9a-f]{40}) (\S+)$/.exec(refLine);
    if (!match) throw new Error("git_refs_malformed");
    const [, oid, name] = match;
    for (const capability of capabilities.split(" ")) {
      if (capability.startsWith("symref=HEAD:")) headTarget = capability.slice("symref=HEAD:".length);
    }
    if (name.endsWith("^{}")) {
      if (name.startsWith("refs/tags/")) peeled.set(name.slice("refs/tags/".length, -3), oid);
      continue;
    }
    refs.set(name, oid);
  }
  if (!sawService) throw new Error("git_refs_malformed");
  const tags = new Map<string, string>();
  for (const [name, oid] of refs) {
    if (!name.startsWith("refs/tags/")) continue;
    const tag = name.slice("refs/tags/".length);
    tags.set(tag, peeled.get(tag) ?? oid);
  }
  return { headTarget, refs, tags };
}

export type PublicationStatus =
  | { published: true; how: "tag" | "default-branch"; detail: string }
  | { published: false; detail: string };

/**
 * Was `claim` published by the repository this record describes? A tag the log
 * names must peel to the logged commit; otherwise the commit must be reachable
 * from the default branch. The file must exist at that commit and hash to
 * `expectedSha256` (the SHA-256 the TD-signed log says it ran).
 */
export function publicationStatus(
  publication: GithubPublication,
  claim: PublicationClaim,
  expectedSha256: string
): PublicationStatus {
  const commit = claim.commit.toLowerCase();
  if (!isCommitSha(commit)) return { published: false, detail: `the log names no valid commit for ${claim.path}` };
  const tag = typeof claim.tag === "string" && claim.tag.length > 0 ? claim.tag : null;
  const tagged = tag !== null && publication.tags[tag] === commit;
  const onDefaultBranch = publication.defaultBranchAncestors.includes(commit);
  if (!tagged && !onDefaultBranch) {
    return {
      published: false,
      detail: `${claim.path} @ ${commit.slice(0, 12)}${tag ? ` (tag ${tag.slice(0, 80)})` : ""} is neither an advertised tag of ${publication.repository} nor reachable from its ${publication.defaultBranch} branch`
    };
  }
  const file = publication.files.find((entry) => entry.commit === commit && entry.path === claim.path);
  if (!file || file.sha256 === null) {
    return { published: false, detail: `${claim.path} does not exist in ${publication.repository} @ ${commit.slice(0, 12)}` };
  }
  if (file.sha256 !== expectedSha256.toLowerCase()) {
    return {
      published: false,
      detail: `${claim.path} @ ${commit.slice(0, 12)} in ${publication.repository} hashes to ${file.sha256.slice(0, 16)}.., not the ${expectedSha256.slice(0, 16)}.. the TD ran`
    };
  }
  return {
    published: true,
    how: tagged ? "tag" : "default-branch",
    detail: tagged ? `${claim.path} released as ${tag}` : `${claim.path} on ${publication.defaultBranch}`
  };
}

/** Structural validation of a publication record before any check reads it. */
export function validGithubPublication(value: unknown): value is GithubPublication {
  if (!value || typeof value !== "object") return false;
  const record = value as Partial<GithubPublication>;
  if (record.v !== GITHUB_PUBLICATION_VERSION) return false;
  if (typeof record.repository !== "string" || normalizeRepository(record.repository) !== record.repository) return false;
  if (typeof record.fetchedAtMs !== "number" || !Number.isFinite(record.fetchedAtMs)) return false;
  if (typeof record.defaultBranch !== "string" || record.defaultBranch.length === 0) return false;
  if (!isCommitSha(record.defaultBranchHead)) return false;
  if (!record.tags || typeof record.tags !== "object" || Array.isArray(record.tags)) return false;
  if (!Object.values(record.tags).every(isCommitSha)) return false;
  if (!Array.isArray(record.defaultBranchAncestors) || !record.defaultBranchAncestors.every(isCommitSha)) return false;
  if (!Array.isArray(record.files)) return false;
  return record.files.every((file) => file
    && isCommitSha(file.commit)
    && isSafeRepositoryPath(file.path)
    && (file.sha256 === null || (typeof file.sha256 === "string" && /^[0-9a-f]{64}$/.test(file.sha256))));
}
