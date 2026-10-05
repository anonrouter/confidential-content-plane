// The release-collateral role's wire contract (PROVIDER_POOL_PLAN.md, W3; review
// findings C2 and S1).
//
// NOT src/collateral/. That is the vendor collateral relay: a public service
// handing browsers Intel, NVIDIA and AMD collateral, with its own entry point
// and no runtime role. This is RUNTIME_ROLE=release-collateral, an internal service
// that looks up PROVIDER RELEASE collateral for the pool.
//
// WHAT THE ROLE IS FOR. Verifying a provider's release authority means looking
// up what that provider PUBLISHES: GitHub refs, files at a commit, ancestry and
// releases, and on Base the dstack KMS registry and app contract. A pooled
// worker holds several providers' keys and every pooled prompt, so it must not
// be the process that opens sessions to github.com or a public RPC node. The
// release-collateral role holds no key and sees no prompt, and makes those lookups for
// it.
//
// WHY THE CONTRACT LOOKS LIKE THIS. A deputy that forwards caller-chosen
// strings is still an exfiltration channel: a request discloses its path, its
// commit and its calldata to the upstream even when the answer is 404. So the
// caller names an OPERATION and fills in a few fixed-shape fields, and the
// server builds everything else. There is no URL, host, header, query string,
// HTTP method, JSON-RPC id, call option, block, state override or batch in any
// request, and no field for one: every schema below is strict.
//
// The three operations are the three methods of `NearReleaseSources`
// (src/providers/attestation/authority/collateral.ts), not the eight requests
// underneath them. The caller cannot ask for a ref advertisement, a compare or
// an eth_call on its own, so it never chooses the compare's head, the block, the
// selector, the callee or the order requests go out in.
//
// THE RESIDUAL, stated here because this file is where it is decided. Three
// kinds of value come from provider evidence and have to reach an upstream for
// the lookup to mean anything: a commit hash, a compose file path, and the
// (app, compose hash) of an on-chain subject. A compromised caller can put
// chosen bits in those. This file bounds how many bits one value can hold;
// src/releaseCollateral/server.ts bounds how many new values are accepted per hour.
// It is a narrow channel to GitHub and to the RPC operator. It is not zero.
//
// Shared by the server, which enforces it, and the client, which only uses it
// to avoid sending what would be refused. The server trusts nothing the client
// did.

import { z } from "zod";
import type { DstackKmsIdentity } from "../providers/attestation/authority/dstackOnchain.js";
import { isSafeTag, type PublicationClaim } from "../providers/attestation/authority/github.js";
import {
  NEAR_COMPOSE_MANAGER_REPOSITORY,
  NEAR_DSTACK_KMS,
  NEAR_OFFICIAL_COMPOSE_REPOSITORY
} from "../providers/attestation/authority/near.js";

export const RELEASE_COLLATERAL_RPC_PREFIX = "/internal/release-collateral/v1";

/** Every operation the role serves. A path that is not one of these is a 404. */
export const RELEASE_COLLATERAL_OPERATIONS = [
  "github-publication",
  "github-release-images",
  "dstack-onchain-authorization"
] as const;

export type ReleaseCollateralOperation = (typeof RELEASE_COLLATERAL_OPERATIONS)[number];

export function releaseCollateralPath(operation: ReleaseCollateralOperation): string {
  return `${RELEASE_COLLATERAL_RPC_PREFIX}/${operation}`;
}

// --- what a request may pick from ---------------------------------------------
//
// A request names a repository or a registry only by choosing an entry here.
// Compared exactly: no trimming, case folding or URL form is accepted, so there
// is one spelling of each. One list per operation, so a repository allowed for
// releases cannot be asked for its files.

/** Repositories whose refs, ancestry and files may be read. */
export const PUBLICATION_REPOSITORIES = [NEAR_OFFICIAL_COMPOSE_REPOSITORY] as const;

/** Repositories whose release listing may be read. */
export const RELEASE_REPOSITORIES = [NEAR_COMPOSE_MANAGER_REPOSITORY] as const;

/** The on-chain KMS registries, by name. The address and chain are the server's. */
export const ONCHAIN_REGISTRIES = {
  "near-base-mainnet": NEAR_DSTACK_KMS
} as const satisfies Record<string, DstackKmsIdentity>;

export type OnchainRegistryName = keyof typeof ONCHAIN_REGISTRIES;

const ONCHAIN_REGISTRY_NAMES = Object.keys(ONCHAIN_REGISTRIES) as [OnchainRegistryName, ...OnchainRegistryName[]];

// --- the variable fields --------------------------------------------------------
//
// One canonical spelling each: lowercase hex, no `0x`. A second spelling of the
// same value would be a second thing a caller could vary.

/** A git commit: exactly 40 lowercase hex. */
const COMMIT = /^[0-9a-f]{40}$/;
/** A 32-byte value (compose hash, OS image hash): exactly 64 lowercase hex. */
const HASH32 = /^[0-9a-f]{64}$/;
/** An address without its `0x`, which the server adds: exactly 40 lowercase hex. */
const ADDRESS = /^[0-9a-f]{40}$/;

/**
 * A compose file path, in the only shapes compose-manager's logs name:
 * `<name>.yaml` (or `.yml`), at the repository root or under ONE directory
 * (`prod/`, `experiments/`). Every path in the captured NEAR and Venice
 * evidence is one of these; the longest is 50 characters.
 *
 * The fetcher's own check (`isSafeRepositoryPath`) admits 512 characters of a
 * wider alphabet at any depth. That is right for a worker reading its own
 * evidence and far too much to accept from another process: a path is sent to
 * raw.githubusercontent.com whether or not the file exists.
 *
 * Directory: 1 to 24 of [A-Za-z0-9_-], starting alphanumeric.
 * Name: 1 to 64 of [A-Za-z0-9._-], starting alphanumeric. At most 94 in all.
 */
const COMPOSE_PATH = /^(?:[A-Za-z0-9][A-Za-z0-9_-]{0,23}\/)?[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.ya?ml$/;

export function isComposeFilePath(value: unknown): value is string {
  return typeof value === "string" && COMPOSE_PATH.test(value);
}

/** Most claims one publication request may carry: the fetcher's own file limit. */
export const MAX_PUBLICATION_CLAIMS = 512;

const claimSchema = z.object({
  commit: z.string().regex(COMMIT),
  path: z.string().regex(COMPOSE_PATH),
  // The fetcher's own tag shape. A tag is only ever looked up in the ref
  // advertisement the server already holds; it is never sent anywhere.
  tag: z.string().max(200).refine(isSafeTag).optional()
}).strict();

export const publicationRequestSchema = z.object({
  repository: z.enum(PUBLICATION_REPOSITORIES),
  // May be empty: the record then says only what the repository advertises,
  // which is what the fetcher returns for a log with no usable claim.
  claims: z.array(claimSchema).max(MAX_PUBLICATION_CLAIMS)
}).strict();

export const releaseImagesRequestSchema = z.object({
  repository: z.enum(RELEASE_REPOSITORIES)
}).strict();

export const onchainRequestSchema = z.object({
  registry: z.enum(ONCHAIN_REGISTRY_NAMES),
  appId: z.string().regex(ADDRESS),
  composeHash: z.string().regex(HASH32),
  // Must also be an image the server knows dstack published; see the server.
  osImageHash: z.string().regex(HASH32)
}).strict();

export type PublicationRequest = z.output<typeof publicationRequestSchema>;
export type ReleaseImagesRequest = z.output<typeof releaseImagesRequestSchema>;
export type OnchainRequest = z.output<typeof onchainRequestSchema>;
export type ReleaseCollateralClaim = PublicationRequest["claims"][number];

/**
 * Request body limits, per operation. The two fixed-shape bodies are a few
 * hundred bytes. A publication request is 512 claims of at most a commit, a
 * 94-character path and a 200-character tag.
 */
export const RELEASE_COLLATERAL_BODY_LIMIT_BYTES: Readonly<Record<ReleaseCollateralOperation, number>> = Object.freeze({
  "github-publication": 256 * 1024,
  "github-release-images": 256,
  "dstack-onchain-authorization": 512
});

const claimKey = (claim: ReleaseCollateralClaim) => `${claim.commit}\n${claim.path}\n${claim.tag ?? ""}`;

/**
 * Distinct claims in one fixed order.
 *
 * The server runs this on every request, whatever order it arrived in. The
 * fetcher asks its questions in claim order, so the order of a request would
 * otherwise show in the order of the upstream requests: a hundred claims can
 * be arranged in more ways than a commit hash has values.
 */
export function canonicalClaims(claims: readonly ReleaseCollateralClaim[]): ReleaseCollateralClaim[] {
  const distinct = new Map<string, ReleaseCollateralClaim>();
  for (const claim of claims) distinct.set(claimKey(claim), claim);
  return [...distinct.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, claim]) => claim);
}

/**
 * A provider log's claims as the contract carries them, for the CLIENT.
 *
 * It mirrors what the fetcher does with the same input: the commit is
 * lowercased, a claim whose commit or path is unusable is dropped, and a tag
 * that is not a safe ref name is ignored (the commit then has to be on the
 * default branch). The one difference is the path shape, which is this
 * contract's and narrower: a claim outside it is dropped here and so fails the
 * verifier as an unpublished file, where a worker making its own lookups would
 * have fetched it.
 */
export function contractClaims(claims: readonly PublicationClaim[]): ReleaseCollateralClaim[] {
  const kept: ReleaseCollateralClaim[] = [];
  for (const claim of claims) {
    const commit = typeof claim.commit === "string" ? claim.commit.toLowerCase() : "";
    if (!COMMIT.test(commit) || !isComposeFilePath(claim.path)) continue;
    kept.push(isSafeTag(claim.tag) ? { commit, path: claim.path, tag: claim.tag } : { commit, path: claim.path });
  }
  return canonicalClaims(kept);
}

/** An on-chain subject as the contract carries it, or null when it cannot be. */
export function contractOnchainSubject(subject: {
  appId: string;
  composeHash: string;
  osImageHash: string;
}): { appId: string; composeHash: string; osImageHash: string } | null {
  const appId = subject.appId.toLowerCase().replace(/^0x/, "");
  const composeHash = subject.composeHash.toLowerCase();
  const osImageHash = subject.osImageHash.toLowerCase();
  return ADDRESS.test(appId) && HASH32.test(composeHash) && HASH32.test(osImageHash)
    ? { appId, composeHash, osImageHash }
    : null;
}

// --- failures -------------------------------------------------------------------
//
// A fixed vocabulary. Nothing a caller sent is ever part of an error, in the
// response or in a log line.

export const RELEASE_COLLATERAL_ERROR_CODES = [
  /** The request is not one this contract admits. Nothing was looked up. */
  "release_collateral_request_refused",
  /** Well formed, but the OS image is not one dstack published. Nothing was looked up. */
  "release_collateral_os_image_unknown",
  /** The request rate, or the allowance for values not seen before, is spent. */
  "release_collateral_rate_limited",
  /** Too many lookups are already in flight. */
  "release_collateral_busy",
  /** The lookup was made and produced no answer within bounds. */
  "release_collateral_unavailable"
] as const;

export type ReleaseCollateralErrorCode = (typeof RELEASE_COLLATERAL_ERROR_CODES)[number];
