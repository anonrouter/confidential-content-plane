// Release-authority collateral: how the fetch layer hands publication data to
// the pure verifiers, and how it travels with the evidence.
//
// The worker (the only process with provider egress) fetches the provider's
// evidence AND this collateral, then returns the evidence document with the
// collateral attached under one namespaced key. That key is AnonRouter's, not
// the provider's: it is never read as provider evidence, and every byte of it
// that can be is re-checked against TD-signed values (file hashes against the
// compose-manager log, registers against the quote). What cannot be
// re-checked (GitHub's tag and branch answers) is stated as residual trust.
//
// The same object is the native engine's `collateral.release`
// (native/hw-verifier/src/authority/mod.rs), field for field.

import { parseEventLog, singleEventPayload } from "../../../gateway/eventLog.js";
import type { ChutesReleaseCollateral } from "./chutes.js";
import type { DstackImageMeasurements } from "./dstackImage.js";
import { DSTACK_IMAGE_MEASUREMENTS } from "./dstackImages.generated.js";
import { DstackOnchainFetcher, type DstackOnchainAuthorization } from "./dstackOnchain.js";
import type { GithubPublication } from "./github.js";
import { GithubPublicationFetcher } from "./githubFetcher.js";
import { GithubReleasesFetcher, type GithubReleaseImages } from "./githubReleases.js";
import {
  NEAR_COMPOSE_MANAGER_REPOSITORY,
  NEAR_DSTACK_KMS,
  NEAR_OFFICIAL_COMPOSE_REPOSITORY,
  nearPublicationClaims,
  type NearReleaseCollateral
} from "./near.js";

export const RELEASE_COLLATERAL_FIELD = "anonrouter_release_collateral" as const;

export interface ReleaseCollateral {
  /** Repository publication records (one per official repository). */
  github?: GithubPublication[];
  /** Image digests published by release workflows (one per repository). */
  githubReleases?: GithubReleaseImages[];
  /** Registers computed from published dstack images. */
  dstackImages?: DstackImageMeasurements[];
  /** dstack on-chain KMS authorizations. */
  onchain?: DstackOnchainAuthorization[];
  chutes?: ChutesReleaseCollateral;
}

/** Attach collateral to a provider document without disturbing its own fields.
 *  Overwrites any value the provider put under the same key. */
export function withReleaseCollateral<T extends object>(document: T, collateral: ReleaseCollateral): T & { [RELEASE_COLLATERAL_FIELD]: ReleaseCollateral } {
  return { ...document, [RELEASE_COLLATERAL_FIELD]: collateral };
}

/**
 * A shallow copy of a provider document with the collateral key REMOVED.
 *
 * The key is AnonRouter's namespace, and the verifiers (server and browser)
 * read collateral from it and nowhere else. A provider that sends the key is
 * not trusted for it: if it reached a verifier, the provider would be
 * supplying the very publication data its evidence is checked against. Every
 * adapter path that returns evidence therefore either overwrites the key with
 * the fetch layer's own answer or removes it; on a fetch failure it is absent
 * and the authority checks fail closed.
 */
export function withoutReleaseCollateral<T extends object>(document: T): Omit<T, typeof RELEASE_COLLATERAL_FIELD> {
  // A JSON array cannot carry a named key, and copying it into an object
  // would change the evidence's shape.
  if (Array.isArray(document)) return document;
  const copy: Record<string, unknown> = { ...(document as Record<string, unknown>) };
  delete copy[RELEASE_COLLATERAL_FIELD];
  return copy as Omit<T, typeof RELEASE_COLLATERAL_FIELD>;
}

/** Remove any provider-supplied collateral, then attach ours if the fetch layer produced it. */
export function replaceReleaseCollateral<T extends object>(document: T, collateral: ReleaseCollateral | undefined): Omit<T, typeof RELEASE_COLLATERAL_FIELD> & { [RELEASE_COLLATERAL_FIELD]?: ReleaseCollateral } {
  const stripped = withoutReleaseCollateral(document);
  return collateral ? withReleaseCollateral(stripped, collateral) : stripped;
}

export function releaseCollateralOf(document: unknown): ReleaseCollateral | undefined {
  if (!document || typeof document !== "object") return undefined;
  const value = (document as Record<string, unknown>)[RELEASE_COLLATERAL_FIELD];
  return value && typeof value === "object" && !Array.isArray(value) ? value as ReleaseCollateral : undefined;
}

/** The NEAR view of the collateral: the official repository's record and the image registers. */
export function nearCollateralFrom(collateral: ReleaseCollateral | undefined, repository: string = NEAR_OFFICIAL_COMPOSE_REPOSITORY): NearReleaseCollateral | undefined {
  if (!collateral) return undefined;
  return {
    publication: collateral.github?.find((record) => record.repository === repository),
    images: collateral.dstackImages,
    onchain: collateral.onchain?.[0],
    composeManagerReleases: collateral.githubReleases?.find((record) => record.repository === NEAR_COMPOSE_MANAGER_REPOSITORY)
  };
}

/** NEAR's serving-TD format: a quote plus a compose-manager attestation. */
export function isNearServingDocument(document: unknown): boolean {
  if (!document || typeof document !== "object") return false;
  const doc = document as { intel_quote?: unknown; compose_manager_attestation?: unknown };
  return typeof doc.intel_quote === "string" && Boolean(doc.compose_manager_attestation)
    && typeof doc.compose_manager_attestation === "object";
}

function osImageHashOf(document: unknown): string | null {
  const info = (document as { info?: { os_image_hash?: unknown } } | undefined)?.info;
  return typeof info?.os_image_hash === "string" && /^[0-9a-f]{64}$/i.test(info.os_image_hash)
    ? info.os_image_hash.toLowerCase()
    : null;
}

/** The (app, compose, image) a NEAR document claims, for the on-chain lookup.
 *  Read from the document's own event log; the verifier re-derives each from
 *  the replayed log and MRCONFIGID before trusting the answer. */
function onchainSubject(document: unknown): { appId: string; composeHash: string; osImageHash: string } | null {
  const doc = document as { event_log?: unknown; info?: { tcb_info?: { event_log?: unknown; app_compose?: unknown } } } | undefined;
  try {
    const events = parseEventLog(doc?.event_log ?? doc?.info?.tcb_info?.event_log);
    const appId = singleEventPayload(events, "app-id");
    const composeHash = singleEventPayload(events, "compose-hash");
    const osImageHash = singleEventPayload(events, "os-image-hash");
    return appId && composeHash && osImageHash ? { appId, composeHash, osImageHash } : null;
  } catch {
    return null;
  }
}

export interface NearReleaseSources {
  /** nearai/cvm-compose-files. */
  composeRepository: GithubPublicationFetcher;
  /** nearai/compose-manager releases. */
  composeManagerReleases: GithubReleasesFetcher;
  /** NEAR's dstack KMS on Base. */
  onchain: DstackOnchainFetcher;
  images?: readonly DstackImageMeasurements[];
}

/**
 * Fetch layer for NEAR-format documents (NEAR direct and Venice's NEAR
 * routes). Each source that fails simply contributes nothing: the verifier
 * then fails that layer closed with a specific reason. Nothing here decides.
 */
export class NearReleaseCollateralSource {
  private readonly images: readonly DstackImageMeasurements[];

  constructor(private readonly sources: NearReleaseSources) {
    this.images = sources.images ?? DSTACK_IMAGE_MEASUREMENTS;
  }

  async collect(document: unknown, signal?: AbortSignal): Promise<ReleaseCollateral> {
    const collateral: ReleaseCollateral = {};
    // Only NEAR's serving-TD format (with a compose-manager attestation) has
    // anything to look up; anything else gets no collateral and no traffic.
    if (!isNearServingDocument(document)) return collateral;
    const os = osImageHashOf(document);
    const image = os ? this.images.filter((record) => record.osImageHash === os) : [];
    if (image.length > 0) collateral.dstackImages = [...image];
    const claims = nearPublicationClaims(document);
    const subject = onchainSubject(document);
    const [publication, releases, onchain] = await Promise.allSettled([
      claims.length > 0 ? this.sources.composeRepository.collect(claims, signal) : Promise.reject(new Error("no claims")),
      this.sources.composeManagerReleases.collect(signal),
      subject ? this.sources.onchain.authorize(subject, signal) : Promise.reject(new Error("no subject"))
    ]);
    if (publication.status === "fulfilled") collateral.github = [publication.value];
    if (releases.status === "fulfilled") collateral.githubReleases = [releases.value];
    if (onchain.status === "fulfilled") collateral.onchain = [onchain.value];
    return collateral;
  }
}

/** Base mainnet JSON-RPC endpoints, public and keyless, tried in order. */
export const BASE_PUBLIC_RPC_URLS: readonly string[] = Object.freeze(["https://mainnet.base.org", "https://base-rpc.publicnode.com"]);

/** Default public sources for NEAR (no credential anywhere). */
export function defaultNearReleaseSources(fetchImpl?: (input: string, init?: RequestInit) => Promise<Response>): NearReleaseSources {
  return {
    composeRepository: new GithubPublicationFetcher({ repository: NEAR_OFFICIAL_COMPOSE_REPOSITORY, fetch: fetchImpl }),
    composeManagerReleases: new GithubReleasesFetcher(NEAR_COMPOSE_MANAGER_REPOSITORY, { fetch: fetchImpl }),
    onchain: new DstackOnchainFetcher({ kms: NEAR_DSTACK_KMS, rpcUrls: [...BASE_PUBLIC_RPC_URLS], fetch: fetchImpl })
  };
}
