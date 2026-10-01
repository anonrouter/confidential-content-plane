// NEAR AI release authority: prove that a live NEAR serving TD runs what NEAR
// PUBLISHES, without pinning any single build.
//
// What a NEAR serving TD is (live evidence, 2026-10-01): dstack-nvidia guest OS
// + a boot compose that starts NEAR's `compose-manager`, which then pulls model
// compose files from GitHub and runs them. The boot measurements cover the
// manager; the model containers are covered by the manager's action log, which
// a SECOND TDX quote from the same TD binds (report_data = sha256(log) || nonce).
//
// The authority, layer by layer, each fail-closed, each anchored in what NEAR
// itself publishes (research 2026-10-01):
//
//   base image    MRTD/RTMR0-2 equal the registers dstack's PUBLISHED guest
//                 image (GitHub release, os_image_hash = sha256(sha256sum.txt))
//                 produces, named by the replayed RTMR3 "os-image-hash" event
//                 (`dstackImage.ts`).
//   boot compose  MRCONFIGID = 0x01 || sha256(app_compose); the event log
//                 replays to RTMR0-3 and its compose-hash event agrees. NEAR's
//                 own on-chain KMS registry on Base registers the app, the
//                 compose hash and the image (`dstackOnchain.ts`): the boot
//                 compose is rendered per host from a private template, and
//                 this registry is the only place NEAR publishes it. The
//                 measured compose pins compose-manager to NEAR's official
//                 compose repository (`GITHUB_REPO`).
//   manager       every compose-manager image that started (TD-signed log)
//                 and the launcher the boot compose names are digests of a
//                 nearai/compose-manager production release (`githubReleases.ts`).
//   runtime       every compose file the manager ran or staged since boot is
//                 at a commit NEAR published in nearai/cvm-compose-files (an
//                 advertised tag peels to it, or it is on the default branch)
//                 and hashes to the SHA-256 the TD logged (`github.ts`).
//
// Static measurement pins stay possible as an ADDITIONAL constraint (see
// near.ts), never as the gate: a NEAR redeploy of published software must keep
// passing without an AnonRouter release.
//
// Residual trust, all of it NEAR's own or GitHub's: one NEAR EOA controls the
// on-chain registry and can upgrade it; the compose repository's commits and
// tags are unsigned and tags are unprotected (a deleted tag fails closed); the
// action log is self-reported by in-TD software (bound by the quote, not
// hash-chained); request-time env values interpolated into composes are not
// logged; release notes and RPC answers are unsigned.

import { createHash } from "node:crypto";
import { readAttestedAppCompose } from "../../../gateway/appCompose.js";
import {
  EventLogError,
  inconsistentRtmr3Events,
  parseEventLog,
  replayRtmrs,
  singleEventPayload,
  type DstackEventLogEntry
} from "../../../gateway/eventLog.js";
import { check, hexEqual } from "../checks.js";
import { parseTdxQuote, type ParsedTdxQuote } from "../tdxQuote.js";
import type { AttestationCheck } from "../types.js";
import {
  normalizeRepository,
  publicationStatus,
  validGithubPublication,
  type GithubPublication,
  type PublicationClaim
} from "./github.js";
import { DSTACK_IMAGE_AUTHORITY, dstackImageCheck, type DstackImageAuthorityPolicy, type DstackImageMeasurements } from "./dstackImage.js";
import { dstackOnchainCheck, type DstackKmsIdentity, type DstackOnchainAuthorization } from "./dstackOnchain.js";
import { composeManagerImagesCheck, type GithubReleaseImages } from "./githubReleases.js";
import { pythonSortedJson } from "./pythonJson.js";

export const NEAR_RELEASE_AUTHORITY = "near-compose-manager-github/v1" as const;
export const NEAR_OFFICIAL_COMPOSE_REPOSITORY = "nearai/cvm-compose-files" as const;
/** Where compose-manager and its launcher are released (promote.yml, prod-* releases). */
export const NEAR_COMPOSE_MANAGER_REPOSITORY = "nearai/compose-manager" as const;
/** NEAR AI's dstack KMS on Base mainnet: the registry of boot composes and images it serves keys to. */
export const NEAR_DSTACK_KMS: DstackKmsIdentity = Object.freeze({
  chainId: 8453,
  kms: "0x8fa1593fac104c1aa0c59eaa3553f7e3e162d637"
});

/** The trust decision, fixed in code: which authority and which repository. */
export interface NearReleaseAuthorityPolicy {
  authority: typeof NEAR_RELEASE_AUTHORITY;
  /** "owner/name" of the only repository compose-manager may run files from. */
  composeRepository: string;
  /** How recent the repository read must be (tags can be deleted). */
  maxPublicationAgeMs: number;
  image: DstackImageAuthorityPolicy;
  /** The provider's on-chain KMS registry for its boot layer. */
  kms: DstackKmsIdentity;
  /** Where the compose-manager images are released. */
  composeManagerRepository: string;
  /** Optional ADDITIONAL static pins (MRTD/RTMR0-3 + composeSha256). Never the gate. */
  pinned?: readonly unknown[];
}

/**
 * Whether a measurement policy is exactly the NEAR release authority this code
 * implements. The repository and image authority are fixed here, like the
 * Tinfoil authority: a policy naming another repository is not "a NEAR
 * authority with a different repo", it is no authority at all, and fails.
 */
export function isNearReleaseAuthorityPolicy(value: unknown): value is NearReleaseAuthorityPolicy {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const policy = value as Partial<NearReleaseAuthorityPolicy>;
  return policy.authority === NEAR_RELEASE_AUTHORITY
    && policy.composeRepository === NEAR_OFFICIAL_COMPOSE_REPOSITORY
    && typeof policy.maxPublicationAgeMs === "number"
    && policy.maxPublicationAgeMs > 0
    && policy.maxPublicationAgeMs <= 24 * 60 * 60_000
    && policy.image?.authority === DSTACK_IMAGE_AUTHORITY
    && typeof policy.image.allowPrerelease === "boolean"
    && policy.kms?.chainId === NEAR_DSTACK_KMS.chainId
    && policy.kms.kms === NEAR_DSTACK_KMS.kms
    && policy.composeManagerRepository === NEAR_COMPOSE_MANAGER_REPOSITORY
    && (policy.pinned === undefined || Array.isArray(policy.pinned));
}

/** The collateral a fetch layer attaches for this authority. */
export interface NearReleaseCollateral {
  publication?: GithubPublication;
  images?: DstackImageMeasurements[];
  onchain?: DstackOnchainAuthorization;
  composeManagerReleases?: GithubReleaseImages;
}

interface ManagerAction {
  action?: unknown;
  commit?: unknown;
  file?: unknown;
  file_sha256?: unknown;
  tag?: unknown;
  image?: unknown;
}

interface NearDocument {
  intel_quote?: unknown;
  event_log?: unknown;
  info?: {
    compose_hash?: unknown;
    vm_config?: unknown;
    tcb_info?: { app_compose?: unknown; event_log?: unknown };
  };
  compose_manager_attestation?: {
    actions?: unknown;
    actions_hash?: unknown;
    nonce?: unknown;
    quote?: unknown;
  };
}

/** Every compose file a NEAR log says the manager ran or staged, as publication claims. */
export function nearPublicationClaims(document: unknown): Array<PublicationClaim & { sha256: string; action: string }> {
  const actions = (document as NearDocument | undefined)?.compose_manager_attestation?.actions;
  if (!Array.isArray(actions)) return [];
  const claims: Array<PublicationClaim & { sha256: string; action: string }> = [];
  for (const raw of actions as ManagerAction[]) {
    // Any action that names a file AND the hash of what it loaded is a claim
    // that this exact file entered the TD (compose_up, compose_stage, ...).
    // compose_down names no hash and loads nothing.
    if (typeof raw?.file_sha256 !== "string") continue;
    claims.push({
      action: typeof raw.action === "string" ? raw.action : "?",
      commit: typeof raw.commit === "string" ? raw.commit.toLowerCase() : "",
      path: typeof raw.file === "string" ? raw.file : "",
      tag: typeof raw.tag === "string" ? raw.tag : null,
      sha256: raw.file_sha256.toLowerCase()
    });
  }
  return claims;
}

/** The repository the measured boot compose points compose-manager at, or why not. */
export function composeManagerRepository(dockerComposeFile: string): { repository: string | null; detail: string } {
  // Lexical, like appCompose.ts: no YAML parser in the verifier. Every
  // assignment of GITHUB_REPO anywhere in the compose must name one value.
  const values = new Set<string>();
  const pattern = /GITHUB_REPO\s*[=:]\s*["']?([^\s"'#]+)/g;
  for (const match of dockerComposeFile.matchAll(pattern)) values.add(match[1]);
  if (values.size === 0) return { repository: null, detail: "the measured boot compose sets no GITHUB_REPO for compose-manager" };
  if (values.size > 1) return { repository: null, detail: "the measured boot compose sets GITHUB_REPO to more than one value" };
  const [value] = [...values];
  if (!value.startsWith("https://github.com/")) {
    return { repository: null, detail: "compose-manager's GITHUB_REPO is not a github.com repository" };
  }
  const repository = normalizeRepository(value);
  return repository
    ? { repository, detail: `compose-manager is configured for github.com/${repository}` }
    : { repository: null, detail: "compose-manager's GITHUB_REPO is malformed" };
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * The release-authority checks for one NEAR serving TD document (NEAR direct or
 * Venice's NEAR format). Pure: everything it needs is in its arguments.
 */
export function nearReleaseAuthorityChecks(input: {
  document: unknown;
  quote: ParsedTdxQuote;
  nonce: string;
  policy: NearReleaseAuthorityPolicy;
  collateral: NearReleaseCollateral | undefined;
  now: number;
}): AttestationCheck[] {
  const { quote, nonce, policy, now } = input;
  const doc = input.document as NearDocument | undefined;
  const checks: AttestationCheck[] = [];

  // --- boot compose and event log -----------------------------------------
  const appComposeRaw = doc?.info?.tcb_info?.app_compose;
  const appCompose = typeof appComposeRaw === "string" ? appComposeRaw : null;
  const composeHash = appCompose ? sha256Hex(appCompose) : null;
  const mrConfigOk = composeHash !== null && hexEqual(quote.mrConfigId, ("01" + composeHash).padEnd(96, "0"));
  let events: DstackEventLogEntry[] | null = null;
  let eventDetail = "";
  try {
    events = parseEventLog(doc?.event_log ?? doc?.info?.tcb_info?.event_log);
  } catch (error) {
    eventDetail = error instanceof EventLogError ? error.message : "event log unreadable";
  }
  let replayOk = false;
  let composeEvent: string | null = null;
  let osImageHash: string | null = null;
  let appId: string | null = null;
  if (events) {
    const replayed = replayRtmrs(events);
    replayOk = hexEqual(replayed[0], quote.rtmr0) && hexEqual(replayed[1], quote.rtmr1)
      && hexEqual(replayed[2], quote.rtmr2) && hexEqual(replayed[3], quote.rtmr3)
      && inconsistentRtmr3Events(events).length === 0;
    try {
      composeEvent = singleEventPayload(events, "compose-hash");
      osImageHash = singleEventPayload(events, "os-image-hash");
      appId = singleEventPayload(events, "app-id");
    } catch (error) {
      eventDetail = error instanceof EventLogError ? error.message : "event log unreadable";
      replayOk = false;
    }
    if (!replayOk && !eventDetail) eventDetail = "the event log does not replay to the quote's RTMRs";
  }
  const declaredComposeHash = typeof doc?.info?.compose_hash === "string" ? doc.info.compose_hash : null;
  const bootOk = mrConfigOk && replayOk && hexEqual(composeEvent, composeHash)
    && (declaredComposeHash === null || hexEqual(declaredComposeHash, composeHash));
  checks.push(check("authority_boot_compose_measured", bootOk, true, bootOk
    ? `boot compose ${composeHash!.slice(0, 16)}.. is MRCONFIGID and the measured compose-hash; the event log replays to RTMR0-3`
    : !appCompose ? "the document carries no app_compose"
      : !mrConfigOk ? "MRCONFIGID does not bind the returned app_compose"
        : eventDetail || "the measured compose-hash event disagrees with the app_compose"));

  // --- compose-manager repository (from the measured boot compose) ---------
  let managerRepository: string | null = null;
  let managerDetail = "the boot compose could not be read";
  let dockerComposeFile: string | null = null;
  if (appCompose) {
    try {
      const manifest = readAttestedAppCompose(appCompose);
      dockerComposeFile = manifest.dockerComposeFile;
      if (manifest.dockerComposeFile) {
        const found = composeManagerRepository(manifest.dockerComposeFile);
        managerRepository = found.repository;
        managerDetail = found.detail;
      } else {
        managerDetail = "the boot compose has no docker-compose document";
      }
    } catch {
      managerDetail = "the boot compose is not a dstack app-compose manifest";
    }
  }
  const authorityRepository = normalizeRepository(policy.composeRepository);
  const repoOk = bootOk && managerRepository !== null && managerRepository === authorityRepository;
  checks.push(check("authority_compose_repository", repoOk, true, repoOk
    ? `${managerDetail}, the release authority's official compose repository`
    : managerRepository && managerRepository !== authorityRepository
      ? `compose-manager is configured for github.com/${managerRepository}, not the official ${authorityRepository}`
      : managerDetail));

  // --- the provider registered this boot compose and image on chain --------
  checks.push(dstackOnchainCheck({
    record: input.collateral?.onchain,
    kms: policy.kms,
    maxAgeMs: policy.maxPublicationAgeMs,
    appId: bootOk ? appId : null,
    composeHash: bootOk ? composeHash : null,
    osImageHash: bootOk ? osImageHash : null,
    now
  }));

  // --- the compose-manager log, bound by the second quote ------------------
  const manager = doc?.compose_manager_attestation;
  const second = typeof manager?.quote === "string" ? parseTdxQuote(manager.quote) : null;
  let logOk = false;
  let logDetail = "the document carries no compose-manager attestation";
  if (manager && second) {
    const sameTd = hexEqual(second.mrTd, quote.mrTd) && hexEqual(second.mrConfigId, quote.mrConfigId)
      && hexEqual(second.rtmr0, quote.rtmr0) && hexEqual(second.rtmr1, quote.rtmr1)
      && hexEqual(second.rtmr2, quote.rtmr2) && hexEqual(second.rtmr3, quote.rtmr3);
    const text = Array.isArray(manager.actions) ? pythonSortedJson(manager.actions) : null;
    const actionsHash = text === null ? null : sha256Hex(text);
    const declared = typeof manager.actions_hash === "string" ? manager.actions_hash : null;
    const bindsLog = actionsHash !== null && hexEqual(second.reportData.slice(0, 64), actionsHash)
      && hexEqual(declared, actionsHash);
    const bindsNonce = hexEqual(second.reportData.slice(64, 128), nonce);
    logOk = sameTd && bindsLog && bindsNonce && !second.debugEnabled;
    logDetail = logOk
      ? `a second quote from the same TD binds sha256 of the ${(manager.actions as unknown[]).length}-entry action log and the caller nonce`
      : !sameTd ? "the compose-manager quote is from a different TD (registers differ)"
        : !bindsLog ? "the compose-manager quote does not bind sha256 of the action log"
          : !bindsNonce ? "the compose-manager quote does not carry the caller nonce"
            : "the compose-manager quote is from a debug TD";
  } else if (manager) {
    logDetail = "the compose-manager quote did not parse";
  }
  checks.push(check("authority_runtime_log_bound", logOk, true, logDetail));

  // --- every compose file that entered the TD is published -----------------
  const publication = input.collateral?.publication;
  const claims = nearPublicationClaims(doc);
  let publishedOk = false;
  let publishedDetail: string;
  if (!logOk) {
    publishedDetail = "no verified action log to check against the repository";
  } else if (!publication) {
    publishedDetail = "no publication collateral for the official repository was supplied";
  } else if (!validGithubPublication(publication)) {
    publishedDetail = "the publication collateral is malformed";
  } else if (publication.repository !== authorityRepository) {
    publishedDetail = `the publication collateral describes ${publication.repository}, not ${authorityRepository}`;
  } else if (claims.length === 0 || !claims.some((claim) => claim.action === "compose_up")) {
    publishedDetail = "the action log starts no compose file";
  } else {
    const failures: string[] = [];
    let tagged = 0;
    for (const claim of claims) {
      const status = publicationStatus(publication, claim, claim.sha256);
      if (!status.published) failures.push(`${claim.action}: ${status.detail}`);
      else if (status.how === "tag") tagged += 1;
    }
    publishedOk = failures.length === 0;
    const distinct = new Set(claims.map((claim) => `${claim.commit}:${claim.path}`)).size;
    publishedDetail = publishedOk
      ? `${claims.length} compose actions (${distinct} distinct files, ${tagged} by release tag) all match files published in ${publication.repository}`
      : `unpublished compose (${failures.length} of ${claims.length}): ${failures.slice(0, 3).join("; ")}${failures.length > 3 ? "; ..." : ""}`;
  }
  checks.push(check("authority_runtime_composes_published", publishedOk, true, publishedDetail));

  // --- every compose-manager image that ran, and the boot compose's launcher,
  //     is a production release ---------------------------------------------
  checks.push(logOk
    ? composeManagerImagesCheck({
      document: doc,
      dockerComposeFile: bootOk ? dockerComposeFile : null,
      record: input.collateral?.composeManagerReleases,
      repository: policy.composeManagerRepository,
      maxAgeMs: policy.maxPublicationAgeMs,
      now
    })
    : check("authority_compose_manager_released", false, true, "no verified action log to check the compose-manager images against"));

  const fresh = Boolean(publication && typeof publication.fetchedAtMs === "number"
    && now - publication.fetchedAtMs <= policy.maxPublicationAgeMs && publication.fetchedAtMs - now <= 30_000);
  checks.push(check("authority_publication_fresh", fresh, true, fresh
    ? undefined
    : "the official repository was not read recently enough to rule out a withdrawn release"));

  // --- base image ------------------------------------------------------------
  checks.push(dstackImageCheck({
    quote,
    osImageHash: replayOk ? osImageHash : null,
    policy: policy.image,
    images: input.collateral?.images
  }));

  return checks;
}
