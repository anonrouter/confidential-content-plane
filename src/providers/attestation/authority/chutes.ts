// Chutes release authority: a live instance's registers must be a tuple Chutes
// PUBLISHES, from a guest-image version Chutes released in its public
// repository. No AnonRouter-side list of builds.
//
// Chutes' only machine-readable publication of what its TEE servers run is the
// unauthenticated API `GET https://api.chutes.ai/servers/tee/measurements`
// (research 2026-10-01). Each entry is one (version, host shape) with MRTD and
// the RUNTIME RTMR0-3. Within a version MRTD, RTMR1, RTMR2 and RTMR3 are one
// value; RTMR0 varies with the host topology. The list's source of truth is a
// values file in a PRIVATE repository (chutes-ops); the image source is the
// public github.com/chutesai/sek8s, whose CI tags every release `v<version>`.
//
// So the narrowest honest check is two-part, both required:
//   1. the instance's exact (MRTD, RTMR0..3) is an entry of a recent snapshot of
//      the published list (snapshot fetched by a separate layer);
//   2. that entry's version is a release tag `v<version>` advertised by
//      chutesai/sek8s, i.e. the version was released from public source.
//
// Residual trust: the list is operator-published, unsigned, has no
// transparency log or public history, and hides release-candidate entries; the
// sek8s tags are lightweight and unsigned; images are built and uploaded by an
// operator. MRTD (firmware committed in sek8s) and RTMR1/RTMR2 (kernel, initrd,
// cmdline on vm.chutes.ai) were reproduced for 1.4.x by hand; RTMR0 and RTMR3
// are accepted on Chutes' word. Neither the chute container nor the model
// weights appear in any register.

import { check, hexEqual } from "../checks.js";
import type { ParsedTdxQuote } from "../tdxQuote.js";
import type { AttestationCheck } from "../types.js";

export const CHUTES_RELEASE_AUTHORITY = "chutes-published-measurements/v1" as const;
export const CHUTES_MEASUREMENTS_SOURCE = "https://api.chutes.ai/servers/tee/measurements" as const;
export const CHUTES_IMAGE_REPOSITORY = "chutesai/sek8s" as const;

export interface ChutesReleaseAuthorityPolicy {
  authority: typeof CHUTES_RELEASE_AUTHORITY;
  measurementsSource: string;
  imageRepository: string;
  maxPublicationAgeMs: number;
}

export interface ChutesPublishedMeasurement {
  version: string;
  name: string;
  mrtd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  gpuCount: number | null;
  fingerprint: string | null;
}

export interface ChutesReleaseCollateral {
  v: 1;
  source: string;
  fetchedAtMs: number;
  /** SHA-256 of the exact list body, so a snapshot can be audited later. */
  bodySha256: string;
  measurements: ChutesPublishedMeasurement[];
  imageRepository: {
    repository: string;
    fetchedAtMs: number;
    /** release tag -> commit, as advertised by the repository. */
    tags: Record<string, string>;
  };
}

const HEX96 = /^[0-9a-f]{96}$/;

/** Normalize the published API body into runtime tuples. Unusable entries are dropped. */
export function normalizeChutesMeasurements(body: unknown): ChutesPublishedMeasurement[] {
  if (!Array.isArray(body)) return [];
  const out: ChutesPublishedMeasurement[] = [];
  for (const entry of body as Array<Record<string, unknown>>) {
    const runtime = entry?.runtime_rtmrs as Record<string, unknown> | undefined;
    const lower = (value: unknown) => (typeof value === "string" ? value.toLowerCase() : "");
    const item: ChutesPublishedMeasurement = {
      version: typeof entry?.version === "string" ? entry.version : "",
      name: typeof entry?.name === "string" ? entry.name : "",
      mrtd: lower(entry?.mrtd),
      rtmr0: lower(runtime?.RTMR0),
      rtmr1: lower(runtime?.RTMR1),
      rtmr2: lower(runtime?.RTMR2),
      rtmr3: lower(runtime?.RTMR3),
      gpuCount: typeof entry?.gpu_count === "number" ? entry.gpu_count : null,
      fingerprint: typeof entry?.fingerprint === "string" ? entry.fingerprint : null
    };
    if (/^\d+\.\d+\.\d+$/.test(item.version)
      && [item.mrtd, item.rtmr0, item.rtmr1, item.rtmr2, item.rtmr3].every((value) => HEX96.test(value))) {
      out.push(item);
    }
  }
  return out;
}

/** The published entry an instance's registers match exactly, if any. */
export function matchChutesPublished(quote: ParsedTdxQuote, published: ChutesPublishedMeasurement[]): ChutesPublishedMeasurement | null {
  return published.find((entry) => hexEqual(entry.mrtd, quote.mrTd)
    && hexEqual(entry.rtmr0, quote.rtmr0)
    && hexEqual(entry.rtmr1, quote.rtmr1)
    && hexEqual(entry.rtmr2, quote.rtmr2)
    && hexEqual(entry.rtmr3, quote.rtmr3)) ?? null;
}

/** `<label>_release_authority` for one Chutes instance. */
export function chutesReleaseAuthorityCheck(input: {
  label: string;
  quote: ParsedTdxQuote;
  policy: ChutesReleaseAuthorityPolicy;
  collateral: ChutesReleaseCollateral | undefined;
  now: number;
}): AttestationCheck {
  const name = `${input.label}_release_authority`;
  const { collateral, policy, now } = input;
  if (!collateral || collateral.v !== 1 || !Array.isArray(collateral.measurements)) {
    return check(name, false, true, "no snapshot of Chutes' published measurements was supplied");
  }
  if (collateral.source !== policy.measurementsSource) {
    return check(name, false, true, "the measurement snapshot is not from Chutes' official endpoint");
  }
  const age = now - collateral.fetchedAtMs;
  if (!(age <= policy.maxPublicationAgeMs && age >= -30_000)) {
    return check(name, false, true, "the snapshot of Chutes' published measurements is too old");
  }
  const tags = collateral.imageRepository;
  if (!tags || tags.repository !== policy.imageRepository || typeof tags.tags !== "object" || tags.tags === null) {
    return check(name, false, true, `no tag list for ${policy.imageRepository} was supplied`);
  }
  const tagAge = now - tags.fetchedAtMs;
  if (!(tagAge <= policy.maxPublicationAgeMs && tagAge >= -30_000)) {
    return check(name, false, true, `the tag list for ${policy.imageRepository} is too old`);
  }
  const entry = matchChutesPublished(input.quote, collateral.measurements);
  if (!entry) {
    return check(name, false, true,
      `MRTD/RTMR0-3 (MRTD ${input.quote.mrTd.slice(0, 16)}..) are not an entry of Chutes' published list (${collateral.bodySha256.slice(0, 16)}..)`);
  }
  const tag = `v${entry.version}`;
  if (!tags.tags[tag]) {
    return check(name, false, true,
      `published sek8s ${entry.version} has no release tag ${tag} in ${policy.imageRepository}: it was not released from public source`);
  }
  return check(name, true, true,
    `registers are Chutes' published "${entry.name}" for sek8s ${entry.version}, released as ${tag} (${tags.tags[tag].slice(0, 12)}) in ${policy.imageRepository}`);
}
