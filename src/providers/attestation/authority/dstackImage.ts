// dstack base-image authority: MRTD and RTMR0-2 must be registers that
// dstack's PUBLISHED guest image produces.
//
// What is measured where (dstack-mr, Dstack-TEE/dstack):
//   MRTD   the TDVF firmware pages (and QEMU's page-add mode)   image + QEMU
//   RTMR0  firmware config, TD HOB, ACPI tables                 image + VM shape
//   RTMR1  the kernel (bzImage) and boot-services events         image (+ memory on 0.5.x)
//   RTMR2  kernel command line (it carries the rootfs hash) and initrd   image
// RTMR3 is the workload (app-id, compose-hash, os-image-hash, ...) and is
// handled by the event-log replay, not here.
//
// The image is identified by `os_image_hash` = sha256(sha256sum.txt of the
// release), which the guest measures into RTMR3 as the "os-image-hash" event.
// The caller passes that value only after the event log has replayed, so it
// is hardware-attested. `vm_config` is never trusted: a record passes a TD
// only when ALL FOUR registers equal one computed set, so a lying vm_config
// can only select a set that then fails to match.
//
// The register sets are DERIVED collateral: computed by
// native/dstack-image-measurements (dstack-mr from the official dstack repo at
// a pinned commit) from the release asset dstack publishes on GitHub, after
// checking every file against the release's sha256sum.txt. They are facts
// about a published artifact, not a reviewed allowlist. A new image or host
// shape needs the generator re-run (scripts/dstack-image-measurements.sh), never
// a review or a policy change.

import { check, hexEqual } from "../checks.js";
import type { ParsedTdxQuote } from "../tdxQuote.js";
import type { AttestationCheck } from "../types.js";

export const DSTACK_IMAGE_AUTHORITY = "dstack-published-os-images/v1" as const;

export interface DstackImageAuthorityPolicy {
  authority: typeof DSTACK_IMAGE_AUTHORITY;
  /** Accept a published PRERELEASE image (owner decision; default refuse). */
  allowPrerelease: boolean;
}

export interface DstackRegisterSet {
  /** The dstack-mr inputs (vm_config without the image fields), for the audit trail. */
  shape: Record<string, unknown>;
  mrtd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
}

export interface DstackImageMeasurements {
  /** sha256(sha256sum.txt), the dstack os_image_hash. */
  osImageHash: string;
  /** Published asset name, e.g. "dstack-nvidia-0.5.11". */
  image: string;
  /** Release URL the bytes came from and what was checked. */
  source: string;
  prerelease: boolean;
  isDev: boolean;
  /** Tool and dstack commit that computed the registers. */
  computedBy: string;
  /** SHA-256 of dstack's TDX measurement document for the image. */
  measurementDocumentSha256: string;
  measurements: DstackRegisterSet[];
}

const hex = (value: unknown, chars: number) => typeof value === "string" && value.length === chars && /^[0-9a-f]+$/.test(value);

export function validDstackImageMeasurements(value: unknown): value is DstackImageMeasurements {
  if (!value || typeof value !== "object") return false;
  const record = value as Partial<DstackImageMeasurements>;
  return hex(record.osImageHash, 64)
    && typeof record.image === "string" && record.image.length > 0
    && typeof record.source === "string"
    && typeof record.prerelease === "boolean"
    && typeof record.isDev === "boolean"
    && typeof record.computedBy === "string"
    && hex(record.measurementDocumentSha256, 64)
    && Array.isArray(record.measurements) && record.measurements.length > 0
    && record.measurements.every((set) => set && typeof set.shape === "object"
      && hex(set.mrtd, 96) && hex(set.rtmr0, 96) && hex(set.rtmr1, 96) && hex(set.rtmr2, 96));
}

/** `authority_base_image_published`: the TD booted a published dstack image. */
export function dstackImageCheck(input: {
  quote: ParsedTdxQuote;
  /** From the REPLAYED event log only; null when the log did not replay. */
  osImageHash: string | null;
  policy: DstackImageAuthorityPolicy;
  images: DstackImageMeasurements[] | undefined;
}): AttestationCheck {
  const name = "authority_base_image_published";
  const { quote, osImageHash } = input;
  if (!osImageHash || !/^[0-9a-f]{64}$/.test(osImageHash)) {
    return check(name, false, true, "no replayed os-image-hash event names the guest image");
  }
  const record = (input.images ?? []).find((image) => validDstackImageMeasurements(image) && image.osImageHash === osImageHash);
  if (!record) {
    return check(name, false, true,
      `no registers computed from dstack's published image ${osImageHash.slice(0, 16)}.. were supplied (run scripts/dstack-image-measurements.sh for it)`);
  }
  if (record.isDev) return check(name, false, true, `${record.image} is a development image`);
  if (record.prerelease && !input.policy.allowPrerelease) {
    return check(name, false, true, `${record.image} is a prerelease, which this policy does not accept`);
  }
  const matched = record.measurements.find((set) => hexEqual(set.mrtd, quote.mrTd)
    && hexEqual(set.rtmr0, quote.rtmr0) && hexEqual(set.rtmr1, quote.rtmr1) && hexEqual(set.rtmr2, quote.rtmr2));
  if (!matched) {
    const sameImageRegisters = record.measurements.some((set) => hexEqual(set.rtmr1, quote.rtmr1) && hexEqual(set.rtmr2, quote.rtmr2));
    return check(name, false, true, sameImageRegisters
      ? `MRTD/RTMR0 match no VM shape computed from ${record.image}: the firmware or virtual hardware is not a computed published configuration`
      : `MRTD/RTMR0-2 do not reproduce from ${record.image} as published (${record.computedBy})`);
  }
  const shape = matched.shape as { cpu_count?: unknown; num_gpus?: unknown };
  return check(name, true, true,
    `MRTD and RTMR0-2 reproduce from dstack's published ${record.image} (${osImageHash.slice(0, 16)}..) for a ${String(shape.cpu_count ?? "?")} CPU / ${String(shape.num_gpus ?? "?")} GPU VM (${record.computedBy})`);
}
