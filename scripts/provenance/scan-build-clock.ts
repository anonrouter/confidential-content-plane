// Does this image record its own build clock inside a file's CONTENT?
//
// =============================================================================
// WHY THIS IS A DIFFERENT QUESTION FROM "ARE THE TIMESTAMPS NORMALISED"
// =============================================================================
//
// A reproducible-build discussion usually stops at metadata: file mtimes, the
// image config's `created`, the history entries. All of those are fixable, and
// the standard fixes are well known (`SOURCE_DATE_EPOCH`, buildkit's
// `rewrite-timestamp`).
//
// None of them touch file CONTENT. If a build step writes the wall clock into a
// file it then ships -- `/var/log/dpkg.log` is the canonical example, and every
// Debian-derived image that runs `apt-get install` without deleting it has one
// -- then the layer tar contains a record of WHEN the build ran, not of what it
// built. No timestamp-normalisation flag rewrites it, because to the build
// system it is ordinary data.
//
// That makes it a hard obstruction rather than a hard problem: two honest
// builds of identical source, on identical inputs, in the same environment,
// cannot produce the same bytes. It has to be measured rather than assumed,
// because the alternative is asserting an image is irreproducible without
// having looked, which is the same failure as asserting it is reproducible
// without having built it.
//
// =============================================================================
// WHAT THIS DOES NOT CLAIM
// =============================================================================
//
// A hit is evidence that reproduction is impossible for that artifact as built.
// NO hits is not evidence that it is possible: the clock could be embedded in a
// binary format this scan cannot read, package versions could have moved in the
// archive, or the build could be non-deterministic for reasons that have
// nothing to do with time. Only a rebuild decides that, and this exists to say
// what a rebuild would be up against before spending the compute.
//
//   npx tsx scripts/provenance/scan-build-clock.ts <layout-or-reference> <rfc3339-start> <rfc3339-end> [--json]

import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { EscrowError, fail, run } from "./escrowRuntime.js";

export const SCAN_SCHEMA = "anonrouter-build-clock-scan-v1";

export interface BuildClockHit {
  path: string;
  bytes: number;
  /** Distinct minute-resolution stamps found, capped so one log cannot flood the report. */
  matches: string[];
  totalMatches: number;
}

export interface BuildClockScan {
  schema: typeof SCAN_SCHEMA;
  reference: string;
  window: { start: string; end: string; minutes: string[] };
  filesScanned: number;
  filesSkippedTooLarge: number;
  hits: BuildClockHit[];
  /** True when at least one shipped file records the build's own wall clock. */
  embedsBuildClock: boolean;
}

/** Files above this are not scanned. A log that matters is never megabytes. */
const MAX_BYTES = 1024 * 1024;
const MAX_MATCHES_REPORTED = 5;

/**
 * Every minute between start and end, as `YYYY-MM-DD HH:MM`.
 *
 * Minute resolution rather than second: `dpkg.log` lines and `apt/history.log`
 * headers are second-resolution, so a minute prefix matches them all while
 * still being specific enough that a random file cannot contain one by
 * accident. A build window wider than a few hours is refused rather than
 * scanned, because at that point the pattern stops being evidence.
 */
export function minutesInWindow(start: string, end: string): string[] {
  const from = Date.parse(start);
  const to = Date.parse(end);
  if (!Number.isFinite(from) || !Number.isFinite(to)) fail(`build window is not two RFC3339 timestamps: ${start} .. ${end}`);
  if (to < from) fail(`build window ends before it starts: ${start} .. ${end}`);
  const minutes: string[] = [];
  for (let t = Math.floor(from / 60000) * 60000; t <= to; t += 60000) {
    minutes.push(new Date(t).toISOString().slice(0, 16).replace("T", " "));
    if (minutes.length > 240) {
      fail(
        `build window ${start} .. ${end} spans more than four hours.\n` +
          "A window that wide would make a match weak evidence rather than strong, so this refuses instead of\n" +
          "reporting a hit it cannot stand behind."
      );
    }
  }
  return minutes;
}

/**
 * Same forced-open walk as the comparison tool, for the same reason: Debian
 * ships `/var/lock/lvm` at mode 0700 owned by root, so an unprivileged
 * extraction produces a directory whose contents cannot be listed. A scan that
 * gave up there would report "no build clock found" for precisely the images
 * most likely to contain one.
 *
 * `lstat`, so a symlink is skipped as a symlink rather than followed and its
 * target scanned twice.
 */
function walk(directory: string, base: string, out: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EACCES") throw error;
    const stats = lstatSync(directory, { throwIfNoEntry: false });
    chmodSync(directory, ((stats?.mode ?? 0) & 0o7777) | 0o700);
    entries = readdirSync(directory);
  }
  for (const entry of entries) {
    const full = join(directory, entry);
    const stats = lstatSync(full, { throwIfNoEntry: false });
    if (!stats) continue;
    if (stats.isSymbolicLink()) continue;
    if (stats.isDirectory()) walk(full, base, out);
    else if (stats.isFile()) out.push(relative(base, full));
  }
  return out;
}

export function scanBuildClock(reference: string, start: string, end: string): BuildClockScan {
  const minutes = minutesInWindow(start, end);
  const scratch = mkdtempSync(join(tmpdir(), "build-clock-"));
  try {
    let layout = reference;
    if (!existsSync(join(reference, "index.json"))) {
      layout = join(scratch, "layout");
      run("crane", ["pull", "--format=oci", reference, layout], { maxBuffer: 8 * 1024 * 1024 });
    }
    const rootfs = join(scratch, "rootfs");
    run("mkdir", ["-p", rootfs]);

    const index = JSON.parse(readFileSync(join(layout, "index.json"), "utf8")) as {
      manifests: Array<{ digest: string }>;
    };
    if (index.manifests.length !== 1) fail(`${reference}: layout index names ${index.manifests.length} manifests`);
    const manifestDigest = index.manifests[0].digest;
    const manifestBytes = readFileSync(join(layout, "blobs", "sha256", manifestDigest.replace("sha256:", "")));
    if (`sha256:${createHash("sha256").update(manifestBytes).digest("hex")}` !== manifestDigest) {
      fail(`${reference}: manifest blob does not hash to the digest the index names`);
    }
    const manifest = JSON.parse(manifestBytes.toString("utf8")) as { layers: Array<{ digest: string }> };
    for (const layer of manifest.layers) {
      // Best effort, exactly as the comparison tool does it: layer tars carry
      // entries an unprivileged extraction cannot recreate, and abandoning the
      // scan over a device node would mean never scanning anything.
      run("tar", ["-xf", join(layout, "blobs", "sha256", layer.digest.replace("sha256:", "")), "-C", rootfs], {
        allowFailure: true,
        maxBuffer: 64 * 1024 * 1024
      });
    }

    const hits: BuildClockHit[] = [];
    let filesScanned = 0;
    let filesSkippedTooLarge = 0;
    for (const path of walk(rootfs, rootfs)) {
      const full = join(rootfs, path);
      const stats = statSync(full, { throwIfNoEntry: false });
      if (!stats) continue;
      if (stats.size > MAX_BYTES) {
        filesSkippedTooLarge += 1;
        continue;
      }
      filesScanned += 1;
      let text: string;
      try {
        text = readFileSync(full, "latin1");
      } catch {
        continue;
      }
      const found: string[] = [];
      let total = 0;
      for (const minute of minutes) {
        let at = text.indexOf(minute);
        while (at >= 0) {
          total += 1;
          if (found.length < MAX_MATCHES_REPORTED && !found.includes(minute)) found.push(minute);
          at = text.indexOf(minute, at + minute.length);
        }
      }
      if (total > 0) hits.push({ path, bytes: stats.size, matches: found, totalMatches: total });
    }
    hits.sort((a, b) => b.totalMatches - a.totalMatches);

    return {
      schema: SCAN_SCHEMA,
      reference,
      window: { start, end, minutes },
      filesScanned,
      filesSkippedTooLarge,
      hits,
      embedsBuildClock: hits.length > 0
    };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const json = process.argv.includes("--json");
  const args = process.argv.slice(2).filter((a) => a !== "--json");
  try {
    if (args.length !== 3) fail("usage: scan-build-clock.ts <layout-or-reference> <rfc3339-start> <rfc3339-end> [--json]");
    const scan = scanBuildClock(args[0], args[1], args[2]);
    if (json) {
      process.stdout.write(`${JSON.stringify(scan, null, 2)}\n`);
    } else {
      process.stdout.write(`scanned ${scan.filesScanned} files (${scan.filesSkippedTooLarge} over 1 MiB skipped)\n`);
      process.stdout.write(`build window ${scan.window.start} .. ${scan.window.end}\n\n`);
      if (!scan.embedsBuildClock) {
        process.stdout.write("No shipped file contains this image's own build minute.\n");
        process.stdout.write("That does NOT mean the image is reproducible. It means this particular\n");
        process.stdout.write("obstruction is absent, and only a rebuild decides the rest.\n");
      } else {
        process.stdout.write(`${scan.hits.length} shipped file(s) record the build's own wall clock:\n`);
        for (const hit of scan.hits) {
          process.stdout.write(`  ${hit.path}  (${hit.bytes} bytes, ${hit.totalMatches} occurrences)\n`);
          process.stdout.write(`      e.g. ${hit.matches.join(", ")}\n`);
        }
        process.stdout.write("\nThese are file CONTENTS, not metadata. No timestamp-normalisation flag\n");
        process.stdout.write("rewrites them, so two honest builds of identical source cannot produce\n");
        process.stdout.write("identical bytes. Byte-for-byte reproduction of THIS artifact is not\n");
        process.stdout.write("difficult; it is impossible.\n");
      }
    }
    process.exit(scan.embedsBuildClock ? 3 : 0);
  } catch (error) {
    const message = error instanceof EscrowError || error instanceof Error ? error.message : String(error);
    process.stderr.write(`build-clock scan failed: ${message}\n`);
    process.exit(1);
  }
}
