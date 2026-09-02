// Explain, file by file, why two OCI images differ.
//
// WHY THIS EXISTS
//
// "The rebuild produced a different digest" is not a finding, it is the absence
// of one. Two images can differ because a timestamp moved, because a base image
// was repinned, or because someone inserted a file, and only the last one
// matters while all three look identical at the digest level.
//
// WO-07's rule is that a near match is not reproducible. That rule is only
// enforceable if a near match can be described exactly, so this exists to make
// "explain every difference" something a script does rather than something a
// person promises.
//
// WHY IT READS OCI LAYOUTS RATHER THAN A REGISTRY
//
// The escrow archive already holds every mirrored image as an OCI layout on
// disk, and a rebuild writes one directly. Working on layouts means the whole
// comparison runs with no registry, no daemon and no network, which is the
// state the no-upstream recovery drill has to work in. Registry references are
// still accepted; they are pulled into a temporary layout first, so there is one
// code path rather than two that could disagree.
//
//   npx tsx scripts/provenance/compare-oci-images.ts <A> <B>
//   npx tsx scripts/provenance/compare-oci-images.ts --json <A> <B>
//
// Each argument is either an OCI layout directory or a registry reference.

import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { EscrowError, fail, run } from "./escrowRuntime.js";

export interface FileFacts {
  kind: "file" | "dir" | "symlink" | "hardlink" | "other";
  mode: string;
  size: number;
  linkTarget: string | null;
  sha256: string | null;
}

export interface KeyedDifference {
  key: string;
  a: string | null;
  b: string | null;
}

export interface ImageComparison {
  identical: boolean;
  manifestDigestA: string;
  manifestDigestB: string;
  layerDigestsA: string[];
  layerDigestsB: string[];
  configDifferences: string[];
  /**
   * Annotations live in the MANIFEST, not the config, so nothing below the
   * manifest can report them and the digests can differ with every other field
   * agreeing. Docker Official Images set `org.opencontainers.image.created` from
   * the builder's wall clock, which is exactly a difference of this shape.
   */
  manifestAnnotationDifferences: KeyedDifference[];
  /**
   * `history[i].created` timestamps, separated from `configDifferences` because
   * they are the single most common reason two builds of identical bytes
   * disagree, and burying them in a list of free-text strings makes a
   * reproducibility verdict unreadable.
   */
  historyTimestampDifferences: KeyedDifference[];
  onlyInA: string[];
  onlyInB: string[];
  changed: Array<{ path: string; reasons: string[] }>;
}

interface Layout {
  directory: string;
  manifestDigest: string;
  configDigest: string;
  layerDigests: string[];
  annotations: Record<string, string>;
  cleanup: () => void;
}

function sha256(buf: Buffer): string {
  return `sha256:${createHash("sha256").update(buf).digest("hex")}`;
}

function blobPath(directory: string, digest: string): string {
  return join(directory, "blobs", "sha256", digest.replace("sha256:", ""));
}

/**
 * Open an OCI layout, or pull a registry reference into a temporary one.
 *
 * Verifies that the manifest blob hashes to the digest the index names. A
 * layout whose index and blobs disagree is corrupt, and comparing against it
 * would produce a confident answer about the wrong bytes.
 */
function open(reference: string): Layout {
  let directory = reference;
  let cleanup = () => {};
  if (!existsSync(join(reference, "index.json"))) {
    const scratch = mkdtempSync(join(tmpdir(), "oci-compare-pull-"));
    run("crane", ["pull", "--format=oci", reference, join(scratch, "layout")], { maxBuffer: 8 * 1024 * 1024 });
    directory = join(scratch, "layout");
    cleanup = () => rmSync(scratch, { recursive: true, force: true });
  }

  const index = JSON.parse(readFileSync(join(directory, "index.json"), "utf8")) as {
    manifests: Array<{ digest: string; mediaType: string }>;
  };
  if (index.manifests.length !== 1) {
    fail(`${reference}: layout index names ${index.manifests.length} manifests; expected exactly one`);
  }
  const manifestDigest = index.manifests[0].digest;
  const manifestBytes = readFileSync(blobPath(directory, manifestDigest));
  if (sha256(manifestBytes) !== manifestDigest) {
    fail(`${reference}: manifest blob does not hash to the digest the index names`);
  }
  const manifest = JSON.parse(manifestBytes.toString("utf8")) as {
    config: { digest: string };
    layers: Array<{ digest: string }>;
    annotations?: Record<string, string>;
  };

  // EVERY referenced blob, not just the manifest.
  //
  // This check was missing, and a test caught what that costs: a layout whose
  // config blob had been rewritten in place still compared as IDENTICAL,
  // because the manifest digest is computed over the manifest and the manifest
  // had not changed. So the one comparison this project relies on to say "these
  // are the same image" could be made to say it about an image whose contents
  // had been swapped underneath it.
  //
  // It matters most where the tool is used unattended: the no-upstream restore
  // drill compares an escrowed archive against a rebuild, and a corrupted or
  // tampered archive is exactly the condition that drill exists to detect.
  for (const referenced of [manifest.config.digest, ...manifest.layers.map((l) => l.digest)]) {
    const path = blobPath(directory, referenced);
    if (!existsSync(path)) fail(`${reference}: blob ${referenced} is referenced by the manifest and missing`);
    if (sha256(readFileSync(path)) !== referenced) {
      fail(
        `${reference}: blob stored as ${referenced} does not hash to that digest.\n` +
          "The layout is corrupt or tampered with. Comparing against it would produce a confident answer about\n" +
          "bytes nobody can name."
      );
    }
  }

  return {
    directory,
    manifestDigest,
    configDigest: manifest.config.digest,
    layerDigests: manifest.layers.map((l) => l.digest),
    annotations: manifest.annotations ?? {},
    cleanup
  };
}

/**
 * Flatten a layout to a path -> facts map by applying layers in order.
 *
 * Applied in order, with whiteouts honoured, so a file rewritten by a later
 * layer reads as one file rather than as a difference. Comparing layer by layer
 * would report churn that a running container never sees, which is exactly the
 * noise that makes a reviewer stop reading the report.
 */
function flatten(layout: Layout): Map<string, FileFacts> {
  const files = new Map<string, FileFacts>();
  const scratch = mkdtempSync(join(tmpdir(), "oci-compare-layer-"));
  try {
    for (const layer of layout.layerDigests) {
      const extracted = join(scratch, "layer");
      rmSync(extracted, { recursive: true, force: true });
      run("mkdir", ["-p", extracted]);
      // Layer tars carry entries the extracting user cannot always create
      // (device nodes, unknown owners). Failure to restore ownership is not a
      // reason to abandon the comparison, so extraction is best-effort and the
      // facts below come from what landed.
      run("tar", ["-xf", blobPath(layout.directory, layer), "-C", extracted], {
        allowFailure: true,
        maxBuffer: 64 * 1024 * 1024
      });
      for (const { path, facts } of walk(extracted, extracted)) {
        const name = path.replace(/^\.?\//, "");
        const base = name.split("/").pop() ?? "";
        if (base === ".wh..wh..opq") {
          // Opaque whiteout: everything below this directory from earlier layers
          // is removed.
          const prefix = `${name.slice(0, name.length - base.length)}`;
          for (const existing of [...files.keys()]) {
            if (existing.startsWith(prefix) && existing !== prefix) files.delete(existing);
          }
          continue;
        }
        if (base.startsWith(".wh.")) {
          files.delete(`${name.slice(0, name.length - base.length)}${base.slice(4)}`);
          continue;
        }
        files.set(name, facts);
      }
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  return files;
}

/**
 * Walk the extracted layer, recording each entry's facts as it is visited.
 *
 * Facts are captured DURING the walk rather than afterwards, because of the
 * directories this has to open by force. A layer tar can carry a directory an
 * unprivileged extraction cannot then read: Debian ships `/var/lock/lvm` as mode
 * 0700 owned by root, and `node:22-bookworm-slim` has one, which made every
 * comparison of a Debian-based image die with EACCES.
 *
 * Refusing there would mean never comparing a Debian-based image, and silently
 * skipping the subtree would hide whatever is inside it, which is worse. So the
 * mode is recorded first and the directory is opened by adding the owner bits
 * back afterwards. The recorded facts are the ones from before the chmod, so
 * the report describes the image rather than what this process did to it.
 */
function walk(
  directory: string,
  base: string,
  out: Array<{ path: string; facts: FileFacts }> = []
): Array<{ path: string; facts: FileFacts }> {
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
    out.push({ path: relative(base, full), facts: factsOf(full, stats) });
    if (stats?.isDirectory()) walk(full, base, out);
  }
  return out;
}

/**
 * `lstat`, not `stat`.
 *
 * With `stat` a symlink reads as its target, so a file replaced by a symlink to
 * an identical file compared as unchanged, and a dangling symlink -- of which a
 * Debian image has many -- reported as "other" with no target recorded. Neither
 * is a difference a reader should have to take on trust.
 */
function factsOf(path: string, stats = lstatSync(path, { throwIfNoEntry: false })): FileFacts {
  if (!stats) return { kind: "other", mode: "?", size: 0, linkTarget: null, sha256: null };
  const mode = (stats.mode & 0o7777).toString(8).padStart(4, "0");
  if (stats.isSymbolicLink()) {
    return { kind: "symlink", mode, size: 0, linkTarget: readlinkSync(path), sha256: null };
  }
  if (stats.isDirectory()) return { kind: "dir", mode, size: 0, linkTarget: null, sha256: null };
  if (!stats.isFile()) return { kind: "other", mode, size: stats.size, linkTarget: null, sha256: null };
  return { kind: "file", mode, size: stats.size, linkTarget: null, sha256: sha256(readOpening(path, stats.mode)) };
}

/**
 * Read a file, opening it by force if the extracted mode forbids it.
 *
 * Layer tars contain files an unprivileged extraction cannot read back: mode
 * 0000 whiteout markers are the common case, and `.wh.faillog` is the one that
 * surfaced this. The mode has already been recorded by the caller, so adding
 * the owner read bit here changes what this process can see and not what the
 * report says the image contains.
 *
 * Refusing instead would mean the tool cannot compare any image that deletes a
 * root-owned file, and skipping the content would let a difference inside such
 * a file go unreported, which is the worse of the two.
 */
function readOpening(path: string, mode: number): Buffer {
  try {
    return readFileSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EACCES") throw error;
    chmodSync(path, (mode & 0o7777) | 0o400);
    return readFileSync(path);
  }
}

function compareConfigs(a: Record<string, any>, b: Record<string, any>): string[] {
  const differences: string[] = [];
  // `created` is deliberately absent: it is a build timestamp, and it is
  // reported by compareHistoryTimestamps alongside the per-step ones it belongs
  // with. Reporting it in both places printed the same fact twice under two
  // headings, which is how a reader stops reading.
  for (const key of ["architecture", "os", "variant"]) {
    if (JSON.stringify(a[key]) !== JSON.stringify(b[key])) {
      differences.push(`config.${key}: ${JSON.stringify(a[key])} vs ${JSON.stringify(b[key])}`);
    }
  }
  for (const key of ["Env", "Entrypoint", "Cmd", "WorkingDir", "User"]) {
    const left = JSON.stringify(a.config?.[key]);
    const right = JSON.stringify(b.config?.[key]);
    if (left !== right) differences.push(`config.config.${key}: ${left} vs ${right}`);
  }
  const historyA = (a.history ?? []) as Array<{ created_by?: string; created?: string }>;
  const historyB = (b.history ?? []) as Array<{ created_by?: string; created?: string }>;
  if (historyA.length !== historyB.length) {
    differences.push(`history length: ${historyA.length} vs ${historyB.length}`);
  } else {
    for (let i = 0; i < historyA.length; i += 1) {
      if (historyA[i].created_by !== historyB[i].created_by) {
        differences.push(
          `history[${i}].created_by:\n      A ${historyA[i].created_by}\n      B ${historyB[i].created_by}`
        );
      }
    }
  }
  return differences;
}

/**
 * `history[i].created`, reported separately and structurally.
 *
 * A build clock differing is not the same KIND of fact as a changed script, and
 * a verdict that cannot tell them apart is a verdict nobody can act on. It is
 * still a difference: this exists to name the cause precisely, never to excuse
 * it.
 */
function compareHistoryTimestamps(a: Record<string, any>, b: Record<string, any>): KeyedDifference[] {
  const historyA = (a.history ?? []) as Array<{ created?: string }>;
  const historyB = (b.history ?? []) as Array<{ created?: string }>;
  const differences: KeyedDifference[] = [];
  if ((a.created ?? null) !== (b.created ?? null)) {
    differences.push({ key: "config.created", a: a.created ?? null, b: b.created ?? null });
  }
  for (let i = 0; i < Math.max(historyA.length, historyB.length); i += 1) {
    const left = historyA[i]?.created ?? null;
    const right = historyB[i]?.created ?? null;
    if (left !== right) differences.push({ key: `history[${i}].created`, a: left, b: right });
  }
  return differences;
}

function compareAnnotations(a: Record<string, string>, b: Record<string, string>): KeyedDifference[] {
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  return keys
    .filter((key) => (a[key] ?? null) !== (b[key] ?? null))
    .map((key) => ({ key, a: a[key] ?? null, b: b[key] ?? null }));
}

export function compareImages(referenceA: string, referenceB: string): ImageComparison {
  const a = open(referenceA);
  const b = open(referenceB);
  try {
    const result: ImageComparison = {
      identical: a.manifestDigest === b.manifestDigest,
      manifestDigestA: a.manifestDigest,
      manifestDigestB: b.manifestDigest,
      layerDigestsA: a.layerDigests,
      layerDigestsB: b.layerDigests,
      configDifferences: [],
      manifestAnnotationDifferences: [],
      historyTimestampDifferences: [],
      onlyInA: [],
      onlyInB: [],
      changed: []
    };
    if (result.identical) return result;

    const configA = JSON.parse(readFileSync(blobPath(a.directory, a.configDigest), "utf8"));
    const configB = JSON.parse(readFileSync(blobPath(b.directory, b.configDigest), "utf8"));
    result.configDifferences = compareConfigs(configA, configB);
    result.historyTimestampDifferences = compareHistoryTimestamps(configA, configB);
    result.manifestAnnotationDifferences = compareAnnotations(a.annotations, b.annotations);

    const filesA = flatten(a);
    const filesB = flatten(b);
    for (const path of filesA.keys()) if (!filesB.has(path)) result.onlyInA.push(path);
    for (const path of filesB.keys()) if (!filesA.has(path)) result.onlyInB.push(path);
    for (const [path, factsA] of filesA) {
      const factsB = filesB.get(path);
      if (!factsB) continue;
      const reasons: string[] = [];
      if (factsA.kind !== factsB.kind) reasons.push(`kind ${factsA.kind} -> ${factsB.kind}`);
      if (factsA.mode !== factsB.mode) reasons.push(`mode ${factsA.mode} -> ${factsB.mode}`);
      if (factsA.size !== factsB.size) reasons.push(`size ${factsA.size} -> ${factsB.size}`);
      if (factsA.linkTarget !== factsB.linkTarget) {
        reasons.push(`link ${factsA.linkTarget ?? "-"} -> ${factsB.linkTarget ?? "-"}`);
      }
      if (factsA.sha256 !== factsB.sha256) reasons.push(`content ${factsA.sha256 ?? "-"} -> ${factsB.sha256 ?? "-"}`);
      if (reasons.length > 0) result.changed.push({ path, reasons });
    }
    result.onlyInA.sort();
    result.onlyInB.sort();
    result.changed.sort((x, y) => (x.path < y.path ? -1 : 1));
    return result;
  } finally {
    a.cleanup();
    b.cleanup();
  }
}

export function renderComparison(comparison: ImageComparison): string {
  const lines: string[] = [];
  lines.push(`A  ${comparison.manifestDigestA}`);
  lines.push(`B  ${comparison.manifestDigestB}`);
  lines.push("");
  if (comparison.identical) {
    lines.push("IDENTICAL. The manifest digests are equal, so these are the same image.");
    return lines.join("\n");
  }

  lines.push("NOT IDENTICAL. Every difference follows, which is the only honest");
  lines.push("alternative to calling a near match reproducible.");
  lines.push("");

  const shared = comparison.layerDigestsA.filter((d) => comparison.layerDigestsB.includes(d)).length;
  lines.push(
    `layers: ${comparison.layerDigestsA.length} vs ${comparison.layerDigestsB.length}, ${shared} identical by digest`
  );
  for (let i = 0; i < Math.max(comparison.layerDigestsA.length, comparison.layerDigestsB.length); i += 1) {
    const left = comparison.layerDigestsA[i];
    const right = comparison.layerDigestsB[i];
    if (left !== right) lines.push(`  layer[${i}] A ${left ?? "-"}\n            B ${right ?? "-"}`);
  }
  lines.push("");

  if (comparison.manifestAnnotationDifferences.length > 0) {
    lines.push("manifest annotations:");
    for (const difference of comparison.manifestAnnotationDifferences) {
      lines.push(`  ${difference.key}\n      A ${difference.a ?? "(absent)"}\n      B ${difference.b ?? "(absent)"}`);
    }
    lines.push("");
  }

  if (comparison.configDifferences.length > 0) {
    lines.push("image configuration:");
    for (const difference of comparison.configDifferences) lines.push(`  ${difference}`);
    lines.push("");
  }

  if (comparison.historyTimestampDifferences.length > 0) {
    lines.push(`build timestamps: ${comparison.historyTimestampDifferences.length} differing`);
    for (const difference of comparison.historyTimestampDifferences) {
      lines.push(`  ${difference.key}: ${difference.a ?? "(absent)"} vs ${difference.b ?? "(absent)"}`);
    }
    lines.push("");
  }

  lines.push(
    `filesystem: ${comparison.onlyInA.length} only in A, ${comparison.onlyInB.length} only in B, ${comparison.changed.length} changed`
  );
  for (const path of comparison.onlyInA) lines.push(`  ONLY IN A  ${path}`);
  for (const path of comparison.onlyInB) lines.push(`  ONLY IN B  ${path}`);
  for (const change of comparison.changed) lines.push(`  CHANGED    ${change.path}  (${change.reasons.join("; ")})`);
  lines.push("");
  lines.push("A difference in something derived from the build environment (a recorded");
  lines.push("revision, a timestamp) is explainable. A difference in a script or a binary");
  lines.push("is not, and must be treated as a different image until it is explained.");
  return lines.join("\n");
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const args = process.argv.slice(2).filter((a) => a !== "--json");
  try {
    if (args.length !== 2) fail("usage: compare-oci-images.ts [--json] <A> <B>   (OCI layout dir or registry reference)");
    const comparison = compareImages(args[0], args[1]);
    process.stdout.write(
      process.argv.includes("--json")
        ? `${JSON.stringify(comparison, null, 2)}\n`
        : `${renderComparison(comparison)}\n`
    );
    process.exit(comparison.identical ? 0 : 3);
  } catch (error) {
    const message = error instanceof EscrowError || error instanceof Error ? error.message : String(error);
    process.stderr.write(`comparison failed: ${message}\n`);
    process.exit(1);
  }
}
