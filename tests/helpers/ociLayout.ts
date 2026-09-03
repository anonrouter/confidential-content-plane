// Build a minimal OCI image layout on disk, so the comparison and judging tools
// can be tested without a registry, a daemon or a network.
//
// The tools under test read layouts directly and hash what they find, which is
// what makes this possible at all. Testing them against a real image would test
// Docker Hub's availability at least as much as the code, and the one property
// that matters here -- that a difference is reported rather than rounded away --
// is easiest to prove on an image whose every byte the test chose.

import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { join } from "node:path";

export interface LayoutSpec {
  /** path -> file contents, applied as one layer. */
  files: Record<string, string>;
  /** Extra layers, each its own path -> contents map, applied in order. */
  extraLayers?: Array<Record<string, string>>;
  /** path -> octal mode, applied after the files are written. */
  modes?: Record<string, number>;
  /**
   * path -> octal mode, patched directly into the TAR HEADER after the archive
   * is built.
   *
   * `modes` cannot express every case: a file at mode 0000 or 0200 cannot be
   * read by `tar` even as its owner, so the archive can never be created with
   * one. Layer tars in the wild contain exactly that -- whiteout markers are
   * mode 0000 -- so the header is patched afterwards instead.
   */
  rawModes?: Record<string, number>;
  /**
   * path -> link target. Written INSTEAD of a regular file at that path, which
   * is what makes a file-to-symlink substitution expressible: the comparison
   * followed symlinks once, so a file replaced by a link to identical content
   * read as unchanged.
   */
  symlinks?: Record<string, string>;
  created?: string;
  historyCreated?: string[];
  annotations?: Record<string, string>;
  architecture?: string;
  env?: string[];
}

function sha256(buf: Buffer): string {
  return `sha256:${createHash("sha256").update(buf).digest("hex")}`;
}

function writeBlob(root: string, bytes: Buffer): { digest: string; size: number } {
  const digest = sha256(bytes);
  writeFileSync(join(root, "blobs", "sha256", digest.slice("sha256:".length)), bytes);
  return { digest, size: bytes.length };
}

/**
 * Rewrite one entry's mode in a ustar archive, in place.
 *
 * The header stores the mode as octal at offset 100 and a checksum at offset
 * 148 computed over the header with the checksum field read as spaces. Both are
 * recalculated here, because a header whose checksum does not match is one tar
 * will refuse rather than misread -- which would make this helper produce
 * archives that only appear to test something.
 */
function patchTarModes(tarPath: string, rawModes: Record<string, number>): void {
  const buffer = readFileSync(tarPath);
  for (let offset = 0; offset + 512 <= buffer.length; ) {
    const rawName = buffer.subarray(offset, offset + 100).toString("utf8").replace(/\0.*$/, "");
    if (rawName === "") break;
    const name = rawName.replace(/^\.?\//, "").replace(/\/$/, "");
    const sizeField = buffer.subarray(offset + 124, offset + 136).toString("utf8").replace(/\0.*$/, "").trim();
    const size = parseInt(sizeField || "0", 8) || 0;
    if (Object.prototype.hasOwnProperty.call(rawModes, name)) {
      const octal = `${(rawModes[name] & 0o7777).toString(8).padStart(7, "0")}\0`;
      buffer.write(octal, offset + 100, "utf8");
      buffer.fill(0x20, offset + 148, offset + 156);
      let sum = 0;
      for (let i = offset; i < offset + 512; i += 1) sum += buffer[i];
      buffer.write(`${sum.toString(8).padStart(6, "0")}\0 `, offset + 148, "utf8");
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  writeFileSync(tarPath, buffer);
}

function tarLayer(
  root: string,
  files: Record<string, string>,
  modes: Record<string, number> = {},
  symlinks: Record<string, string> = {},
  rawModes: Record<string, number> = {}
): { digest: string; size: number } {
  const staging = mkdtempSync(join(tmpdir(), "oci-layer-"));
  try {
    for (const [path, contents] of Object.entries(files)) {
      const full = join(staging, path);
      mkdirSync(join(full, ".."), { recursive: true });
      writeFileSync(full, contents);
    }
    for (const [path, target] of Object.entries(symlinks)) {
      const full = join(staging, path);
      mkdirSync(join(full, ".."), { recursive: true });
      rmSync(full, { force: true });
      symlinkSync(target, full);
    }
    for (const [path, mode] of Object.entries(modes)) {
      chmodSync(join(staging, path), mode);
    }
    const tarPath = join(staging, "..", `layer-${createHash("sha256").update(JSON.stringify(files)).digest("hex").slice(0, 12)}.tar`);
    // Deterministic enough for a test: the entries come from a fixed map and
    // the tar is rebuilt from scratch each time.
    // `-h` is deliberately NOT passed: a layer tar records symlinks as
    // symlinks, and dereferencing them here would make a file-to-symlink
    // substitution untestable.
    execFileSync("tar", ["-cf", tarPath, "-C", staging, "."]);
    if (Object.keys(rawModes).length > 0) patchTarModes(tarPath, rawModes);
    const bytes = readFileSync(tarPath);
    rmSync(tarPath, { force: true });
    return writeBlob(root, bytes);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

/** Create a layout under `directory` and return its manifest digest. */
export function writeLayout(directory: string, spec: LayoutSpec): string {
  mkdirSync(join(directory, "blobs", "sha256"), { recursive: true });
  writeFileSync(join(directory, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }));

  const layers = [
    tarLayer(directory, spec.files, spec.modes, spec.symlinks, spec.rawModes),
    ...(spec.extraLayers ?? []).map((f) => tarLayer(directory, f))
  ];
  const created = spec.created ?? "2026-01-01T00:00:00Z";
  const history = (spec.historyCreated ?? layers.map(() => created)).map((at, index) => ({
    created: at,
    created_by: `step ${index}`
  }));
  const config = {
    created,
    architecture: spec.architecture ?? "amd64",
    os: "linux",
    config: { Env: spec.env ?? ["PATH=/usr/bin"], Cmd: ["/bin/true"] },
    rootfs: { type: "layers", diff_ids: layers.map((l) => l.digest) },
    history
  };
  const configBlob = writeBlob(directory, Buffer.from(JSON.stringify(config)));

  const manifest = {
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: { mediaType: "application/vnd.oci.image.config.v1+json", digest: configBlob.digest, size: configBlob.size },
    layers: layers.map((l) => ({ mediaType: "application/vnd.oci.image.layer.v1.tar", digest: l.digest, size: l.size })),
    ...(spec.annotations ? { annotations: spec.annotations } : {})
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const manifestBlob = writeBlob(directory, manifestBytes);
  writeFileSync(
    join(directory, "index.json"),
    JSON.stringify({
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.index.v1+json",
      manifests: [
        {
          mediaType: "application/vnd.oci.image.manifest.v1+json",
          digest: manifestBlob.digest,
          size: manifestBlob.size
        }
      ]
    })
  );
  return manifestBlob.digest;
}

/** Byte-for-byte copy of a layout, so "the same image" is literally the same. */
export function copyLayout(from: string, to: string): void {
  execFileSync("cp", ["-R", from, to]);
}

/**
 * Change one config field the way a DIFFERENT BUILD would: every digest above
 * it moves with it, so the layout stays internally consistent.
 *
 * This is what a real difference looks like, and it is what the comparison has
 * to report rather than round away.
 */
export function mutateConfigConsistently(
  directory: string,
  mutate: (config: Record<string, unknown>) => void
): string {
  const indexPath = join(directory, "index.json");
  const index = JSON.parse(readFileSync(indexPath, "utf8"));
  const manifestPath = join(directory, "blobs", "sha256", index.manifests[0].digest.slice("sha256:".length));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const configPath = join(directory, "blobs", "sha256", manifest.config.digest.slice("sha256:".length));
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  mutate(config);

  const configBytes = Buffer.from(JSON.stringify(config));
  const configDigest = sha256(configBytes);
  writeFileSync(join(directory, "blobs", "sha256", configDigest.slice("sha256:".length)), configBytes);
  renameSync(configPath, `${configPath}.superseded`);
  manifest.config.digest = configDigest;
  manifest.config.size = configBytes.length;

  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const manifestDigest = sha256(manifestBytes);
  writeFileSync(join(directory, "blobs", "sha256", manifestDigest.slice("sha256:".length)), manifestBytes);
  renameSync(manifestPath, `${manifestPath}.superseded`);
  index.manifests[0].digest = manifestDigest;
  index.manifests[0].size = manifestBytes.length;
  writeFileSync(indexPath, JSON.stringify(index));
  return manifestDigest;
}

/**
 * Rewrite the config blob IN PLACE, leaving its filename and every digest above
 * it stale. That is tampering rather than a rebuild, and it is a different
 * failure with a different required response.
 *
 * This case is here because the tool used to accept it. The manifest digest is
 * computed over the manifest, the manifest had not changed, and so a layout
 * whose contents had been swapped underneath it compared as IDENTICAL.
 */
export function tamperConfigBlob(directory: string, mutate: (config: Record<string, unknown>) => void): void {
  const index = JSON.parse(readFileSync(join(directory, "index.json"), "utf8"));
  const manifestPath = join(directory, "blobs", "sha256", index.manifests[0].digest.slice("sha256:".length));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const configPath = join(directory, "blobs", "sha256", manifest.config.digest.slice("sha256:".length));
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  mutate(config);
  writeFileSync(configPath, Buffer.from(JSON.stringify(config)));
}

/** Rewrite the manifest's annotations, keeping the layout internally consistent. */
export function reannotate(directory: string, annotations: Record<string, string>): string {
  const indexPath = join(directory, "index.json");
  const index = JSON.parse(readFileSync(indexPath, "utf8"));
  const oldDigest: string = index.manifests[0].digest;
  const manifestPath = join(directory, "blobs", "sha256", oldDigest.slice("sha256:".length));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  manifest.annotations = annotations;
  const bytes = Buffer.from(JSON.stringify(manifest));
  const digest = sha256(bytes);
  writeFileSync(join(directory, "blobs", "sha256", digest.slice("sha256:".length)), bytes);
  renameSync(manifestPath, `${manifestPath}.superseded`);
  index.manifests[0].digest = digest;
  index.manifests[0].size = bytes.length;
  writeFileSync(indexPath, JSON.stringify(index));
  return digest;
}
