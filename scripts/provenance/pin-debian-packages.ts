// Resolve Debian package pins from a snapshot, through the signed index.
//
// =============================================================================
// WHY THIS IS A SCRIPT AND NOT A LIST SOMEBODY PASTED
// =============================================================================
//
// The scratch-built base images fetch .debs by URL and sha256. Those values have
// to come from somewhere, and "somewhere" decides what the pin is worth:
//
//   * a hash of whatever the URL served when a person ran curl pins only that
//     download;
//   * a hash taken from the `Packages` index, where the index itself was checked
//     against the sha256 in `Release`, pins the bytes DEBIAN published, because
//     `Release` is what Debian's archive key signs.
//
// This does the second. It fetches `Release`, fetches the `Packages` index the
// Release names, refuses if the index does not hash to the value Release
// carries, and only then reads a package's sha256 out of it.
//
// =============================================================================
// THREE SUITES, BECAUSE PICKING ONE SILENTLY GETS THE WRONG VERSION
// =============================================================================
//
// A first pass at these pins read only `bookworm main` and pinned
// ca-certificates 20230311+deb12u1. The image it produced carried 142 root
// certificates while the image it replaces carries 150, because the deployed
// one installs from `bookworm-updates`, where ca-certificates is 20250419~deb12u1.
//
// Eight missing roots is not a cosmetic difference; it is a TLS handshake that
// works in one image and fails in the other, discovered in production. So all
// three suites are read and the newest version wins, by Debian's ordering
// rather than by string comparison -- `20250419~deb12u1` sorts BEFORE
// `20230311+deb12u1` as a string, which is the trap that produced the wrong pin
// in the first place.
//
//   npx tsx scripts/provenance/pin-debian-packages.ts <snapshot> <pkg> [pkg...]
//   npx tsx scripts/provenance/pin-debian-packages.ts --json 20260901T000000Z libc6 dash

import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { EscrowError, fail } from "./escrowRuntime.js";

export const PIN_SCHEMA = "anonrouter-debian-package-pins-v1";

const DEBIAN = "http://snapshot.debian.org/archive/debian";
const SECURITY = "http://snapshot.debian.org/archive/debian-security";

interface Suite {
  name: string;
  base: string;
  dist: string;
}

export interface Pin {
  package: string;
  version: string;
  suite: string;
  sha256: string;
  size: number;
  url: string;
}

/**
 * Debian version comparison, enough of it to order the pins here.
 *
 * `~` sorts before everything including the empty string, digits compare
 * numerically, and letters sort before non-letters. Implemented rather than
 * approximated with `<` because approximating it is exactly how this file's
 * predecessor pinned a two-year-old ca-certificates.
 */
export function compareDebianVersions(a: string, b: string): number {
  const split = (v: string) => {
    const colon = v.indexOf(":");
    const epoch = colon >= 0 ? Number(v.slice(0, colon)) : 0;
    const rest = colon >= 0 ? v.slice(colon + 1) : v;
    const dash = rest.lastIndexOf("-");
    return dash >= 0
      ? { epoch, upstream: rest.slice(0, dash), revision: rest.slice(dash + 1) }
      : { epoch, upstream: rest, revision: "" };
  };
  const order = (ch: string): number => {
    if (ch === "") return 0;
    if (ch === "~") return -1;
    if (/[A-Za-z]/.test(ch)) return ch.charCodeAt(0);
    return ch.charCodeAt(0) + 256;
  };
  const cmpPart = (x: string, y: string): number => {
    let i = 0;
    let j = 0;
    while (i < x.length || j < y.length) {
      let first = 0;
      while ((i < x.length && !/\d/.test(x[i])) || (j < y.length && !/\d/.test(y[j]))) {
        const cx = i < x.length && !/\d/.test(x[i]) ? x[i] : "";
        const cy = j < y.length && !/\d/.test(y[j]) ? y[j] : "";
        first = order(cx) - order(cy);
        if (first !== 0) return first;
        if (cx) i += 1;
        if (cy) j += 1;
      }
      let nx = "";
      let ny = "";
      while (i < x.length && /\d/.test(x[i])) nx += x[i++];
      while (j < y.length && /\d/.test(y[j])) ny += y[j++];
      const dx = Number(nx || "0");
      const dy = Number(ny || "0");
      if (dx !== dy) return dx - dy;
    }
    return 0;
  };
  const va = split(a);
  const vb = split(b);
  if (va.epoch !== vb.epoch) return va.epoch - vb.epoch;
  const upstream = cmpPart(va.upstream, vb.upstream);
  if (upstream !== 0) return upstream;
  return cmpPart(va.revision, vb.revision);
}

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url);
  if (!response.ok) fail(`GET ${url} returned HTTP ${response.status}`);
  return response.text();
}

async function fetchBuffer(url: string): Promise<Buffer> {
  const response = await fetch(url);
  if (!response.ok) fail(`GET ${url} returned HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

/**
 * The `Packages` index the `Release` file names, verified against it.
 *
 * A plain `Packages` is preferred over `Packages.gz` when both are listed, only
 * because decompressing adds a step whose failure mode would be indistinguishable
 * from a hash mismatch. Whichever is used, the check is the same: the bytes must
 * hash to the value in Release or this refuses.
 */
async function verifiedPackagesIndex(suite: Suite): Promise<string> {
  const release = await fetchText(`${suite.base}/dists/${suite.dist}/Release`);
  // `.gz` FIRST. A Release file lists an uncompressed `Packages` with a hash
  // even when the archive stores only the compressed form, so preferring the
  // plain name produces a 404 on a suite that is perfectly well formed. That is
  // what happened on `bookworm` itself.
  // Order matters and every form is needed. `bookworm` stores .gz and .xz,
  // `bookworm-updates` stores ONLY .xz, and both Release files also list an
  // uncompressed `Packages` that the archive does not serve. Trying one form
  // and reporting a 404 as a broken archive is what the first version did.
  const wanted = [
    "main/binary-amd64/Packages.gz",
    "main/binary-amd64/Packages.xz",
    "main/binary-amd64/Packages"
  ];
  const sha256Section = release.split(/^SHA256:$/m)[1] ?? "";
  const entries = new Map<string, { sha256: string; size: number }>();
  for (const line of sha256Section.split("\n")) {
    const match = line.match(/^\s+([0-9a-f]{64})\s+(\d+)\s+(\S+)$/);
    if (match && wanted.includes(match[3])) {
      entries.set(match[3], { sha256: match[1], size: Number(match[2]) });
    }
  }
  let lastError = "";
  for (const path of wanted) {
    const entry = entries.get(path);
    if (!entry) continue;
    let bytes: Buffer;
    try {
      bytes = await fetchBuffer(`${suite.base}/dists/${suite.dist}/${path}`);
    } catch (error) {
      // Listed in Release and not stored: try the next form rather than
      // treating a storage choice as a broken archive.
      lastError = error instanceof Error ? error.message : String(error);
      continue;
    }
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (digest !== entry.sha256) {
      fail(
        `${suite.name}: ${path} hashes to ${digest}, but the signed Release says ${entry.sha256}.\n` +
          "The index and the Release disagree, so nothing read out of it can be trusted."
      );
    }
    if (path.endsWith(".gz")) {
      const { gunzipSync } = await import("node:zlib");
      return gunzipSync(bytes).toString("utf8");
    }
    if (path.endsWith(".xz")) {
      // Node has no xz. The bytes are already verified against the signed
      // Release at this point, so shelling out decompresses something whose
      // integrity is settled rather than trusting the tool with the check.
      const { execFileSync } = await import("node:child_process");
      try {
        return execFileSync("xz", ["-dc"], { input: bytes, maxBuffer: 256 * 1024 * 1024 }).toString("utf8");
      } catch {
        fail(
          `${suite.name}: this suite publishes only Packages.xz and \`xz\` is not installed.\n` +
            "Install xz-utils; refusing rather than silently skipping a suite, because skipping one is how\n" +
            "ca-certificates got pinned two years stale."
        );
      }
    }
    return bytes.toString("utf8");
  }
  fail(`${suite.name}: no usable Packages index for main/binary-amd64${lastError ? ` (${lastError})` : ""}`);
}

export async function resolvePins(snapshot: string, packages: string[]): Promise<Pin[]> {
  if (!/^\d{8}T\d{6}Z$/.test(snapshot)) fail(`snapshot must look like 20260901T000000Z, got ${snapshot}`);
  const suites: Suite[] = [
    { name: "bookworm", base: `${DEBIAN}/${snapshot}`, dist: "bookworm" },
    { name: "bookworm-updates", base: `${DEBIAN}/${snapshot}`, dist: "bookworm-updates" },
    { name: "bookworm-security", base: `${SECURITY}/${snapshot}`, dist: "bookworm-security" }
  ];
  const want = new Set(packages);
  const best = new Map<string, Pin>();

  for (const suite of suites) {
    const index = await verifiedPackagesIndex(suite);
    for (const block of index.split("\n\n")) {
      const name = /^Package: (.+)$/m.exec(block)?.[1];
      if (!name || !want.has(name)) continue;
      const version = /^Version: (.+)$/m.exec(block)?.[1];
      const sha256 = /^SHA256: (.+)$/m.exec(block)?.[1];
      const filename = /^Filename: (.+)$/m.exec(block)?.[1];
      const size = /^Size: (\d+)$/m.exec(block)?.[1];
      if (!version || !sha256 || !filename || !size) continue;
      const candidate: Pin = {
        package: name,
        version,
        suite: suite.name,
        sha256,
        size: Number(size),
        url: `${suite.base}/${filename}`
      };
      const current = best.get(name);
      if (!current || compareDebianVersions(candidate.version, current.version) > 0) best.set(name, candidate);
    }
  }

  const missing = packages.filter((p) => !best.has(p));
  if (missing.length > 0) fail(`no package found in any suite for: ${missing.join(", ")}`);
  return packages.map((p) => best.get(p)!);
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const json = process.argv.includes("--json");
  const args = process.argv.slice(2).filter((a) => a !== "--json");
  const [snapshot, ...packages] = args;
  if (!snapshot || packages.length === 0) {
    process.stderr.write("usage: pin-debian-packages.ts [--json] <snapshot> <package>...\n");
    process.exit(2);
  }
  resolvePins(snapshot, packages)
    .then((pins) => {
      if (json) {
        process.stdout.write(`${JSON.stringify({ schema: PIN_SCHEMA, snapshot, pins }, null, 2)}\n`);
        return;
      }
      for (const pin of pins) {
        process.stdout.write(`ADD --checksum=sha256:${pin.sha256} \\\n    ${pin.url} /in/${pin.package}.deb\n`);
        process.stdout.write(`#   ${pin.package} ${pin.version} (${pin.suite})\n`);
      }
    })
    .catch((error) => {
      const message = error instanceof EscrowError || error instanceof Error ? error.message : String(error);
      process.stderr.write(`pinning failed: ${message}\n`);
      process.exit(1);
    });
}
