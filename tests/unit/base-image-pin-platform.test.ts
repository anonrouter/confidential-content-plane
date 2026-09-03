import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Every `FROM ...@sha256:` in this repository must name a SINGLE-PLATFORM image
// manifest, never a multi-architecture index.
//
// An index digest is immutable, which is exactly what makes it look like a pin.
// It is not one: it resolves to a different image per builder architecture, so
// two builds of identical source on an amd64 machine and an arm64 machine
// produce different images and nothing in the artifact records which one ran.
// For a component that terminates TLS or proxies plaintext inside the trust
// domain, that is the difference between knowing what runs and knowing a set of
// things one of which runs.
//
// The root Dockerfile's node base was moved off an index for this reason. Six
// other pins were still on one, including the edge that sees customer plaintext
// and both HAProxy egress proxies, and this suite is what stops that recurring.
//
// OFFLINE ON PURPOSE, like its sibling base-image-pin.test.ts. It does not ask
// a registry what a digest is today; it asserts the build inputs still name the
// digests that were resolved and reviewed. A registry lookup here would make a
// working defence depend on network reachability.
//
// Refresh the reviewed set with:
//   npx tsx scripts/audit-base-image-pins.ts
// which resolves every pin against its registry, compares the served
// docker-content-digest against the pin, and exits 3 if any names an index.

const ROOT = fileURLToPath(new URL("../..", import.meta.url));

/**
 * The reviewed pins. Each was resolved against its registry, confirmed to be a
 * single-platform `linux/amd64` manifest, and confirmed to be the amd64 child
 * of the index the tag points at.
 */
const REVIEWED: Record<string, string> = {
  "node:22-bookworm-slim": "sha256:a17d50af28002a160548bd4225b3cfcb12c5efcb171f79e68758f2885fb1b066",
  "node:22-alpine": "sha256:76789712cd1ae89a1225eac9077010d68987a423588042dac30446f502f1858c",
  "caddy:2.11.4-alpine": "sha256:98eb57d882ccd5213d1688764db10c1ca2c58a1ca3a6717a3411ad798f7a423a",
  "caddy:2.11.4-builder-alpine": "sha256:302c5bf7723b61c0491544221aa21d63467cd035950c3c23129e8fd77c25fc8b",
  "haproxy:2.9-alpine": "sha256:45ea835f850da6ba34d5756b0010e202750aa5011a80c99d9b72ff26fc90dbcc",
  "alpine:3.21": "sha256:483f502c0e6aff6d80a807f25d3f88afa40439c29fdd2d21a0912e0f42db842a",
  // FIRST-PARTY base, not a public one. The xlarge edge layers only a Caddyfile
  // on top of the measured single-provider edge, because that image already has
  // the caddy file capability stripped and verified and a RUN step needs a
  // builder this machine does not have. Confirmed a single-platform OCI manifest
  // rather than an index (`crane manifest` reports no `manifests` array), which
  // is a property build-image-crane.sh guarantees by construction.
  "ghcr.io/anonrouter/anonrouter-edge-ingress": "sha256:66868f6d8819b676c10e2c4910186f0d382df758b2e25899096766ee4c3af6e1",
  // The upstream base of the delegated ingress, which is what production
  // actually derives from.
  //
  // MISSING UNTIL 2026-09-01, and the suite had been failing on it since the
  // delegated ingress image was added: the Dockerfile list is discovered from
  // deploy/phala/images/*, so a new image directory joins the check
  // automatically and this map does not. The failure was real rather than
  // noise — an unreviewed base on the component that terminates customer TLS is
  // exactly what this suite exists to catch — and it went unnoticed because
  // nothing ran the suite between the two commits.
  //
  // Confirmed a single-platform linux/amd64 OCI manifest, not an index: `crane
  // manifest` reports 11 layers and no `manifests` array, and the escrow
  // mirroring tool refuses an index outright, so this digest could not have
  // been mirrored if it were one.
  "dstacktee/dstack-ingress:2.3": "sha256:527c53523b9226782a11dbd800a3ff55e8a1f0b88e6224e8f7e4db7419769fbe",
  // AnonRouter's own scratch-built replacement for the caddy base, which the
  // edge now derives from. It is here for the same reason as every other entry
  // -- a pin nobody reviewed is what this suite exists to catch -- and it earns
  // a stronger review than the public ones can get: it was produced by two
  // independent public-CI jobs at this digest and is signed against a pinned
  // OIDC identity, so a reader can check the pin rather than take it.
  //
  //   cosign verify \
  //     --certificate-identity 'https://github.com/anonrouter/confidential-content-plane/.github/workflows/anonrouter-base-build.yml@refs/heads/main' \
  //     --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  //     ghcr.io/anonrouter/mirror/anonrouter-caddy-base@sha256:b834a839...
  "ghcr.io/anonrouter/mirror/anonrouter-caddy-base":
    "sha256:62c3df7708bf00f13240cb028cba40d44757ea5c6c8584bc8867e288a61555f5",
  // The same, for the content-plane runtime base. Referenced by the Dockerfile
  // the exporter generates rather than by a file in this repository, so it is
  // listed here to keep the reviewed set complete rather than because this
  // suite's discovery finds it.
  "ghcr.io/anonrouter/mirror/anonrouter-node-base":
    "sha256:e8f6e5faabd917808380efd228046d3a6593ccfe982b2af454e02080546e338d"
};

/** Digests that are known INDEXES. Naming them is what makes the failure legible. */
const KNOWN_INDEX_DIGESTS: Record<string, string> = {
  "sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648": "caddy:2.11.4-alpine index (14 children)",
  "sha256:3e29449a6beed63262e36104adf531b4e41b359f61937303f5ea8607987b3748": "haproxy:2.9-alpine index (16 children)",
  "sha256:56fa17d2a7e7f168a043a2712e63aed1f8543aeafdcee47c58dcffe38ed51099": "alpine:3.21 index (16 children)",
  "sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436": "node:22-bookworm-slim index"
};

function dockerfiles(): string[] {
  const imagesDir = join(ROOT, "deploy/phala/images");
  const found = [join(ROOT, "Dockerfile")];
  for (const entry of readdirSync(imagesDir)) {
    const candidate = join(imagesDir, entry, "Dockerfile");
    try {
      if (statSync(candidate).isFile()) found.push(candidate);
    } catch {
      // not an image directory
    }
  }
  return found;
}

interface Pin {
  file: string;
  line: number;
  reference: string;
  digest: string;
}

function pins(): Pin[] {
  const collected: Pin[] = [];
  for (const file of dockerfiles()) {
    readFileSync(file, "utf8").split("\n").forEach((text, index) => {
      // The tag is OPTIONAL. `repo@sha256:...` with no tag is a valid and
      // strictly MORE precise reference, and requiring a tag meant the collector
      // silently skipped such lines -- so a Dockerfile written that way passed
      // every assertion below by never being collected at all. That is the exact
      // failure mode the vacuity guard in the first test exists to catch, and it
      // caught it.
      const match = /^FROM\s+([^\s:@]+)(?::(\S+?))?@(sha256:[0-9a-f]{64})/.exec(text.trim());
      if (!match) return;
      collected.push({
        file: file.slice(ROOT.length),
        line: index + 1,
        reference: match[2] ? `${match[1]}:${match[2]}` : match[1],
        digest: match[3]
      });
    });
  }
  return collected;
}

describe("every base image pin names a single-platform manifest", () => {
  const collected = pins();

  it("finds at least one pin in every Dockerfile it enumerated", () => {
    // A guard on the guard: if the collector silently matched nothing, every
    // assertion below would pass vacuously.
    //
    // Expressed against what was enumerated rather than a fixed count, because
    // this suite also runs inside the published content-plane export, which
    // carries only the Dockerfiles the content plane needs. A magic number here
    // would pass in the monorepo and fail in the artifact it is meant to guard.
    const files = dockerfiles();
    expect(files.length).toBeGreaterThan(0);
    expect(collected.length).toBeGreaterThanOrEqual(files.length);
    for (const file of files) {
      const relative = file.slice(ROOT.length);
      expect(
        collected.some((pin) => pin.file === relative),
        `${relative} has no digest-pinned FROM line`
      ).toBe(true);
    }
  });

  it("pins no known multi-architecture index digest", () => {
    for (const pin of collected) {
      const known = KNOWN_INDEX_DIGESTS[pin.digest];
      expect(
        known,
        `${pin.file}:${pin.line} pins ${known}. An index digest resolves per builder architecture; `
          + "repin to the linux/amd64 child (npx tsx scripts/audit-base-image-pins.ts prints it)."
      ).toBeUndefined();
    }
  });

  it("pins exactly the reviewed digest for every reviewed reference", () => {
    for (const pin of collected) {
      const reviewed = REVIEWED[pin.reference];
      expect(reviewed, `${pin.file}:${pin.line} pins unreviewed base ${pin.reference}`).toBeDefined();
      expect(pin.digest, `${pin.file}:${pin.line} (${pin.reference})`).toBe(reviewed);
    }
  });

  it("leaves no FROM line unpinned", () => {
    for (const file of dockerfiles()) {
      readFileSync(file, "utf8").split("\n").forEach((text, index) => {
        const trimmed = text.trim();
        if (!trimmed.startsWith("FROM ")) return;
        // A stage that builds on a previous named stage carries no digest and
        // needs none: it names something this file already pinned.
        const target = trimmed.split(/\s+/)[1];
        if (!target.includes(":") && !target.includes("/")) return;
        expect(trimmed, `${file.slice(ROOT.length)}:${index + 1} is not digest-pinned`).toContain("@sha256:");
      });
    }
  });
});
