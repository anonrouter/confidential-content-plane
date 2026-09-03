// A base image may not name a repository that did not build it.
//
// THE DEFECT THIS PINS. Both replacement bases were written to look as much
// like the Docker Official Images they replace as possible, because every
// gratuitous difference is a behavioural risk in the deployment. That is the
// right instinct for `PATH`, for `CMD`, for the exposed ports and for the
// working directory. It is exactly wrong for provenance metadata.
//
// The caddy base copied `org.opencontainers.image.source` from the stock image
// and shipped `https://github.com/caddyserver/caddy-docker`. On the stock image
// that label is true. On this one it is false, and specifically false in the
// dimension the whole exercise is about: the OCI spec defines `image.source` as
// the URL to get the source code FOR BUILDING THE IMAGE, caddy-docker's recipe
// does not produce these bytes, and a verifier who followed the label would
// find a repository that cannot rebuild what they are holding. The image whose
// reason for existing is a source-to-digest binding would have been the one
// artifact in the chain carrying a false pointer to its source.
//
// It was found by diffing the candidate edge image's config against the
// deployed one and reading what MOVED rather than what broke: nothing failed,
// no check complained, and the label had simply been inherited two images deep.
//
// So the rule is mechanical: any label that names a source repository must name
// one of ours, and the ban list holds the upstreams whose images these replace,
// because those are the values a future copy-the-stock-image edit would
// reintroduce.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const BASE_IMAGE_ROOT = "deploy/provenance/base-images";

/** Repositories that build AnonRouter's own images. */
const OUR_REPOSITORIES = [
  "https://github.com/anonrouter/confidential-content-plane",
  "https://github.com/anonrouter/anonrouter"
];

/**
 * Upstreams whose images these replace. Each is a value that WAS present, or is
 * one line of copy-paste away from being present, and none of them builds an
 * image in this directory.
 */
const NOT_OURS = [
  "caddyserver/caddy-docker",
  "nodejs/docker-node",
  "docker-library",
  "debian/",
  "alpinelinux/"
];

/** Labels whose value is a claim about where the source lives. */
const SOURCE_LABELS = ["org.opencontainers.image.source", "org.label-schema.vcs-url"];

function dockerfiles(): Array<{ name: string; path: string; text: string }> {
  if (!existsSync(BASE_IMAGE_ROOT)) return [];
  return readdirSync(BASE_IMAGE_ROOT, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => ({ name: e.name, path: join(BASE_IMAGE_ROOT, e.name, "Dockerfile") }))
    .filter((f) => existsSync(f.path))
    .map((f) => ({ ...f, text: readFileSync(f.path, "utf8") }));
}

/** `LABEL key=value` and `LABEL key="value"`, one per line, which is the form used here. */
function labels(text: string): Array<{ key: string; value: string }> {
  const out: Array<{ key: string; value: string }> = [];
  for (const line of text.split("\n")) {
    const match = /^LABEL\s+([A-Za-z0-9._-]+)=("?)(.*?)\2\s*$/.exec(line.trim());
    if (match) out.push({ key: match[1], value: match[3] });
  }
  return out;
}

const found = dockerfiles();

describe("replacement base images do not misattribute their own source", () => {
  it("there are base images to check at all", () => {
    // Without this, deleting the directory would turn every assertion below
    // into a vacuous pass.
    expect(found.length).toBeGreaterThanOrEqual(2);
    expect(found.map((f) => f.name).sort()).toEqual(["caddy", "node"]);
  });

  for (const file of found) {
    describe(file.name, () => {
      it("names one of our repositories as its source, or none at all", () => {
        for (const label of labels(file.text)) {
          if (!SOURCE_LABELS.includes(label.key)) continue;
          expect(
            OUR_REPOSITORIES.some((repo) => label.value === repo),
            `${file.path} sets ${label.key}=${label.value}, which is not a repository that builds this image`
          ).toBe(true);
        }
      });

      it("carries no label pointing at the upstream it replaces", () => {
        for (const label of labels(file.text)) {
          for (const upstream of NOT_OURS) {
            expect(
              label.value.includes(upstream),
              `${file.path} sets ${label.key}=${label.value}, which points at ${upstream}`
            ).toBe(false);
          }
        }
      });
    });
  }

  it("the caddy base states its source, rather than omitting the question", () => {
    // Omission would also pass the two rules above, and would be a worse
    // outcome than a wrong value: nobody notices a missing label.
    const caddy = found.find((f) => f.name === "caddy");
    expect(caddy).toBeDefined();
    expect(labels(caddy!.text).find((l) => l.key === "org.opencontainers.image.source")?.value).toBe(
      "https://github.com/anonrouter/confidential-content-plane"
    );
  });
});

describe("the ban list is not vacuous", () => {
  it("catches the exact string that shipped", () => {
    const shipped = 'LABEL org.opencontainers.image.source="https://github.com/caddyserver/caddy-docker"';
    const parsed = labels(shipped);
    expect(parsed).toHaveLength(1);
    expect(NOT_OURS.some((u) => parsed[0].value.includes(u))).toBe(true);
    expect(OUR_REPOSITORIES.includes(parsed[0].value)).toBe(false);
  });

  it("parses both quoted and unquoted label forms, since both are used", () => {
    expect(labels("LABEL org.opencontainers.image.version=v2.11.4")[0]).toEqual({
      key: "org.opencontainers.image.version",
      value: "v2.11.4"
    });
    expect(labels('LABEL org.opencontainers.image.source="https://example.invalid/x"')[0]).toEqual({
      key: "org.opencontainers.image.source",
      value: "https://example.invalid/x"
    });
  });
});
