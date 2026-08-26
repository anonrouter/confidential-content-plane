#!/usr/bin/env node
// Turn a pre-deployment Phala release request into the independently
// distributable manifest for the deployment that actually ran.
//
// Phala adds platform-owned fields (KMS identity, pre-launch script, storage
// mode, feature flags) to app-compose before measuring it. build-release.sh
// cannot predict those bytes. This gate therefore starts from nonce-bound live
// evidence and refuses to finalize unless the reviewed Compose document and
// ordered environment-name allowlist survived deployment byte-for-byte.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

function fail(message) {
  console.error(`release finalization refused: ${message}`);
  process.exit(1);
}

function usage() {
  console.error(
    "usage: scripts/finalize-phala-release.mjs "
      + "--manifest <predeploy.json> --evidence <live-evidence.json> --out <final.json>"
  );
  process.exit(2);
}

const args = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const flag = process.argv[index];
  const value = process.argv[index + 1];
  if (!flag?.startsWith("--") || value === undefined) usage();
  args.set(flag, value);
}
const manifestPath = args.get("--manifest");
const evidencePath = args.get("--evidence");
const outPath = args.get("--out");
if (!manifestPath || !evidencePath || !outPath || args.size !== 3) usage();

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`${label} is not readable JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function parseAppCompose(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${label}.app_compose is not a non-empty string`);
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    fail(`${label}.app_compose is not valid JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail(`${label}.app_compose is not a JSON object`);
  }
  return parsed;
}

function sameStringArray(left, right) {
  return Array.isArray(left)
    && Array.isArray(right)
    && left.length === right.length
    && left.every((value, index) => typeof value === "string" && value === right[index]);
}

function extractImages(compose) {
  const images = [];
  const pattern = /^[ \t-]*image:\s*(?:["']?)([^"'#\r\n]+?)(?:["']?)\s*(?:#.*)?$/gm;
  for (const match of compose.matchAll(pattern)) {
    const image = match[1].trim();
    if (image && !images.includes(image)) images.push(image);
  }
  return images;
}

const request = readJson(manifestPath, "pre-deployment manifest");
const evidence = readJson(evidencePath, "live evidence");
const binding = evidence?.binding;
if (!binding || typeof binding !== "object" || Array.isArray(binding)) {
  fail("live evidence has no binding object");
}
if (request?.source?.dirty !== false) {
  fail("source tree was dirty when the pre-deployment manifest was built");
}
if (typeof request.release_id !== "string" || request.release_id !== binding.release_id) {
  fail("release_id in live evidence does not equal the reviewed release");
}
if (typeof binding.compose_hash !== "string" || !/^[0-9a-f]{64}$/.test(binding.compose_hash)) {
  fail("live binding has no lowercase SHA-256 compose_hash");
}

const requested = parseAppCompose(request.app_compose, "pre-deployment manifest");
const live = parseAppCompose(evidence.app_compose, "live evidence");
if (sha256(evidence.app_compose) !== binding.compose_hash) {
  fail("SHA-256 of live app_compose does not equal the hardware-bound compose_hash");
}
if (typeof requested.docker_compose_file !== "string"
    || requested.docker_compose_file !== live.docker_compose_file) {
  fail("Phala did not measure the exact reviewed Docker Compose bytes");
}
if (!sameStringArray(requested.allowed_envs, live.allowed_envs)) {
  fail("Phala did not preserve the exact ordered environment-name allowlist");
}

for (const field of [
  "manifest_version", "name", "runner", "public_logs", "public_sysinfo",
  "public_tcbinfo", "kms_enabled", "gateway_enabled", "secure_time"
]) {
  if (requested[field] !== live[field]) {
    fail(`reviewed app-compose field changed during deployment: ${field}`);
  }
}

const images = extractImages(live.docker_compose_file);
if (images.length === 0 || images.some((image) => !/@sha256:[0-9a-f]{64}$/.test(image))) {
  fail("live Docker Compose contains a missing or non-digest-pinned image");
}
const expectedMainImage = `${request?.image?.reference}@${request?.image?.digest}`;
if (!images.includes(expectedMainImage)) {
  fail("live Docker Compose does not contain the reviewed AnonRouter image digest");
}

for (const field of ["app_id", "instance_id", "origin", "transport", "tls_spki_sha256"]) {
  if (typeof binding[field] !== "string" || binding[field].length === 0) {
    fail(`live binding is missing ${field}`);
  }
}

/**
 * Carry the third-party plaintext-capable provenance state into the manifest.
 *
 * WO-07 section 2.2: a component whose source-to-digest binding is unproven is
 * a RECORDED GAP, and the gap must travel with the release rather than living
 * only in a document someone may not read. A manifest that lists our own image
 * digests and says nothing about the TLS terminator reads as a complete chain
 * when it is not.
 *
 * The ledger is validated by tests/unit/third-party-provenance.test.ts, which
 * refuses a claimed binding with no evidence. This function is deliberately a
 * plain reader: it copies the state, it does not decide it, and it fails loudly
 * rather than emitting an empty section if the ledger is missing.
 */
function thirdPartyProvenance() {
  const path = "deploy/provenance/plaintext-capable-components.json";
  let ledger;
  try {
    ledger = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`cannot read the third-party provenance ledger at ${path}: ${error.message}`);
  }
  const plaintext = (ledger.components ?? []).filter((c) => c.plaintextCapable);
  const gaps = plaintext.filter((c) => c.binding?.status === "NONE");
  for (const component of plaintext) {
    // Defence in depth against a hand-edited ledger reaching a release.
    if (component.binding?.status !== "NONE" && !component.binding?.evidence) {
      fail(`third-party component ${component.id} claims ${component.binding?.status} with no evidence`);
    }
  }
  return {
    ledger_sha256: sha256(readFileSync(path, "utf8")),
    components: plaintext.map((c) => ({
      id: c.id,
      role: c.role,
      upstream: c.upstream?.project ?? null,
      pinned_digest: c.pinned?.digest ?? null,
      binding: c.binding?.status ?? "NONE"
    })),
    recorded_gaps: gaps.map((c) => c.id),
    // COUNTED FROM THE LEDGER, never worded in advance.
    //
    // This sentence used to end "treat this release as having an unproven
    // link", singular, while the ledger recorded three gaps, and a unit test
    // asserted the singular phrasing so the understatement was load-bearing.
    // Anything a release manifest says about its own gaps must be derived from
    // the gap list, because prose written beside a count drifts from it and
    // always drifts in the flattering direction.
    //
    // The gap ids are repeated inside the sentence as well as in
    // `recorded_gaps`. A reader who skims one field should not be able to come
    // away with a smaller number than a reader who reads both.
    note:
      gaps.length === 0
        ? "Every plaintext-capable third-party component has an established source-to-digest binding."
        : `${gaps.length} plaintext-capable third-party component(s) in this release have NO `
          + `established source-to-digest binding: ${gaps.map((c) => c.id).join(", ")}. `
          + "A pinned digest, a stated revision, a verified upstream source pin and an UNSIGNED "
          + "registry attestation are each an assertion about intent or about a registry's push "
          + `access, not evidence that the running bytes came from the named source. Treat this `
          + `release as having ${gaps.length} unproven link(s), named here rather than rounded up `
          + "to verified."
  };
}

const requestedKeys = Object.keys(requested);
const platformFields = Object.keys(live).filter((key) => !requestedKeys.includes(key)).sort();
const finalized = {
  schema: "anonrouter.release-manifest/v2",
  status: "live-hardware-measurement",
  release_id: request.release_id,
  source: request.source,
  image: request.image,
  compose: {
    file: request?.compose?.file,
    requested_hash: request?.compose?.hash,
    measured_hash: binding.compose_hash,
    docker_compose_sha256: sha256(live.docker_compose_file),
    app_name: typeof live.name === "string" ? live.name : null,
    platform_injected_fields: platformFields
  },
  deployment: {
    app_id: binding.app_id,
    instance_id: binding.instance_id,
    origin: binding.origin,
    transport: binding.transport,
    tls_spki_sha256: binding.tls_spki_sha256,
    os_image_hash: evidence?.info?.os_image_hash ?? null,
    evidence_issued_at_ms: evidence?.issued_at_ms ?? null
  },
  images,
  third_party_provenance: thirdPartyProvenance(),
  app_compose: evidence.app_compose,
  requested_app_compose: request.app_compose,
  note: [
    "This final manifest binds reviewed source and image digests to the exact",
    "app-compose measured by the live TDX deployment. Phala-owned fields are",
    "captured only after deployment; the reviewed Docker Compose bytes and",
    "ordered environment-name allowlist were required to match byte-for-byte.",
    "Distribute this file independently of the gateway it describes."
  ].join(" ")
};

writeFileSync(outPath, `${JSON.stringify(finalized, null, 2)}\n`, { mode: 0o644 });
console.log(`finalized ${request.release_id}`);
console.log(`requested compose ${request?.compose?.hash ?? "unknown"}`);
console.log(`measured compose  ${binding.compose_hash}`);
console.log(`platform fields   ${platformFields.join(", ") || "none"}`);
