// Inspection of the attested dstack app-compose manifest.
//
// `tcb_info.app_compose` is the exact JSON string whose SHA-256 is measured into
// RTMR3 as the "compose-hash" event. Because it is measured, everything inside
// it is a hardware-backed fact about the running deployment — including the full
// docker-compose text and the dstack feature switches. That makes two of
// AnonRouter's privacy claims checkable rather than merely asserted:
//
//   public_logs=false        the platform will not serve container logs publicly
//   image digests pinned     the images that ran cannot be swapped behind a tag
//
// This module does NOT parse YAML. Pulling a YAML parser into the verifier would
// add an attack surface and a dependency for a job that needs only a scan for
// image references. It extracts `image:` values lexically and requires each to
// carry an @sha256: digest, which is a conservative check: anything it cannot
// confidently read as digest-pinned is reported as unpinned.

import { createHash } from "node:crypto";

export interface AttestedAppCompose {
  /** SHA-256 of the exact manifest string, lowercase hex. */
  composeHash: string;
  /** dstack manifest fields we care about; unknown fields are ignored. */
  name: string | null;
  runner: string | null;
  /** false is the hardened value; null means the field was absent. */
  publicLogs: boolean | null;
  publicSysinfo: boolean | null;
  kmsEnabled: boolean | null;
  gatewayEnabled: boolean | null;
  /** Environment variable names the manifest allows into the CVM. */
  allowedEnvs: string[];
  /** The raw docker-compose document, when the runner is docker-compose. */
  dockerComposeFile: string | null;
  /** Every `image:` reference found in the compose document. */
  images: AttestedImageReference[];
}

export interface AttestedImageReference {
  /** The reference exactly as written in the compose document. */
  reference: string;
  /** True when the reference carries an @sha256:<64 hex> digest. */
  digestPinned: boolean;
}

export class AppComposeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AppComposeError";
  }
}

const MAX_MANIFEST_BYTES = 1_000_000;
const IMAGE_LINE = /^[ \t-]*image:\s*(?:["']?)([^"'#\r\n]+?)(?:["']?)\s*(?:#.*)?$/gm;
const DIGEST_SUFFIX = /@sha256:[0-9a-f]{64}$/;

function optionalBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/** Extract every image reference from a docker-compose document. */
export function extractComposeImages(dockerComposeFile: string): AttestedImageReference[] {
  const images: AttestedImageReference[] = [];
  const seen = new Set<string>();
  for (const match of dockerComposeFile.matchAll(IMAGE_LINE)) {
    const reference = match[1].trim();
    if (reference.length === 0 || seen.has(reference)) continue;
    seen.add(reference);
    images.push({ reference, digestPinned: DIGEST_SUFFIX.test(reference) });
  }
  return images;
}

/**
 * Parse and hash the attested manifest. The returned `composeHash` is computed
 * from the string as given — the caller compares it to the measured RTMR3
 * "compose-hash" event, which is what makes the rest of this object evidence.
 */
export function readAttestedAppCompose(manifest: unknown): AttestedAppCompose {
  if (typeof manifest !== "string" || manifest.length === 0) {
    throw new AppComposeError("app_compose must be a non-empty string");
  }
  if (Buffer.byteLength(manifest, "utf8") > MAX_MANIFEST_BYTES) {
    throw new AppComposeError("app_compose exceeds the maximum inspected size");
  }
  const composeHash = createHash("sha256").update(manifest, "utf8").digest("hex");

  let parsed: unknown;
  try {
    parsed = JSON.parse(manifest);
  } catch {
    throw new AppComposeError("app_compose is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AppComposeError("app_compose must decode to a JSON object");
  }
  const raw = parsed as Record<string, unknown>;
  const dockerComposeFile = optionalString(raw.docker_compose_file);

  return {
    composeHash,
    name: optionalString(raw.name),
    runner: optionalString(raw.runner),
    publicLogs: optionalBoolean(raw.public_logs),
    publicSysinfo: optionalBoolean(raw.public_sysinfo),
    kmsEnabled: optionalBoolean(raw.kms_enabled),
    gatewayEnabled: optionalBoolean(raw.gateway_enabled),
    allowedEnvs: Array.isArray(raw.allowed_envs)
      ? raw.allowed_envs.filter((entry): entry is string => typeof entry === "string")
      : [],
    dockerComposeFile,
    images: dockerComposeFile ? extractComposeImages(dockerComposeFile) : []
  };
}
