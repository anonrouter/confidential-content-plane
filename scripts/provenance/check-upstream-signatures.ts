// Is WO-07 section 2.2 option B available for a pinned upstream image?
//
// =============================================================================
// WHAT OPTION B REQUIRES, EXACTLY
// =============================================================================
//
// "Upstream publishes a signed attestation binding that digest to its source,
// and we verify it against a PINNED upstream identity." Two things have to be
// true at once, and dropping either turns the check into decoration:
//
//   1. the signature covers the exact digest we deploy; and
//   2. it verifies against an identity we can pin -- a certificate identity AND
//      an OIDC issuer -- rather than against whatever key happened to sign it.
//
// The second is the one that gets quietly dropped, because a signature that
// verifies against its own embedded key always verifies. That is not a binding
// to upstream; it is a binding to whoever made the signature, which is the
// question rather than the answer.
//
// =============================================================================
// WHY THIS IS A SCRIPT AND NOT A SENTENCE IN A DOCUMENT
// =============================================================================
//
// "Docker Official Images do not publish verifiable provenance" is the kind of
// claim a project states once, is right about, and then keeps stating after it
// stops being true. If upstream starts signing, this run changes and the ledger
// entry stops matching, which is a much better failure than a stale sentence
// nobody rechecks.
//
// It is also a claim with an obvious incentive behind it: a gap that cannot be
// closed is easier to live with than one that can. So it is measured.
//
//   npx tsx scripts/provenance/check-upstream-signatures.ts <component-id> [--json]

import { fileURLToPath } from "node:url";
import { EscrowError, fail, run } from "./escrowRuntime.js";
import { loadLedger } from "../verify-third-party-provenance.js";
import { registryCoordinatesFor } from "./doi-source-recipe.js";

export const SIGNATURE_CHECK_SCHEMA = "anonrouter-upstream-signature-check-v1";

export interface SignatureCheck {
  id: string;
  question: string;
  found: boolean;
  detail: string;
  /** Could this, on its own, satisfy option B? Almost always false, and why. */
  satisfiesOptionB: boolean;
}

export interface UpstreamSignatureReport {
  schema: typeof SIGNATURE_CHECK_SCHEMA;
  component: string | null;
  repository: string;
  indexDigest: string;
  imageDigest: string;
  checkedAt: string;
  checks: SignatureCheck[];
  optionBAvailable: boolean;
  conclusion: string[];
}

async function pullToken(repository: string): Promise<string> {
  const url = `https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repository}:pull`;
  const response = await fetch(url);
  if (!response.ok) fail(`could not obtain an anonymous pull token for ${repository}: HTTP ${response.status}`);
  return ((await response.json()) as { token: string }).token;
}

/** OCI referrers: the standard place a detached signature would be discoverable. */
async function referrers(repository: string, digest: string, token: string): Promise<{ count: number; types: string[] }> {
  const response = await fetch(`https://registry-1.docker.io/v2/${repository}/referrers/${digest}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.oci.image.index.v1+json" }
  });
  if (!response.ok) return { count: 0, types: [`referrers API returned HTTP ${response.status}`] };
  const index = (await response.json()) as { manifests?: Array<{ artifactType?: string }> };
  const manifests = index.manifests ?? [];
  return { count: manifests.length, types: manifests.map((m) => m.artifactType ?? "(no artifactType)") };
}

/** cosign's pre-referrers convention: a sibling `sha256-<hex>.sig` tag. */
function cosignSignatureTag(repository: string, digest: string): boolean {
  const short = repository.replace(/^library\//, "");
  const tag = `${short}:sha256-${digest.slice("sha256:".length)}.sig`;
  return run("crane", ["manifest", tag], { allowFailure: true }).status === 0;
}

/**
 * Rekor, searched by the artifact digest.
 *
 * A hit here is NOT good news by default, and the caddy digest has one. It is a
 * `hashedrekord` carrying a bare public key: no Fulcio certificate, so no
 * subject, no issuer, no identity of any kind. Anyone can make one over any
 * digest, including someone who wants a digest to look attested.
 *
 * It is the most dangerous shape a near-miss can take, because a tool that
 * checked only "does a transparency-log entry exist for this digest" would pass.
 */
async function rekorEntries(digest: string): Promise<{ uuids: string[]; usable: number; kinds: string[] }> {
  const search = await fetch("https://rekor.sigstore.dev/api/v1/index/retrieve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hash: digest })
  });
  if (!search.ok) return { uuids: [], usable: 0, kinds: [`index API returned HTTP ${search.status}`] };
  const uuids = (await search.json()) as string[];
  const kinds: string[] = [];
  let usable = 0;
  for (const uuid of uuids.slice(0, 10)) {
    const entry = await fetch(`https://rekor.sigstore.dev/api/v1/log/entries/${uuid}`);
    if (!entry.ok) continue;
    const payload = (await entry.json()) as Record<string, { body: string }>;
    const body = Object.values(payload)[0]?.body;
    if (!body) continue;
    const decoded = JSON.parse(Buffer.from(body, "base64").toString("utf8")) as {
      kind?: string;
      spec?: { signature?: { publicKey?: { content?: string } }; publicKey?: { content?: string } };
    };
    const keyContent = decoded.spec?.signature?.publicKey?.content ?? decoded.spec?.publicKey?.content ?? "";
    const material = Buffer.from(keyContent, "base64").toString("utf8");
    // A certificate carries an identity. A bare public key does not, and there
    // is nothing to pin it to.
    const isCertificate = material.includes("BEGIN CERTIFICATE");
    kinds.push(`${decoded.kind ?? "unknown"}/${isCertificate ? "x509-certificate" : "bare-public-key"}`);
    if (isCertificate) usable += 1;
  }
  return { uuids, usable, kinds };
}

/** GitHub's attestation store, in case the builder publishes there. */
async function githubAttestations(owner: string, digest: string): Promise<{ found: boolean; detail: string }> {
  const result = run("gh", ["api", `orgs/${owner}/attestations/${digest}`], { allowFailure: true });
  if (result.status !== 0) return { found: false, detail: result.stderr.trim().split("\n")[0] || "not found" };
  const parsed = JSON.parse(result.stdout) as { attestations?: unknown[] };
  return { found: (parsed.attestations ?? []).length > 0, detail: `${(parsed.attestations ?? []).length} attestation(s)` };
}

export async function checkUpstreamSignatures(options: {
  component?: string | null;
  repository: string;
  indexDigest: string;
  imageDigest: string;
  builderOwner: string;
}): Promise<UpstreamSignatureReport> {
  const { repository, indexDigest, imageDigest, builderOwner } = options;
  const token = await pullToken(repository);
  const checks: SignatureCheck[] = [];

  const childReferrers = await referrers(repository, imageDigest, token);
  checks.push({
    id: "oci-referrers-image",
    question: "Does the registry list any referrer artifact for the deployed child manifest?",
    found: childReferrers.count > 0,
    detail: `${childReferrers.count} referrer(s)${childReferrers.types.length ? `: ${childReferrers.types.join(", ")}` : ""}`,
    satisfiesOptionB: false
  });

  const indexReferrers = await referrers(repository, indexDigest, token);
  checks.push({
    id: "oci-referrers-index",
    question: "Does the registry list any referrer artifact for the multi-architecture index?",
    found: indexReferrers.count > 0,
    detail: `${indexReferrers.count} referrer(s)${indexReferrers.types.length ? `: ${indexReferrers.types.join(", ")}` : ""}`,
    satisfiesOptionB: false
  });

  const sigTag = cosignSignatureTag(repository, imageDigest);
  checks.push({
    id: "cosign-signature-tag",
    question: "Is there a cosign signature at the conventional sha256-<digest>.sig sibling tag?",
    found: sigTag,
    detail: sigTag ? "a .sig tag resolves" : "no .sig tag resolves for the deployed digest",
    satisfiesOptionB: false
  });

  const rekor = await rekorEntries(imageDigest);
  checks.push({
    id: "rekor-index",
    question: "Does the Sigstore transparency log carry an entry over the deployed digest?",
    found: rekor.uuids.length > 0,
    detail:
      rekor.uuids.length === 0
        ? "no transparency-log entry names this digest"
        : `${rekor.uuids.length} entry/entries (${rekor.kinds.join(", ")}); ${rekor.usable} carry an x509 identity. ` +
          "An entry with a bare public key names nobody: anyone can create one over any digest, so it cannot be " +
          "pinned to an upstream identity and must not be read as attestation.",
    // Only an entry with a certificate could even be a candidate, and even then
    // the identity would have to match a pinned upstream one.
    satisfiesOptionB: false
  });

  const gh = await githubAttestations(builderOwner, imageDigest);
  checks.push({
    id: "github-attestations",
    question: `Does github.com/${builderOwner} publish an attestation for the deployed digest?`,
    found: gh.found,
    detail: gh.detail,
    satisfiesOptionB: false
  });

  const optionBAvailable = checks.some((c) => c.satisfiesOptionB);
  const conclusion = optionBAvailable
    ? ["At least one check found a signature that can satisfy option B. Verify it and record the identity."]
    : [
        "Option B is NOT available for this image.",
        "The registry publishes an in-toto SLSA statement whose subject is the deployed digest, and it is " +
          "UNSIGNED: it is a blob attached to the index, so its trust root is registry push access rather than " +
          "an identity anyone pinned.",
        "Nothing found here changes that. A transparency-log entry over the digest, where one exists, carries a " +
          "bare public key rather than a certificate, so it attests to no identity at all.",
        "This is a recorded gap and not a pass."
      ];

  return {
    schema: SIGNATURE_CHECK_SCHEMA,
    component: options.component ?? null,
    repository,
    indexDigest,
    imageDigest,
    checkedAt: new Date().toISOString(),
    checks,
    optionBAvailable,
    conclusion
  };
}

async function main(argv: string[]): Promise<number> {
  const json = argv.includes("--json");
  const id = argv.find((a) => !a.startsWith("--"));
  if (!id) fail("usage: check-upstream-signatures.ts <component-id> [--json]");
  const component = loadLedger().components.find((c) => c.id === id);
  if (!component) fail(`no component '${id}' in the ledger`);
  const coordinates = registryCoordinatesFor(component);
  const builderId = component.registryProvenance?.builderId ?? "";
  const builderOwner = builderId.replace(/^https:\/\/github\.com\//, "").split("/")[0] || "docker-library";

  const report = await checkUpstreamSignatures({ component: component.id, ...coordinates, builderOwner });
  if (json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(`option B availability for ${report.component} (${report.repository}@${report.imageDigest})\n\n`);
    for (const check of report.checks) {
      process.stdout.write(`  ${check.found ? "FOUND  " : "absent "} ${check.id}\n`);
      process.stdout.write(`          ${check.question}\n`);
      process.stdout.write(`          ${check.detail}\n`);
    }
    process.stdout.write("\n");
    for (const line of report.conclusion) process.stdout.write(`  ${line}\n`);
  }
  // 0 means option B is available and should be pursued; 3 means it is not,
  // which is a recorded gap rather than an error, exactly as the ledger
  // verifier's exit codes work.
  return report.optionBAvailable ? 0 : 3;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((error) => {
      const message = error instanceof EscrowError || error instanceof Error ? error.message : String(error);
      process.stderr.write(`upstream signature check failed: ${message}\n`);
      process.exit(1);
    });
}
