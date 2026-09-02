// Read a Docker Official Image's build recipe OUT OF the deployed artifact.
//
// =============================================================================
// WHY THIS EXISTS, AND WHY IT DOES NOT READ THE LEDGER FOR THE ANSWER
// =============================================================================
//
// WO-07 section 2.2 option A means rebuilding a component from pinned upstream
// source and matching the deployed digest. That needs the recipe: which commit,
// which directory, which parent image, which frontend, which build arguments.
//
// Getting any of those from a document this project wrote would make the
// rebuild a test of our own bookkeeping. The dstack-ingress rebuild avoided
// that by reading the source commit out of /etc/.GIT_REV inside the image, and
// that check immediately retracted a claim the ledger had been making for
// weeks. Docker Official Images bake no such file, but they publish something
// stronger: a `mode=max` in-toto SLSA statement attached to the index, whose
// subject is the exact digest we deploy and which records the git URL, the
// commit, the directory, the resolved parent image by digest, the frontend by
// digest and every build argument.
//
// So the recipe comes from the artifact's own provenance, and the ledger is
// only ever COMPARED against it. If they disagree, this refuses.
//
// =============================================================================
// THE STATEMENT IS UNSIGNED, AND THAT IS NOT A CONTRADICTION
// =============================================================================
//
// The same statement is recorded in the ledger as `registryProvenance` and is
// explicitly NOT a binding: it is unsigned, so its trust root is registry push
// access rather than an identity we pinned. Nothing here changes that.
//
// An unsigned recipe is still the right input to a rebuild, because the rebuild
// does not trust it. If the statement named the wrong commit, the rebuild would
// produce a different image and the comparison would say so. The statement gets
// us something exact to test; the test is what decides.
//
// =============================================================================
// USAGE
// =============================================================================
//
//   npx tsx scripts/provenance/doi-source-recipe.ts <component-id> [--json]
//   npx tsx scripts/provenance/doi-source-recipe.ts --repo library/caddy \
//       --index sha256:... --digest sha256:... [--json]
//
// The component form reads `repository`, `indexDigest` and the pinned digest
// from deploy/provenance/plaintext-capable-components.json and then verifies
// every one of them against the registry. The explicit form exists for the
// negative controls, which must be able to ask for a digest the ledger does not
// name.

import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { EscrowError, fail, requireTool, run } from "./escrowRuntime.js";
import { loadLedger, type Component } from "../verify-third-party-provenance.js";

export const RECIPE_SCHEMA = "anonrouter-doi-source-recipe-v1";

export interface DoiSourceRecipe {
  schema: typeof RECIPE_SCHEMA;
  component: string | null;
  registry: {
    repository: string;
    /** Fully qualified, so a consumer never has to guess whether `library/` belongs in it. */
    pullReference: string;
    indexDigest: string;
    imageDigest: string;
    platform: string;
    attestationManifest: string;
    statementSha256: string;
    predicateType: string;
    builderId: string;
    signed: false;
  };
  source: {
    gitUrl: string;
    commit: string;
    directory: string | null;
    dockerfile: string;
    buildUrl: string;
  };
  build: {
    frontend: string | null;
    buildContexts: Record<string, string>;
    buildArgs: Record<string, string>;
    platform: string;
    sourceDateEpoch: string | null;
    buildStartedOn: string | null;
    buildFinishedOn: string | null;
  };
  deployedArtifact: {
    manifestMediaType: string;
    annotations: Record<string, string>;
    configCreated: string | null;
    historyCreated: string[];
    layerDigests: string[];
  };
  /**
   * Facts about the artifact that make a byte-for-byte rebuild impossible or
   * uncertain, each one derived from the bytes rather than asserted. This is a
   * DIAGNOSIS, not a verdict: nothing here decides whether a rebuild passed.
   */
  reproducibilityObstructions: Array<{ id: string; detail: string }>;
}

const DIGEST = /^sha256:[0-9a-f]{64}$/;

function crane(args: string[]): string {
  return run("crane", args, { maxBuffer: 64 * 1024 * 1024 }).stdout;
}

function craneRaw(args: string[]): { text: string; sha256: string } {
  const text = crane(args);
  return { text, sha256: createHash("sha256").update(text).digest("hex") };
}

/** `library/caddy` -> `caddy`, which is what crane wants for Docker Hub. */
function shortRepo(repository: string): string {
  return repository.replace(/^library\//, "");
}

/**
 * Find the attestation manifest whose subject is OUR digest.
 *
 * The index carries one attestation manifest per platform, each annotated with
 * the image digest it describes. Taking the first would silently attach another
 * architecture's provenance to an amd64 record: it would parse, it would look
 * right, and every value in it would be about a different image.
 */
function attestationManifestFor(repository: string, indexDigest: string, imageDigest: string): string {
  const index = JSON.parse(crane(["manifest", `${shortRepo(repository)}@${indexDigest}`])) as {
    manifests?: Array<{ digest: string; annotations?: Record<string, string> }>;
  };
  const children = index.manifests ?? [];
  if (!children.some((m) => m.digest === imageDigest)) {
    fail(
      `${repository}@${indexDigest} does not contain ${imageDigest}.\n` +
        "The index and the pinned child disagree, so nothing below this point would be about the deployed image."
    );
  }
  const match = children.find(
    (m) =>
      m.annotations?.["vnd.docker.reference.type"] === "attestation-manifest" &&
      m.annotations?.["vnd.docker.reference.digest"] === imageDigest
  );
  if (!match) fail(`${repository}@${indexDigest} carries no attestation manifest referencing ${imageDigest}`);
  return match.digest;
}

function slsaStatementFor(repository: string, attestationManifest: string): { statement: any; sha256: string } {
  const manifest = JSON.parse(crane(["manifest", `${shortRepo(repository)}@${attestationManifest}`])) as {
    layers?: Array<{ digest: string; annotations?: Record<string, string> }>;
  };
  const layer = (manifest.layers ?? []).find((l) =>
    (l.annotations?.["in-toto.io/predicate-type"] ?? "").startsWith("https://slsa.dev/provenance")
  );
  if (!layer) fail(`attestation manifest ${attestationManifest} carries no SLSA provenance layer`);
  const blob = craneRaw(["blob", `${shortRepo(repository)}@${layer.digest}`]);
  return { statement: JSON.parse(blob.text), sha256: blob.sha256 };
}

/**
 * Split docker-library's build URL into its parts.
 *
 * The form is `<git url>#<commit>:<directory>`, and the commit is the only
 * place the exact revision appears. A tag would be worthless here: this value
 * has to identify one tree forever.
 */
function parseBuildUrl(uri: string): { gitUrl: string; commit: string; directory: string | null } {
  const match = uri.match(/^(.*?)#([0-9a-f]{40})(?::(.*))?$/);
  if (!match) fail(`configSource uri is not a docker-library build url with a full commit: ${uri}`);
  return { gitUrl: match[1], commit: match[2], directory: match[3] ?? null };
}

export function readRecipe(options: {
  repository: string;
  indexDigest: string;
  imageDigest: string;
  component?: string | null;
}): DoiSourceRecipe {
  requireTool("crane", ["version"]);
  const { repository, indexDigest, imageDigest } = options;
  for (const [name, value] of Object.entries({ indexDigest, imageDigest })) {
    if (!DIGEST.test(value)) fail(`${name} must be a full sha256 digest, got ${value}`);
  }

  const attestationManifest = attestationManifestFor(repository, indexDigest, imageDigest);
  const { statement, sha256: statementSha256 } = slsaStatementFor(repository, attestationManifest);

  // The statement must be ABOUT our digest. An index annotation and the
  // statement's own subject disagreeing is the one failure that would make this
  // record actively misleading rather than merely incomplete.
  const subjects: string[] = (statement.subject ?? []).map((s: any) => `sha256:${s.digest?.sha256}`);
  if (!subjects.includes(imageDigest)) {
    fail(`the SLSA statement's subject does not include ${imageDigest}; it names ${subjects.join(", ") || "nothing"}`);
  }

  const predicate = statement.predicate ?? {};
  const invocation = predicate.invocation ?? {};
  const args: Record<string, string> = invocation.parameters?.args ?? {};

  const configSourceUri: string = invocation.configSource?.uri ?? "";
  const source = parseBuildUrl(configSourceUri);
  const dockerfile: string = invocation.configSource?.entryPoint ?? "Dockerfile";

  // Named contexts are how docker-library substitutes a resolved parent for the
  // `FROM alpine:3.23` a Dockerfile names. Without them a rebuild pulls today's
  // tag, which is a different image, and the difference would be attributed to
  // the source.
  const buildContexts: Record<string, string> = {};
  const buildArgs: Record<string, string> = {};
  let frontend: string | null = null;
  for (const [key, value] of Object.entries(args)) {
    if (key.startsWith("context:")) buildContexts[key.slice("context:".length)] = value;
    else if (key === "build-arg:BUILDKIT_SYNTAX") frontend = value;
    else if (key.startsWith("build-arg:")) buildArgs[key.slice("build-arg:".length)] = value;
  }
  const sourceDateEpoch = buildArgs.SOURCE_DATE_EPOCH ?? null;

  const manifestText = crane(["manifest", `${shortRepo(repository)}@${imageDigest}`]);
  if (createHash("sha256").update(manifestText).digest("hex") !== imageDigest.slice("sha256:".length)) {
    fail(`${repository}@${imageDigest}: the registry served manifest bytes that do not hash to the requested digest`);
  }
  const manifest = JSON.parse(manifestText) as {
    mediaType: string;
    annotations?: Record<string, string>;
    layers: Array<{ digest: string }>;
  };
  const config = JSON.parse(crane(["config", `${shortRepo(repository)}@${imageDigest}`])) as {
    created?: string;
    history?: Array<{ created?: string }>;
  };
  const historyCreated = (config.history ?? []).map((h) => h.created ?? "");

  const obstructions: Array<{ id: string; detail: string }> = [];
  const createdAnnotation = manifest.annotations?.["org.opencontainers.image.created"] ?? null;
  if (createdAnnotation && sourceDateEpoch === null) {
    obstructions.push({
      id: "build-clock-in-manifest-annotation",
      detail:
        `the manifest carries org.opencontainers.image.created=${createdAnnotation}, and the recorded build ` +
        "arguments contain no SOURCE_DATE_EPOCH, so docker-library's generator took this value from the " +
        "builder's wall clock (meta.jq: `env.SOURCE_DATE_EPOCH // now`). The annotation is part of the " +
        "manifest bytes, so it is part of the digest."
    });
  }
  const distinctHistory = [...new Set(historyCreated.filter(Boolean))];
  const subSecond = distinctHistory.filter((t) => /\.\d+Z$/.test(t));
  if (distinctHistory.length > 1) {
    obstructions.push({
      id: "build-clock-in-image-config",
      detail:
        `the image config records ${distinctHistory.length} distinct history timestamps` +
        (subSecond.length > 0 ? `, ${subSecond.length} of them at sub-second precision` : "") +
        ` (config.created=${config.created ?? "absent"}). A build with SOURCE_DATE_EPOCH set normalises every ` +
        "one of these to the same second, so these values can be reproduced neither by leaving the epoch unset " +
        "(the clock moves) nor by setting it (the values collapse)."
    });
  }
  // buildkit's DAEMON compresses the layer blobs, and the compressed bytes are
  // what the digest covers. The provenance pins the Dockerfile FRONTEND by
  // digest and names no daemon version anywhere, so two builds of identical
  // uncompressed content can differ purely by who compressed them and there is
  // no recorded value to match.
  const buildkitMetadata = predicate.metadata?.["https://mobyproject.org/buildkit@v1#metadata"] ?? {};
  const namesDaemonVersion = JSON.stringify(buildkitMetadata).includes("buildkitVersion");
  if (!namesDaemonVersion) {
    obstructions.push({
      id: "builder-daemon-not-recorded",
      detail:
        "the statement pins the Dockerfile frontend by digest" +
        (frontend ? ` (${frontend})` : "") +
        " but records no buildkitd version. Layer blobs are compressed by the daemon, so an unpinned daemon " +
        "can change every layer digest without changing a byte of content, and the recipe offers nothing to pin it to."
    });
  }
  if (Object.keys(buildContexts).length === 0) {
    obstructions.push({
      id: "parent-not-recorded",
      detail:
        "the provenance records no named build context, so the parent image this build actually consumed is " +
        "not pinned by the recipe and a rebuild would resolve whatever the FROM tag points at today."
    });
  }

  return {
    schema: RECIPE_SCHEMA,
    component: options.component ?? null,
    registry: {
      repository,
      pullReference: `docker.io/${repository}@${imageDigest}`,
      indexDigest,
      imageDigest,
      platform: invocation.environment?.platform ?? "unknown",
      attestationManifest,
      statementSha256,
      predicateType: statement.predicateType,
      builderId: predicate.builder?.id ?? "unknown",
      signed: false
    },
    source: { ...source, dockerfile, buildUrl: configSourceUri },
    build: {
      frontend,
      buildContexts,
      buildArgs,
      platform: invocation.environment?.platform ?? "unknown",
      sourceDateEpoch,
      buildStartedOn: predicate.metadata?.buildStartedOn ?? null,
      buildFinishedOn: predicate.metadata?.buildFinishedOn ?? null
    },
    deployedArtifact: {
      manifestMediaType: manifest.mediaType,
      annotations: manifest.annotations ?? {},
      configCreated: config.created ?? null,
      historyCreated,
      layerDigests: manifest.layers.map((l) => l.digest)
    },
    reproducibilityObstructions: obstructions
  };
}

/**
 * Resolve a component from the ledger, and refuse anything the recipe cannot be
 * read for.
 *
 * The registry coordinates are not in the schema as free text by accident: they
 * are `pinned.digest`, `pinned.indexDigest` and the registry path implied by
 * `pinned.image`. Deriving the path from the image reference rather than
 * carrying a fourth field means the ledger cannot name one image and query
 * another.
 */
export function registryCoordinatesFor(component: Component): {
  repository: string;
  indexDigest: string;
  imageDigest: string;
} {
  if (!component.pinned.digest) fail(`${component.id}: no pinned digest, so there is no artifact to read a recipe from`);
  if (!component.pinned.indexDigest) {
    fail(
      `${component.id}: no pinned indexDigest.\n` +
        "The SLSA statement hangs off the multi-architecture index, not the child manifest, and the tag that\n" +
        "once resolved to it moves. Without the index digest the provenance is unreachable for any image whose\n" +
        "tag has since been republished, which is the normal case rather than the exception."
    );
  }
  const image = component.pinned.image ?? fail(`${component.id}: no pinned image reference`);
  const name = image.split("@")[0].split(":")[0];
  const repository = name.includes("/") ? name : `library/${name}`;
  return { repository, indexDigest: component.pinned.indexDigest, imageDigest: component.pinned.digest };
}

function main(argv: string[]): number {
  const json = argv.includes("--json");
  const rest = argv.filter((a) => a !== "--json");
  const flag = (name: string): string | null => {
    const at = rest.indexOf(`--${name}`);
    return at >= 0 ? rest[at + 1] ?? null : null;
  };

  let coordinates: { repository: string; indexDigest: string; imageDigest: string };
  let component: string | null = null;
  const explicitRepository = flag("repo");
  if (explicitRepository) {
    coordinates = {
      repository: explicitRepository,
      indexDigest: flag("index") ?? fail("--index is required with --repo"),
      imageDigest: flag("digest") ?? fail("--digest is required with --repo")
    };
  } else {
    const id = rest.find((a) => !a.startsWith("--"));
    if (!id) fail("usage: doi-source-recipe.ts <component-id> [--json]   or   --repo <path> --index <d> --digest <d>");
    const found = loadLedger().components.find((c) => c.id === id);
    if (!found) fail(`no component '${id}' in the ledger`);
    component = found.id;
    coordinates = registryCoordinatesFor(found);
  }

  const recipe = readRecipe({ ...coordinates, component });
  if (json) {
    process.stdout.write(`${JSON.stringify(recipe, null, 2)}\n`);
    return 0;
  }

  const say = (line = "") => process.stdout.write(`${line}\n`);
  say(`recipe for ${recipe.component ?? recipe.registry.repository}@${recipe.registry.imageDigest}`);
  say(`  read from the UNSIGNED registry SLSA statement ${recipe.registry.statementSha256.slice(0, 16)}…`);
  say(`  source     ${recipe.source.gitUrl}#${recipe.source.commit}:${recipe.source.directory ?? ""}`);
  say(`  dockerfile ${recipe.source.dockerfile}`);
  say(`  frontend   ${recipe.build.frontend ?? "(none recorded)"}`);
  for (const [name, value] of Object.entries(recipe.build.buildContexts)) say(`  context    ${name} = ${value}`);
  for (const [name, value] of Object.entries(recipe.build.buildArgs)) say(`  build-arg  ${name} = ${value}`);
  say(`  SOURCE_DATE_EPOCH ${recipe.build.sourceDateEpoch ?? "NOT SET in the recorded build"}`);
  say("");
  say(`${recipe.reproducibilityObstructions.length} obstruction(s) to a byte-for-byte rebuild, derived from the artifact:`);
  for (const obstruction of recipe.reproducibilityObstructions) {
    say(`  ${obstruction.id}`);
    say(`    ${obstruction.detail}`);
  }
  say("");
  say("This tool did NOT rebuild anything. It reports what the deployed artifact says about");
  say("its own build, so a rebuild has something exact to test rather than something to assume.");
  return 0;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (error) {
    const message = error instanceof EscrowError || error instanceof Error ? error.message : String(error);
    process.stderr.write(`doi-source-recipe failed: ${message}\n`);
    process.exit(1);
  }
}
