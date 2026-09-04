// The README the public content-plane repository would carry.
//
// =============================================================================
// WHY THIS IS A SEPARATE MODULE AND NOT A STRING INSIDE THE EXPORTER
// =============================================================================
//
// It used to be a literal block inside scripts/export-content-plane.ts, and the
// literal said "The one unproven link" while the ledger recorded three. Nothing
// could catch that, because the only way to read the generated README was to run
// the exporter, write a directory, and diff it by hand. The claim and the
// evidence lived in different files with no mechanical relationship.
//
// So the gap section is now DERIVED from the ledger rather than typed next to
// it. The count, the component ids, the deployed digests and the reason each
// link is still unproven all come from
// deploy/provenance/plaintext-capable-components.json. Adding a fourth gap
// changes the README automatically; removing one requires evidence the ledger
// schema will not accept without it.
//
// And because this is a pure function of the ledger, a unit test can assert the
// published claim without running the exporter at all. See
// tests/unit/third-party-provenance.test.ts.
//
// =============================================================================
// THE RULE THIS FILE EXISTS TO ENFORCE
// =============================================================================
//
// A source pin is not a binding. An unsigned registry attestation is not a
// binding. Neither may be worded so a reader could mistake it for one. The
// project's own principle is that a transparency chain which quietly rounds an
// unverifiable link up to "verified" is worse than no chain, because it launders
// an assumption into an apparent proof, and the first public artifact is the
// worst possible place to make that mistake.

import type { Component, Ledger } from "./verify-third-party-provenance.js";

/** Recorded gaps, in a stable order so the README diff is reviewable. */
function gapsOf(ledger: Ledger): Component[] {
  return ledger.components
    .filter((c) => c.plaintextCapable && c.binding.status === "NONE")
    .sort((a, b) => (a.id < b.id ? -1 : 1));
}

/**
 * What is known about a gap, worded so that "known" never reads as "proven".
 *
 * Each branch names the strongest thing we actually have and then says, in the
 * same breath, what it does not establish. The order matters: the reader gets
 * the limit before they get the reassurance.
 */
/**
 * Where the thing actually is, said once.
 *
 * `pinned` is the third-party artifact this entry's provenance is ABOUT.
 * `runtime`, when present and derived, is what production actually pulls.
 * Printing only the first said production pulls from a competitor's registry at
 * boot, which is false and, being checkable, was worse than saying nothing.
 *
 * Shared by the gap and the established-binding sections rather than written
 * twice. It WAS written twice for one revision, and the copy in the
 * established-binding section immediately said "Deployed at
 * dstacktee/dstack-ingress" for a component the ledger records as not being
 * pulled from there. Closing a gap must not reintroduce the sentence that gap's
 * own notes exist to correct.
 */
function deployedSentence(component: Component): string {
  const pinnedRef = `\`${component.pinned.image ?? "(image name not recorded)"}@${component.pinned.digest}\``;
  if (!component.pinned.digest) {
    return "Not currently deployed. The entry exists anyway, because the binding has to be in place before the component is first used, not after.";
  }
  if (component.runtime && component.runtime.relationship === "derived-from-pinned") {
    return (
      `Production runs \`${component.runtime.image}@${component.runtime.digest}\`, an AnonRouter image ` +
      `built FROM ${pinnedRef}. So the upstream artifact is a build-time dependency and not a runtime one: ` +
      `nothing is pulled from the upstream registry at boot. Its provenance is still the question this ` +
      `entry is about, because the derived image contains it.`
    );
  }
  return `Deployed at ${pinnedRef}.`;
}

function gapProse(component: Component): string[] {
  const lines: string[] = [];
  lines.push(`**\`${component.id}\`** ${component.role}. ${deployedSentence(component)}`);
  lines.push("");
  if (component.deployedSource && component.sourcePin && component.deployedSource.commit !== component.sourcePin.commit) {
    lines.push(
      `The deployed artifact records its own source commit as \`${component.deployedSource.commit}\``,
      `(read from \`${component.deployedSource.path}\` inside the image, not asserted about it), and that is`,
      `**not** the commit pinned below. A rebuild must target the deployed commit; building the reviewed one`,
      "would run the right procedure against the wrong bytes.",
      ""
    );
  }

  if (component.registryProvenance) {
    lines.push(
      `The registry publishes an **unsigned** in-toto SLSA statement whose subject is that exact`,
      `digest, naming upstream commit \`${component.registryProvenance.sourceCommit}\``,
      `(\`${component.registryProvenance.sourcePath ?? ""}\`). That is useful and it is **not a binding**:`,
      "its trust root is whoever can push to that registry repository, not an identity we pinned.",
      "It tells a rebuilder exactly which commit to build and compare. It does not tell anyone that",
      "the image in service came from that commit."
    );
  } else if (component.sourcePin) {
    lines.push(
      `The upstream source is pinned to commit \`${component.sourcePin.commit}\` and verified file by`,
      `file against that commit's tree (\`${component.sourcePin.treeDigest}\`), licence read and`,
      `confirmed \`${component.sourcePin.license}\`. That is **not a binding** either. A source pin says`,
      "which bytes we intend to build. A binding says the running image came from them. Only the",
      "second is what is missing."
    );
  } else {
    lines.push(
      "Nothing beyond a pinned digest has been established for this component. A pinned digest makes",
      "the build reproducible and says nothing about what is inside the image."
    );
  }
  lines.push("");

  // The measurement, when one exists, and it changes what the gap MEANS.
  //
  // Without this a reader is left with the natural assumption: the binding is
  // missing because nobody has done the work yet, and it will appear when
  // somebody does. For these components that is the wrong conclusion, and wrong
  // in the direction that would send a reader off to attempt something that
  // cannot succeed.
  if (component.reproducibility) {
    const r = component.reproducibility;
    const measuredOn = r.measuredAt.slice(0, 10);
    lines.push(
      `**This gap has been measured, and it is not "not attempted yet".** AnonRouter's public CI replayed`,
      "upstream's own recorded build invocation for this exact digest, natively on `linux/amd64`, with every",
      "argument read out of the deployed image's own SLSA statement rather than from any file in this",
      `repository. Result on ${measuredOn}: \`${r.verdict}\`.`,
      "",
      `Two **identical** invocations, minutes apart on the same runner with a cold cache, produced`,
      `\`${r.rebuiltDigest}\` and \`${r.rebuiltAgainDigest ?? "(second run not available)"}\`. Those are different images, so the`,
      "**published recipe is not deterministic**, and no replay of it can match a fixed digest whoever runs",
      "the replay. Why, precisely:",
      ""
    );
    for (const obstruction of r.obstructions) {
      lines.push(`- **\`${obstruction.id}\`** ${obstruction.detail}`);
    }
    lines.push(
      "",
      `Full comparison, layer by layer and path by path: [\`${r.evidenceFile}\`](${r.evidenceFile}).`,
      `The run is public: ${r.run}`,
      ""
    );
    if (r.optionBOutcome === "NO-QUALIFYING-SIGNATURE-FOUND") {
      lines.push(
        `Option B was measured on the same run and found nothing qualifying **as of ${measuredOn}**: no OCI`,
        "referrer, no cosign signature tag, no attestation under the builder's GitHub org. Where the Sigstore",
        "transparency log carries an entry over the digest at all, it is a bare public key with no certificate,",
        "so it names nobody and cannot be pinned to an upstream identity. A check that asked only whether the",
        "digest appears in the log would have accepted it.",
        ""
      );
    }
    // The scope paragraph is NOT optional and NOT paraphrased here. An earlier
    // revision of this generator said the gap was "unavailable for this
    // artifact" and that "trying harder does not change that", which is a
    // universal claim over evidence that was scoped to one recipe on one day.
    // Overstating a negative launders an unmeasured assumption into an apparent
    // proof exactly as overstating a positive does.
    lines.push("**What this does and does not establish:**", "");
    for (const line of r.claimScope) lines.push(line === "" ? "" : line);
    lines.push("");
  }

  if (component.controlledEquivalent) {
    const e = component.controlledEquivalent;
    lines.push(
      `**There is a replacement candidate. It is integrated in source and NOT deployed.**`,
      `\`${e.image}@${e.digest}\` is built by AnonRouter from`,
      `\`${e.sourceRepository}@${e.sourceCommit}\`, reproduced independently by a second CI job at the same`,
      "digest, and signed against a pinned identity and issuer:",
      "",
      "```",
      "cosign verify \\",
      `  --certificate-identity '${e.certificateIdentity}' \\`,
      `  --certificate-oidc-issuer '${e.certificateOidcIssuer}' \\`,
      `  ${e.image}@${e.digest}`,
      "```",
      "",
      // The recursive part, and the reason the first version of these candidates
      // was not good enough. A replacement that inherits an unbound base has
      // moved the gap down a layer, and a reader has no way to tell from a
      // digest and a signature.
      `**It inherits no container base image.** \`inheritedBaseImages\` is empty and the ledger schema will`,
      "not accept a non-empty one. Everything in it is a release artifact pinned by a digest upstream",
      "publishes, a file from a Debian package pinned by a sha256 that also appears in the index Debian's",
      "OpenPGP-signed `Release` covers, or a literal in a published assembly script.",
      ""
    );
    if (e.buildToolDependencies.length > 0) {
      lines.push(
        "It is not zero-dependency, and the remainder is named rather than omitted. These images BUILD it",
        "and none of their bytes ship:",
        ""
      );
      for (const tool of e.buildToolDependencies) {
        lines.push(`- \`${tool.image}@${tool.digest}\` — ${tool.why}`);
      }
      lines.push("");
    }
    lines.push(
      `**Compatibility was measured, not asserted.** \`${e.compatibility.harness}\` builds the same source on`,
      `the base this replaces and on the candidate, runs an identical matrix under the real deployment`,
      `policy, and requires them to agree: ${e.compatibility.checks} checks, ${e.compatibility.differingChecks} differing. A deliberately broken`,
      `variant is the control, and the matrix detected it in ${e.compatibility.controlDetectedDifferences} check(s) — without that, agreement`,
      `would be consistent with a matrix that cannot tell two images apart. Evidence:`,
      `[\`${e.compatibility.evidenceFile}\`](${e.compatibility.evidenceFile}).`,
      "",
      "It proves **nothing about the artifact above**. A replacement is not a binding for the thing in",
      "service, and saying otherwise would be the exact rounding-up this document exists to refuse.",
      `Referenced now by ${e.integratedIn.map((w) => `\`${w}\``).join(", ")}, so the NEXT build uses it;`,
      "nothing running does. Promoting it moves the measured Compose hash, the app id and the attestation",
      "policy, which makes it a measured-release decision rather than a documentation edit.",
      ""
    );
  }
  return lines;
}

/** Established bindings, in the same stable order, for the same reason. */
function boundOf(ledger: Ledger): Component[] {
  return ledger.components
    .filter((c) => c.plaintextCapable && c.binding.status !== "NONE")
    .sort((a, b) => (a.id < b.id ? -1 : 1));
}

/**
 * The component table's "where the source is" cell, DERIVED.
 *
 * It used to be a literal reading "UPSTREAM, Phala. Apache-2.0. See the gaps
 * below" for `dstack-ingress`, which stopped being true the moment that gap
 * closed and would have kept being published anyway: the table sat above the
 * generated section and nothing related the two. A README that contradicts
 * itself in adjacent paragraphs is worse than one that says less, and the
 * contradiction here would have been in the direction of understating a proof
 * while overstating a gap.
 */
function whereTheSourceIs(component: Component | undefined, fallback: string): string {
  if (!component) return fallback;
  if (component.controlledEquivalent) {
    // NAME THE COMPONENT, NOT ITS REPLACEMENT.
    //
    // This returned "AnonRouter FROM-scratch base", which reads as a statement
    // that the base in use IS AnonRouter's scratch build. It is not: the ledger
    // records that image as `deployed: false`, and the schema refuses to let it
    // say otherwise. The table cell would have told a public reader the opposite
    // of what the ledger two sections below says.
    //
    // That is the same failure this function's own doc comment describes -- a
    // README contradicting itself in adjacent paragraphs -- and it also misses
    // the goal of being deployment-neutral, which is achieved by saying nothing
    // about what runs, not by naming a different artifact.
    return (
      `${component.upstream.project} (${component.upstream.license}); binding not established, ` +
      "AnonRouter FROM-scratch replacement available; see Build provenance"
    );
  }
  return component.binding.status === "NONE"
    ? `${component.upstream.project} (${component.upstream.license}); see Build provenance`
    : `${component.upstream.project} (${component.upstream.license}); reproducibly rebuilt by AnonRouter CI`;
}

/**
 * What a reader runs to check an established binding for themselves.
 *
 * A binding nobody outside AnonRouter can re-check is an assertion with extra
 * steps. The identity printed here is the one `cosign verify` accepts, which is
 * not the same string as the `job_workflow_ref` OIDC claim: Fulcio's SAN carries
 * an `https://github.com/` prefix the claim omits, and publishing the claim
 * produced a value that looked right and could not verify.
 */
function boundProse(component: Component): string[] {
  const evidence = component.binding.evidence;
  const lines: string[] = [];
  lines.push(`**\`${component.id}\`** ${component.role}. ${deployedSentence(component)}`);
  lines.push("");
  if (evidence?.method === "rebuild") {
    lines.push(
      `Rebuilt by \`${evidence.builderWorkflowRef}\` (workflow commit`,
      `\`${evidence.builderWorkflowSha}\`) from \`${component.upstream.project}@${evidence.sourceCommit}\`,`,
      `producing \`${evidence.rebuiltDigest}\`, which is the deployed digest.`,
      ""
    );
    if (component.deployedSource) {
      lines.push(
        `The commit was not chosen. It was read from \`${component.deployedSource.path}\` inside the deployed`,
        "image before any source was fetched, so it is a property of the artifact rather than a claim about it.",
        ""
      );
    }
  } else if (evidence?.method === "attestation") {
    lines.push(
      `Verified against upstream identity \`${evidence.certificateIdentity}\` under issuer`,
      `\`${evidence.certificateOidcIssuer}\`, over digest \`${evidence.attestedDigest}\`.`,
      ""
    );
  }
  return lines;
}

/**
 * Stable repository/build status. This deliberately says nothing about which
 * release production currently runs; that belongs to signed release evidence
 * and fresh attestation, not to a repository landing page.
 */
function artifactProse(component: Component): string[] {
  const names: Record<string, string> = {
    "caddy-edge-base": "Caddy edge base",
    "dstack-ingress": "Dstack ingress",
    "node-base-image": "Node runtime base"
  };
  const friendlyName = names[component.id] ?? component.id;
  const name = `${friendlyName} (\`${component.id}\`)`;
  const evidence = component.binding.evidence;
  if (evidence?.method === "rebuild") {
    return [
      `- **${name}: reproducibly bound.** Public CI rebuilt`,
      `  \`${component.upstream.project}@${evidence.sourceCommit}\` and reproduced the recorded image`,
      "  digest byte for byte. The result is signed against a pinned workflow identity."
    ];
  }

  if (component.controlledEquivalent) {
    const replacement = component.controlledEquivalent;
    // NAME THE ARTIFACT THE GAP IS ABOUT, alongside the replacement.
    //
    // This entry read "**Node runtime base: reproducible AnonRouter build.**"
    // and then described only the candidate. `nodejs/docker-node` appeared
    // NOWHERE in the README, so a reader was told the runtime base is a
    // reproducible AnonRouter build with nothing to correct that impression --
    // while the ledger records that image as `deployed: false` and the
    // component's own binding as NOT established.
    //
    // Being deployment-neutral means declining to say which release is running.
    // It does not mean omitting which artifact the gap is about, and it cannot
    // mean letting an undeployed replacement stand in for it. The wording below
    // keeps the concise replacement guarantees this section is for and adds the
    // two facts whose absence made it misleading: what the tracked artifact is,
    // and that the replacement is not deployed.
    const status =
      component.binding.status === "NONE" ? "source-to-digest binding NOT established" : component.binding.status;
    return [
      `- **${friendlyName} (\`${component.id}\`): reproducible AnonRouter build, NOT DEPLOYED.**`,
      `  The tracked artifact is \`${component.upstream.project}\` (${component.upstream.license}), ${status}.`,
      "  The replacement FROM-scratch image is reproduced by two independent CI jobs, signed,",
      `  and passes ${replacement.compatibility.checks}/${replacement.compatibility.checks} compatibility checks with a working negative control.`
    ];
  }

  return [
    `- **${name}: tracked dependency.** Its exact status and evidence are recorded in`,
    "  `deploy/provenance/plaintext-capable-components.json`."
  ];
}

/**
 * The full README text.
 *
 * `ledger` is the committed provenance ledger. Passing it in rather than reading
 * it here keeps this function pure, so the test and the exporter cannot end up
 * reading different files.
 */
/**
 * The clean claim is about a DEPLOYMENT, so it needs a deployment measurement.
 *
 * "Every plaintext-capable component in this deployment has an established
 * binding" is the strongest sentence this README makes, and every other input
 * to it is about artifacts. Artifacts cannot support it. A digest pinned in a
 * compose file is a request; the sentence is about what was granted.
 *
 * The specific way this goes wrong is not hypothetical. When the two base
 * images are promoted, their ledger entries stop being candidates and become
 * ordinary bindings. At that moment the gap count reaches zero from a text
 * edit, and if the CVM has not been redeployed and re-attested, the README
 * announces a clean chain about a deployment still running the previous images
 * -- with every schema check passing, because nothing in a per-component record
 * knows what is running.
 *
 * So the generator refuses. Not a warning and not a softer sentence: producing
 * the file at all is what publishes the claim, and a refusal that names the
 * missing evidence is the only version of this that cannot be skimmed past.
 */
function requireDeploymentAttestation(ledger: Ledger): void {
  const attestation = ledger.deploymentAttestation;
  const plaintextCapable = ledger.components.filter((c) => c.plaintextCapable);
  if (!attestation) {
    throw new Error(
      "REFUSING to generate a README claiming no unproven links.\n\n" +
        "Every plaintext-capable component now records a binding, which is a claim about\n" +
        "ARTIFACTS. The sentence this README would print is about a DEPLOYMENT, and the\n" +
        "ledger has no `deploymentAttestation`: nobody has recorded that a guest measured\n" +
        "the promoted compose, produced an app id and re-attested.\n\n" +
        "Add `deploymentAttestation` with the compose hash, app id, the image digests the\n" +
        "GUEST reported, the time, the compose file measured, and the evidence path."
    );
  }
  const observed = new Set(attestation.observedImageDigests);
  // A null pinned digest means the component is not deployed at all, so there
  // is nothing for a deployment measurement to have observed. Those are
  // skipped rather than reported missing: demanding that a guest observe an
  // image nobody deploys would make this refusal permanent and therefore
  // something to be removed rather than satisfied.
  const missing = plaintextCapable
    .map((c) => ({ id: c.id, digest: c.pinned?.digest ?? null }))
    .filter((c): c is { id: string; digest: string } => c.digest !== null && !observed.has(c.digest));
  if (missing.length > 0) {
    throw new Error(
      "REFUSING to generate a README claiming no unproven links.\n\n" +
        `The recorded deployment attestation (app ${attestation.appId}, ${attestation.attestedAt})\n` +
        "does not observe every plaintext-capable component it would be vouching for:\n" +
        missing.map((c) => `  ${c.id} pinned at ${c.digest}`).join("\n") +
        "\n\nA measurement of a different deployment is not evidence about this one."
    );
  }
}

export function buildPublicReadme(ledger: Ledger): string {
  const gaps = gapsOf(ledger);
  const bound = boundOf(ledger);
  const tracked = [...gaps, ...bound].sort((a, b) => (a.id < b.id ? -1 : 1));
  const byId = (id: string) => ledger.components.find((c) => c.id === id);

  return [
    "# AnonRouter confidential content plane",
    "",
    "Every component that can touch prompt or response plaintext inside the Intel",
    "TDX trust domain, and the tests that enforce the boundary.",
    "",
    "## What this repository is for, and what it is not",
    "",
    "Attestation proves **which code ran**. It never proves what that code does.",
    "This repository exists so the second question has an answer a stranger can",
    "check by reading rather than by trusting: this is the source, and these are",
    "the tests that hold the boundary it describes.",
    "",
    "The repository also carries reproducible build evidence for the images it",
    "publishes. Verifying a particular running service is a separate step: compare",
    "fresh hardware attestation with that release's signed manifest and policy.",
    "",
    "## The boundary, component by component",
    "",
    "For every component that can touch a prompt, a reader can either read the",
    "source here or follow a reference to pinned upstream source. Which applies:",
    "",
    "| Component | Can touch plaintext | Where the source is |",
    "| --- | --- | --- |",
    "| `relay` | full request and response bodies, transiently | here |",
    "| classifier (in-process on the relay) | the truncated latest user turn | here |",
    "| `compat` broker | full bodies **and** the caller's static `ar_` key | here |",
    "| `<provider>-worker` | full bodies plus one provider credential | here |",
    `| \`edge\` (in-CVM L7 router) | full bodies, after TLS terminates in-TD | here (configuration); its base image is ${whereTheSourceIs(byId("caddy-edge-base"), "**UPSTREAM**")} |`,
    "| `<provider>-egress` | ciphertext only (SNI passthrough) | here (configuration) |",
    "| `gateway-attestation` | **no content at all** | here |",
    `| \`dstack-ingress\` | ciphertext, then the plaintext stream in transit | ${whereTheSourceIs(byId("dstack-ingress"), "**UPSTREAM, Phala. Apache-2.0**")} |`,
    "",
    "The `relay`, `compat`, `worker` and `gateway-attestation` roles are all the",
    "same first-party image, selected by `RUNTIME_ROLE`. Its **base image** is",
    "upstream: it runs every line of code in this repository, so it is",
    "plaintext-capable whatever the code above it does, and it is covered by the",
    "ledger like any other third-party component.",
    "",
    "## Build provenance",
    "",
    "This is the stable build status of the artifacts maintained by this repository.",
    "It is intentionally not a production status page.",
    "",
    ...tracked.flatMap(artifactProse),
    "",
    "A digest pin or an unsigned registry statement alone is not treated as a source",
    "binding. Exact digests, build identities, attestations, compatibility evidence",
    "and remaining trust dependencies are recorded in",
    "`deploy/provenance/plaintext-capable-components.json` and enforced by",
    "`tests/unit/third-party-provenance.test.ts`.",
    "",
    "## Verifying a deployment",
    "",
    "This README deliberately does not say which release production currently runs.",
    "Verify a particular deployment using its independently distributed signed release",
    "manifest and attestation policy, then require fresh hardware evidence to match them.",
    "Repository build evidence answers where an image came from; deployment attestation",
    "answers whether that image is the one running.",
    "",
    "## What is deliberately NOT here",
    "",
    "The control plane: accounts, authentication, API keys, billing, payments,",
    "admin and the database. None of it can touch a prompt, and none of it is",
    "reachable from the entry point this image runs. That is enforced, not asserted:",
    "`tests/unit/content-plane-closure.test.ts` computes the module graph from",
    "`src/contentPlane.ts` and fails if any control-plane module becomes reachable,",
    "at runtime or at compile time.",
    "",
    "The **content-free control RPC schemas** ARE here, in",
    "`src/routes/internal/rpcSchemas.ts`, even though the server that serves them",
    "runs elsewhere. They are the boundary contract, and publishing them is what",
    "lets a reader check the boundary carries no prompt field rather than take it",
    "on trust. `tests/unit/rpc-boundary-contract.test.ts` enforces it.",
    "",
    "Some enforcement suites stay in the private monorepo because they assert",
    "against files this repository deliberately does not contain. They are listed,",
    "with the reason for each, in `EXPORT-MANIFEST.json` under `monorepoOnlySuites`,",
    "so the reduction is visible rather than silent.",
    "",
    "## Verifying",
    "",
    "```",
    "npm ci",
    "npm run build      # single-platform linux/amd64 Docker v2 manifest",
    "npm test           # the boundary and privacy suites",
    "```",
    "",
    "That checks this repository against itself. Verifying a **live deployment**",
    "against it is a different procedure with different limits, and the limits are",
    "the important part. See `docs/publication/INDEPENDENT_VERIFICATION.md`.",
    "",
    "## Licence",
    "",
    "Apache-2.0. See LICENSE and NOTICE.",
    ""
  ].join("\n");
}
