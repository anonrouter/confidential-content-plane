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
function gapProse(component: Component): string[] {
  const lines: string[] = [];
  const deployed = component.pinned.digest
    ? `Deployed at \`${component.pinned.image ?? "(image name not recorded)"}@${component.pinned.digest}\`.`
    : "Not currently deployed. The entry exists anyway, because the binding has to be in place before the component is first used, not after.";
  lines.push(`**\`${component.id}\`** ${component.role}. ${deployed}`);
  lines.push("");

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
  return lines;
}

/**
 * The full README text.
 *
 * `ledger` is the committed provenance ledger. Passing it in rather than reading
 * it here keeps this function pure, so the test and the exporter cannot end up
 * reading different files.
 */
export function buildPublicReadme(ledger: Ledger): string {
  const gaps = gapsOf(ledger);
  const gapIds = gaps.map((c) => `\`${c.id}\``).join(", ");
  const count = gaps.length;
  const word = count === 1 ? "link" : "links";

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
    "**It does not, by itself, prove that the image running in the trust domain was",
    "built from these bytes.** That is a separate artifact, a source-to-digest",
    "binding, and it is produced by a CI build that signs its output against a",
    "pinned OIDC identity. Until such a build has produced a digest equal to the one",
    "a deployment is measured against, the honest statement is:",
    "",
    "> This repository shows what the code says. It does not yet show what the",
    "> deployment ran.",
    "",
    "Running `npm ci && npm run build` here produces **an** image. Nothing in this",
    "repository asserts that it equals any deployed digest, and you should not",
    "assume it does. The build is deterministic in its inputs, which is a",
    "precondition for that binding and is not the binding.",
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
    "| `edge` (in-CVM L7 router) | full bodies, after TLS terminates in-TD | here (configuration); **its base image is UPSTREAM, see the gaps below** |",
    "| `<provider>-egress` | ciphertext only (SNI passthrough) | here (configuration) |",
    "| `gateway-attestation` | **no content at all** | here |",
    "| `dstack-ingress` | ciphertext, then the plaintext stream in transit | **UPSTREAM, Phala. Apache-2.0. See the gaps below** |",
    "",
    "The `relay`, `compat`, `worker` and `gateway-attestation` roles are all the",
    "same first-party image, selected by `RUNTIME_ROLE`. Its **base image** is",
    "upstream and is one of the gaps below: it runs every line of code in this",
    "repository, so it is plaintext-capable whatever the code above it does.",
    "",
    `### The ${count} unproven ${word}, stated rather than rounded up`,
    "",
    `${count} plaintext-capable component${count === 1 ? "" : "s"} in this deployment ${count === 1 ? "is" : "are"} not built from this`,
    `source, and for ${count === 1 ? "it" : "each of them"} the source-to-digest binding is **NOT established**: ${gapIds}.`,
    "",
    "A binding means one of exactly two things, and neither has been done for any",
    "of them:",
    "",
    "- **Rebuild.** Build the component in our public CI from pinned upstream source",
    "  and confirm the digest equals the deployed one. A near miss is not a partial",
    "  pass, and a laptop build is a rehearsal rather than evidence, because the",
    "  point is that a reader can check it without trusting whoever ran it.",
    "- **Verified upstream provenance.** Verify an upstream signature against a",
    "  **pinned** upstream identity, both certificate identity and OIDC issuer, over",
    "  the digest actually deployed.",
    "",
    ...gaps.flatMap(gapProse),
    "This is stated here, in the README, because a transparency chain that quietly",
    "rounds an unverifiable link up to \"verified\" is worse than no chain: it",
    "launders an assumption into an apparent proof. Someone told the chain is",
    "incomplete can reason about the residual risk. Someone told it is complete",
    "cannot.",
    "",
    "The machine-readable version of the same statement is",
    "`deploy/provenance/plaintext-capable-components.json`, published here, and it",
    "is what the signed release manifest carries. **This section is generated from",
    "that file**, so the two cannot drift: `tests/unit/third-party-provenance.test.ts`,",
    "also published here, fails if this README names fewer gaps than the ledger",
    "records or lets a source pin read as a binding. Run `npm test` and check.",
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
