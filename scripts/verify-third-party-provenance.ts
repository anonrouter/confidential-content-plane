// WO-07 section 2.2: report the source-to-digest binding of every
// plaintext-capable component that is not our source.
//
// WHAT THIS DOES AND, MORE IMPORTANTLY, WHAT IT DOES NOT
//
// It validates the committed ledger and reports the state of every binding. It
// does NOT establish one. Establishing a binding means either rebuilding the
// component from pinned upstream source and comparing digests (option A) or
// verifying an upstream signature against a pinned identity (option B), and
// both need network access, a registry and a builder. None of that happens
// here.
//
// That distinction is the whole design. The failure mode this gate exists to
// prevent is a chain that reports "verified" for a link nobody checked, so a
// check that could not run must be loudly distinguishable from a check that
// passed. Hence three exit codes, not two:
//
//   0  every plaintext-capable component has an established binding
//   1  the ledger is malformed, or claims a binding it has no evidence for
//   3  the ledger is well formed and there are RECORDED GAPS
//
// Exit 3 is not a crash and not a pass. It is the honest state of this
// workstream today, and a release manifest is required to carry it.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { z } from "zod";

export const LEDGER_PATH = "deploy/provenance/plaintext-capable-components.json";

/**
 * Evidence shapes. These are what make a claimed binding checkable by someone
 * who did not run the build.
 */
const rebuildEvidence = z.object({
  method: z.literal("rebuild"),
  /** The upstream commit the rebuild used. A tag is not enough: tags move. */
  sourceCommit: z.string().regex(/^[0-9a-f]{40}$/, "sourceCommit must be a full 40-character commit SHA"),
  /** The digest the rebuild produced, which must equal the deployed digest. */
  rebuiltDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  /** Who built it, pinned by workflow ref and the commit of the workflow itself. */
  builderWorkflowRef: z.string().min(1),
  builderWorkflowSha: z.string().regex(/^[0-9a-f]{40}$/),
  verifiedAt: z.string().datetime()
});

const attestationEvidence = z.object({
  method: z.literal("attestation"),
  /** The upstream identity the signature was verified against, pinned. */
  certificateIdentity: z.string().min(1),
  certificateOidcIssuer: z.string().url(),
  /** The digest the attestation covers. */
  attestedDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  /** Digest of the attestation bundle itself, so the record is reproducible. */
  bundleSha256: z.string().regex(/^[0-9a-f]{64}$/),
  verifiedAt: z.string().datetime()
});

/**
 * A verified pin of the upstream SOURCE.
 *
 * Deliberately separate from `binding`, and deliberately unable to satisfy it.
 * Pinning the source proves which bytes we intend to build; a binding proves
 * the running image came from them. Collapsing the two into one field is
 * exactly the rounding-up this gate exists to prevent, so they cannot be
 * confused here: a component can have a complete, verified source pin and still
 * be a RECORDED GAP, which is precisely the state dstack-ingress is in.
 */
const sourcePinSchema = z.object({
  repository: z.string().min(1),
  path: z.string().min(1).optional(),
  commit: z.string().regex(/^[0-9a-f]{40}$/, "sourcePin.commit must be a full 40-character commit SHA"),
  treeDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  license: z.string().min(1),
  verifiedAt: z.string().datetime(),
  buildInputs: z.record(z.string().nullable()).optional(),
  evidenceFile: z.string().min(1).optional()
});

/**
 * Registry-published provenance, which is DELIBERATELY NOT A BINDING.
 *
 * Docker Official Images attach an unsigned in-toto SLSA statement to the image
 * index whose subject is the exact digest we deploy, naming the upstream repo and
 * commit it was built from. That is genuinely useful and genuinely insufficient.
 *
 * Insufficient because it is unsigned: the trust root is whoever can push to that
 * registry repository, not an identity we pinned. It cannot satisfy `binding`,
 * and the schema below makes that structural rather than a matter of discipline —
 * there is no status value it can produce.
 *
 * Useful because it names the exact commit to rebuild from and compare. It turns
 * a gap nobody can act on into one with a defined next step, which is what
 * separates a recorded gap from an admission of ignorance.
 */
/**
 * What production actually runs, when that is not the pinned upstream artifact.
 *
 * `pinned` records the third-party artifact whose provenance this entry is
 * about. That is usually also the thing production pulls, and for
 * `dstack-ingress` it is not: production runs an AnonRouter image derived from
 * the pinned one, so a reader told only about `pinned` would conclude the
 * deployment pulls from a competitor's registry at boot. It does not, and has
 * not for some time.
 *
 * The field exists because the public README is generated from this file and
 * said exactly that. A wrong sentence in a transparency document is worse than
 * a missing one: it is checkable, it is checked, and it is wrong.
 */
const runtimeArtifactSchema = z.object({
  image: z.string().min(1),
  digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  /**
   * `identical` means production pulls the pinned artifact itself.
   * `derived-from-pinned` means it pulls an AnonRouter image built FROM it, so
   * the pinned artifact remains a build-time dependency and stops being a
   * runtime one.
   */
  relationship: z.enum(["identical", "derived-from-pinned"]),
  note: z.string().min(1)
});

/**
 * The commit the DEPLOYED artifact records as its own source.
 *
 * Read OUT OF the artifact, never asserted about it. Upstream dstack-ingress
 * bakes `git rev-parse HEAD` into /etc/.GIT_REV, which turns the source commit
 * into a property of the image rather than a claim someone makes on its behalf.
 *
 * This field exists because the two can disagree and did. `sourcePin` records
 * the tree we reviewed; this records the tree the running image was built from.
 * Nothing in the original schema could express that difference, so a rebuild of
 * the pinned commit could have been compared against the deployed digest and
 * reported a confident result about the wrong bytes.
 */
const deployedSourceSchema = z.object({
  commit: z.string().regex(/^[0-9a-f]{40}$/),
  /**
   * Only one value, deliberately. If a weaker method is ever added it must be a
   * visible schema change, because "upstream told us" and "the image says so"
   * are not the same kind of fact and should never share a field.
   */
  method: z.literal("artifact-embedded"),
  /** Where inside the artifact the value was read from. */
  path: z.string().min(1),
  observedAt: z.string().datetime()
});

/**
 * What a REBUILD ACTUALLY MEASURED, including when it failed.
 *
 * `binding` records whether a source-to-digest binding exists. It has three
 * values and none of them can say WHY a gap is still a gap, so for a long time
 * the reason lived in prose that nobody could check and that would age badly
 * in the one direction that matters: "we have not rebuilt it yet" and "no
 * rebuild by anyone can ever match it" are different facts with different
 * consequences, and only the first one improves by trying harder.
 *
 * This field is the measurement. It is written from a public CI run's verdict
 * file, it is allowed to record a failure, and the schema below makes it
 * impossible for a REBUILT claim to sit next to a measurement that contradicts
 * it.
 */
const reproducibilitySchema = z.object({
  method: z.literal("public-ci-rebuild"),
  /** Straight from judge-doi-rebuild.ts. Never hand-written. */
  verdict: z.enum([
    "REPRODUCED",
    "REPRODUCED-WITH-SUPPLIED-METADATA",
    "NOT-REPRODUCED-RECIPE-NONDETERMINISTIC",
    "NOT-REPRODUCED"
  ]),
  /**
   * Can option A ever succeed for this artifact? False means the recipe is
   * non-deterministic or the artifact embeds its own build clock, so the answer
   * does not change by rebuilding again on a better day.
   */
  optionAAvailable: z.boolean(),
  /** Can option B ever succeed? Measured by check-upstream-signatures.ts. */
  optionBAvailable: z.boolean(),
  run: z.string().url(),
  builderWorkflowRef: z.string().min(1),
  builderWorkflowSha: z.string().regex(/^[0-9a-f]{40}$/),
  rebuiltDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  rebuiltAgainDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/).nullable(),
  sourceDateEpochRebuildDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/).nullable(),
  /** Each derived from the artifact or from a comparison, never asserted. */
  obstructions: z
    .array(z.object({ id: z.string().min(1), detail: z.string().min(1) }))
    .min(1),
  evidenceFile: z.string().min(1),
  measuredAt: z.string().datetime()
});

/**
 * An AnonRouter-built artifact intended to REPLACE an upstream one whose
 * provenance cannot be established.
 *
 * Deliberately not `binding` and deliberately not `runtime`. It is neither: it
 * says nothing about the deployed digest, and recording it as though it did
 * would be the exact rounding-up this ledger exists to prevent. A reproducible
 * image AnonRouter can prove the provenance of does not retroactively prove
 * anything about the one in service.
 *
 * `deployed: false` is the only value the schema accepts, because promoting one
 * of these into service changes the measured compose, the app id and the policy,
 * and that is a measured-release decision rather than a ledger edit.
 */
const controlledEquivalentSchema = z.object({
  image: z.string().min(1),
  digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  sourceRepository: z.string().min(1),
  sourceCommit: z.string().regex(/^[0-9a-f]{40}$/),
  builderWorkflowRef: z.string().min(1),
  builderWorkflowSha: z.string().regex(/^[0-9a-f]{40}$/),
  certificateIdentity: z.string().min(1),
  certificateOidcIssuer: z.string().url(),
  /** Two independent CI runs producing the same digest. One run is not a reproducibility claim. */
  independentlyReproducedDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  deployed: z.literal(false),
  note: z.union([z.string(), z.array(z.string())])
});

const registryProvenanceSchema = z.object({
  method: z.literal("registry-provenance"),
  attestedDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  attestationManifest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  /** Digest of the statement blob, so this record is reproducible by anyone. */
  statementSha256: z.string().regex(/^[0-9a-f]{64}$/),
  predicateType: z.string().url(),
  builderId: z.string().min(1),
  configSourceUri: z.string().min(1),
  sourceCommit: z.string().regex(/^[0-9a-f]{40}$/),
  sourcePath: z.string().nullable(),
  /** Always false. Present so a future signed variant is a visible change. */
  signed: z.literal(false),
  fetchedAt: z.string().datetime()
});

const componentSchema = z
  .object({
    id: z.string().min(1),
    role: z.string().min(1),
    plaintextCapable: z.boolean(),
    upstream: z.object({
      project: z.string().min(1),
      sourceUrl: z.string().url(),
      license: z.string().min(1),
      redistributable: z.boolean()
    }),
    pinned: z.object({
      image: z.string().nullable(),
      digest: z.string().regex(/^sha256:[0-9a-f]{64}$/).nullable(),
      revision: z.string().nullable(),
      /**
       * The multi-architecture index the pinned child manifest belongs to.
       *
       * Not decoration, and not the pin. Two things need it. A reader checking
       * that `digest` really is this repository's linux/amd64 child has to be
       * able to walk the index; and the registry's SLSA statement hangs off the
       * INDEX rather than the child, so without this the recipe is unreachable
       * for any image whose tag has since moved. `node:22-bookworm-slim` had
       * already moved when this field was added, which is how the requirement
       * surfaced.
       */
      indexDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/).optional(),
      /** Which child of that index. Recorded so "amd64" is a claim we made, not one inferred. */
      platform: z.string().optional()
    }),
    sourcePin: sourcePinSchema.nullable().optional(),
    runtime: runtimeArtifactSchema.nullable().optional(),
    deployedSource: deployedSourceSchema.nullable().optional(),
    registryProvenance: registryProvenanceSchema.nullable().optional(),
    reproducibility: reproducibilitySchema.nullable().optional(),
    controlledEquivalent: controlledEquivalentSchema.nullable().optional(),
    binding: z.object({
      status: z.enum(["REBUILT", "ATTESTED", "NONE"]),
      evidence: z.union([rebuildEvidence, attestationEvidence]).nullable()
    }),
    note: z.union([z.string(), z.array(z.string())]).optional()
  })
  .superRefine((component, ctx) => {
    const { status, evidence } = component.binding;

    // `identical` means what it says. If production runs the pinned artifact,
    // the two digests must agree, otherwise the field is describing a third
    // image nobody named.
    if (component.runtime?.relationship === "identical"
      && component.pinned.digest !== null
      && component.runtime.digest !== component.pinned.digest) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${component.id}: runtime claims to be identical to the pinned artifact but names a different digest`
      });
    }
    if (component.runtime?.relationship === "derived-from-pinned"
      && component.pinned.digest !== null
      && component.runtime.digest === component.pinned.digest) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${component.id}: runtime claims to be derived from the pinned artifact but names the same digest`
      });
    }

    // Registry provenance must describe the digest we actually deploy. Provenance
    // for a different digest is provenance for a different image, and recording
    // it here would be worse than recording nothing.
    if (component.registryProvenance && component.pinned.digest
      && component.registryProvenance.attestedDigest !== component.pinned.digest) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${component.id}: registryProvenance attests a different digest than the pinned one`
      });
    }

    // A measurement that contradicts the claimed status is the most dangerous
    // state this file can be in, because both halves look deliberate. The
    // measurement wins: it came from a public CI run and the status is a word
    // somebody typed.
    if (component.reproducibility && status === "REBUILT" && component.reproducibility.verdict !== "REPRODUCED") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          `${component.id}: status REBUILT, but the recorded measurement says ` +
          `${component.reproducibility.verdict}. A rebuild that did not reproduce the deployed digest is not a binding.`
      });
    }
    if (component.reproducibility && status === "REBUILT" && component.reproducibility.optionAAvailable === false) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${component.id}: status REBUILT, but the measurement records option A as unavailable for this artifact.`
      });
    }
    if (component.reproducibility && component.reproducibility.rebuiltDigest === component.pinned.digest
      && component.reproducibility.verdict.startsWith("NOT-REPRODUCED")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          `${component.id}: the measurement names the deployed digest as the rebuilt one while reporting ` +
          `${component.reproducibility.verdict}. Those cannot both be true.`
      });
    }

    // A controlled equivalent is an alternative, never a proof about the
    // artifact in service. If it were allowed to share the pinned digest it
    // would read as one.
    if (component.controlledEquivalent && component.pinned.digest === component.controlledEquivalent.digest) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${component.id}: controlledEquivalent names the pinned digest, which would make a replacement read as a binding`
      });
    }
    if (component.controlledEquivalent
      && component.controlledEquivalent.digest !== component.controlledEquivalent.independentlyReproducedDigest) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          `${component.id}: controlledEquivalent was not independently reproduced. ` +
          "A digest produced once on one machine is not a reproducibility claim."
      });
    }

    // A claimed binding with no evidence is the exact failure this gate exists
    // to catch, so it is a schema error rather than a warning.
    if (status === "NONE" && evidence !== null) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: `${component.id}: status NONE must not carry evidence` });
      return;
    }
    if (status === "NONE") return;

    if (evidence === null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${component.id}: status ${status} claims a binding but carries no evidence`
      });
      return;
    }
    const expected = status === "REBUILT" ? "rebuild" : "attestation";
    if (evidence.method !== expected) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${component.id}: status ${status} requires ${expected} evidence, found ${evidence.method}`
      });
      return;
    }

    // The binding must be to the digest actually deployed. Evidence about some
    // other digest is evidence about some other image.
    if (component.pinned.digest === null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${component.id}: status ${status} requires a pinned digest to bind to`
      });
      return;
    }
    const bound = evidence.method === "rebuild" ? evidence.rebuiltDigest : evidence.attestedDigest;
    if (bound !== component.pinned.digest) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${component.id}: evidence covers ${bound}, but the pinned digest is ${component.pinned.digest}`
      });
    }

    // If we pinned a source, a rebuild claim must be a rebuild OF THAT SOURCE.
    // Otherwise the ledger could pin one commit, build another, and read as
    // consistent.
    //
    // `deployedSource` takes precedence when the two disagree, and that
    // precedence is the whole reason the field exists. A rebuild is trying to
    // reproduce the DEPLOYED artifact; building the reviewed commit instead
    // would compare the right procedure against the wrong bytes and report the
    // difference as a reproducibility failure rather than as the pin being off.
    const mustRebuildFrom = component.deployedSource?.commit ?? component.sourcePin?.commit;
    if (evidence.method === "rebuild" && mustRebuildFrom && evidence.sourceCommit !== mustRebuildFrom) {
      const which = component.deployedSource ? "the commit the deployed image records" : "the pinned source";
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${component.id}: rebuilt from ${evidence.sourceCommit}, but ${which} is ${mustRebuildFrom}`
      });
    }
  });

export const ledgerSchema = z.object({
  $comment: z.union([z.string(), z.array(z.string())]).optional(),
  schemaVersion: z.literal(1),
  components: z.array(componentSchema).min(1)
});

export type Ledger = z.infer<typeof ledgerSchema>;
export type Component = z.infer<typeof componentSchema>;

export function parseLedger(raw: string): Ledger {
  return ledgerSchema.parse(JSON.parse(raw));
}

export function loadLedger(root = process.cwd()): Ledger {
  return parseLedger(readFileSync(`${root}/${LEDGER_PATH}`, "utf8"));
}

/**
 * The components a release manifest must name as unproven.
 *
 * Only plaintext-capable ones: a component that cannot see a prompt is out of
 * scope for this gate, and widening it would bury the entries that matter.
 */
export function recordedGaps(ledger: Ledger): Component[] {
  return ledger.components.filter((c) => c.plaintextCapable && c.binding.status === "NONE");
}

export function establishedBindings(ledger: Ledger): Component[] {
  return ledger.components.filter((c) => c.plaintextCapable && c.binding.status !== "NONE");
}

function report(ledger: Ledger): number {
  const lines: string[] = [];
  const say = (line = "") => lines.push(line);

  say("WO-07 third-party plaintext-capable provenance");
  say(`  ledger: ${LEDGER_PATH}`);
  say("");

  const plaintext = ledger.components.filter((c) => c.plaintextCapable);
  const gaps = recordedGaps(ledger);
  const bound = establishedBindings(ledger);

  say(`${plaintext.length} plaintext-capable third-party component(s)`);
  say("");

  for (const component of bound) {
    const evidence = component.binding.evidence;
    say(`  BOUND  ${component.id}  (${component.binding.status})`);
    say(`         digest ${component.pinned.digest}`);
    if (evidence?.method === "rebuild") {
      say(`         rebuilt from ${component.upstream.project}@${evidence.sourceCommit}`);
      say(`         by ${evidence.builderWorkflowRef}@${evidence.builderWorkflowSha}`);
    } else if (evidence?.method === "attestation") {
      say(`         attested by ${evidence.certificateIdentity} via ${evidence.certificateOidcIssuer}`);
    }
  }

  for (const component of gaps) {
    say(`  GAP    ${component.id}`);
    say(`         ${component.role}`);
    say(`         upstream ${component.upstream.project} (${component.upstream.license})`);
    say(`         pinned   ${component.pinned.image ?? "not deployed"}${component.pinned.digest ? `@${component.pinned.digest}` : ""}`);
    if (component.sourcePin) {
      say(`         source   ${component.sourcePin.repository}@${component.sourcePin.commit}`);
      say(`                  tree ${component.sourcePin.treeDigest}`);
      say("                  SOURCE PINNED AND VERIFIED, NOT REBUILT. Still a gap:");
      say("                  nothing yet ties a running image to these bytes.");
    }
    if (component.deployedSource) {
      say(`         deployed ${component.deployedSource.commit}`);
      say(`                  read from ${component.deployedSource.path} inside the artifact itself`);
      if (component.sourcePin && component.sourcePin.commit !== component.deployedSource.commit) {
        say("                  DIVERGENT: the reviewed commit is NOT the commit the");
        say("                  deployed image was built from. A rebuild must target the");
        say("                  deployed one, or it compares the right procedure against");
        say("                  the wrong bytes.");
      }
    }
    if (component.registryProvenance) {
      const rp = component.registryProvenance;
      say(`         registry ${rp.configSourceUri}`);
      say(`                  built by ${rp.builderId}, statement ${rp.statementSha256.slice(0, 16)}…`);
      say("                  UNSIGNED registry provenance. NOT a binding: its trust root is");
      say("                  registry push access, not a pinned identity. It does name the");
      say(`                  exact commit to rebuild and compare: ${rp.sourceCommit}`);
    }
  }

  say("");
  say("This tool did NOT rebuild anything and did NOT verify a signature.");
  say("It reports the committed ledger. Establishing a binding needs a builder,");
  say("a registry and network access, none of which are used here, so a check");
  say("that has not run can never be mistaken for one that passed.");
  say("");

  if (gaps.length === 0) {
    say("RESULT: every plaintext-capable third-party component has an established binding");
    process.stdout.write(`${lines.join("\n")}\n`);
    return 0;
  }

  say(`RESULT: ${gaps.length} RECORDED GAP(S), which the release manifest and the public`);
  say("        documentation must both name. This is not a pass and not a failure:");
  say("        it is the honest state of the chain.");
  process.stdout.write(`${lines.join("\n")}\n`);
  return 3;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  try {
    process.exit(report(loadLedger()));
  } catch (error) {
    process.stderr.write(`third-party provenance ledger is invalid:\n${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
}
