// Decide what a Docker Official Image rebuild actually established.
//
// =============================================================================
// THE ONE RULE
// =============================================================================
//
// A source-to-digest binding exists when a rebuild from pinned upstream source
// produces the deployed digest. Nothing else is one. Not ten of eleven layers,
// not an identical filesystem, not "the only difference is a timestamp". WO-07
// section 2.2 says so, this project has already refused a near match once on
// exactly those grounds, and the refusal is what made the run that closed
// `dstack-ingress` worth doing.
//
// So this file has exactly one way to emit REPRODUCED, and it is
// `deployedVsRebuild.identical`. Every other output is a difference to explain.
//
// =============================================================================
// WHY IT ALSO JUDGES THE REBUILD AGAINST ITSELF
// =============================================================================
//
// Comparing a rebuild with the deployed image answers "did WE reproduce it",
// and a failure there is ambiguous: our builder could be at fault, which is
// what the Rosetta near-miss turned out to be.
//
// Building the same source twice, in the same environment, minutes apart,
// answers a different and stronger question: is THE PUBLISHED RECIPE
// deterministic. If two identical invocations of it disagree, then no replay of
// that recipe can match a fixed target, whoever runs it. That distinction
// decides whether the ledger records "not attempted yet" or "attempted, and the
// recipe as published cannot get there".
//
// =============================================================================
// THE LIMIT OF THAT CLAIM, STATED HERE BECAUSE IT WAS ONCE OVERSTATED
// =============================================================================
//
// An earlier version of this file said a disagreement meant "no rebuild by any
// party can ever match" and that option A was "unavailable for the component".
// Both are broader than the measurement. What is measured is the recipe
// docker-library publishes, the inputs reachable from it, and the date.
//
// It does NOT rule out: upstream publishing a qualifying signature tomorrow,
// which would satisfy option B without any rebuild; a party holding build
// inputs nobody outside their infrastructure has; or this project accepting a
// different kind of evidence after review. A verdict that forecloses those is
// making the same mistake as a chain that rounds an unproven link up, in the
// other direction: it launders an unmeasured universal into an apparent proof.
//
// =============================================================================
// THE GENEROSITY GUARD
// =============================================================================
//
// The replay is handed the deployed manifest's own annotations, including the
// build clock, because docker-library derives that value from `now` and there
// is no honest way to recompute it. That makes the test maximally favourable,
// which is fine while it FAILS: a refutation that survives being handed the
// answer is a strong refutation.
//
// It would not be fine if it passed. A rebuild given the target's metadata has
// not independently produced that metadata, so `bindingEligible` is false
// whenever the annotations were supplied, even on an exact match. The guard
// exists so nobody has to remember the caveat later.

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compareImages, renderComparison, type ImageComparison } from "./compare-oci-images.js";
import { EscrowError, fail } from "./escrowRuntime.js";

export const VERDICT_SCHEMA = "anonrouter-doi-rebuild-verdict-v1";

export type DoiVerdict =
  | "REPRODUCED"
  | "REPRODUCED-WITH-SUPPLIED-METADATA"
  | "NOT-REPRODUCED-RECIPE-NONDETERMINISTIC"
  | "NOT-REPRODUCED";

export interface DoiRebuildJudgement {
  schema: typeof VERDICT_SCHEMA;
  component: string;
  deployedDigest: string;
  rebuiltDigest: string;
  rebuiltAgainDigest: string | null;
  sourceDateEpochRebuildDigest: string | null;
  annotationsSuppliedFromDeployed: boolean;
  findings: {
    /** Two identical invocations of the same recipe produced the same bytes. */
    selfReproducible: boolean | null;
    reproducedDeployed: boolean;
    /** Setting SOURCE_DATE_EPOCH is the other half of the fork, and it fails too. */
    sourceDateEpochReproducedDeployed: boolean | null;
    layersIdenticalVsDeployed: number;
    layersTotalDeployed: number;
    changedPathsVsDeployed: number;
    manifestAnnotationsDifferingVsDeployed: string[];
    buildTimestampsDifferingVsDeployed: number;
  };
  comparisons: {
    deployedVsRebuild: ImageComparison;
    rebuildVsRebuildAgain: ImageComparison | null;
    deployedVsSourceDateEpochRebuild: ImageComparison | null;
  };
  verdict: DoiVerdict;
  /** May this be recorded as a WO-07 option A binding? Only ever true on an unaided exact match. */
  bindingEligible: boolean;
  reason: string[];
}

export interface JudgeInputs {
  component: string;
  deployed: string;
  rebuild: string;
  rebuildAgain?: string | null;
  sourceDateEpochRebuild?: string | null;
  annotationsSuppliedFromDeployed: boolean;
}

export function judge(inputs: JudgeInputs): DoiRebuildJudgement {
  const deployedVsRebuild = compareImages(inputs.deployed, inputs.rebuild);
  const rebuildVsRebuildAgain = inputs.rebuildAgain ? compareImages(inputs.rebuild, inputs.rebuildAgain) : null;
  const deployedVsSourceDateEpochRebuild = inputs.sourceDateEpochRebuild
    ? compareImages(inputs.deployed, inputs.sourceDateEpochRebuild)
    : null;

  const selfReproducible = rebuildVsRebuildAgain ? rebuildVsRebuildAgain.identical : null;
  const reproducedDeployed = deployedVsRebuild.identical;
  const reason: string[] = [];

  let verdict: DoiVerdict;
  if (reproducedDeployed) {
    verdict = inputs.annotationsSuppliedFromDeployed ? "REPRODUCED-WITH-SUPPLIED-METADATA" : "REPRODUCED";
  } else if (selfReproducible === false) {
    verdict = "NOT-REPRODUCED-RECIPE-NONDETERMINISTIC";
  } else {
    verdict = "NOT-REPRODUCED";
  }

  // `bindingEligible` is the field the ledger is allowed to act on, and it is
  // deliberately narrower than `verdict`. Supplying the target's annotations
  // means the rebuild did not produce them, so an exact match under those
  // conditions is a result worth reviewing and not a binding worth recording.
  const bindingEligible = verdict === "REPRODUCED";

  if (reproducedDeployed && inputs.annotationsSuppliedFromDeployed) {
    reason.push(
      "The rebuild equals the deployed digest, but it was handed the deployed manifest's own annotations " +
        "(including org.opencontainers.image.created) as build inputs. It therefore did not independently " +
        "produce those bytes, and this is NOT recordable as a binding without a run that derives every " +
        "annotation from source."
    );
  } else if (reproducedDeployed) {
    reason.push("The rebuild produced the deployed digest with no value taken from the deployed artifact.");
  } else {
    if (selfReproducible === false) {
      reason.push(
        "Two identical invocations of the recipe docker-library publishes for this digest, in the same " +
          "environment minutes apart, produced different images. The published recipe is therefore not " +
          "deterministic, so no replay of it can match a fixed digest, whoever runs the replay."
      );
      reason.push(
        "SCOPE, stated because the earlier wording here was broader than the measurement: this is about the " +
          "published recipe, the inputs reachable from it, and today's date. It does not establish that the " +
          "digest can never be bound. Upstream could publish a qualifying signature, which would satisfy " +
          "option B with no rebuild at all; a party holding inputs outside this recipe could produce evidence " +
          "this run cannot; and this project could accept a different kind of evidence after review."
      );
      const clock = rebuildVsRebuildAgain?.historyTimestampDifferences.length ?? 0;
      const annotations = rebuildVsRebuildAgain?.manifestAnnotationDifferences.map((d) => d.key) ?? [];
      const content = rebuildVsRebuildAgain?.changed.length ?? 0;
      reason.push(
        `Between the two runs: ${annotations.length} manifest annotation(s) differ` +
          (annotations.length > 0 ? ` (${annotations.join(", ")})` : "") +
          `, ${clock} build timestamp(s) differ, and ${content} shipped path(s) differ in content or metadata.`
      );
    } else if (selfReproducible === true) {
      reason.push(
        "The recipe IS deterministic in this environment: two identical invocations produced identical bytes. " +
          "The remaining difference is therefore between our builder or inputs and the original build, not " +
          "between two runs of the same thing."
      );
    }
    if (deployedVsSourceDateEpochRebuild) {
      reason.push(
        deployedVsSourceDateEpochRebuild.identical
          ? "Setting SOURCE_DATE_EPOCH to the deployed build clock DID reproduce the deployed digest."
          : "Setting SOURCE_DATE_EPOCH to the deployed build clock did not reproduce it either, which closes the " +
            "other half of the fork: leaving the epoch unset lets the clock move, and setting it collapses the " +
            "per-step timestamps the deployed config records at sub-second precision. Neither branch can produce " +
            "the deployed bytes."
      );
    }
    reason.push(
      "This is a RECORDED GAP, not a failed job. A near match is not a partial pass, and the ledger keeps " +
        "the binding at NONE."
    );
  }

  return {
    schema: VERDICT_SCHEMA,
    component: inputs.component,
    deployedDigest: deployedVsRebuild.manifestDigestA,
    rebuiltDigest: deployedVsRebuild.manifestDigestB,
    rebuiltAgainDigest: rebuildVsRebuildAgain?.manifestDigestB ?? null,
    sourceDateEpochRebuildDigest: deployedVsSourceDateEpochRebuild?.manifestDigestB ?? null,
    annotationsSuppliedFromDeployed: inputs.annotationsSuppliedFromDeployed,
    findings: {
      selfReproducible,
      reproducedDeployed,
      sourceDateEpochReproducedDeployed: deployedVsSourceDateEpochRebuild?.identical ?? null,
      layersIdenticalVsDeployed: deployedVsRebuild.layerDigestsA.filter((d) =>
        deployedVsRebuild.layerDigestsB.includes(d)
      ).length,
      layersTotalDeployed: deployedVsRebuild.layerDigestsA.length,
      changedPathsVsDeployed: deployedVsRebuild.changed.length,
      manifestAnnotationsDifferingVsDeployed: deployedVsRebuild.manifestAnnotationDifferences.map((d) => d.key),
      buildTimestampsDifferingVsDeployed: deployedVsRebuild.historyTimestampDifferences.length
    },
    comparisons: { deployedVsRebuild, rebuildVsRebuildAgain, deployedVsSourceDateEpochRebuild },
    verdict,
    bindingEligible,
    reason
  };
}

export function renderJudgement(judgement: DoiRebuildJudgement): string {
  const lines: string[] = [];
  lines.push(`component        ${judgement.component}`);
  lines.push(`deployed         ${judgement.deployedDigest}`);
  lines.push(`rebuilt          ${judgement.rebuiltDigest}`);
  if (judgement.rebuiltAgainDigest) lines.push(`rebuilt again    ${judgement.rebuiltAgainDigest}`);
  if (judgement.sourceDateEpochRebuildDigest) {
    lines.push(`with SOURCE_DATE_EPOCH  ${judgement.sourceDateEpochRebuildDigest}`);
  }
  lines.push("");
  lines.push(`VERDICT          ${judgement.verdict}`);
  lines.push(`binding eligible ${judgement.bindingEligible ? "yes" : "NO"}`);
  lines.push("");
  for (const line of judgement.reason) lines.push(`  ${line}`);
  lines.push("");
  lines.push("--- deployed vs rebuild ---");
  lines.push(renderComparison(judgement.comparisons.deployedVsRebuild));
  if (judgement.comparisons.rebuildVsRebuildAgain) {
    lines.push("");
    lines.push("--- rebuild vs the same rebuild, run again ---");
    lines.push(renderComparison(judgement.comparisons.rebuildVsRebuildAgain));
  }
  if (judgement.comparisons.deployedVsSourceDateEpochRebuild) {
    lines.push("");
    lines.push("--- deployed vs rebuild with SOURCE_DATE_EPOCH set to the deployed build clock ---");
    lines.push(renderComparison(judgement.comparisons.deployedVsSourceDateEpochRebuild));
  }
  return lines.join("\n");
}

function main(argv: string[]): number {
  const flag = (name: string): string | null => {
    const at = argv.indexOf(`--${name}`);
    return at >= 0 ? argv[at + 1] ?? null : null;
  };
  const component = flag("component") ?? fail("--component is required");
  const deployed = flag("deployed") ?? fail("--deployed is required");
  const rebuild = flag("rebuild") ?? fail("--rebuild is required");
  const judgement = judge({
    component,
    deployed,
    rebuild,
    rebuildAgain: flag("rebuild-again"),
    sourceDateEpochRebuild: flag("rebuild-source-date-epoch"),
    annotationsSuppliedFromDeployed: argv.includes("--annotations-from-deployed")
  });
  const out = flag("out");
  if (out) writeFileSync(out, `${JSON.stringify(judgement, null, 2)}\n`);
  process.stdout.write(`${renderJudgement(judgement)}\n`);
  return judgement.bindingEligible ? 0 : 3;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (error) {
    const message = error instanceof EscrowError || error instanceof Error ? error.message : String(error);
    process.stderr.write(`judging the rebuild failed: ${message}\n`);
    process.exit(1);
  }
}
