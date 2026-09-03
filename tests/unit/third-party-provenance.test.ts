import { describe, expect, it } from "vitest";
import {
  establishedBindings,
  loadLedger,
  parseLedger,
  recordedGaps
} from "../../scripts/verify-third-party-provenance.js";
import { buildPublicReadme } from "../../scripts/export-public-readme.js";

// WO-07 section 2.2: a source-to-digest binding, or a named gap. Never a
// silent third state.
//
// The failure this suite exists to prevent is not a broken build. It is a
// release manifest that says "verified" about a link nobody checked, which is
// worse than no chain at all because it launders an assumption into an
// apparent proof. So the assertions below are mostly about what the ledger is
// NOT allowed to say.

const REBUILT = {
  method: "rebuild" as const,
  sourceCommit: "a".repeat(40),
  rebuiltDigest: `sha256:${"b".repeat(64)}`,
  builderWorkflowRef: "anonrouter/public/.github/workflows/build.yml@refs/heads/main",
  builderWorkflowSha: "c".repeat(40),
  verifiedAt: "2026-08-21T00:00:00.000Z"
};

/** A measurement shaped like the ones the public CI rebuild writes. */
const MEASURED = {
  method: "public-ci-rebuild" as const,
  verdict: "NOT-REPRODUCED-RECIPE-NONDETERMINISTIC" as const,
  optionAOutcome: "NOT-REPRODUCED-FROM-PUBLISHED-RECIPE" as const,
  optionBOutcome: "NO-QUALIFYING-SIGNATURE-FOUND" as const,
  claimScope: ["scoped to the published recipe, its reachable inputs and the measurement date"],
  run: "https://github.com/anonrouter/confidential-content-plane/actions/runs/1",
  builderWorkflowRef: "https://github.com/anonrouter/x/.github/workflows/y.yml@refs/heads/main",
  builderWorkflowSha: "d".repeat(40),
  rebuiltDigest: `sha256:${"7".repeat(64)}`,
  rebuiltAgainDigest: `sha256:${"8".repeat(64)}`,
  sourceDateEpochRebuildDigest: null,
  obstructions: [{ id: "recipe-nondeterministic", detail: "two identical invocations disagreed" }],
  evidenceFile: ".evidence/doi-base-rebuild/example-verdict.json",
  measuredAt: "2026-09-02T22:16:47.000Z"
};

function ledgerWith(
  binding: unknown,
  pinnedDigest: string | null = `sha256:${"b".repeat(64)}`,
  extra?: Record<string, unknown>
) {
  return JSON.stringify({
    schemaVersion: 1,
    components: [
      {
        id: "example",
        role: "terminates TLS in the trust domain",
        plaintextCapable: true,
        upstream: {
          project: "Example/example",
          sourceUrl: "https://github.com/Example/example",
          license: "Apache-2.0",
          redistributable: true
        },
        pinned: { image: "example:1", digest: pinnedDigest, revision: null },
        ...(extra ?? {}),
        binding
      }
    ]
  });
}

describe("the committed ledger", () => {
  const ledger = loadLedger();

  it("parses", () => {
    expect(ledger.schemaVersion).toBe(1);
    expect(ledger.components.length).toBeGreaterThan(0);
  });

  it("covers every plaintext-capable third-party component we know about", () => {
    const ids = ledger.components.map((c) => c.id);
    // dstack-ingress terminates customer TLS in-TD; the node base image runs
    // every line of code that touches a prompt; the caddy base image is the L7
    // router that proxies bodies after TLS terminates in-TD. All three are
    // third-party, all three are on the serving path.
    expect(ids).toContain("dstack-ingress");
    expect(ids).toContain("node-base-image");
    expect(ids).toContain("caddy-edge-base");
  });

  it("does not record dstack-ingress as undeployed, because it is deployed", () => {
    // This existed as a false claim: `pinned.image: null` plus a note saying
    // "no image is deployed to bind to". It made a gap on the serving path read
    // as theoretical. The digest below is the one named in the MEASURED
    // app_compose of the prod5 release, so a rebuild has a concrete target.
    const ingress = ledger.components.find((c) => c.id === "dstack-ingress");
    expect(ingress?.pinned.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(ingress?.pinned.image).toContain("dstack-ingress");
    // The note must AFFIRM deployment rather than merely stop denying it. The
    // old false claim survives in the note as a quoted correction, on purpose,
    // so a reader can see what changed; asserting its plain absence would fail
    // on the correction itself and push someone into deleting the history.
    const note = [ingress?.note ?? ""].flat().join(" ");
    expect(note).toMatch(/An image IS deployed/);
  });

  it("records dstack-ingress as REBUILT, with evidence a third party can check", () => {
    // This assertion used to require NONE, and it was right to: a gap must
    // never be rounded up. The gap is now closed by measurement rather than by
    // assertion, so what it guards has moved. A binding is only a binding if a
    // reader can re-run it, so the evidence is what is checked, not the word.
    const ingress = ledger.components.find((c) => c.id === "dstack-ingress");
    expect(ingress?.plaintextCapable).toBe(true);
    expect(ingress?.binding.status).toBe("REBUILT");
    const evidence = ingress?.binding.evidence;
    expect(evidence?.method).toBe("rebuild");
    if (evidence?.method !== "rebuild") throw new Error("unreachable");
    // The rebuild must target the commit the DEPLOYED image records, not the
    // one this repository reviewed. Building the reviewed commit would be the
    // right procedure against the wrong bytes.
    expect(evidence.sourceCommit).toBe(ingress?.deployedSource?.commit);
    expect(evidence.rebuiltDigest).toBe(ingress?.pinned.digest);
    // The identity a verifier pins must be the one cosign accepts. The bare
    // job_workflow_ref claim omits the https://github.com/ prefix Fulcio's SAN
    // carries, and pinning the claim produces a value that cannot verify.
    expect(evidence.builderWorkflowRef).toMatch(/^https:\/\/github\.com\//);
    expect(evidence.builderWorkflowSha).toMatch(/^[0-9a-f]{40}$/);
    expect(recordedGaps(ledger).map((c) => c.id)).not.toContain("dstack-ingress");
  });

  it("agrees with the public README, which must name EVERY gap", () => {
    // The README is what a reader sees, and publication is irreversible. If the
    // ledger and the README ever disagree, the published claim is the wrong one.
    //
    // This used to read the committed candidate-README.md artifact and assert
    // only that `dstack-ingress` appeared in it. Both halves were wrong. The
    // artifact goes stale the moment the generator changes, so the test could
    // pass against a README nobody would publish; and naming one of three gaps
    // is exactly the understatement this suite exists to prevent. Worse, the one
    // it checked for was the component the ledger then claimed was not deployed,
    // while the two it ignored were live.
    //
    // Now it generates the README from the same ledger the release manifest
    // reads, so there is no artifact to go stale and no gap it can miss.
    const readme = buildPublicReadme(ledger);
    for (const gap of recordedGaps(ledger)) {
      expect(readme, `README must name the recorded gap ${gap.id}`).toContain(gap.id);
    }
    expect(readme).toMatch(/NOT established/i);
  });

  it("states the gap count, and states the right one", () => {
    const readme = buildPublicReadme(ledger);
    const count = recordedGaps(ledger).length;
    expect(readme).toContain(`The ${count} unproven link`);
    // The specific phrasing that shipped in the reviewed candidate, banned by
    // name so it cannot come back by copy-paste. "The one unproven link" was
    // literally true of no state this ledger has ever been in.
    if (count !== 1) expect(readme).not.toMatch(/\bthe one unproven link\b/i);
  });

  it("never lets a source pin or a registry attestation read as a binding", () => {
    // The two ways this claim can be quietly overstated. A reader who takes
    // either for a binding has been misled about the one thing the ledger
    // exists to keep honest.
    const readme = buildPublicReadme(ledger);
    for (const gap of recordedGaps(ledger)) {
      if (gap.sourcePin) {
        expect(readme).toMatch(/A source pin says\s+which bytes we intend to build/);
      }
      if (gap.registryProvenance) {
        expect(readme).toMatch(/\*\*unsigned\*\*/i);
        expect(readme).toMatch(/not a binding/i);
      }
    }
  });

  it("puts every plaintext-capable component in exactly one bucket", () => {
    const plaintext = ledger.components.filter((c) => c.plaintextCapable);
    expect(recordedGaps(ledger).length + establishedBindings(ledger).length).toBe(plaintext.length);
  });
});

describe("the ledger cannot claim a binding it has no evidence for", () => {
  it("rejects REBUILT with no evidence", () => {
    expect(() => parseLedger(ledgerWith({ status: "REBUILT", evidence: null })))
      .toThrow(/claims a binding but carries no evidence/);
  });

  it("rejects ATTESTED with no evidence", () => {
    expect(() => parseLedger(ledgerWith({ status: "ATTESTED", evidence: null })))
      .toThrow(/claims a binding but carries no evidence/);
  });

  it("rejects evidence of the wrong kind for the claimed status", () => {
    expect(() => parseLedger(ledgerWith({ status: "ATTESTED", evidence: REBUILT })))
      .toThrow(/requires attestation evidence, found rebuild/);
  });

  it("rejects a binding to a digest other than the one deployed", () => {
    expect(() => parseLedger(ledgerWith({ status: "REBUILT", evidence: REBUILT }, `sha256:${"d".repeat(64)}`)))
      .toThrow(/evidence covers .*, but the pinned digest is/);
  });

  it("rejects a claimed binding with nothing to bind to", () => {
    expect(() => parseLedger(ledgerWith({ status: "REBUILT", evidence: REBUILT }, null)))
      .toThrow(/requires a pinned digest to bind to/);
  });

  it("rejects a gap that smuggles evidence in anyway", () => {
    expect(() => parseLedger(ledgerWith({ status: "NONE", evidence: REBUILT })))
      .toThrow(/status NONE must not carry evidence/);
  });

  it("rejects a moving target as a rebuild source", () => {
    // A tag is not a source pin: tags move, and a binding to a tag binds to
    // nothing in particular.
    expect(() => parseLedger(ledgerWith({ status: "REBUILT", evidence: { ...REBUILT, sourceCommit: "v0.5.0" } })))
      .toThrow(/full 40-character commit SHA/);
  });

  it("accepts a complete, self-consistent rebuild binding", () => {
    const parsed = parseLedger(ledgerWith({ status: "REBUILT", evidence: REBUILT }));
    expect(parsed.components[0]?.binding.status).toBe("REBUILT");
    expect(recordedGaps(parsed)).toEqual([]);
    expect(establishedBindings(parsed).map((c) => c.id)).toEqual(["example"]);
  });
});

describe("a source pin is not a binding", () => {
  const ledger = loadLedger();
  const ingress = ledger.components.find((c) => c.id === "dstack-ingress");

  it("records a verified upstream source pin", () => {
    expect(ingress?.sourcePin).toBeTruthy();
    expect(ingress?.sourcePin?.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(ingress?.sourcePin?.treeDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(ingress?.sourcePin?.license).toBe("Apache-2.0");
  });

  it("was not what closed the gap, and could not have been", () => {
    // The assertion that matters, restated now that a binding exists. A source
    // pin is real progress and is not the thing WO-07 section 2.2 asks for, so
    // the guarantee worth keeping is that the pin ALONE never promoted this
    // component out of the gap list.
    //
    // The two commits are the proof: the pin names b1a90408, the rebuild that
    // closed the gap names b322d14e. So the binding demonstrably did not come
    // from the pin, and a component with only a pin still cannot reach REBUILT
    // because the schema demands rebuild evidence.
    const evidence = ingress?.binding.evidence;
    expect(evidence?.method).toBe("rebuild");
    if (evidence?.method !== "rebuild") throw new Error("unreachable");
    expect(evidence.sourceCommit).not.toBe(ingress?.sourcePin?.commit);
    // A component carrying only a pin parses, and parses as a GAP. That is
    // the shape this component was in before the rebuild, and it must stay
    // reachable: if a pin alone could not be expressed, the distinction between
    // pinning and binding would have quietly disappeared from the schema.
    const pinnedOnly = parseLedger(
      ledgerWith({ status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`, {
        sourcePin: ingress?.sourcePin
      })
    );
    expect(recordedGaps(pinnedOnly)).toHaveLength(1);
  });

  it("records the build inputs that decide what the image contains", () => {
    const inputs = ingress?.sourcePin?.buildInputs ?? {};
    expect(inputs.baseImage).toMatch(/@sha256:[0-9a-f]{64}$/);
    expect(inputs.debianSnapshot).toMatch(/^\d{8}T\d{6}Z$/);
    expect(inputs.legoSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("names the upstream repository the source actually came from", () => {
    expect(ingress?.upstream.project).toBe("Dstack-TEE/dstack-examples");
    expect(ingress?.sourcePin?.repository).toBe(ingress?.upstream.project);
  });

  it("refuses a rebuild claimed from a different commit than the pinned source", () => {
    // The ledger could otherwise pin one commit, claim a build of another, and
    // still read as internally consistent.
    const pinned = "e".repeat(40);
    const raw = JSON.parse(ledgerWith({ status: "REBUILT", evidence: REBUILT }));
    raw.components[0].sourcePin = {
      repository: "Example/example",
      commit: pinned,
      treeDigest: `sha256:${"f".repeat(64)}`,
      license: "Apache-2.0",
      verifiedAt: "2026-08-21T00:00:00.000Z"
    };
    expect(() => parseLedger(JSON.stringify(raw)))
      .toThrow(/rebuilt from .*, but the pinned source is/);
  });

  it("accepts a rebuild from the pinned source", () => {
    const raw = JSON.parse(ledgerWith({ status: "REBUILT", evidence: REBUILT }));
    raw.components[0].sourcePin = {
      repository: "Example/example",
      commit: REBUILT.sourceCommit,
      treeDigest: `sha256:${"f".repeat(64)}`,
      license: "Apache-2.0",
      verifiedAt: "2026-08-21T00:00:00.000Z"
    };
    expect(() => parseLedger(JSON.stringify(raw))).not.toThrow();
  });

  it("rejects a source pin on a moving reference", () => {
    const raw = JSON.parse(ledgerWith({ status: "NONE", evidence: null }));
    raw.components[0].sourcePin = {
      repository: "Example/example",
      commit: "main",
      treeDigest: `sha256:${"f".repeat(64)}`,
      license: "Apache-2.0",
      verifiedAt: "2026-08-21T00:00:00.000Z"
    };
    expect(() => parseLedger(JSON.stringify(raw))).toThrow(/full 40-character commit SHA/);
  });
});


describe("registry provenance is recorded without being mistaken for a binding", () => {
  const provenance = {
    method: "registry-provenance" as const,
    attestedDigest: `sha256:${"b".repeat(64)}`,
    attestationManifest: `sha256:${"d".repeat(64)}`,
    statementSha256: "e".repeat(64),
    predicateType: "https://slsa.dev/provenance/v0.2",
    builderId: "https://github.com/docker-library",
    configSourceUri: "https://github.com/nodejs/docker-node.git#" + "f".repeat(40) + ":22/bookworm-slim",
    sourceCommit: "f".repeat(40),
    sourcePath: "22/bookworm-slim",
    signed: false as const,
    fetchedAt: "2026-08-24T04:30:00.000Z"
  };

  it("accepts it alongside a gap", () => {
    expect(() => parseLedger(ledgerWith(
      { status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`,
      { registryProvenance: provenance }
    ))).not.toThrow();
  });

  it("leaves the component a RECORDED GAP", () => {
    // The whole point. Provenance that quietly upgraded a gap to a binding would
    // be the rounding-up this gate exists to prevent, and it would be invisible.
    const parsed = parseLedger(ledgerWith(
      { status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`,
      { registryProvenance: provenance }
    ));
    expect(recordedGaps(parsed)).toHaveLength(1);
    expect(establishedBindings(parsed)).toHaveLength(0);
  });

  it("cannot be supplied as binding evidence", () => {
    // Structural, not a matter of discipline: there is no status value that
    // accepts registry-provenance as evidence.
    expect(() => parseLedger(ledgerWith({ status: "ATTESTED", evidence: provenance })))
      .toThrow();
    expect(() => parseLedger(ledgerWith({ status: "REBUILT", evidence: provenance })))
      .toThrow();
  });

  it("rejects provenance attesting a DIFFERENT digest than the one deployed", () => {
    // Provenance for another digest is provenance for another image. Recording it
    // would be worse than recording nothing, because it reads as reassurance.
    expect(() => parseLedger(ledgerWith(
      { status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`,
      { registryProvenance: { ...provenance, attestedDigest: `sha256:${"9".repeat(64)}` } }
    ))).toThrow(/different digest/);
  });

  it("refuses to record it as signed", () => {
    // If upstream ever does sign, that must be a visible schema change rather
    // than a boolean someone flipped.
    expect(() => parseLedger(ledgerWith(
      { status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`,
      { registryProvenance: { ...provenance, signed: true } }
    ))).toThrow();
  });

  it("requires a full commit, because a tag moves", () => {
    expect(() => parseLedger(ledgerWith(
      { status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`,
      { registryProvenance: { ...provenance, sourceCommit: "v22.1.0" } }
    ))).toThrow();
  });
});

describe("a measured impossibility is recorded as one, and cannot be read as a binding", () => {
  const ledger = loadLedger();

  it("records what the public CI rebuild actually measured for both base images", () => {
    // The distinction this block exists for: "nobody has rebuilt it yet" and
    // "no rebuild by anyone can ever match it" are different facts, and only
    // the first improves by trying again. Without the measurement a reader
    // draws the first conclusion, which for these two is wrong in the
    // direction that would waste somebody's week.
    for (const id of ["caddy-edge-base", "node-base-image"]) {
      const component = ledger.components.find((c) => c.id === id);
      expect(component?.reproducibility, id).toBeTruthy();
      expect(component?.reproducibility?.verdict, id).toBe("NOT-REPRODUCED-RECIPE-NONDETERMINISTIC");
      expect(component?.reproducibility?.optionAOutcome, id).toBe("NOT-REPRODUCED-FROM-PUBLISHED-RECIPE");
      expect(component?.reproducibility?.optionBOutcome, id).toBe("NO-QUALIFYING-SIGNATURE-FOUND");
      // The scope statement is mandatory, and it must actually say what the
      // measurement does NOT establish. A scope field that only restates the
      // finding would be decoration.
      const scope = (component?.reproducibility?.claimScope ?? []).join(" ");
      expect(scope, id).toMatch(/does not establish|DOES NOT ESTABLISH/i);
      // Two runs of the same recipe, and they must be different images or the
      // "non-deterministic" verdict is not what was measured.
      expect(component?.reproducibility?.rebuiltAgainDigest, id).not.toBe(
        component?.reproducibility?.rebuiltDigest
      );
      // And neither may be the deployed digest, which the schema also refuses.
      expect(component?.reproducibility?.rebuiltDigest, id).not.toBe(component?.pinned.digest);
    }
  });

  it("leaves both components RECORDED GAPS, which is the whole point", () => {
    for (const id of ["caddy-edge-base", "node-base-image"]) {
      const component = ledger.components.find((c) => c.id === id);
      expect(component?.binding.status, id).toBe("NONE");
      expect(recordedGaps(ledger).map((c) => c.id)).toContain(id);
    }
  });

  it("refuses REBUILT beside a measurement that says otherwise", () => {
    // The most dangerous state this file can be in, because both halves look
    // deliberate. The measurement wins: it came from a public CI run and the
    // status is a word somebody typed.
    const raw = JSON.parse(ledgerWith({ status: "REBUILT", evidence: REBUILT }));
    raw.components[0].reproducibility = { ...MEASURED, rebuiltDigest: `sha256:${"7".repeat(64)}` };
    expect(() => parseLedger(JSON.stringify(raw))).toThrow(/did not reproduce the deployed digest is not a binding/);
  });

  it("refuses REBUILT when the measurement did not record option A as REPRODUCED", () => {
    // The verdict and the option-A outcome are separate fields and can be made
    // to disagree by hand. When they do, the one that describes what the
    // rebuild produced wins over the one that summarises it.
    const raw = JSON.parse(ledgerWith({ status: "REBUILT", evidence: REBUILT }));
    raw.components[0].reproducibility = {
      ...MEASURED,
      verdict: "REPRODUCED",
      optionAOutcome: "NOT-REPRODUCED-FROM-PUBLISHED-RECIPE",
      rebuiltDigest: `sha256:${"7".repeat(64)}`
    };
    expect(() => parseLedger(JSON.stringify(raw)))
      .toThrow(/records option A as NOT-REPRODUCED-FROM-PUBLISHED-RECIPE/);
  });

  it("refuses a measurement whose scope statement says only what it DOES establish", () => {
    // The scope field is what stops a scoped negative being read as a universal
    // one, so a scope field that merely restates the finding is worse than
    // none: it looks like the guard is present.
    const raw = JSON.parse(ledgerWith({ status: "NONE", evidence: null }));
    raw.components[0].reproducibility = {
      ...MEASURED,
      claimScope: ["The published recipe is not deterministic."]
    };
    expect(() => parseLedger(JSON.stringify(raw))).toThrow(/does NOT establish/);
  });

  it("refuses a measurement that names the deployed digest while reporting failure", () => {
    // A rebuild that produced the deployed digest and a verdict of
    // NOT-REPRODUCED cannot both be true, and the pair would read as a
    // transcription slip in whichever direction the reader preferred.
    const raw = JSON.parse(ledgerWith({ status: "NONE", evidence: null }));
    raw.components[0].reproducibility = { ...MEASURED, rebuiltDigest: `sha256:${"b".repeat(64)}` };
    expect(() => parseLedger(JSON.stringify(raw))).toThrow(/cannot both be true/);
  });

  it("requires a measurement to name at least one obstruction", () => {
    const raw = JSON.parse(ledgerWith({ status: "NONE", evidence: null }));
    raw.components[0].reproducibility = { ...MEASURED, obstructions: [] };
    expect(() => parseLedger(JSON.stringify(raw))).toThrow();
  });

  it("tells a README reader the measurement is about the published recipe, not the universe", () => {
    const readme = buildPublicReadme(ledger);
    expect(readme).toMatch(/not "not attempted yet"/);
    expect(readme).toMatch(/published recipe is not deterministic/);
    // The scope paragraph must reach the reader, not just the ledger.
    expect(readme).toMatch(/What this does and does not establish/);
    // And it must still be a gap in the reader's eyes, not a resolved item.
    expect(readme).toMatch(/NOT established/);
  });

  it("never lets an absolute impossibility claim back into the published README", () => {
    // THE DRIFT GUARD, and it exists because the drift already happened once.
    // The generator said the gap was "unavailable for this artifact", that
    // "trying harder does not change that", and that "no rebuild by any party
    // can match a fixed digest". Every one of those is a universal claim built
    // on evidence scoped to one recipe on one day.
    //
    // Overstating a negative is the same failure as overstating a positive: it
    // launders something unmeasured into an apparent proof. The banned phrases
    // are listed literally so the ban survives a rewrite that reintroduces the
    // meaning by copy-paste.
    const readme = buildPublicReadme(ledger);
    const banned = [
      /\bcannot be closed\b/i,
      /\bunclosable\b/i,
      /by any party can (?:ever )?(?:match|close)/i,
      /\bunavailable for this artifact\b/i,
      /trying harder does not/i,
      /\bit is impossible\b/i,
      /\bcan never be (?:bound|reproduced)\b/i
    ];
    for (const pattern of banned) {
      expect(readme, `the generated README must not claim: ${pattern}`).not.toMatch(pattern);
    }
  });

  it("keeps the same ban over the ledger's own prose, which the README is generated from", () => {
    // The README is derived, so a phrase banned there can still be sitting in
    // the source it is derived from, waiting for the next generator change to
    // surface it. Both are checked.
    //
    // `claimScope` is exempt: it exists to QUOTE the overstatements it corrects,
    // and a ban that forbids naming the mistake forces the record to be deleted
    // rather than fixed.
    for (const component of ledger.components) {
      const prose = [component.note ?? [], component.reproducibility?.obstructions?.map((o) => o.detail) ?? []]
        .flat()
        .join("\n");
      expect(prose, component.id).not.toMatch(/by ANY party/);
      expect(prose, component.id).not.toMatch(/\bunavailable for this artifact\b/i);
      expect(prose, component.id).not.toMatch(/\bcannot be closed\b/i);
    }
  });
});

describe("a controlled equivalent is an alternative, never a proof about the deployed digest", () => {
  const equivalent = {
    image: "ghcr.io/anonrouter/mirror/example-base",
    digest: `sha256:${"1".repeat(64)}`,
    sourceRepository: "anonrouter/confidential-content-plane",
    sourceCommit: "2".repeat(40),
    builderWorkflowRef: "https://github.com/anonrouter/x/.github/workflows/y.yml@refs/heads/main",
    builderWorkflowSha: "3".repeat(40),
    certificateIdentity: "https://github.com/anonrouter/x/.github/workflows/y.yml@refs/heads/main",
    certificateOidcIssuer: "https://token.actions.githubusercontent.com",
    independentlyReproducedDigest: `sha256:${"1".repeat(64)}`,
    inheritedBaseImages: [],
    buildToolDependencies: [
      {
        image: "debian:bookworm-slim",
        digest: `sha256:${"5".repeat(64)}`,
        why: "runs dpkg-deb; none of its bytes ship",
        shipsBytes: false
      }
    ],
    compatibility: {
      method: "differential-harness",
      harness: "scripts/provenance/example-harness.sh",
      comparedAgainst: "the base it replaces",
      checks: 12,
      differingChecks: 0,
      controlDetectedDifferences: 1,
      evidenceFile: ".evidence/base-image-compat/example.json"
    },
    integratedIn: ["some/Dockerfile"],
    deployed: false,
    note: "undeployed candidate"
  };

  it("parses beside a gap without closing it", () => {
    const parsed = parseLedger(
      ledgerWith({ status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`, {
        controlledEquivalent: equivalent
      })
    );
    expect(recordedGaps(parsed)).toHaveLength(1);
    expect(establishedBindings(parsed)).toHaveLength(0);
  });

  it("refuses to share the pinned digest, which would make a replacement read as a binding", () => {
    expect(() =>
      parseLedger(
        ledgerWith({ status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`, {
          controlledEquivalent: { ...equivalent, digest: `sha256:${"b".repeat(64)}`, independentlyReproducedDigest: `sha256:${"b".repeat(64)}` }
        })
      )
    ).toThrow(/would make a replacement read as a binding/);
  });

  it("refuses one that was only built once", () => {
    // A digest produced once on one machine is not a reproducibility claim.
    // The project's own bar, from the DCAP phase-one gap list: two independent
    // builders producing the same digest.
    expect(() =>
      parseLedger(
        ledgerWith({ status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`, {
          controlledEquivalent: { ...equivalent, independentlyReproducedDigest: `sha256:${"9".repeat(64)}` }
        })
      )
    ).toThrow(/not independently reproduced/);
  });

  it("is recorded for both gaps, and neither closes one", () => {
    const ledger = loadLedger();
    for (const id of ["caddy-edge-base", "node-base-image"]) {
      const component = ledger.components.find((c) => c.id === id);
      const candidate = component?.controlledEquivalent;
      expect(candidate, id).toBeTruthy();
      expect(candidate?.deployed, id).toBe(false);
      expect(candidate?.digest, id).not.toBe(component?.pinned.digest);
      // Two independent CI jobs, same digest. The schema enforces the equality;
      // this asserts the committed record actually carries it rather than
      // repeating the same value by accident of being hand-written.
      expect(candidate?.independentlyReproducedDigest, id).toBe(candidate?.digest);
      expect(candidate?.certificateOidcIssuer, id).toBe("https://token.actions.githubusercontent.com");
      // The identity a verifier pins must be the form cosign accepts, not the
      // bare job_workflow_ref claim, which omits the https://github.com/ prefix
      // Fulcio's SAN carries.
      expect(candidate?.certificateIdentity, id).toMatch(/^https:\/\/github\.com\//);
      // And the component must still be a gap. A candidate that quietly closed
      // one would be the exact rounding-up this ledger exists to refuse.
      expect(component?.binding.status, id).toBe("NONE");
    }
  });

  it("is described in the README as proving nothing about the deployed digest", () => {
    const readme = buildPublicReadme(loadLedger());
    expect(readme).toMatch(/NOT deployed/);
    expect(readme).toMatch(/proves \*\*nothing about the artifact above\*\*/);
  });

  it("tells a README reader that it inherits no base and what it does depend on", () => {
    // The recursive accounting has to reach the reader, not just the ledger.
    // A signed, reproducible replacement that quietly sits on an unbound Docker
    // Official Image looks identical from outside to one that does not, and the
    // first version of both candidates was the former.
    const readme = buildPublicReadme(loadLedger());
    expect(readme).toMatch(/inherits no container base image/);
    expect(readme).toMatch(/none of their bytes ship/);
    // And the compatibility claim must carry its control, since agreement from
    // a matrix that cannot tell two images apart is not evidence.
    expect(readme).toMatch(/checks, 0 differing/);
    expect(readme).toMatch(/deliberately broken/);
  });

  it("refuses one that INHERITS a base image, which is how the gap moves instead of closing", () => {
    // THE CORRECTION THIS FIELD EXISTS FOR. The first version of both
    // candidates was `FROM debian:bookworm-slim`, a Docker Official Image with
    // exactly the unbound provenance of the components being replaced. It was
    // reproducible, it was signed, and it closed nothing.
    //
    // An empty array rather than an optional field, so "we did not think about
    // it" and "there is nothing to inherit" cannot look the same.
    expect(() =>
      parseLedger(
        ledgerWith({ status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`, {
          controlledEquivalent: { ...equivalent, inheritedBaseImages: ["debian:bookworm-slim@sha256:5ae3"] }
        })
      )
    ).toThrow();
  });

  it("refuses a build tool that claims its bytes ship", () => {
    // A build tool whose bytes reach the image is an inherited base wearing a
    // different label.
    expect(() =>
      parseLedger(
        ledgerWith({ status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`, {
          controlledEquivalent: {
            ...equivalent,
            buildToolDependencies: [{ ...equivalent.buildToolDependencies[0], shipsBytes: true }]
          }
        })
      )
    ).toThrow();
  });

  it("refuses a compatibility record with any differing check", () => {
    // "Two CI jobs produced the same digest" is necessary and not sufficient.
    // A candidate that behaves differently from the thing it replaces is a
    // candidate, not a replacement.
    expect(() =>
      parseLedger(
        ledgerWith({ status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`, {
          controlledEquivalent: {
            ...equivalent,
            compatibility: { ...equivalent.compatibility, differingChecks: 1 }
          }
        })
      )
    ).toThrow();
  });

  it("refuses a compatibility record whose control caught nothing", () => {
    // A matrix that cannot tell two images apart proves nothing by agreeing,
    // and this is the shape of result that looks most like success.
    expect(() =>
      parseLedger(
        ledgerWith({ status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`, {
          controlledEquivalent: {
            ...equivalent,
            compatibility: { ...equivalent.compatibility, controlDetectedDifferences: 0 }
          }
        })
      )
    ).toThrow();
  });

  it("records both committed candidates as inheriting nothing and behaving identically", () => {
    const ledger = loadLedger();
    for (const id of ["caddy-edge-base", "node-base-image"]) {
      const candidate = ledger.components.find((c) => c.id === id)?.controlledEquivalent;
      expect(candidate?.inheritedBaseImages, id).toEqual([]);
      expect(candidate?.compatibility.differingChecks, id).toBe(0);
      expect(candidate?.compatibility.controlDetectedDifferences, id).toBeGreaterThan(0);
      expect(candidate?.buildToolDependencies.length, id).toBeGreaterThan(0);
      for (const tool of candidate?.buildToolDependencies ?? []) {
        expect(tool.shipsBytes, `${id} build tool ${tool.image}`).toBe(false);
      }
      // Integrated in source and still not deployed. Those are different states
      // and collapsing them is how a candidate quietly becomes production.
      expect(candidate?.integratedIn.length, id).toBeGreaterThan(0);
      expect(candidate?.deployed, id).toBe(false);
    }
  });

  it("cannot claim to be deployed", () => {
    // Promoting one changes the measured Compose, the app id and the policy.
    // That is a measured-release decision, so the schema will not let a ledger
    // edit express it.
    expect(() =>
      parseLedger(
        ledgerWith({ status: "NONE", evidence: null }, `sha256:${"b".repeat(64)}`, {
          controlledEquivalent: { ...equivalent, deployed: true }
        })
      )
    ).toThrow();
  });
});

describe("the committed ledger's registry provenance is real", () => {
  const ledger = loadLedger();

  it("records it for both Docker Official Images", () => {
    const withProvenance = ledger.components.filter((c) => c.registryProvenance);
    expect(withProvenance.map((c) => c.id).sort()).toEqual(["caddy-edge-base", "node-base-image"]);
  });

  it("attests exactly the digests we deploy", () => {
    for (const component of ledger.components) {
      if (!component.registryProvenance) continue;
      expect(component.registryProvenance.attestedDigest).toBe(component.pinned.digest);
    }
  });

  it("does not close a gap for either image it describes", () => {
    // Registry provenance is unsigned, so it can characterise a gap and never
    // close one. Asserted per component rather than as a total count: the count
    // moved when dstack-ingress was rebuilt, and a count assertion would have
    // read that unrelated win as a regression here.
    for (const component of ledger.components) {
      if (!component.registryProvenance) continue;
      expect(component.binding.status, component.id).toBe("NONE");
      expect(recordedGaps(ledger).map((c) => c.id)).toContain(component.id);
    }
  });
});
