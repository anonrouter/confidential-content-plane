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

  it("records dstack-ingress as an unproven gap rather than rounding it up", () => {
    const ingress = ledger.components.find((c) => c.id === "dstack-ingress");
    expect(ingress?.plaintextCapable).toBe(true);
    expect(ingress?.binding.status).toBe("NONE");
    expect(ingress?.binding.evidence).toBeNull();
    expect(recordedGaps(ledger).map((c) => c.id)).toContain("dstack-ingress");
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

  it("still counts as a recorded gap despite the pin", () => {
    // This is the assertion that matters. Pinning the source is real progress
    // and it is not the thing WO-07 section 2.2 asks for. If having a source
    // pin ever silently promoted a component out of the gap list, the release
    // manifest would stop naming it.
    expect(ingress?.binding.status).toBe("NONE");
    expect(recordedGaps(ledger).map((c) => c.id)).toContain("dstack-ingress");
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

  it("does not reduce the recorded gap count", () => {
    // Three gaps before, three after. Characterising a gap is not closing it.
    expect(recordedGaps(ledger)).toHaveLength(3);
  });
});
