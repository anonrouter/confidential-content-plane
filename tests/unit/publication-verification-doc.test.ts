// The hand-written verification document must agree with the ledger.
//
// THE FAILURE THIS PINS, found on 2026-09-03 while auditing branches for a
// stale measurement policy.
//
// `docs/publication/INDEPENDENT_VERIFICATION.md` ships inside the public export.
// So does `README.md`, which is GENERATED from the provenance ledger and held
// against it by `tests/unit/third-party-provenance.test.ts`. The generated one
// said "The 2 unproven links" and "1 established binding". The hand-written one
// said "The three third-party gaps" and described `dstack-ingress` as an
// unclosed source pin at a digest that is no longer deployed — weeks after the
// rebuild that closed it.
//
// Two documents in one published tree, contradicting each other about the
// central claim, with a test holding one of them and nothing holding the other.
// `.evidence/public-content-plane-export/SUPERSEDED.md` already records an
// earlier instance of exactly this shape, which is the argument for a check
// rather than a careful edit: the ledger moves when provenance work lands, and
// nothing about closing a gap prompts anyone to reread a publication document.
//
// Understating a proof is a smaller error than overstating one. It is still a
// checkable sentence that does not survive checking, and a reader who finds one
// published claim contradicting another has no way to know which to believe.
//
// This does not try to hold the whole document to the ledger — most of it is
// prose about method, which is the right form for it. It holds the parts that
// are counts and statuses, because those are the parts that go stale silently.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadLedger, recordedGaps, establishedBindings } from "../../scripts/verify-third-party-provenance.js";

const DOC = "docs/publication/INDEPENDENT_VERIFICATION.md";
const doc = readFileSync(DOC, "utf8");
const ledger = loadLedger();
const gaps = recordedGaps(ledger);
const bound = establishedBindings(ledger);

/** The section of the document that makes claims about the gap ledger. */
function gapSection(): string {
  const start = doc.indexOf("## The third-party gaps");
  expect(start, `${DOC} has no third-party gaps section to check`).toBeGreaterThan(-1);
  const rest = doc.slice(start + 1);
  const end = rest.indexOf("\n## ");
  return end === -1 ? rest : rest.slice(0, end);
}

describe("the published verification document agrees with the ledger", () => {
  it("names every recorded gap", () => {
    const section = gapSection();
    for (const gap of gaps) {
      const image = gap.pinned?.image ?? gap.id;
      expect(
        section.includes(image) || section.includes(gap.id),
        `${DOC} does not name the recorded gap ${gap.id} (${image})`
      ).toBe(true);
    }
  });

  it("states the number of gaps the ledger records, in words", () => {
    // The count is where the previous version was wrong, and a count is the
    // one thing in a prose document that can be checked exactly.
    const words = ["zero", "one", "two", "three", "four", "five"];
    const expected = words[gaps.length] ?? String(gaps.length);
    expect(
      new RegExp(`\\*\\*${expected}\\*\\* are unproven|\\b${expected}\\b[^.]{0,40}unproven`, "i").test(gapSection()),
      `${DOC} must say ${expected} components are unproven; the ledger records ${gaps.length}`
    ).toBe(true);
  });

  it("does not describe a closed binding as an open gap", () => {
    // The specific regression: `dstack-ingress` was REBUILT and the document
    // still listed it among the gaps.
    const section = gapSection();
    for (const component of bound) {
      if (!component.plaintextCapable) continue;
      if (!section.includes(component.id)) continue;
      const line = section.split("\n").find((l) => l.includes(component.id)) ?? "";
      expect(
        /NOT ESTABLISHED/i.test(line),
        `${DOC} lists ${component.id} as NOT ESTABLISHED, but the ledger records ${component.binding.status}`
      ).toBe(false);
    }
  });

  it("does not carry the superseded digests of components that have moved", () => {
    // `d05a7b34` was the dstack-ingress digest this document quoted. The
    // deployment moved off it; a published document quoting a digest nobody
    // runs invites a reader to verify the wrong thing.
    const pinned = new Set(
      ledger.components.map((c) => c.pinned?.digest).filter((d): d is string => typeof d === "string")
    );
    for (const match of gapSection().matchAll(/`sha256:([0-9a-f]{8})[^`]*`/g)) {
      const prefix = match[1];
      expect(
        [...pinned].some((d) => d.startsWith(`sha256:${prefix}`)),
        `${DOC} quotes sha256:${prefix}… which is not a digest the ledger pins`
      ).toBe(true);
    }
  });
});

describe("the document does not resurrect the claim that no policy exists", () => {
  it("does not say the production measurement policy does not exist", () => {
    // It did, long after one existed. The heading is checked rather than the
    // prose, because the heading is what a skimming reader takes away.
    expect(doc).not.toMatch(/^## The measurement policy does not exist yet$/m);
  });

  it("says a policy must not be reused across a measurement change", () => {
    // The load-bearing instruction, and the reason the document exists at all:
    // a stale policy fails against a healthy deployment, and the temptation is
    // then to relax the verifier rather than fetch the right file.
    expect(doc).toMatch(/do not reuse an old one|does not fail safe/i);
  });
});
