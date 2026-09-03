import { execFileSync } from "node:child_process";
import { gzipSync } from "node:zlib";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { compareImages } from "../../scripts/provenance/compare-oci-images.js";
import { copyLayout, tamperConfigBlob, writeLayout } from "../helpers/ociLayout.js";

// Adversarial coverage for the OCI comparison.
//
// =============================================================================
// WHY THIS FILE EXISTS SEPARATELY
// =============================================================================
//
// `compare-oci-images.ts` is the one tool this whole workstream relies on to
// say "these are the same image". It decides whether a rebuild reproduced a
// deployed digest, whether two independent CI jobs agree, and whether the
// no-upstream restore drill found a tampered escrow archive. Everything
// downstream inherits its blind spots.
//
// Four of them were real, and every one was found by USING the tool rather than
// by reading it. Each has a test here that fails if the fix is reverted,
// because a fix nobody can re-break is a fix nobody can trust.
//
//   1. config-blob swap        the tool verified only the manifest blob, so a
//                              layout whose config had been rewritten in place
//                              compared as IDENTICAL;
//   2. permissions             mode changes have to be reported, or a file made
//                              world-writable reads as unchanged;
//   3. symlink substitution    `stat` follows links, so a file replaced by a
//                              symlink to identical content read as unchanged;
//   4. unreadable entries      Debian's mode-0700 /var/lock/lvm and mode-0000
//                              whiteout markers made it throw EACCES rather
//                              than compare.
//
// The fifth and sixth live in the shell rather than in TypeScript and are
// covered at the bottom: `grep -q` under pipefail reporting a MATCH as a
// failure, and `security.capability` matching libcap's own string table.

let scratch: string;
const at = (name: string) => join(scratch, name);

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), "oci-adversarial-"));
});
afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

describe("1. a config blob swapped under its own digest", () => {
  it("is refused rather than reported as identical", () => {
    writeLayout(at("swap-a"), { files: { "usr/bin/thing": "hello" } });
    copyLayout(at("swap-a"), at("swap-b"));
    tamperConfigBlob(at("swap-b"), (config) => {
      config.architecture = "swapped-underneath";
    });
    expect(() => compareImages(at("swap-a"), at("swap-b"))).toThrow(/does not hash to that digest/);
  });

  it("is refused on the LEFT side too, not only the right", () => {
    // Asymmetry here would matter: the restore drill compares an escrowed
    // archive against a rebuild, and the archive is the argument more likely to
    // have been tampered with.
    writeLayout(at("swapl-a"), { files: { "usr/bin/thing": "hello" } });
    copyLayout(at("swapl-a"), at("swapl-b"));
    tamperConfigBlob(at("swapl-a"), (config) => {
      config.architecture = "swapped-underneath";
    });
    expect(() => compareImages(at("swapl-a"), at("swapl-b"))).toThrow(/does not hash to that digest/);
  });

  it("is refused when a LAYER blob is swapped, not just the config", () => {
    // The fix hashes every blob the manifest names. A test that only covered
    // the config would pass against a version that special-cased it.
    writeLayout(at("swapy-a"), { files: { "usr/bin/thing": "hello" } });
    copyLayout(at("swapy-a"), at("swapy-b"));
    const index = JSON.parse(execFileSync("cat", [join(at("swapy-b"), "index.json")], { encoding: "utf8" }));
    const manifestPath = join(at("swapy-b"), "blobs", "sha256", index.manifests[0].digest.slice(7));
    const manifest = JSON.parse(execFileSync("cat", [manifestPath], { encoding: "utf8" }));
    writeFileSync(join(at("swapy-b"), "blobs", "sha256", manifest.layers[0].digest.slice(7)), "not a tar at all");
    expect(() => compareImages(at("swapy-a"), at("swapy-b"))).toThrow(/does not hash to that digest/);
  });
});

describe("2. permissions", () => {
  it("reports a mode change on an otherwise identical file", () => {
    writeLayout(at("mode-a"), { files: { "usr/bin/thing": "hello" }, modes: { "usr/bin/thing": 0o644 } });
    writeLayout(at("mode-b"), { files: { "usr/bin/thing": "hello" }, modes: { "usr/bin/thing": 0o777 } });
    const comparison = compareImages(at("mode-a"), at("mode-b"));
    expect(comparison.identical).toBe(false);
    const change = comparison.changed.find((c) => c.path === "usr/bin/thing");
    expect(change, "the mode change must be reported for the file it happened to").toBeTruthy();
    expect(change!.reasons.join(" ")).toMatch(/mode 0644 -> 0777/);
    // And the content must NOT be reported as changed, or the report would be
    // telling a reader to look for a substituted binary that is not there.
    expect(change!.reasons.join(" ")).not.toMatch(/content/);
  });

  it("reports a setuid bit appearing, which an unprivileged extraction destroys", () => {
    // THE CHANGE THAT MATTERS MOST AND LOOKS SMALLEST, and it was invisible.
    // `tar -x` as a non-root user silently drops setuid and setgid, so a binary
    // that gained setuid between two builds landed on disk as 0755 on both
    // sides and compared as unchanged. The mode now comes from the tar HEADER,
    // which records what the image contains rather than what the extraction
    // managed to restore.
    writeLayout(at("suid-a"), { files: { "usr/bin/thing": "hello" }, rawModes: { "usr/bin/thing": 0o755 } });
    writeLayout(at("suid-b"), { files: { "usr/bin/thing": "hello" }, rawModes: { "usr/bin/thing": 0o4755 } });
    const comparison = compareImages(at("suid-a"), at("suid-b"));
    expect(comparison.changed.find((c) => c.path === "usr/bin/thing")!.reasons.join(" "))
      .toMatch(/mode 0755 -> 4755/);
  });
});

describe("3. symlink substitution", () => {
  it("reports a file replaced by a symlink to identical content", () => {
    // THE BUG: `statSync` follows symlinks, so the tool saw the target's
    // content on both sides, found it equal, and reported no change. An
    // attacker who can add a link can redirect a binary without the comparison
    // noticing, which is precisely the substitution this tool exists to catch.
    writeLayout(at("link-a"), {
      files: { "usr/bin/thing": "payload", "usr/bin/other": "payload" }
    });
    writeLayout(at("link-b"), {
      files: { "usr/bin/other": "payload" },
      symlinks: { "usr/bin/thing": "other" }
    });
    const comparison = compareImages(at("link-a"), at("link-b"));
    expect(comparison.identical).toBe(false);
    const change = comparison.changed.find((c) => c.path === "usr/bin/thing");
    expect(change, "a file replaced by a symlink must be reported").toBeTruthy();
    expect(change!.reasons.join(" ")).toMatch(/kind file -> symlink/);
    expect(change!.reasons.join(" ")).toMatch(/link - -> other/);
  });

  it("reports a symlink whose TARGET changed even though both sides are links", () => {
    writeLayout(at("link2-a"), { files: { "a": "x", "b": "x" }, symlinks: { "l": "a" } });
    writeLayout(at("link2-b"), { files: { "a": "x", "b": "x" }, symlinks: { "l": "b" } });
    const comparison = compareImages(at("link2-a"), at("link2-b"));
    const change = comparison.changed.find((c) => c.path === "l");
    expect(change, "a repointed symlink must be reported").toBeTruthy();
    expect(change!.reasons.join(" ")).toMatch(/link a -> b/);
  });

  it("does not report a dangling symlink as an unreadable 'other'", () => {
    // Debian images are full of these. Before the lstat fix they were recorded
    // as kind "other" with no target, so two images differing in where a
    // dangling link points compared as equal.
    writeLayout(at("dangle-a"), { files: { "keep": "x" }, symlinks: { "l": "nowhere-a" } });
    writeLayout(at("dangle-b"), { files: { "keep": "x" }, symlinks: { "l": "nowhere-b" } });
    const comparison = compareImages(at("dangle-a"), at("dangle-b"));
    const change = comparison.changed.find((c) => c.path === "l");
    expect(change!.reasons.join(" ")).toMatch(/link nowhere-a -> nowhere-b/);
  });
});

describe("4. entries an unprivileged extraction cannot read", () => {
  it("compares a layer containing a mode-0000 file instead of throwing", () => {
    // The mode-0000 whiteout marker case, which killed every comparison of an
    // image that deletes a root-owned file. Refusing there would have meant
    // never comparing a Debian-derived image at all.
    writeLayout(at("perm-a"), { files: { "var/log/.wh.faillog": "", "keep": "x" }, rawModes: { "var/log/.wh.faillog": 0o000 } });
    copyLayout(at("perm-a"), at("perm-b"));
    expect(() => compareImages(at("perm-a"), at("perm-b"))).not.toThrow();
    expect(compareImages(at("perm-a"), at("perm-b")).identical).toBe(true);
  });

  it("still reports a difference inside a file it had to force open", () => {
    // The dangerous version of the fix would be to skip what it cannot read.
    // Then an unreadable file would be a place to hide a change.
    writeLayout(at("perm2-a"), { files: { secret: "before", keep: "x" }, rawModes: { secret: 0o000 } });
    writeLayout(at("perm2-b"), { files: { secret: "after", keep: "x" }, rawModes: { secret: 0o000 } });
    const comparison = compareImages(at("perm2-a"), at("perm2-b"));
    const change = comparison.changed.find((c) => c.path === "secret");
    expect(change, "a change inside an unreadable file must still be reported").toBeTruthy();
    expect(change!.reasons.join(" ")).toMatch(/content sha256:/);
  });
});

describe("5. the capability check, which failed twice in opposite directions", () => {
  const script = "scripts/provenance/layer-carries-capability.sh";
  const run = (blob: string) => {
    try {
      return { status: 0, out: execFileSync("bash", [script, blob], { encoding: "utf8" }).trim() };
    } catch (error: any) {
      return { status: error.status as number, out: String(error.stdout ?? "").trim() };
    }
  };

  it("finds the PAX keyword in a gzipped layer, which `grep -q` under pipefail could not", () => {
    // FAILURE ONE. `gzip -dc blob | grep -q X` reports FAILURE when grep
    // MATCHES: grep exits at the first hit, gzip dies of SIGPIPE, and pipefail
    // surfaces gzip's status. The check answered "clean" for every image,
    // including one that carries the capability.
    const blob = at("cap-gz");
    writeFileSync(blob, gzipSync(Buffer.from("....SCHILY.xattr.security.capability\0\x01....")));
    const result = run(blob);
    expect(result.status, "a layer that carries the xattr must exit 0").toBe(0);
    expect(Number(result.out)).toBeGreaterThan(0);
  });

  it("does NOT match libcap's own string table", () => {
    // FAILURE TWO. `security.capability` is a literal inside libcap.so.2 and
    // libcap-ng.so.0, which Debian ships, so the short pattern matched any
    // image containing libcap whether or not a single file carried the xattr.
    // It reported "dirty" about a clean image.
    const blob = at("cap-libcap");
    writeFileSync(blob, gzipSync(Buffer.from("...cap_get_file\0security.capability\0cap_set_file...")));
    const result = run(blob);
    expect(result.status, "libcap's string table is not a file capability").toBe(1);
    expect(result.out).toBe("0");
  });

  it("finds it in an uncompressed layer too", () => {
    const blob = at("cap-raw");
    writeFileSync(blob, Buffer.from("....SCHILY.xattr.security.capability\0...."));
    expect(run(blob).status).toBe(0);
  });

  it("reports zero for a blob that is neither gzip nor a match", () => {
    const blob = at("cap-none");
    writeFileSync(blob, Buffer.from("nothing interesting here"));
    const result = run(blob);
    expect(result.status).toBe(1);
    expect(result.out).toBe("0");
  });
});
