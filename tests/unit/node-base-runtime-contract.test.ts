import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const assemble = readFileSync("deploy/provenance/base-images/node/assemble.sh", "utf8");

describe("scratch Node base production startup contract", () => {
  it("ships the provider credential decoder", () => {
    expect(assemble).toContain(
      'install -m 0755 /tmp/coreutils/usr/bin/base64 "$OUT/usr/bin/base64"',
    );
  });

  it("exercises the exact decode mode during the rootfs build", () => {
    expect(assemble).toContain('chroot "$OUT" /usr/bin/base64 -d');
    expect(assemble).toContain("base64 decoder failed the production startup contract");
  });
});
