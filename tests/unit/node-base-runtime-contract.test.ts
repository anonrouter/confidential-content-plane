import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const assemble = readFileSync("deploy/provenance/base-images/node/assemble.sh", "utf8");
const dockerfile = readFileSync("Dockerfile", "utf8");
const policy = readFileSync("config/confidential-route-policy.json", "utf8");

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

  it("ships the fail-closed route policy in the production image", () => {
    expect(JSON.parse(policy)).toHaveProperty("withheld");
    const productionAt = dockerfile.indexOf("AS production");
    const copy = "COPY --from=build /app/config/confidential-route-policy.json ./config/confidential-route-policy.json";
    expect(productionAt).toBeGreaterThan(-1);
    expect(dockerfile.indexOf(copy)).toBeGreaterThan(productionAt);
  });
});
