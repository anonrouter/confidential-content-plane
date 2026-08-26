import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  computeClosure,
  controlPlaneLeakage,
  CONTENT_PLANE_ENTRIES,
  CONTROL_PLANE_FILES,
  CONTROL_PLANE_PATTERN
} from "../../scripts/phala-usw/contentPlaneClosure.js";

// D-22: the content-plane image must contain only what can touch a prompt.
//
// This suite is the enforcement, not a description. D-22's argument is that
// "publish the plaintext-capable workload" and "publish the whole backend" are
// currently the same statement, and that a reviewer asking "what code here can
// see a prompt" should not first have to exclude the payments stack. That stays
// true only while something fails when a new import re-links them, which is
// what these assertions do.
//
// The six original edges, all now cut, for the record:
//
//   routes/chat.ts        -> auth/authenticate.ts      (inline dev ticket path)
//   routes/embeddings.ts  -> auth/authenticate.ts      (same)
//   routes/image.ts       -> auth/authenticate.ts      (same)
//   routes/health.ts      -> auth/admin.ts             (admin crypto-health)
//   routes/health.ts      -> payments/cryptoLedger.ts  (admin crypto-health)
//   providers/catalog/apply.ts -> admin/signals.ts     (catalog APPLY, control-side)
//
// plus one type-only edge that would have forced control-plane source into the
// public repository merely to make it compile:
//
//   inference/controlClient.ts -> inference/controlPlane.ts -> auth/types.ts

const ROOT = fileURLToPath(new URL("../..", import.meta.url));

describe("the content-plane entry point exists and refuses non-content roles", () => {
  const entry = join(ROOT, "src/contentPlane.ts");

  it("exists", () => {
    expect(existsSync(entry)).toBe(true);
  });

  it("never reaches the monolith", () => {
    // index.ts falls through to server.ts for `api` and `control`. That is right
    // for a dev process and wrong for an image that runs inside a TD.
    const source = readFileSync(entry, "utf8");
    expect(source).not.toContain("./server.js");
    expect(source).toContain("./roles.js");
  });

  it("fails closed on an unrecognized role rather than defaulting to the monolith", () => {
    const source = readFileSync(entry, "utf8");
    expect(source).toMatch(/is not a content-plane role/);
    // No silent fallback: the throw must precede the dynamic import of roles.
    expect(source.indexOf("is not a content-plane role")).toBeLessThan(source.indexOf('await import("./roles.js")'));
  });

  it("serves exactly the roles the data-plane document permits to hold content", () => {
    const source = readFileSync(entry, "utf8");
    for (const role of [
      "relay",
      "compat",
      "gateway-attestation",
      "venice-worker",
      "fireworks-worker",
      "bedrock-worker",
      "deepinfra-worker",
      "chutes-worker",
      "tinfoil-worker",
      "near-worker"
    ]) {
      expect(source, role).toContain(`"${role}"`);
    }
  });
});

describe("no control-plane source is reachable from the content plane", () => {
  it("has no control-plane code in the RUNTIME closure, which is what ships in the image", () => {
    const files = computeClosure(ROOT, CONTENT_PLANE_ENTRIES, "value");
    const leaked = controlPlaneLeakage(files);
    expect(leaked, `control-plane modules reachable at runtime: ${leaked.join(", ")}`).toEqual([]);
    // Sanity: the closure is non-trivial, so an empty result cannot be passing
    // because the walker found nothing at all.
    expect(files.length).toBeGreaterThan(50);
  });

  it("has no control-plane code in the COMPILE closure, which is what the export must contain", () => {
    // Type-only imports are erased by tsc and cost nothing at runtime, but the
    // file must be PRESENT for the export to build. A type-only edge into the
    // control plane would mean publishing control-plane source purely to make
    // the public repository compile.
    const files = computeClosure(ROOT, CONTENT_PLANE_ENTRIES, "compile");
    const leaked = controlPlaneLeakage(files);
    expect(leaked, `control-plane modules needed to compile: ${leaked.join(", ")}`).toEqual([]);
  });

  it("keeps the compile closure at most modestly larger than the runtime one", () => {
    const value = computeClosure(ROOT, CONTENT_PLANE_ENTRIES, "value");
    const compile = computeClosure(ROOT, CONTENT_PLANE_ENTRIES, "compile");
    expect(compile.length).toBeGreaterThanOrEqual(value.length);
    // Every compile-only file is published but never executed, so a large gap
    // is worth noticing rather than accepting silently.
    expect(compile.length - value.length).toBeLessThan(30);
  });
});

describe("the detector itself bites", () => {
  it("flags control-plane paths when they are present", () => {
    // A checker that has never failed is not evidence. These are the shapes the
    // real assertions above are looking for.
    expect(controlPlaneLeakage(["src/auth/apiKeys.ts"])).toEqual(["src/auth/apiKeys.ts"]);
    expect(controlPlaneLeakage(["src/payments/ledger.ts"])).toEqual(["src/payments/ledger.ts"]);
    expect(controlPlaneLeakage(["src/server.ts"])).toEqual(["src/server.ts"]);
    expect(controlPlaneLeakage(["src/inference/controlPlane.ts"])).toEqual(["src/inference/controlPlane.ts"]);
  });

  it("does not flag content-plane paths", () => {
    expect(controlPlaneLeakage(["src/relay/ingress.ts", "src/compat/broker.ts", "src/routes/chat.ts"])).toEqual([]);
  });

  it("proves the monolith entry point WOULD leak, so the split is doing real work", () => {
    // src/index.ts reaches server.ts. If this came back empty in the MONOREPO,
    // either the walker broke or the monolith stopped being the monolith.
    //
    // In the published export the monolith is absent, and its absence is a
    // stronger result than this assertion: there is no control plane to leak.
    // So the check is skipped there rather than failed, and the skip is
    // explicit so it cannot be mistaken for a pass.
    if (!existsSync(join(ROOT, "src/index.ts"))) {
      expect(existsSync(join(ROOT, "src/server.ts"))).toBe(false);
      return;
    }
    const leaked = controlPlaneLeakage(computeClosure(ROOT, ["src/index.ts"], "value"));
    expect(leaked.length).toBeGreaterThan(10);
    expect(leaked).toContain("src/server.ts");
  });

  it("names the control-plane trees explicitly", () => {
    for (const dir of ["payments", "admin", "auth", "connect", "workspaces", "trial", "promotions"]) {
      expect(CONTROL_PLANE_PATTERN.test(`src/${dir}/x.ts`), dir).toBe(true);
    }
    expect(CONTROL_PLANE_FILES).toContain("src/server.ts");
    expect(CONTROL_PLANE_FILES).toContain("src/inference/controlPlane.ts");
  });
});

describe("the inline ticket path is a capability, not an import", () => {
  it("no content route imports the auth chain directly", () => {
    for (const route of ["src/routes/chat.ts", "src/routes/embeddings.ts", "src/routes/image.ts"]) {
      const source = readFileSync(join(ROOT, route), "utf8");
      expect(source, route).not.toContain("auth/authenticate.js");
      expect(source, route).toContain("inlineTicketIssuer");
    }
  });

  it("each route fails closed when the capability is absent", () => {
    // Absence is what makes the content tier ticket-only, and it is a stronger
    // statement than the config flag because no environment variable can
    // introduce a capability that was never registered.
    for (const route of ["src/routes/embeddings.ts", "src/routes/image.ts"]) {
      const source = readFileSync(join(ROOT, route), "utf8");
      expect(source, route).toContain("!server.inlineTicketIssuer");
      expect(source, route).toContain("ticket_required");
    }
    const chat = readFileSync(join(ROOT, "src/routes/chat.ts"), "utf8");
    expect(chat).toContain("allowInline && request.server.inlineTicketIssuer");
    expect(chat).toContain("ticket_required");
  });

  it("only the monolith registers it", () => {
    // In the export there is no monolith, so the capability is registered
    // nowhere at all and every content route is ticket-only unconditionally.
    if (existsSync(join(ROOT, "src/server.ts"))) {
      expect(readFileSync(join(ROOT, "src/server.ts"), "utf8")).toContain('server.decorate("inlineTicketIssuer"');
    }
    expect(readFileSync(join(ROOT, "src/roles.ts"), "utf8")).not.toContain("inlineTicketIssuer");
  });

  it("keeps authenticate and scope enforcement together in the implementation", () => {
    // "Authenticated but unscoped" must not be a state any caller can construct.
    // Only meaningful where the implementation exists; the export has none.
    if (!existsSync(join(ROOT, "src/server.ts"))) return;
    const server = readFileSync(join(ROOT, "src/server.ts"), "utf8");
    const impl = server.slice(server.indexOf('server.decorate("inlineTicketIssuer"'));
    const body = impl.slice(0, impl.indexOf("});"));
    expect(body).toContain("authenticateRequest");
    expect(body).toContain('requireApiKeyScope(request, "inference")');
    expect(body).toContain("issueAndRedeemInline");
  });
});
