// D-22: compute the module graph reachable from the content-plane entry point.
//
// This is the enforcement behind the split, not a description of it. The point
// of D-22 is that "publish the plaintext-capable workload" and "publish the
// whole backend" must stop being the same statement, and the only way that stays
// true is if something fails when a new import quietly re-links them.
//
// TWO CLOSURES, BECAUSE THEY ANSWER DIFFERENT QUESTIONS
//
//   VALUE    what actually executes, and therefore what ships in dist/ and is
//            inside the measured image. This is the TCB question.
//   COMPILE  value edges plus type-only ones. `tsc` erases `import type`, so
//            those cost nothing at runtime, but the file must still be PRESENT
//            for the export to build. This is the "what must the public
//            repository contain" question.
//
// Conflating them is easy and wrong in both directions: reporting only the
// value closure understates what has to be published, and reporting only the
// compile closure overstates what is in the image.

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, normalize, relative, resolve } from "node:path";

/** Source trees that belong to the control plane and must never be reachable. */
export const CONTROL_PLANE_PATTERN = /^src\/(payments|admin|auth|connect|workspaces|trial|promotions)\//;

/** Modules that are control-plane by identity rather than by directory. */
export const CONTROL_PLANE_FILES: readonly string[] = Object.freeze([
  "src/server.ts",
  "src/index.ts",
  "src/inference/controlPlane.ts",
  "src/inference/inProcessControlClient.ts",
  "src/localServicesSupervisor.ts",
  // Configuration boundary. src/db/config.ts holds the database settings, the
  // DATABASE_URL parsing and the local development connection string;
  // src/appConfig.ts is the only thing that composes them into a config. If
  // either becomes reachable from the content plane, the confidential image is
  // once again carrying database configuration it has no use for, and the
  // public export once again publishes a hardcoded connection string.
  "src/db/config.ts",
  "src/appConfig.ts"
]);

export type ClosureMode = "value" | "compile";

interface Edge {
  readonly spec: string;
  readonly typeOnly: boolean;
}

/**
 * Extract import edges, distinguishing type-only ones.
 *
 * Two forms are erased by `tsc`: `import type X from "y"`, and a named clause
 * in which EVERY binding carries the `type` modifier. The second is easy to
 * miss and is used in this codebase, so it is handled explicitly.
 */
function edgesOf(source: string): Edge[] {
  const out: Edge[] = [];
  const statement = /(?:^|\n)\s*(?:import|export)\s+(type\s+)?([\s\S]*?)from\s*["']([^"']+)["']/g;
  let match: RegExpExecArray | null;
  while ((match = statement.exec(source)) !== null) {
    const typeKeyword = Boolean(match[1]);
    const clause = match[2] ?? "";
    const named = clause.match(/\{([\s\S]*)\}/);
    let everyBindingIsType = false;
    if (named) {
      const parts = named[1].split(",").map((p) => p.trim()).filter(Boolean);
      everyBindingIsType = parts.length > 0 && parts.every((p) => /^type\s/.test(p));
    }
    out.push({ spec: match[3], typeOnly: typeKeyword || everyBindingIsType });
  }
  const dynamic = /import\s*\(\s*["']([^"']+)["']\s*\)/g;
  while ((match = dynamic.exec(source)) !== null) {
    out.push({ spec: match[1], typeOnly: false });
  }
  // Bare side-effect imports: `import "./x.js";`. These have NO `from` clause,
  // so the statement pattern above never matches them. Missing them is not
  // cosmetic: `httpBase.ts` pulls in the Fastify module augmentations this way,
  // and omitting that one file made the whole export fail to compile with
  // "Property 'config' does not exist on type 'FastifyInstance'".
  const sideEffect = /(?:^|\n)\s*import\s+["']([^"']+)["']\s*;?/g;
  while ((match = sideEffect.exec(source)) !== null) {
    out.push({ spec: match[1], typeOnly: false });
  }
  return out;
}

/** Resolve a NodeNext ".js" specifier back to its TypeScript source. */
function resolveSpecifier(fromFile: string, spec: string): string | null {
  if (!spec.startsWith(".")) return null;
  const base = normalize(join(dirname(fromFile), spec));
  const candidates = [
    base.replace(/\.js$/, ".ts"),
    `${base}.ts`,
    join(base, "index.ts"),
    `${base.replace(/\.js$/, "")}/index.ts`,
    base
  ];
  return candidates.find((c) => existsSync(c) && !c.endsWith("/")) ?? null;
}

export function computeClosure(repoRoot: string, entries: readonly string[], mode: ClosureMode): string[] {
  const seen = new Set<string>();
  const stack = entries.map((e) => resolve(repoRoot, e));
  while (stack.length > 0) {
    const file = stack.pop() as string;
    if (seen.has(file) || !existsSync(file)) continue;
    seen.add(file);
    for (const edge of edgesOf(readFileSync(file, "utf8"))) {
      if (mode === "value" && edge.typeOnly) continue;
      const resolved = resolveSpecifier(file, edge.spec);
      if (resolved) stack.push(resolved);
    }
  }
  return [...seen].map((f) => relative(repoRoot, f)).sort();
}

export function controlPlaneLeakage(files: readonly string[]): string[] {
  return files.filter((f) => CONTROL_PLANE_PATTERN.test(f) || CONTROL_PLANE_FILES.includes(f));
}

/** The entry points the content-plane image builds from. */
export const CONTENT_PLANE_ENTRIES: readonly string[] = Object.freeze(["src/contentPlane.ts"]);
