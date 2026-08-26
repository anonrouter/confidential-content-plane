// Deterministic catalog hashing. `source_hash` is the identity of a normalized
// catalog: two catalogs hash equal iff they are byte-identical after canonical
// serialization, regardless of provider-array ordering or object key ordering.
//
// A stable hash lets the pipeline skip rewriting every model (and skip creating
// pricing-audit / snapshot noise) when the provider catalog has not changed, and
// serves as the public ETag / catalog version.

import { createHash } from "node:crypto";
import { CATALOG_SCHEMA_VERSION, type NormalizedModel } from "./normalized.js";

/**
 * Canonical JSON: object keys sorted recursively, arrays kept in place, so the
 * output is a deterministic function of the value's content. Undefined-valued
 * keys are dropped (they never appear in strict-normalized output anyway).
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const out: Record<string, unknown> = {};
    for (const [key, v] of entries) {
      out[key] = sortValue(v);
    }
    return out;
  }
  return value;
}

/** Stable ordering of a normalized catalog: by provider model id (unique). */
export function sortNormalizedModels(models: NormalizedModel[]): NormalizedModel[] {
  return [...models].sort((a, b) =>
    a.providerModelId < b.providerModelId ? -1 : a.providerModelId > b.providerModelId ? 1 : 0
  );
}

/**
 * The catalog source hash: sha-256 over the schema version + the canonically
 * serialized, deterministically sorted normalized models. Volatile fields
 * (fetched_at, updatedAt) are intentionally NOT part of the normalized model, so
 * re-fetching an unchanged provider catalog yields an identical hash.
 */
export function computeSourceHash(models: NormalizedModel[]): string {
  const canonical = canonicalJson({
    schema_version: CATALOG_SCHEMA_VERSION,
    models: sortNormalizedModels(models)
  });
  return createHash("sha256").update(canonical).digest("hex");
}

/** Per-model content hash. Lets an apply detect which individual rows changed. */
export function computeModelHash(model: NormalizedModel): string {
  return createHash("sha256").update(canonicalJson(model)).digest("hex");
}
