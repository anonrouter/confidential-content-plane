// Privacy tier taxonomy for the high-privacy inference path (Venice-only MVP).
//
// The database stores an effective privacy class per model/provider
// (migration 007): anonymous < private < tee < e2ee, plus `unknown`. This module
// layers the launch routing policy on top of that ladder:
//
//   - Default routing (including /auto) may select only e2ee, tee, or private.
//   - `anonymous` requires explicit user opt-in and is never a default.
//   - Any opt-in-only route (a model kept `routing_enabled = false`) is excluded
//     from automatic routing regardless of its privacy class.
//
// See docs/HIGH_PRIVACY_INFERENCE_IMPLEMENTATION_PLAN.md §4, §8.

export type PrivacyClass = "anonymous" | "private" | "tee" | "e2ee" | "unknown";

export const DEFAULT_ROUTABLE_PRIVACY_CLASSES: readonly PrivacyClass[] = ["private", "tee", "e2ee"];

/** Privacy classes a request may opt into via `routing.privacy_classes`. */
export const SELECTABLE_PRIVACY_CLASSES: readonly PrivacyClass[] = ["anonymous", "private", "tee", "e2ee", "unknown"];

export function isPrivacyClass(value: string): value is PrivacyClass {
  return value === "anonymous" || value === "private" || value === "tee" || value === "e2ee" || value === "unknown";
}

/**
 * Whether a privacy class is allowed in default/automatic routing when the
 * request does not explicitly widen `routing.privacy_classes`. `anonymous` and
 * `unknown` are excluded so /auto never silently downgrades below "private".
 */
export function isDefaultRoutableClass(privacyClass: string): boolean {
  return DEFAULT_ROUTABLE_PRIVACY_CLASSES.includes(privacyClass as PrivacyClass);
}

/**
 * The set of privacy classes a routing request accepts, defaulting to the
 * privacy-preserving tiers only. Passing an explicit set is the user opt-in that
 * lets `anonymous`/`unknown` participate.
 */
export function resolveRequestedPrivacyClasses(requested: readonly string[] | undefined): Set<PrivacyClass> {
  if (!requested || requested.length === 0) {
    return new Set(DEFAULT_ROUTABLE_PRIVACY_CLASSES);
  }
  const set = new Set<PrivacyClass>();
  for (const value of requested) {
    if (isPrivacyClass(value)) set.add(value);
  }
  if (set.size === 0) {
    return new Set(DEFAULT_ROUTABLE_PRIVACY_CLASSES);
  }
  return set;
}

/** User-facing label for a model's effective privacy class (honest wording). */
export function privacyTierLabel(privacyClass: string): string {
  switch (privacyClass) {
    case "e2ee":
      return "End-to-end encrypted (client → attested enclave)";
    case "tee":
      return "Confidential (TEE-attested)";
    case "private":
      return "Private (no-retention)";
    case "anonymous":
      return "Standard (opt-in)";
    default:
      return "Unclassified — not marketed as private";
  }
}

/**
 * Whether a message that opts into a non-default privacy class is asking for a
 * weaker tier than the default. Used to require an explicit acknowledgement
 * before serving `anonymous`/`unknown`, so a downgrade is never silent.
 */
export function isDowngradeFromDefault(privacyClass: string): boolean {
  return !isDefaultRoutableClass(privacyClass);
}
