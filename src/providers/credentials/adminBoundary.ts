/**
 * Field-aware secret guard for the credential-administration boundary.
 *
 * `assertNoProviderSecretShape` in ./capability.ts is a purely shape-based
 * scan: any string of 20+ characters drawn from a credential-ish alphabet that
 * is not pure hex is treated as a provider secret. That is the correct default
 * for a value nobody has constrained, and it is deliberately not a list of
 * known key formats, because the next provider's key format is not knowable in
 * advance.
 *
 * It is the wrong test for a field whose exact format this control plane
 * defines. `capabilityId` is `cap-` followed by 24 hex characters, minted here
 * by `mintCapability`; at 28 characters and not pure hex it matched the secret
 * shape exactly, so the guard refused the very identifier the schema on the
 * same route REQUIRES. `POST /internal/control/credential-outcome` could not
 * accept any well-formed body: every report was a 400 and the capability it
 * named was never consumed. `outcomeCode` (up to 48 characters of `[a-z0-9_]`)
 * and any `credentialId` of 20 characters or more failed the same way.
 *
 * The fix is not to loosen the heuristic. Loosening it is what would let a
 * secret through: `sk-` followed by 40 hex-ish characters is indistinguishable
 * from a prefixed identifier to a rule that only counts characters. The fix is
 * to stop asking a shape question about fields whose shape is already pinned,
 * and to keep asking it about everything else:
 *
 *   - A PERMITTED METADATA FIELD is exempt from the heuristic only because its
 *     exact format is declared below and enforced here. A secret pasted into
 *     `capabilityId` does not match `^cap-[0-9a-f]{24}$` and is refused on
 *     format. Exemption is never granted by field NAME alone.
 *   - A FREE-TEXT FIELD (`label`) is operator-controlled prose, so the shape
 *     heuristic still applies to it in full. This is the field a pasted secret
 *     actually arrives in.
 *   - An UNKNOWN OR NESTED VALUE has no declared format, so it gets the full
 *     recursive scan, including the secret-named-key check. Both schemas are
 *     `.strict()` and reject unknown keys immediately afterwards; the scan runs
 *     first so a secret is refused as a secret, and never reaches a log line.
 *
 * Fail-closed is preserved end to end. The default for anything not explicitly
 * described here is the strict scan, not admission.
 *
 * The format constants are exported and used to BUILD the zod schemas in
 * src/routes/providerCredentials.ts. There is one definition of each format, so
 * the guard and the schema cannot drift back into disagreeing about what a
 * valid identifier looks like, which is the defect this module exists to fix.
 */

import {
  CAPABILITY_ACTIONS,
  CAPABILITY_MAX_TTL_SECONDS,
  CapabilityError,
  assertNoProviderSecretShape
} from "./capability.js";

/**
 * Exact formats for every field exempt from the shape heuristic.
 *
 * `capabilityId` must stay in agreement with `mintCapability`, which emits
 * `cap-` + `randomBytes(12).toString("hex")`. A unit test asserts a freshly
 * minted capability satisfies this pattern, so the two cannot drift apart
 * silently the way the guard and the schema did.
 */
export const CREDENTIAL_FIELD_FORMATS = {
  provider: /^[a-z0-9][a-z0-9._-]{2,63}$/,
  credentialId: /^[a-z0-9][a-z0-9_-]{0,63}$/,
  deploymentId: /^[a-z0-9][a-z0-9_-]{0,63}$/,
  capabilityId: /^cap-[0-9a-f]{24}$/,
  /** Enumerated reason code. Never a provider body, never an exception message. */
  outcomeCode: /^[a-z0-9_]{1,48}$/,
  /**
   * Truncated digest the content plane computed AFTER the secret arrived there.
   * Bounded at 32 hex characters so it identifies a key in an operator view
   * without being long enough to confirm a guessed secret.
   */
  fingerprint: /^[0-9a-f]{8,32}$/
} as const;

export const CREDENTIAL_OUTCOMES = ["applied", "rejected", "failed"] as const;
export type CredentialOutcome = (typeof CREDENTIAL_OUTCOMES)[number];

export const CREDENTIAL_LABEL_MAX_LENGTH = 120;

export const CREDENTIAL_ADMIN_ROUTES = [
  "/v1/admin/provider-credentials/capability",
  "/internal/control/credential-outcome"
] as const;
export type CredentialAdminRoute = (typeof CREDENTIAL_ADMIN_ROUTES)[number];

/**
 * How one declared field is checked. Anything not declared is scanned, so
 * adding a field to a schema without adding it here fails closed rather than
 * quietly gaining an exemption.
 */
type FieldRule =
  | { kind: "pattern"; pattern: RegExp }
  | { kind: "enum"; values: readonly string[] }
  | { kind: "integer"; min: number; max: number }
  | { kind: "free-text"; maxLength: number };

const POLICY: Record<CredentialAdminRoute, Record<string, FieldRule>> = {
  "/v1/admin/provider-credentials/capability": {
    provider: { kind: "pattern", pattern: CREDENTIAL_FIELD_FORMATS.provider },
    credentialId: { kind: "pattern", pattern: CREDENTIAL_FIELD_FORMATS.credentialId },
    deploymentId: { kind: "pattern", pattern: CREDENTIAL_FIELD_FORMATS.deploymentId },
    action: { kind: "enum", values: CAPABILITY_ACTIONS },
    label: { kind: "free-text", maxLength: CREDENTIAL_LABEL_MAX_LENGTH },
    ttlSeconds: { kind: "integer", min: 1, max: CAPABILITY_MAX_TTL_SECONDS }
  },
  "/internal/control/credential-outcome": {
    capabilityId: { kind: "pattern", pattern: CREDENTIAL_FIELD_FORMATS.capabilityId },
    outcome: { kind: "enum", values: CREDENTIAL_OUTCOMES },
    outcomeCode: { kind: "pattern", pattern: CREDENTIAL_FIELD_FORMATS.outcomeCode },
    fingerprint: { kind: "pattern", pattern: CREDENTIAL_FIELD_FORMATS.fingerprint },
    label: { kind: "free-text", maxLength: CREDENTIAL_LABEL_MAX_LENGTH }
  }
};

/** Refusals never echo the value: a message that quoted the body would copy the
 *  very content the refusal exists to stop. Field names only. */
const refuseFormat = (where: string, field: string): never => {
  throw new CapabilityError(
    `${where}: field "${field}" does not have the exact format this boundary permits. `
      + "Only content-free metadata in its declared form may cross; raw provider credentials go "
      + "directly to the attested content plane (D31)."
  );
};

/**
 * Refuse any credential-administration body that could carry a provider secret.
 *
 * Runs BEFORE schema parsing, exactly as the shape-only guard did, so an
 * operator who pastes a secret into any field gets a clear refusal rather than
 * a generic validation error.
 */
export function assertCredentialAdminBoundary(body: unknown, route: CredentialAdminRoute, where: string): void {
  const rules = POLICY[route];
  if (!rules) {
    throw new CapabilityError(`${where}: no credential-administration policy is declared for ${route}`);
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new CapabilityError(`${where}: body must be an object of content-free metadata fields`);
  }

  for (const [field, value] of Object.entries(body as Record<string, unknown>)) {
    const rule = rules[field];

    // Undeclared field: no pinned format, so it gets the full recursive scan
    // including the secret-named-key check. Wrapping it in a single-key object
    // reuses the shared heuristic unchanged and keeps the reported path honest.
    if (!rule) {
      assertNoProviderSecretShape({ [field]: value }, where);
      continue;
    }

    // An explicit null or undefined is simply an absent optional field.
    if (value === null || value === undefined) continue;

    switch (rule.kind) {
      case "pattern":
        if (typeof value !== "string" || !rule.pattern.test(value)) refuseFormat(where, field);
        break;

      case "enum":
        if (typeof value !== "string" || !rule.values.includes(value)) refuseFormat(where, field);
        break;

      case "integer":
        if (typeof value !== "number" || !Number.isInteger(value) || value < rule.min || value > rule.max) {
          refuseFormat(where, field);
        }
        break;

      case "free-text":
        // Operator prose. No format can be pinned, so the shape heuristic
        // applies in full: this is the field a pasted secret arrives in.
        if (typeof value !== "string" || value.length > rule.maxLength) refuseFormat(where, field);
        assertNoProviderSecretShape({ [field]: value }, where);
        break;
    }
  }
}
