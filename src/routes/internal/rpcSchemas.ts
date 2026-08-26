import { z } from "zod";
import { routingConfigSchema } from "../../providers/types.js";
import { OPAQUE_RECEIPT_ID_PATTERN } from "../../inference/contentReceipts.js";
// Handler-free, like everything else this module is allowed to import: the
// formats and the capability constants are pure definitions over node:crypto.
import {
  CAPABILITY_ACTIONS,
  CAPABILITY_MAX_TTL_SECONDS,
  type CapabilityAction
} from "../../providers/credentials/capability.js";
import {
  CREDENTIAL_FIELD_FORMATS,
  CREDENTIAL_LABEL_MAX_LENGTH,
  CREDENTIAL_OUTCOMES,
  type CredentialOutcome
} from "../../providers/credentials/adminBoundary.js";

// The content-free control RPC boundary contract.
//
// SPLIT OUT OF `control.ts` FOR D-22, WHICH REQUIRES PUBLISHING IT.
//
// D-22: "The public repository must include the content-free control RPC
// schemas, even though the server that serves them runs on Vultr. They are the
// boundary contract, and publishing them is what lets a reviewer check the
// boundary is content-free rather than take it on trust."
//
// They previously lived beside the control-side ROUTE HANDLERS, which import
// the catalog apply path, the account-identity chain and the admin signal
// recorder. Publishing the contract therefore meant publishing the control
// plane, and `tests/unit/rpc-boundary-contract.test.ts` -- the test that
// ENFORCES the contract -- dragged 81 files of control-plane source with it.
//
// Separating the schemas from the handlers is what makes the contract
// publishable on its own. A reader can now check that nothing crossing this
// boundary is content-shaped, using the same definitions the running server
// validates against, without being handed the billing ledger to read as well.
//
// Every schema here is `.strict()` on purpose: zod SILENTLY STRIPS unknown keys
// otherwise, so a relay that began attaching a content-derived field would be
// quietly tolerated instead of failing loudly in review and in the contract
// test.

export const redeemSchema = z.object({ ticketId: z.string().min(1).max(256) }).strict();

// DENIED AT THIS BOUNDARY, and named here so the denial is visible rather than
// implied by absence.
//
// `classification` used to carry the relay's classifier output — task,
// effective task, complexity, needs-web, maybe-sensitive, abstention and the
// confidence numbers — so the control plane could pick a model for /auto.
// CONTROL_RPC_CONTRACT.md removes it: it is content-derived metadata that
// discloses the SUBJECT of a prompt ("this is a coding request", "this looked
// sensitive") to a plane that must not learn it, and no billing invariant needs
// it. Automatic model selection therefore moved INTO the content plane, which
// already holds the prompt and already runs the classifier; the control plane
// now receives only the resolved `modelPublicId` and re-validates it.
//
// The names are listed so the boundary can reject them by name with a specific
// error instead of a generic "unrecognized key", and so a reviewer grepping for
// "classification" finds the denial rather than nothing at all.
export const AUTHORIZE_DENIED_CONTENT_DERIVED_FIELDS = [
  "classification",
  "requiresTools",
  "requiresVision"
] as const;

export const authorizeSchema = z
  .object({
    redemption: z.string().min(1).max(256),
    requestId: z.string().min(1).max(256),
    operation: z.enum(["chat", "embeddings", "image"]).optional().default("chat"),
    modelPublicId: z.string().min(1).max(256),
    automatic: z.boolean(),
    stream: z.boolean(),
    // Re-validate with the SAME bounds as the client edge instead of trusting the
    // relay to have bounded them. routing.allow/exclude counts drive the O(n*m)
    // glob matcher run per enabled model, so an unbounded count from a compromised
    // relay would CPU-starve the control event loop (auth/billing/ticket issuance).
    routing: routingConfigSchema.optional(),
    inputCeiling: z.number().int().nonnegative().max(100_000_000),
    requestedMaxOutputTokens: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional(),
    /** Relay-computed canonical reasoning digest; cross-checked with the ticket. */
    reasoningKey: z.string().max(32).optional(),
    /** Relay-computed canonical provider-policy digest; cross-checked with the ticket. */
    providerPolicyKey: z.string().max(1_024).optional(),
    /** Relay-derived E2EE modality (from TEE headers); cross-checked with the ticket. */
    e2ee: z.boolean().optional(),
    /** Whole-body ciphertext transport; valid only with e2ee:true. */
    opaqueE2ee: z.boolean().optional()
    // requiresTools / requiresVision are DENIED here. Whether a request carries
    // tool definitions or an image is derived from its content, and the control
    // plane no longer needs to know: capability filtering and the
    // no_tools_capable_model / no_vision_capable_model errors are produced in
    // the content plane, from the same content-free catalog the control plane
    // publishes. See AUTHORIZE_DENIED_CONTENT_DERIVED_FIELDS above.
  })
  .strict();

export const nextAttemptSchema = z
  .object({
    requestId: z.string().min(1).max(256),
    previousOutcome: z.enum([
      "provider_unavailable",
      "rate_limited",
      "provider_rejected",
      "network_error",
      "invalid_response"
    ]),
    latencyMs: z.number().nonnegative()
  })
  .strict();

export const settleSchema = z
  .object({
    requestId: z.string().min(1).max(256),
    usage: z.object({
      inputTokens: z.number(),
      outputTokens: z.number(),
      cachedTokens: z.number(),
      // Optional during rolling upgrades; old workers did not report it.
      cacheWriteTokens: z.number().optional().default(0)
    }),
    firstTokenLatencyMs: z.number().int().nonnegative().optional(),
    latencyMs: z.number().nonnegative(),
    /**
     * The whole cross-boundary commitment, replacing the `teeSignatureBinding`
     * object that used to carry `requestHash` and `responseHash` here.
     *
     * 128 uniformly random bits minted in the content plane. The control plane
     * learns that a provider receipt exists for this settlement and can join
     * the two; it cannot learn, confirm or brute-force anything about the
     * request or the response, because the value is not derived from either.
     *
     * The old object also carried provider/model/route/providerRequestId. Those
     * are gone from this route too: provider and model are already on the
     * reservation, and the provider's own request id is an upstream correlation
     * handle the control plane has no use for.
     */
    opaqueReceiptId: z.string().regex(OPAQUE_RECEIPT_ID_PATTERN).optional()
  })
  .strict();

export const deliveryStartedSchema = z.object({ requestId: z.string().min(1).max(256) }).strict();

export const providerRejectionSchema = z
  .object({
    requestId: z.string().min(1).max(256),
    attemptIndex: z.number().int().min(0).max(64),
    automatic: z.boolean(),
    relayOutcome: z
      .enum(["provider_unavailable", "rate_limited", "provider_rejected", "network_error", "invalid_response"])
      .optional(),
    anonrouterCode: z.string().max(64).optional(),
    providerStatus: z.number().int().min(100).max(599).optional(),
    providerRequestId: z.string().max(256).optional(),
    // providerCode is DENIED. It carried the provider's own machine code, and
    // the codes that matter most are prompt-derived: Venice's
    // `content_violation` tells the control plane that a moderation classifier
    // rejected this account's prompt. Refund conservation needs only the
    // generic outcome above, which it already has, so the category is dropped
    // rather than mapped. CONTROL_RPC_CONTRACT.md forbids reintroducing it
    // without a field-specific architecture review.
    latencyMs: z.number().nonnegative()
  })
  .strict();
export const providerDispatchAttemptSchema = z.object({
  // Rolling-upgrade compatibility: workers predating regional capabilities are
  // the `primary` deployment. A regional token can never exploit this default,
  // because resolveMetadataRequestScope requires its configured non-primary id.
  deploymentId: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/).optional().default("primary"),
  dispatchToken: z.string().min(1).max(256),
  requestId: z.string().min(1).max(256),
  operation: z.enum(["chat", "embeddings", "image"]),
  providerName: z.string().min(1).max(64),
  externalModelId: z.string().min(1).max(256),
  stream: z.boolean(),
  effectiveMaxOutputTokens: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  reasoningKey: z.string().min(1).max(32),
  providerReasoningKey: z.string().min(1).max(32),
  opaqueE2ee: z.boolean().optional(),
  // Image-only content-free provider-work facts the worker re-reports so control
  // can reject any post-authorization size/format tampering at the fence.
  imageWidth: z.number().int().positive().max(8192).optional(),
  imageHeight: z.number().int().positive().max(8192).optional(),
  imageResponseFormat: z.string().max(32).optional()
}).strict();
export const attestationAttemptSchema = z.object({
  deploymentId: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/).optional().default("primary"),
  dispatchToken: z.string().min(1).max(256),
  providerName: z.string().min(1).max(64),
  externalModelId: z.string().min(1).max(256)
}).strict();

export const captureSchema = z
  .object({
    requestId: z.string().min(1).max(256),
    firstTokenLatencyMs: z.number().int().nonnegative().optional(),
    latencyMs: z.number().nonnegative()
  })
  .strict();

export const abortSchema = z
  .object({
    requestId: z.string().min(1).max(256),
    status: z.enum(["failed", "rate_limited", "insufficient_balance"]),
    providerRejected: z.boolean().optional(),
    firstTokenLatencyMs: z.number().int().nonnegative().optional(),
    latencyMs: z.number().nonnegative()
  })
  .strict();

/**
 * The credential-administration outcome the content plane reports after it has
 * installed, rotated or revoked a provider secret.
 *
 * AN EXTENSION BEYOND THE ROUTE INVENTORY APPROVED AT 697414c, and recorded as
 * one rather than slipped in. That contract fixed the Phala-to-GCP route list
 * and does not contain this route; it does, however, require that GCP receive
 * "opaque ID, label, fingerprint, status, rotation/revocation timestamps,
 * target deployment and bounded outcome/audit metadata" after a credential
 * operation. This is the channel that carries it, agreed with the control-plane
 * implementation. A field-level review should confirm the addition rather than
 * inherit it.
 *
 * The fingerprint is TRUNCATED. The control plane refuses a
 * credential-administration body carrying a secret-shaped value on SHAPE, so a
 * full 64-character digest would be rejected as a possible secret — and it is
 * the right bound independently, because a full digest of a provider key is a
 * confirmable commitment to it.
 */
export const credentialOutcomeSchema = z
  .object({
    // ^cap-[0-9a-f]{24}$, the exact format mintCapability emits and the
    // credential_capabilities CHECK constraint enforces. This field previously
    // carried the PROVIDER name pattern here while the control plane pinned the
    // capability pattern, which is two definitions of one protocol field again:
    // the loose one accepts ids the database will then refuse. One definition,
    // in CREDENTIAL_FIELD_FORMATS, used by the schema, the boundary guard and
    // the DDL alike.
    capabilityId: z.string().regex(CREDENTIAL_FIELD_FORMATS.capabilityId),
    outcome: z.enum(CREDENTIAL_OUTCOMES as unknown as [CredentialOutcome, ...CredentialOutcome[]]),
    /** A bounded machine code. Never a provider message and never free text. */
    outcomeCode: z.string().regex(CREDENTIAL_FIELD_FORMATS.outcomeCode),
    fingerprint: z.string().regex(CREDENTIAL_FIELD_FORMATS.fingerprint).optional(),
    label: z.string().trim().min(1).max(CREDENTIAL_LABEL_MAX_LENGTH).optional()
  })
  .strict();

/**
 * The operator's request for authorization to perform ONE credential operation.
 *
 * Lives here rather than beside its handler for the same reason as every schema
 * above: the contract must be publishable without the handlers (D-22).
 */
export const credentialCapabilityIssueSchema = z
  .object({
    provider: z.string().regex(CREDENTIAL_FIELD_FORMATS.provider),
    /** Opaque identifier for the credential. Never derived from the secret. */
    credentialId: z.string().regex(CREDENTIAL_FIELD_FORMATS.credentialId),
    action: z.enum(CAPABILITY_ACTIONS as unknown as [CapabilityAction, ...CapabilityAction[]]),
    deploymentId: z.string().regex(CREDENTIAL_FIELD_FORMATS.deploymentId),
    label: z.string().trim().min(1).max(CREDENTIAL_LABEL_MAX_LENGTH).optional(),
    ttlSeconds: z.number().int().positive().max(CAPABILITY_MAX_TTL_SECONDS).optional()
  })
  .strict();

/**
 * Field names that may never appear on this boundary again. The contract test
 * asserts each is absent from every schema above, so a revert or a rebase that
 * reintroduces one fails loudly instead of quietly reopening O13.
 */
export const CONTROL_RPC_REMOVED_FIELDS = [
  "classification",
  "requiresTools",
  "requiresVision",
  "providerCode",
  "teeSignatureBinding",
  "constraints"
] as const;

/**
 * Every schema that guards a body crossing INTO the accounts host, keyed by the
 * route it guards.
 *
 * Exported for tests/unit/rpc-boundary-contract.test.ts, which enumerates the
 * exact accepted field set for each one and fails when it changes. That makes
 * adding a field to this boundary a deliberate, reviewed act rather than a
 * one-line edit: the contract in docs/PHALA_CONFIDENTIAL_DATA_PLANE.md section
 * 6 is only real if something enforces it.
 */
export const CONTROL_RPC_SCHEMAS = {
  "/internal/control/redeem": redeemSchema,
  "/internal/control/authorize": authorizeSchema,
  "/internal/control/authorize-next-attempt": nextAttemptSchema,
  "/internal/control/settle": settleSchema,
  "/internal/control/delivery-started": deliveryStartedSchema,
  "/internal/control/provider-rejection": providerRejectionSchema,
  "/internal/control/dispatch-attempt": providerDispatchAttemptSchema,
  "/internal/control/attestation-attempt": attestationAttemptSchema,
  "/internal/control/capture": captureSchema,
  "/internal/control/abort": abortSchema,
  "/internal/control/credential-outcome": credentialOutcomeSchema
} as const;
