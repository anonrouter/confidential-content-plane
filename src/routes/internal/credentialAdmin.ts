import type { FastifyInstance } from "fastify";
import { createHash } from "node:crypto";
import { z } from "zod";
import { AppError } from "../../security/errors.js";
import { parseBody } from "../helpers.js";
import {
  CapabilityError,
  CAPABILITY_PROTOCOL,
  decodeCapability,
  verifyCapability,
  type CapabilityAction,
  type CredentialCapability,
  type SignedCapability
} from "../../providers/credentials/capability.js";
import {
  INSTALL_ACTIONS,
  REVOKE_ACTIONS,
  parseCapabilitySigners
} from "../../credentials/capabilityConfig.js";
import { ConsumedCapabilityLog } from "../../credentials/consumedCapabilities.js";
import { veniceKeyFingerprint, KEY_ID_PATTERN } from "../../providers/veniceKeys.js";
import { credentialOutcomeSchema } from "./rpcSchemas.js";

/**
 * Provider-credential administration that TERMINATES IN THE ATTESTED WORKLOAD.
 *
 * The pre-confidential topology did the opposite: the control plane held the
 * provider key and pushed it to the worker over a bearer-token RPC. That makes
 * the control plane a credential custodian, and the launch boundary rules it
 * out — no provider credential may traverse or persist in GCP.
 *
 * What replaces it, in order:
 *
 *   1. the admin client verifies fresh Phala evidence and proves the TLS it is
 *      speaking terminates inside that attested workload, BEFORE a secret is
 *      entered anywhere;
 *   2. it obtains from the control plane only a short-lived, single-use,
 *      content-free AUTHORIZATION, which contains no secret;
 *   3. it POSTs the raw secret and that authorization HERE, directly, over the
 *      connection it verified.
 *
 * The control plane authorizes and never holds. It is told afterwards only what
 * it needs to display and audit, through `/internal/control/credential-outcome`:
 * the capability id, an outcome, a bounded outcome code, a TRUNCATED fingerprint
 * this process computes after the secret arrives, and a label.
 *
 * WHY THIS IS NOT GUARDED BY A BEARER TOKEN
 *
 * Because a bearer token would be a second way in, and the weaker one. The
 * capability signature IS the authorization: it is bound to this deployment,
 * this provider, this credential id, this action and this moment, and it works
 * once. A shared token is bound to none of those things. Adding one would mean
 * anything holding it could install a credential, which is precisely the
 * property being removed.
 *
 * THE PROTOCOL IS THE CONTROL PLANE'S, deliberately. See
 * src/credentials/capabilityConfig.ts and
 * docs/architecture/confidential-backend/CAPABILITY_PROTOCOL_DECISION.md.
 */

const MAX_SECRET_LENGTH = 4096;

/** The transport envelope: canonical bytes, detached signature, signer id. */
const signedCapabilitySchema = z
  .object({
    capability: z.string().min(1).max(8192),
    signature: z.string().min(1).max(256),
    keyId: z.string().min(3).max(64)
  })
  .strict();

const installSchema = z
  .object({
    capability: signedCapabilitySchema,
    /**
     * The raw provider secret. It is read, validated, stored through the
     * measured mechanism and dropped. It is never logged, never echoed, never
     * returned, and never included in an error.
     */
    secret: z.string().min(1).max(MAX_SECRET_LENGTH)
  })
  .strict();

const revokeSchema = z.object({ capability: signedCapabilitySchema }).strict();

/**
 * TRUNCATED, and computed here rather than anywhere upstream.
 *
 * The control plane's contract refuses a credential-administration body
 * carrying a secret-shaped value on SHAPE, not just by field name, so a full
 * 64-character digest in this field would be rejected as a possible secret. It
 * is also the right call independently: a full digest of a provider key is a
 * confirmable commitment to it.
 */
function fingerprintFor(provider: string, secret: string): string {
  const full = provider === "venice"
    ? veniceKeyFingerprint(secret)
    : createHash("sha256").update(secret).digest("hex");
  return full.slice(0, 16);
}

export async function registerCredentialAdminRoutes(server: FastifyInstance) {
  const settings = server.config.internal.credentialAdmin;
  if (settings.mode !== "capability") return;

  const provider = server.config.internal.role === "fireworks-worker" ? "fireworks"
    : server.config.internal.role === "bedrock-worker" ? "aws-bedrock"
      : server.config.internal.role === "deepinfra-worker" ? "deepinfra"
        : server.config.internal.role === "chutes-worker" ? "chutes"
          : server.config.internal.role === "tinfoil-worker" ? "tinfoil"
            : server.config.internal.role === "near-worker" ? "near-ai"
              : server.config.internal.role === "phala-ai-worker" ? "phala-ai"
                : "venice";

  // Fail at BOOT, not at first use. A workload configured for capability mode
  // without a pinned signer cannot verify anything, and discovering that during
  // a credential installation — with an operator holding a secret — is the worst
  // possible moment.
  const signers = parseCapabilitySigners(settings.capabilitySigners);
  if (Object.keys(signers.publicKeys).length === 0) {
    throw new Error("CREDENTIAL_ADMIN_MODE=capability requires at least one pinned CREDENTIAL_CAPABILITY_SIGNERS entry");
  }
  // The TLS identity is not part of the capability protocol; the client binds it
  // by verifying attestation against the key on its own socket before sending
  // anything. It is still required here so `/v1/credentials/identity` can state
  // what this endpoint is, which is what the client compares against.
  if (!settings.tlsSpkiSha256) {
    throw new Error("CREDENTIAL_ADMIN_MODE=capability requires CONTENT_TLS_SPKI_SHA256 to publish the serving endpoint identity");
  }

  const consumed = new ConsumedCapabilityLog(settings.consumedCapabilityFile);
  const deploymentId = server.config.internal.confidentialDeploymentId;

  /**
   * Verify, then consume. Both, in that order, before anything is stored.
   *
   * Consuming before the work happens means a failed installation burns the
   * capability. That is deliberate: a capability that could be retried after a
   * partial failure is a capability that can be replayed, and the operator can
   * always be issued another one. Availability is the cheaper thing to spend.
   *
   * The credential id and action come from the CAPABILITY, never from the
   * request body. A caller who could name what the capability is compared
   * against could satisfy any comparison.
   */
  function authorize(
    signed: SignedCapability,
    allowedActions: readonly CapabilityAction[]
  ): CredentialCapability {
    const claimed = claimedBy(signed);
    if (!allowedActions.includes(claimed.action)) {
      throw new AppError(403, "capability_action_not_permitted", "The authorization capability requests an action this endpoint does not perform");
    }

    let capability: CredentialCapability;
    try {
      capability = verifyCapability({
        signed,
        publicKeys: signers.publicKeys,
        deploymentId,
        // Every one of these is compared against LOCAL truth by the verifier:
        // this deployment's id, this worker's provider, and the action and
        // credential id the signed bytes themselves carry. A caller supplies
        // none of them.
        action: claimed.action,
        provider,
        credentialId: claimed.credentialId,
        now: Math.floor(Date.now() / 1000),
        isConsumed: (id) => consumed.wasConsumed(id)
      });
    } catch (error) {
      if (error instanceof CapabilityError) {
        // The message is the peer verifier's, which names the field that failed
        // and never the value. Mapped to a stable code so a client can branch.
        const code = codeFor(error.message);
        // A spent capability is a conflict, not a forbidden: the caller's
        // authorization was real and is simply used up, and 409 is what tells
        // an operator to request another rather than to check their permissions.
        throw new AppError(code === "capability_already_used" ? 409 : 403, code, error.message);
      }
      throw error;
    }

    // The verifier above already REFUSED a capability the log knows about. This
    // is the COMMIT: it records the id, and the boolean it returns closes the
    // window between that read and this write. Two calls that raced would both
    // pass the verifier's check and only one can win here.
    let firstUse: boolean;
    try {
      firstUse = consumed.consume(capability.capabilityId, capability.expiresAt).firstUse;
    } catch {
      // An unreadable replay log cannot be treated as "nothing consumed yet".
      throw new AppError(503, "capability_replay_log_unavailable", "The replay record could not be read; refusing the operation");
    }
    if (!firstUse) {
      throw new AppError(409, "capability_already_used", "This authorization capability has already been used");
    }
    return capability;
  }

  /**
   * Report the outcome to the control plane. Content-free by construction: a
   * capability id, a bounded machine code, a truncated fingerprint and a label.
   *
   * Best effort. A settled credential operation must not be undone because an
   * audit row would not write, and the operator already has the result in the
   * response. A failure is logged so it is visible rather than silent.
   */
  async function reportOutcome(
    request: { log: FastifyInstance["log"] },
    body: {
      capabilityId: string;
      outcome: "applied" | "rejected" | "failed";
      outcomeCode: string;
      fingerprint?: string;
      label?: string | null;
    }
  ) {
    const url = `${server.config.internal.controlMetadataUrl}/internal/control/credential-outcome`;
    // Validate our OWN outgoing body against the boundary schema before sending
    // it. Every other direction of this boundary is pinned by a strict schema;
    // a route the content plane initiates should not be the exception, and a
    // malformed or over-disclosing outcome should fail here rather than be
    // refused at the far end after the fact.
    const validated = credentialOutcomeSchema.safeParse({
      capabilityId: body.capabilityId,
      outcome: body.outcome,
      outcomeCode: body.outcomeCode,
      ...(body.fingerprint ? { fingerprint: body.fingerprint } : {}),
      ...(body.label ? { label: body.label } : {})
    });
    if (!validated.success) {
      // Never echoes the offending value: an error path is a log path.
      request.log.warn({ capability_id: body.capabilityId }, "credential_outcome_body_invalid");
      return;
    }
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${server.config.internal.workerMetadataToken}`
        },
        body: JSON.stringify(validated.data),
        signal: AbortSignal.timeout(10_000)
      });
      await response.body?.cancel().catch(() => undefined);
      if (!response.ok) {
        request.log.warn({ status_code: response.status, capability_id: body.capabilityId }, "credential_outcome_report_failed");
      }
    } catch {
      request.log.warn({ capability_id: body.capabilityId }, "credential_outcome_report_unreachable");
    }
  }

  function auditView(capability: CredentialCapability, fingerprint: string | null, status: string, label: string | null) {
    // Everything the control plane is allowed to learn, and nothing else. No
    // secret, no secret-derived value beyond the truncated fingerprint, no
    // provider response body, and not the capability itself.
    return {
      ok: true,
      capability_id: capability.capabilityId,
      credential_id: capability.credentialId,
      label,
      provider: capability.provider,
      action: capability.action,
      status,
      ...(fingerprint ? { fingerprint } : {}),
      deployment_id: deploymentId,
      operator_id: capability.operatorId,
      applied_at: new Date().toISOString()
    };
  }

  /**
   * Register or rotate. Rotation is the same operation under the same credential
   * id: the store replaces the entry atomically, so the new secret is live
   * before the old one is unreachable and no request sees an empty keyset.
   */
  server.post("/internal/credentials/secret", async (request) => {
    const body = parseBody(installSchema, request.body);
    const label = readLabel(request.body);
    const capability = authorize(body.capability, INSTALL_ACTIONS);

    const store = server.veniceKeyStore;
    if (!store) {
      await reportOutcome(request, { capabilityId: capability.capabilityId, outcome: "failed", outcomeCode: "credential_store_unavailable" });
      throw new AppError(503, "credential_store_unavailable", "This workload has no measured credential store");
    }
    if (!KEY_ID_PATTERN.test(capability.credentialId)) {
      await reportOutcome(request, { capabilityId: capability.capabilityId, outcome: "rejected", outcomeCode: "credential_id_invalid" });
      throw new AppError(400, "credential_id_invalid", "The credential id is not in the accepted format");
    }

    // Validate against the provider before storing, so a typo does not silently
    // take inference down at the next dispatch. A network failure is NOT proof
    // of an invalid key, so only an explicit rejection refuses.
    if (server.config.env !== "test" && server.config.providers.defaultProvider !== "mock" && provider === "venice") {
      let response: Response;
      try {
        response = await fetch(`${server.config.providers.veniceBaseUrl}/api_keys/rate_limits`, {
          headers: { authorization: `Bearer ${body.secret}` },
          signal: AbortSignal.timeout(10_000)
        });
      } catch {
        await reportOutcome(request, { capabilityId: capability.capabilityId, outcome: "failed", outcomeCode: "provider_unreachable" });
        throw new AppError(503, "credential_verification_unavailable", "The provider could not be reached to verify the credential");
      }
      // Drain without reading: a provider error body is provider output and has
      // no business anywhere near this path.
      await response.body?.cancel().catch(() => undefined);
      if (response.status === 401 || response.status === 403) {
        await reportOutcome(request, { capabilityId: capability.capabilityId, outcome: "rejected", outcomeCode: "provider_rejected_credential" });
        throw new AppError(400, "credential_rejected_by_provider", "The provider rejected the credential");
      }
    }

    store.addKey({ id: capability.credentialId, label, key: body.secret });
    const fingerprint = fingerprintFor(provider, body.secret);

    // Publish the content-free descriptor set so the control plane's metadata
    // catches up immediately rather than at the next poll.
    await server.catalogSyncNow?.().catch(() => undefined);
    await reportOutcome(request, {
      capabilityId: capability.capabilityId,
      outcome: "applied",
      outcomeCode: capability.action === "rotate" ? "rotated" : "registered",
      fingerprint,
      label
    });

    request.log.info(
      {
        credential_id: capability.credentialId,
        action: capability.action,
        operator_id: capability.operatorId,
        deployment_id: deploymentId
      },
      "credential_admin_applied"
    );
    return auditView(capability, fingerprint, "active", label);
  });

  server.post("/internal/credentials/revoke", async (request) => {
    const body = parseBody(revokeSchema, request.body);
    const capability = authorize(body.capability, REVOKE_ACTIONS);

    const store = server.veniceKeyStore;
    if (!store) {
      await reportOutcome(request, { capabilityId: capability.capabilityId, outcome: "failed", outcomeCode: "credential_store_unavailable" });
      throw new AppError(503, "credential_store_unavailable", "This workload has no measured credential store");
    }
    if (store.isLastRemaining(capability.credentialId)) {
      await reportOutcome(request, { capabilityId: capability.capabilityId, outcome: "rejected", outcomeCode: "last_remaining_credential" });
      throw new AppError(409, "credential_last_remaining", "Refusing to remove the last remaining provider credential");
    }
    if (!store.removeKey(capability.credentialId)) {
      await reportOutcome(request, { capabilityId: capability.capabilityId, outcome: "rejected", outcomeCode: "credential_not_found" });
      throw new AppError(404, "credential_not_found", "No such credential is present in the effective keyset");
    }
    await server.catalogSyncNow?.().catch(() => undefined);
    await reportOutcome(request, {
      capabilityId: capability.capabilityId,
      outcome: "applied",
      outcomeCode: "revoked"
    });

    request.log.info(
      {
        credential_id: capability.credentialId,
        action: capability.action,
        operator_id: capability.operatorId,
        deployment_id: deploymentId
      },
      "credential_admin_revoked"
    );
    return auditView(capability, null, "revoked", null);
  });

  /**
   * What this endpoint is, for a client that has just verified the enclave and
   * wants to confirm it is about to talk to the right one BEFORE sending a
   * secret. Content-free, credential-free and unauthenticated on purpose: a
   * client cannot be asked to authenticate to something it has not yet decided
   * to trust.
   *
   * `tls_spki_sha256` is what the client compares against the key it observed on
   * its own socket. The protocol does not carry that binding inside the
   * capability, so this comparison is the client's job and this route is what
   * makes it possible.
   */
  server.get("/internal/credentials/identity", async () => ({
    deployment_id: deploymentId,
    provider,
    tls_spki_sha256: settings.tlsSpkiSha256,
    capability_protocol: CAPABILITY_PROTOCOL,
    capability_signer_key_ids: Object.keys(signers.publicKeys).sort(),
    accepted_actions: [...INSTALL_ACTIONS, ...REVOKE_ACTIONS]
  }));
}

/**
 * Decode the canonical bytes WITHOUT trusting them, to learn what the
 * capability claims to be.
 *
 * The peer verifier takes `action`, `provider` and `credentialId` as INPUTS to
 * compare against, so something has to read them first. Doing that before the
 * signature is checked looks alarming and is not: nothing here is acted on. The
 * claims are handed straight back to `verifyCapability`, which re-decodes the
 * same bytes AFTER verifying the signature and rejects any mismatch. A forged
 * value fails signature verification; a mismatched one fails the comparison.
 * Reading it early only avoids making the caller restate what the capability
 * already says, which would be one more thing a caller could lie about.
 *
 * This uses the peer's own canonical decoder rather than scanning bytes, so a
 * non-canonical encoding is refused here exactly as it would be later.
 */
function claimedBy(signed: SignedCapability): CredentialCapability {
  let encoded: Buffer;
  try {
    encoded = Buffer.from(signed.capability, "base64url");
  } catch {
    throw new AppError(403, "capability_malformed", "The authorization capability is not readable");
  }
  try {
    return decodeCapability(encoded);
  } catch (error) {
    throw new AppError(
      403,
      "capability_malformed",
      error instanceof CapabilityError ? error.message : "The authorization capability is not readable"
    );
  }
}

/** The operator-supplied label, which is metadata and never part of the signed bytes. */
function readLabel(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const label = (body as { label?: unknown }).label;
  return typeof label === "string" && label.trim().length > 0 ? label.trim().slice(0, 120) : null;
}

/** Map the peer verifier's message to a stable machine code. */
function codeFor(message: string): string {
  if (message.includes("unknown capability signing key id")) return "capability_unknown_signer";
  if (message.includes("signature")) return "capability_signature_invalid";
  if (message.includes("different deployment")) return "capability_wrong_deployment";
  if (message.includes("different provider")) return "capability_wrong_provider";
  if (message.includes("different credential id")) return "capability_wrong_credential";
  if (message.includes("does not authorize this action")) return "capability_action_not_permitted";
  if (message.includes("not yet valid")) return "capability_not_yet_valid";
  if (message.includes("has expired")) return "capability_expired";
  if (message.includes("already been used")) return "capability_already_used";
  if (message.includes("lifetime exceeds")) return "capability_ttl_too_long";
  return "capability_malformed";
}
