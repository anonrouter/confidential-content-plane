import type { FastifyInstance } from "fastify";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import {
  attestationView,
  buildAttestationExpectations,
  endpointIdentityFor
} from "../providers/attestation/index.js";
import { AppError } from "../security/errors.js";
import { OPAQUE_RECEIPT_ID_PATTERN } from "../inference/contentReceipts.js";

/**
 * The public receipt endpoint, served by the CONTENT plane.
 *
 *   GET /v1/tee/receipt/:opaqueReceiptId
 *
 * This replaces `GET /v1/tee/signature/:requestId`, which lived on the control
 * plane and read `providers.tee_signature_bindings`. That table held the exact
 * SHA-256 of the customer's request and the model's response, which is why it
 * had to go: CONTROL_RPC_CONTRACT.md keeps those hashes inside the attested
 * workload. They are here now, so the lookup is here too.
 *
 * WHAT AUTHORIZES A CALLER
 *
 * Possession of the receipt id, and nothing else. The id is 128 uniformly
 * random bits returned in the `x-anonrouter-receipt` header of exactly one
 * response, to exactly one caller. This process has no database, no API-key
 * table and no account identity — that is the point of the split — so it cannot
 * authenticate anyone, and inventing an identity channel for a verification
 * endpoint would undo the separation the whole design exists to create.
 *
 * The trade is stated rather than hidden: anyone who obtains the id can read
 * the binding for that one request. The binding contains two hashes and a
 * provider request id. It contains no prompt, no response, no account and no
 * key, and it cannot be walked, enumerated or searched: there is no listing
 * route and 2^128 is not brute-forceable. A caller who has the id already had
 * the response it came from.
 *
 * WHAT IS VERIFIED, AND WHEN
 *
 * The old route trusted an `attested_signing_key` cached in a control-plane
 * table from some earlier verification. This one fetches FRESH nonce-bound
 * attestation evidence for the exact provider route at read time, verifies it,
 * and takes the attested signing identity from that verdict. So the signature
 * check is bound to evidence produced now, not to a row written at some point
 * in the past by an unrelated request.
 *
 * When fresh evidence yields no attested signer, the response reports
 * `signer_binding: "unbound"` and still returns the raw evidence and both
 * hashes. Degrading honestly is the right answer; claiming an enclave binding
 * that was not established is not.
 */

const RECEIPT_TTL_NOTE =
  "Receipts are held in the attested workload's memory and are lost when it restarts. "
  + "The exact request and response hashes are never sent to the control plane.";

export async function registerTeeReceiptRoutes(server: FastifyInstance) {
  server.get("/v1/tee/receipt/:opaqueReceiptId", async (request) => {
    const store = server.contentReceipts;
    if (!store) {
      throw new AppError(503, "receipt_store_unavailable", "This node does not retain settlement receipts");
    }
    // safeParse, so a malformed id is a 400 with a stable code rather than an
    // unhandled zod throw. The value is never echoed back.
    const params = z
      .object({ opaqueReceiptId: z.string().regex(OPAQUE_RECEIPT_ID_PATTERN) })
      .safeParse(request.params);
    if (!params.success) {
      throw new AppError(400, "invalid_receipt_id", "The receipt identifier is not in the issued format");
    }

    const receipt = store.get(params.data.opaqueReceiptId);
    if (!receipt) {
      // Deliberately the same answer for "never existed", "expired" and "lost to
      // a restart". Distinguishing them would turn this route into an oracle for
      // whether a given id was ever issued.
      throw new AppError(404, "receipt_not_found", `No receipt is held for this identifier. ${RECEIPT_TTL_NOTE}`);
    }

    const verifier = server.verifierRegistry?.forProvider(receipt.providerName);
    if (!verifier) {
      throw new AppError(404, "no_verifier", "No verifier is registered for this provider");
    }
    if (!verifier.supportsSignatures) {
      throw new AppError(
        501,
        "tee_signature_not_supported",
        `Provider ${receipt.providerName} does not expose per-request signatures`
      );
    }
    if (!server.workerClient.signatureForRequest || !server.workerClient.attestationForModel) {
      throw new AppError(503, "signature_unavailable", "Signatures are not available on this node");
    }

    // Fresh, nonce-bound evidence for the exact route that served the request.
    // The nonce is generated here and never read back out of the bundle being
    // verified, which is what stops the check from being circular.
    //
    // The old control-plane route read a signing key cached in
    // providers.tee_verifications by some earlier, unrelated request. This
    // fetches evidence NOW. When that evidence yields an attested signing
    // identity, the signature is bound to it; when it does not, the response
    // says so through `signer_binding` rather than failing, and the caller still
    // receives the raw evidence and both hashes to check independently.
    // Overstating the strength of a verdict is the one thing this endpoint must
    // never do.
    const nonce = randomBytes(32).toString("hex");
    const now = Date.now();
    const endpointIdentity = endpointIdentityFor(server.config, receipt.providerName, receipt.externalModelId);
    let attestation: ReturnType<typeof verifier.verifyAttestation> | null = null;
    try {
      const evidence = await server.workerClient.attestationForModel(
        receipt.providerName,
        receipt.externalModelId,
        nonce
      );
      attestation = verifier.verifyAttestation(
        { fetchedAtMs: now, endpointIdentity, payload: evidence },
        buildAttestationExpectations({
          provider: receipt.providerName,
          upstreamModel: receipt.externalModelId,
          canonicalModel: receipt.canonicalModelId ?? receipt.routeId,
          routeId: receipt.routeId,
          endpointIdentity,
          nonce,
          privacyModality: "tee",
          now
        })
      );
    } catch {
      // A provider that cannot produce attestation right now does not
      // invalidate the receipt; it lowers the verdict, which is reported.
      attestation = null;
    }
    const attestedSigningIdentity = attestation?.status === "ok" ? attestation.attestedSigningKey : null;

    const signatureEvidence = await server.workerClient.signatureForRequest(
      receipt.providerName,
      receipt.externalModelId,
      receipt.providerRequestId
    );
    const result = verifier.verifySignature({
      provider: receipt.providerName,
      routeId: receipt.routeId,
      upstreamModel: receipt.externalModelId,
      canonicalModel: receipt.canonicalModelId ?? receipt.routeId,
      providerRequestId: receipt.providerRequestId,
      requestHash: receipt.requestHash,
      responseHash: receipt.responseHash,
      attestedSigningIdentity,
      evidence: signatureEvidence
    });
    const hashBindingChecked = result.verified
      && result.boundRequestHash?.toLowerCase() === receipt.requestHash.toLowerCase()
      && result.boundResponseHash?.toLowerCase() === receipt.responseHash.toLowerCase();

    return {
      receipt_id: receipt.opaqueReceiptId,
      model: receipt.canonicalModelId ?? receipt.routeId,
      provider: receipt.providerName,
      route_id: receipt.routeId,
      recorded_at: new Date(receipt.recordedAtMs).toISOString(),
      expires_at: new Date(receipt.expiresAtMs).toISOString(),
      signature: {
        supported: result.supported,
        verified: result.verified,
        verification_level: result.verificationLevel,
        signature_kind: result.signatureKind,
        signing_identity: result.signingIdentity,
        bound_request_hash: result.boundRequestHash,
        bound_response_hash: result.boundResponseHash,
        // The caller's own request and response. They were computed in this
        // process, retained in this process, and are returned only to whoever
        // holds the receipt id.
        gateway_request_hash: receipt.requestHash,
        gateway_response_hash: receipt.responseHash,
        hash_binding_checked: hashBindingChecked,
        // Whether the signer was pinned to an enclave identity attested a moment
        // ago, or merely recovered from the signature itself. A caller that
        // treats the two as equivalent is fooling itself, so they are named.
        signer_binding: attestedSigningIdentity ? "attested" : "unbound",
        reason: result.reason,
        checks: result.checks
      },
      ...(attestation ? { attestation: attestationView(attestation) } : {}),
      evidence: signatureEvidence,
      note: RECEIPT_TTL_NOTE
    };
  });
}
