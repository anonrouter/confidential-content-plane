// GET /v1/gateway/attestation
//
// Deliberately separate from /v1/tee/attestation. That route describes the
// UPSTREAM model provider's enclave and is served by the credential worker
// through the control plane. This one describes AnonRouter's OWN data plane and
// is served by the process that actually holds the plaintext, which is the only
// process whose self-attestation means anything.
//
// Properties this route must keep:
//   - Credential-free. A client verifies BEFORE it trusts the endpoint with
//     anything, so requiring a ticket or a key would invert the trust order.
//   - Stateless. The CVM has no database and writes no verification row.
//   - Content-free. It never touches a request body.
//   - Fail-closed and legible. When the enclave is absent it returns 503 with a
//     specific code, never a 404 that reads like a routing mistake.

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { AppError } from "../security/errors.js";
import { GATEWAY_NONCE_HEX_LENGTH } from "../gateway/binding.js";
import type { GatewayAttestationService } from "../gateway/service.js";
import { registerRelayIngressGuard } from "../relay/ingress.js";
import { parseBody } from "./helpers.js";

export const GATEWAY_ATTESTATION_PATH = "/v1/gateway/attestation";

const querySchema = z
  .object({
    // Exactly 32 bytes. A shorter nonce would still bind, but a fixed width
    // removes any question about caller entropy and matches the binding module.
    nonce: z.string().regex(new RegExp(`^[0-9a-fA-F]{${GATEWAY_NONCE_HEX_LENGTH}}$`))
  })
  .strict();

declare module "fastify" {
  interface FastifyInstance {
    gatewayAttestation: GatewayAttestationService | null;
  }
}

/**
 * Flood guard for the isolated attestation service.
 *
 * Each call makes the guest agent mint a fresh TDX quote, and that socket is a
 * single serialized resource, so an unauthenticated caller could starve
 * attestation for everyone. The relay registers the same guard for this path,
 * but in the CVM topology the relay does not serve the route at all, so the
 * guard has to exist here too or it exists only where the route does not.
 *
 * Budgets are far below the relay's chat budget on purpose: attestation is a
 * once-per-session call, not a per-request one.
 */
export function registerGatewayAttestationIngressGuard(server: FastifyInstance) {
  return registerRelayIngressGuard(server, {
    globalRequests: 240,
    subnetRequests: 60,
    exactRequests: 20,
    globalConcurrent: 8,
    subnetConcurrent: 4,
    exactConcurrent: 2,
    maxConnections: 128
  });
}

export async function registerGatewayAttestationRoutes(server: FastifyInstance) {
  server.get(GATEWAY_ATTESTATION_PATH, async (request, reply) => {
    const service = server.gatewayAttestation;
    if (!service) {
      throw new AppError(
        503,
        "gateway_attestation_unavailable",
        "This deployment is not running inside an attestable confidential VM"
      );
    }
    const { nonce } = parseBody(querySchema, request.query ?? {});

    let document;
    try {
      // THE HOST HEADER SELECTS WHICH NAME IS ATTESTED, and nothing more.
      //
      // This CVM serves the restored api.anonrouter.ai base URL and the
      // api.private.anonrouter.ai verification alias, each with its own
      // certificate. A verifier compares the bound origin against ITS OWN
      // connection, so a document has to describe the name the caller used or a
      // correctly configured alias fails closed. An unrecognised Host falls back
      // to the canonical origin; a caller cannot introduce an origin, only pick
      // among the ones the measured compose declares.
      document = await service.attest(nonce.toLowerCase(), {
        requestedHost: typeof request.headers.host === "string" ? request.headers.host : undefined
      });
    } catch (error) {
      // Never surface a guest-agent message: it is not content, but it is
      // unbounded upstream text and this route has no reason to echo any.
      request.log.warn(
        { request_id: request.id, error_type: "gateway_attestation_failed" },
        "gateway_attestation_failed"
      );
      throw new AppError(503, "gateway_attestation_failed", "Attestation evidence could not be produced");
    }

    // Evidence is nonce-bound and single-use by construction. Caching it, at any
    // layer, would let a stale document answer a fresh challenge.
    reply.header("cache-control", "no-store, no-transform");
    reply.header("x-request-id", request.id);
    return document;
  });
}
