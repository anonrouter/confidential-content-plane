import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { abortOnClientDisconnect, isAbortError } from "../inference/disconnect.js";
import type { AuthorizeRpcResult, RedeemResult, WorkerOpaqueE2eeResult } from "../inference/rpc.js";
import { qualifiedPublicModelId } from "../providers/types.js";
import { relayIngressContext } from "../relay/ingress.js";
import { AppError } from "../security/errors.js";

const PATH = "/v1/e2ee/chat/completions";
const TICKET_HEADER = "x-anonrouter-ticket";
const PROVIDER_HEADER = "x-anonrouter-e2ee-provider";
const INSTANCE_HEADER = "x-chutes-instance-id";
const NONCE_HEADER = "x-chutes-e2e-nonce";

function oneHeader(request: FastifyRequest, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? undefined : value?.trim();
}

function decodeCanonicalBase64(value: string): Buffer {
  if (value.length === 0 || value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new AppError(502, "worker_e2ee_response_invalid", "Credential worker returned an invalid encrypted response");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0 || decoded.toString("base64") !== value) {
    throw new AppError(502, "worker_e2ee_response_invalid", "Credential worker returned an invalid encrypted response");
  }
  return decoded;
}

function setRateLimitHeaders(reply: FastifyReply, authorization: AuthorizeRpcResult) {
  reply.header("x-ratelimit-limit-requests", String(authorization.rateLimits.requests.limit));
  reply.header("x-ratelimit-remaining-requests", String(authorization.rateLimits.requests.remaining));
  reply.header("x-ratelimit-reset-requests", String(Math.ceil(authorization.rateLimits.requests.resetMs / 1_000)));
  reply.header("x-ratelimit-limit-tokens", String(authorization.rateLimits.tokens.limit));
  reply.header("x-ratelimit-remaining-tokens", String(authorization.rateLimits.tokens.remaining));
  reply.header("x-ratelimit-reset-tokens", String(Math.ceil(authorization.rateLimits.tokens.resetMs / 1_000)));
}

/**
 * Whole-body ciphertext relay for provider-native E2EE protocols. This first
 * shipping transport is Chutes ML-KEM v1, non-streaming. The relay parses only
 * fixed routing metadata and never decodes, logs, or rewrites the body.
 */
export async function registerOpaqueE2eeRoutes(server: FastifyInstance) {
  if (!server.hasContentTypeParser("application/octet-stream")) {
    server.addContentTypeParser("application/octet-stream", { parseAs: "buffer" }, (_request, body, done) => {
      done(null, body);
    });
  }

  server.post(PATH, async (request, reply) => {
    const startedAt = Date.now();
    const requestId = request.id;
    const ingress = relayIngressContext(request);
    const signal = ingress?.signal ?? abortOnClientDisconnect(request, reply);
    const ciphertext = Buffer.isBuffer(request.body) ? request.body : null;
    if (!ciphertext || ciphertext.length === 0) {
      throw new AppError(400, "invalid_e2ee_ciphertext", "A non-empty application/octet-stream ciphertext body is required");
    }

    const ticketId = oneHeader(request, TICKET_HEADER);
    let redeemed: RedeemResult | null = ingress?.chatRedemption ?? null;
    if (!redeemed && ticketId) redeemed = await server.controlClient.redeem(ticketId, signal);
    if (!redeemed) throw new AppError(401, "invalid_ticket", "Inference ticket is invalid or expired");
    if ((redeemed.constraints.operation ?? "chat") !== "chat") {
      throw new AppError(409, "ticket_operation_mismatch", "Ticket is not valid for chat");
    }
    if (redeemed.constraints.automatic) {
      throw new AppError(400, "e2ee_requires_explicit_model", "Whole-body E2EE requires an explicit model");
    }
    if (!redeemed.constraints.e2ee || redeemed.constraints.privacyClass !== "e2ee") {
      throw new AppError(409, "ticket_e2ee_mismatch", "Ticket is not valid for an E2EE route");
    }
    if ((redeemed.constraints.reasoningKey ?? "default") !== "default") {
      throw new AppError(400, "e2ee_reasoning_controls_unsupported", "Whole-body E2EE cannot validate outer reasoning controls");
    }
    if (!Number.isSafeInteger(redeemed.constraints.contextWindow) || (redeemed.constraints.contextWindow ?? 0) <= 0) {
      throw new AppError(503, "e2ee_context_unavailable", "Ticket does not carry a usable model context bound");
    }
    if (!Number.isSafeInteger(redeemed.constraints.maxOutputTokens) || (redeemed.constraints.maxOutputTokens ?? 0) <= 0) {
      throw new AppError(503, "e2ee_output_limit_unavailable", "Ticket does not carry a usable output ceiling");
    }

    const selectedProvider = oneHeader(request, PROVIDER_HEADER);
    if (selectedProvider !== "chutes" || redeemed.constraints.providerName !== "chutes") {
      throw new AppError(409, "ticket_e2ee_provider_mismatch", "This opaque transport requires a Chutes-bound ticket");
    }
    const instanceId = oneHeader(request, INSTANCE_HEADER);
    const nonce = oneHeader(request, NONCE_HEADER);
    if (!instanceId || !nonce) {
      throw new AppError(400, "e2ee_headers_incomplete", "Chutes E2EE requires an attested instance id and single-use nonce");
    }
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(instanceId)) {
      throw new AppError(400, "e2ee_instance_invalid", "Chutes E2EE instance id is invalid");
    }
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) {
      throw new AppError(400, "e2ee_nonce_invalid", "Chutes E2EE nonce is invalid");
    }

    let authorized = false;
    try {
      const authorization = await server.controlClient.authorize({
        redemption: redeemed.redemption,
        requestId,
        operation: "chat",
        modelPublicId: redeemed.constraints.publicModelId,
        automatic: false,
        stream: false,
        inputCeiling: redeemed.constraints.contextWindow!,
        requestedMaxOutputTokens: redeemed.constraints.maxOutputTokens!,
        reasoningKey: "default",
        providerPolicyKey: redeemed.constraints.providerPolicyKey,
        e2ee: true,
        opaqueE2ee: true
        // No capability signals: the body is whole-body ciphertext, so this
        // process cannot see tools or images in it either, and would have
        // nothing honest to declare.
      }, signal);
      authorized = true;
      setRateLimitHeaders(reply, authorization);
      if (authorization.model.providerName !== "chutes" || authorization.model.privacyClass !== "e2ee") {
        throw new AppError(409, "e2ee_route_binding_mismatch", "Authorized route does not match the Chutes E2EE transport");
      }
      if (!server.workerClient.opaqueE2ee) {
        throw new AppError(501, "e2ee_transport_not_supported", "Whole-body E2EE is unavailable on this worker");
      }
      const result: WorkerOpaqueE2eeResult = await server.workerClient.opaqueE2ee({
        dispatchToken: authorization.dispatchToken,
        requestId,
        providerName: authorization.model.providerName,
        externalModelId: authorization.model.externalModelId,
        reasoningKey: "default",
        effectiveMaxOutputTokens: authorization.effectiveMaxOutputTokens,
        protocol: "chutes-mlkem-v1",
        headers: { "X-Instance-Id": instanceId, "X-E2E-Nonce": nonce },
        ciphertextBase64: ciphertext.toString("base64")
      }, signal);
      if (result.statusCode !== 200 || result.contentType !== "application/octet-stream") {
        throw new AppError(502, "worker_e2ee_response_invalid", "Credential worker returned an invalid encrypted response");
      }
      if (Object.keys(result.responseHeaders).length !== 0) {
        throw new AppError(502, "worker_e2ee_response_invalid", "Credential worker returned unsupported response headers");
      }
      const encryptedResponse = decodeCanonicalBase64(result.bodyBase64);

      // Chutes does not expose non-stream token usage outside the encrypted
      // envelope. Capture the already-reserved full-context ceiling; never guess
      // from ciphertext length or fabricate an exact settlement.
      await server.controlClient.capture({ requestId, latencyMs: Date.now() - startedAt }, signal);
      authorized = false;
      reply.header("x-anonrouter-provider", "chutes");
      reply.header("x-anonrouter-selected-model", qualifiedPublicModelId("chutes", authorization.model.publicModelId));
      reply.header("x-anonrouter-privacy-class", "E2EE");
      reply.header("x-anonrouter-provider-attempts", "1");
      reply.header("x-anonrouter-provider-fallback", "false");
      reply.header("cache-control", "no-store");
      return reply.type("application/octet-stream").send(encryptedResponse);
    } catch (error) {
      const clientGone = signal.aborted || isAbortError(error);
      if (authorized) {
        await server.controlClient.abort({
          requestId,
          status: "failed",
          providerRejected: !clientGone,
          latencyMs: Date.now() - startedAt
        }).catch(() => undefined);
      }
      if (clientGone) return reply;
      throw error;
    }
  });
}
