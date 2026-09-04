import type { FastifyInstance, FastifyRequest } from "fastify";
import { abortOnClientDisconnect, isAbortError } from "../inference/disconnect.js";
import type { RedeemResult } from "../inference/rpc.js";
import { normalizeUsage, type TokenUsage } from "../metering/tokens.js";
import {
  embeddingRequestSchema,
  estimateEmbeddingInputTokenCeiling,
  estimateEmbeddingInputTokens,
  type EmbeddingRequestBody,
  type EmbeddingResponse
} from "../providers/embeddings.js";
import { qualifiedPublicModelId } from "../providers/types.js";
import type { InferenceRateLimitResult } from "../rate-limit/limiter.js";
import { relayIngressContext } from "../relay/ingress.js";
import { AppError } from "../security/errors.js";
import { reportProviderRejection } from "../inference/rejectionReporting.js";
import { parseBody } from "./helpers.js";

const TICKET_HEADER = "x-anonrouter-ticket";

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function applyRateLimitHeaders(reply: { header(name: string, value: string): unknown }, limits: InferenceRateLimitResult) {
  reply.header("x-ratelimit-limit-requests", String(limits.requests.limit));
  reply.header("x-ratelimit-remaining-requests", String(limits.requests.remaining));
  reply.header("x-ratelimit-reset-requests", String(Math.ceil(limits.requests.resetMs / 1000)));
  reply.header("x-ratelimit-limit-tokens", String(limits.tokens.limit));
  reply.header("x-ratelimit-remaining-tokens", String(limits.tokens.remaining));
  reply.header("x-ratelimit-reset-tokens", String(Math.ceil(limits.tokens.resetMs / 1000)));
}

function usageStatusForError(error: unknown): "failed" | "rate_limited" | "insufficient_balance" {
  if (error instanceof AppError && error.statusCode === 402) return "insufficient_balance";
  if (error instanceof AppError && (error.code === "rate_limited" || error.code === "concurrency_limited")) {
    return "rate_limited";
  }
  return "failed";
}

/**
 * Rewrite the provider's model id back to the id the CALLER named.
 *
 * `publicModelId` is the route id (`tinfoil/nomic-embed-text`); `canonicalModelId`
 * is the catalog id a request names (`nomic-ai/nomic-embed-text`). They differ
 * whenever a model is served by more than one provider, which is the normal case.
 *
 * Chat has always echoed the canonical id and this echoed the route id, so an
 * embedding response named a model the caller had not asked for. That is not
 * cosmetic: a client verifying a confidential route cross-binds the echoed model
 * against the one it requested, and a disagreement there is exactly the shape of
 * a provider substitution. Reporting one on a correctly-served route trains
 * people to ignore the check that catches a real one.
 */
function publicEmbeddingResponse(response: EmbeddingResponse, publicModelId: string): EmbeddingResponse {
  return { ...response, model: publicModelId };
}

async function redeemForEmbedding(
  server: FastifyInstance,
  request: FastifyRequest,
  body: EmbeddingRequestBody,
  signal: AbortSignal
): Promise<RedeemResult> {
  const ingress = relayIngressContext(request);
  if (ingress?.embeddingRedemption) return ingress.embeddingRedemption;

  const ticketId = headerValue(request.headers[TICKET_HEADER]);
  if (ticketId) {
    const redeemed = await server.controlClient.redeem(ticketId, signal);
    if (!redeemed) throw new AppError(401, "invalid_ticket", "Inference ticket is invalid or expired");
    return redeemed;
  }
  // The relay fails closed without a ticket. The inline identity path is a
  // weaker dev-only mode: forbidden in production by config.ts, and absent
  // entirely on the content tier because the capability is never registered
  // there. See src/inference/inlineTicket.ts.
  if (!server.config.internal.allowInlineTicket || !server.inlineTicketIssuer) {
    throw new AppError(401, "ticket_required", "An inference ticket is required");
  }
  return server.inlineTicketIssuer(request, {
    requestedModel: body.model,
    maxOutputTokens: 0,
    automatic: false,
    operation: "embeddings"
  });
}

/** OpenAI-compatible embeddings over the same ticketed relay and billing path as chat. */
export async function registerEmbeddingRoutes(server: FastifyInstance) {
  server.post("/v1/embeddings", async (request, reply) => {
    const startedAt = Date.now();
    const requestId = request.id;
    const ingress = relayIngressContext(request);
    const signal = ingress?.signal ?? abortOnClientDisconnect(request, reply);
    const body = parseBody(embeddingRequestSchema, request.body) as EmbeddingRequestBody;
    const inputCeiling = estimateEmbeddingInputTokenCeiling(body.input);
    const redeemed = await redeemForEmbedding(server, request, body, signal);
    if (redeemed.constraints.operation !== "embeddings") {
      throw new AppError(409, "ticket_operation_mismatch", "Ticket is not valid for embeddings");
    }
    if (body.model !== redeemed.constraints.requestedModel) {
      throw new AppError(409, "ticket_model_mismatch", "Model does not match the issued ticket");
    }

    let authorized = false;
    try {
      const authorization = await server.controlClient.authorize({
        redemption: redeemed.redemption,
        requestId,
        operation: "embeddings",
        modelPublicId: redeemed.constraints.publicModelId,
        automatic: false,
        stream: false,
        inputCeiling
      }, signal);
      authorized = true;
      applyRateLimitHeaders(reply, authorization.rateLimits);
      const model = authorization.model;
      if (model.modelType !== "embedding") {
        throw new AppError(400, "model_not_embedding", "Model is not an embedding model");
      }

      reply.header("x-anonrouter-selected-model", qualifiedPublicModelId(model.providerName, model.publicModelId));
      reply.header("x-anonrouter-routing", "exact");
      if (!server.workerClient.embeddings) {
        throw new AppError(503, "provider_unavailable", "Embedding worker is unavailable");
      }
      const result = await server.workerClient.embeddings({
        dispatchToken: authorization.dispatchToken,
        requestId,
        providerName: model.providerName,
        externalModelId: model.externalModelId,
        body: { ...body, model: model.publicModelId }
      }, signal);
      const normalized = normalizeUsage(result.usage, {
        inputTokens: estimateEmbeddingInputTokens(body.input),
        outputTokens: 0,
        cachedTokens: 0
      });
      const usage: TokenUsage = { inputTokens: normalized.inputTokens, outputTokens: 0, cachedTokens: 0 };
      await server.controlClient.settle({ requestId, usage, latencyMs: Date.now() - startedAt });
      return publicEmbeddingResponse(result.response, model.canonicalModelId ?? model.publicModelId);
    } catch (error) {
      const clientGone = signal.aborted || isAbortError(error);
      // Content-free rejection-ledger record for a provider-origin failure
      // (no-op for a local admission error, which control records itself).
      await reportProviderRejection(server.controlClient, {
        requestId, attemptIndex: 0, automatic: false, error, signal, startedAt
      });
      // Symmetric with chat (routes/chat.ts): a provider/server fault with zero
      // delivery releases the fenced hold in full (an upstream rejection is not
      // billable), while a client disconnect keeps the conservative capture. Passing
      // providerRejected here stops embeddings over-charging the caller on provider
      // outages/429s. Both outcomes are idempotent and content-free.
      await server.controlClient.abort({
        requestId,
        status: usageStatusForError(error),
        providerRejected: !clientGone,
        latencyMs: Date.now() - startedAt
      }).catch(() => undefined);
      if (clientGone) return reply;
      throw error;
    } finally {
      void authorized;
    }
  });
}
