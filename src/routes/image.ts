import type { FastifyInstance, FastifyRequest } from "fastify";
import { abortOnClientDisconnect, isAbortError } from "../inference/disconnect.js";
import type { ControlClient, RedeemResult } from "../inference/rpc.js";
import type { InferenceRateLimitResult } from "../rate-limit/limiter.js";
import {
  imageGenerationRequestSchema,
  parseImageSize,
  qualifiedPublicModelId,
  type ImageGenerationRequestBody
} from "../providers/types.js";
import { relayIngressContext } from "../relay/ingress.js";
import { AppError } from "../security/errors.js";
import { reportProviderNonBillableOutcome, reportProviderRejection } from "../inference/rejectionReporting.js";
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

/** Flat-priced media settles the exact authorized amount; retry to avoid a lost RPC. */
async function captureWithRetry(
  controlClient: ControlClient,
  params: { requestId: string; latencyMs: number },
  attempts = 2
) {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      await controlClient.capture(params);
      return;
    } catch (error) {
      lastError = error;
      if (attempt + 1 < attempts) await new Promise((resolve) => setTimeout(resolve, 50 * (attempt + 1)));
    }
  }
  throw lastError;
}

async function redeemForImage(
  server: FastifyInstance,
  request: FastifyRequest,
  body: ImageGenerationRequestBody,
  size: { width: number; height: number },
  signal: AbortSignal
): Promise<RedeemResult> {
  const ingress = relayIngressContext(request);
  if (ingress?.imageRedemption) return ingress.imageRedemption;

  const ticketId = headerValue(request.headers[TICKET_HEADER]);
  if (ticketId) {
    const redeemed = await server.controlClient.redeem(ticketId, signal);
    if (!redeemed) throw new AppError(401, "invalid_ticket", "Inference ticket is invalid or expired");
    return redeemed;
  }
  // The relay fails closed without a ticket. The inline identity path is a
  // weaker dev-only mode (forbidden in production, config.ts).
  if (!server.config.internal.allowInlineTicket || !server.inlineTicketIssuer) {
    throw new AppError(401, "ticket_required", "An inference ticket is required");
  }
  return server.inlineTicketIssuer(request, {
    requestedModel: body.model,
    maxOutputTokens: 0,
    automatic: false,
    operation: "image",
    image: { width: size.width, height: size.height, responseFormat: body.response_format }
  });
}

/**
 * Privacy-preserving image generation over the split relay path. The relay holds
 * the prompt and an opaque ticket redemption but no account identity, DB, or
 * Venice credential. It redeems the single-use ticket, validates the body against
 * the ticket-bound (and priced) size/format, has control reserve the flat unit
 * price before dispatch, sends the prompt to the credential-isolated worker, and
 * settles the exact flat price exactly once. The prompt and the base64 image
 * never reach the control plane; neither is intentionally logged.
 */
export async function registerImageRoutes(server: FastifyInstance) {
  server.post("/v1/images/generations", async (request, reply) => {
    // Server-side, independent enforcement of the split image flag. The relay
    // fails closed with the same clear 503 the disabled stub returns.
    if (!server.config.internal.imageGenerationEnabled) {
      throw new AppError(503, "media_disabled", "Media generation is not enabled on this deployment");
    }
    const startedAt = Date.now();
    const requestId = request.id;
    const ingress = relayIngressContext(request);
    const signal = ingress?.signal ?? abortOnClientDisconnect(request, reply);
    const body = parseBody(imageGenerationRequestSchema, request.body) as ImageGenerationRequestBody;
    const size = parseImageSize(body.size);

    const redeemed = await redeemForImage(server, request, body, size, signal);
    if ((redeemed.constraints.operation ?? "chat") !== "image") {
      throw new AppError(409, "ticket_operation_mismatch", "Ticket is not valid for image generation");
    }
    if (body.model !== redeemed.constraints.requestedModel) {
      throw new AppError(409, "ticket_model_mismatch", "Model does not match the issued ticket");
    }
    // The ticket bound the exact priced provider work. A body that drifts from
    // the issued size or output format is rejected before any reservation.
    if (redeemed.constraints.imageWidth !== size.width || redeemed.constraints.imageHeight !== size.height) {
      throw new AppError(409, "ticket_size_mismatch", "Image size does not match the issued ticket");
    }
    if ((redeemed.constraints.imageResponseFormat ?? null) !== body.response_format) {
      throw new AppError(409, "ticket_format_mismatch", "Image response format does not match the issued ticket");
    }

    let publicModelId: string;
    let result: Awaited<ReturnType<NonNullable<typeof server.workerClient.generateImage>>>;
    try {
      const authorization = await server.controlClient.authorize({
        redemption: redeemed.redemption,
        requestId,
        operation: "image",
        modelPublicId: redeemed.constraints.publicModelId,
        automatic: false,
        stream: false,
        // Image carries no token ceiling; control reserves the flat unit price.
        inputCeiling: 0
      }, signal);
      applyRateLimitHeaders(reply, authorization.rateLimits);
      const model = authorization.model;
      if (model.modelType !== "image") {
        throw new AppError(400, "model_not_image", "Model is not an image generation model");
      }
      if (!server.workerClient.generateImage) {
        throw new AppError(503, "provider_unavailable", "Image worker is unavailable");
      }
      publicModelId = model.publicModelId;
      reply.header("x-anonrouter-selected-model", qualifiedPublicModelId(model.providerName, model.publicModelId));
      reply.header("x-anonrouter-routing", "exact");
      result = await server.workerClient.generateImage({
        dispatchToken: authorization.dispatchToken,
        requestId,
        providerName: model.providerName,
        externalModelId: model.externalModelId,
        width: size.width,
        height: size.height,
        responseFormat: body.response_format,
        prompt: body.prompt
      }, signal);
    } catch (error) {
      // Content-free rejection-ledger record for a provider-origin failure
      // (no-op for a local admission error, which control records itself).
      await reportProviderRejection(server.controlClient, {
        requestId, attemptIndex: 0, automatic: false, error, signal, startedAt
      });
      // Pre-fence transport failure releases the reservation to zero; a failure
      // after the worker crossed its durable provider-attempt fence captures the
      // authorized flat price. Both are idempotent and content-free.
      await server.controlClient
        .abort({ requestId, status: usageStatusForError(error), latencyMs: Date.now() - startedAt })
        .catch(() => undefined);
      if (signal.aborted || isAbortError(error)) return reply;
      throw error;
    }

    // Generation succeeded: charge the exact flat price exactly once. capture
    // charges the reserved ceiling (= the reviewed unit price), never a
    // usage-derived amount. If control is briefly unavailable the durable
    // provider-attempt fence lets the stale-reservation sweep capture later, so
    // the delivered image is still returned to the caller.
    try {
      await captureWithRetry(server.controlClient, { requestId, latencyMs: Date.now() - startedAt });
    } catch (captureError) {
      request.log.error(
        { request_id: requestId, error_type: captureError instanceof Error ? captureError.name : "control_rpc_error" },
        "image_settlement_pending"
      );
    }

    if (result.blurred !== undefined) reply.header("x-anonrouter-provider-blurred", String(result.blurred));
    if (result.contentViolation !== undefined) {
      reply.header("x-anonrouter-provider-content-violation", String(result.contentViolation));
    }
    // A provider content-violation arrives on a 200 with a header rather than as
    // an error, so the ledger would otherwise never see it. It is recorded as a
    // GENERIC non-billable provider rejection: the moderation verdict itself is
    // a statement about the caller's prompt and stays in the content plane. The
    // customer still sees the header above; only the control plane's copy of the
    // category is withheld.
    if (result.contentViolation === true) {
      await reportProviderNonBillableOutcome(server.controlClient, {
        requestId, attemptIndex: 0, automatic: false, startedAt,
        // Local semantics only. The helper maps any policy code to the generic
        // provider_rejected outcome and never transmits the code itself.
        providerCode: "content_violation"
      });
    }
    return {
      created: Math.floor(Date.now() / 1000),
      model: publicModelId,
      data: [{ b64_json: result.base64, mime_type: result.mimeType }]
    };
  });
}
