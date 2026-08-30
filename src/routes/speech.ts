import type { FastifyInstance, FastifyRequest } from "fastify";
import { abortOnClientDisconnect, isAbortError } from "../inference/disconnect.js";
import type { ControlClient, RedeemResult } from "../inference/rpc.js";
import type { InferenceRateLimitResult } from "../rate-limit/limiter.js";
import {
  qualifiedPublicModelId,
  speechRequestSchema,
  SPEECH_DEFAULT_RESPONSE_FORMAT,
  type SpeechRequestBody
} from "../providers/types.js";
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

async function redeemForSpeech(
  server: FastifyInstance,
  request: FastifyRequest,
  body: SpeechRequestBody,
  signal: AbortSignal
): Promise<RedeemResult> {
  const ingress = relayIngressContext(request);
  if (ingress?.speechRedemption) return ingress.speechRedemption;

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
    operation: "speech",
    speech: {
      inputChars: body.input.length,
      voice: body.voice ?? null,
      responseFormat: body.response_format
    }
  });
}

/**
 * Privacy-preserving text-to-speech over the split relay path, mirroring image
 * generation exactly. The relay holds the input text and an opaque ticket
 * redemption but no account identity, DB, or provider credential. It redeems the
 * single-use ticket, validates the body against the ticket-bound (and priced)
 * character count, voice, and format, has control reserve the exact
 * per-character price before dispatch, sends the text to the credential-isolated
 * worker, and settles that exact price exactly once. The input text and the
 * audio bytes never reach the control plane; neither is intentionally logged.
 */
export async function registerSpeechRoutes(server: FastifyInstance) {
  server.post("/v1/audio/speech", async (request, reply) => {
    // Server-side, independent enforcement of the split speech flag. The relay
    // fails closed with the same clear 503 the disabled stub returns.
    if (!server.config.internal.speechGenerationEnabled) {
      throw new AppError(503, "media_disabled", "Media generation is not enabled on this deployment");
    }
    const startedAt = Date.now();
    const requestId = request.id;
    const ingress = relayIngressContext(request);
    const signal = ingress?.signal ?? abortOnClientDisconnect(request, reply);
    const body = parseBody(speechRequestSchema, request.body) as SpeechRequestBody;

    const redeemed = await redeemForSpeech(server, request, body, signal);
    if ((redeemed.constraints.operation ?? "chat") !== "speech") {
      throw new AppError(409, "ticket_operation_mismatch", "Ticket is not valid for speech generation");
    }
    if (body.model !== redeemed.constraints.requestedModel) {
      throw new AppError(409, "ticket_model_mismatch", "Model does not match the issued ticket");
    }
    // The ticket bound the exact priced provider work. A body that drifts from
    // the issued character count, voice, or output format is rejected before any
    // reservation — the character count is the priced unit, so a drifting body
    // would otherwise be charged at the wrong length.
    if (redeemed.constraints.speechCharacterCount !== body.input.length) {
      throw new AppError(409, "ticket_input_length_mismatch", "Input length does not match the issued ticket");
    }
    if ((redeemed.constraints.speechVoice ?? null) !== (body.voice ?? null)) {
      throw new AppError(409, "ticket_voice_mismatch", "Voice does not match the issued ticket");
    }
    if ((redeemed.constraints.speechResponseFormat ?? SPEECH_DEFAULT_RESPONSE_FORMAT) !== body.response_format) {
      throw new AppError(409, "ticket_format_mismatch", "Response format does not match the issued ticket");
    }

    let result: Awaited<ReturnType<NonNullable<typeof server.workerClient.generateSpeech>>>;
    try {
      const authorization = await server.controlClient.authorize({
        redemption: redeemed.redemption,
        requestId,
        operation: "speech",
        modelPublicId: redeemed.constraints.publicModelId,
        automatic: false,
        stream: false,
        // Speech carries no token ceiling; control reserves the per-character
        // price for the character count the ticket bound.
        inputCeiling: 0
      }, signal);
      applyRateLimitHeaders(reply, authorization.rateLimits);
      const model = authorization.model;
      if (model.modelType !== "tts") {
        throw new AppError(400, "model_not_speech", "Model is not a speech model");
      }
      if (!server.workerClient.generateSpeech) {
        throw new AppError(503, "provider_unavailable", "Speech worker is unavailable");
      }
      reply.header("x-anonrouter-selected-model", qualifiedPublicModelId(model.providerName, model.publicModelId));
      reply.header("x-anonrouter-routing", "exact");
      result = await server.workerClient.generateSpeech({
        dispatchToken: authorization.dispatchToken,
        requestId,
        providerName: model.providerName,
        externalModelId: model.externalModelId,
        input: body.input,
        voice: body.voice,
        responseFormat: body.response_format
      }, signal);
    } catch (error) {
      // Content-free rejection-ledger record for a provider-origin failure
      // (no-op for a local admission error, which control records itself).
      await reportProviderRejection(server.controlClient, {
        requestId, attemptIndex: 0, automatic: false, error, signal, startedAt
      });
      // Pre-fence transport failure releases the reservation to zero; a failure
      // after the worker crossed its durable provider-attempt fence captures the
      // authorized price. Both are idempotent and content-free.
      await server.controlClient
        .abort({ requestId, status: usageStatusForError(error), latencyMs: Date.now() - startedAt })
        .catch(() => undefined);
      if (signal.aborted || isAbortError(error)) return reply;
      throw error;
    }

    // Generation succeeded: charge the exact authorized price exactly once.
    // capture charges the reserved ceiling (= the reviewed per-character price
    // for the bound length), never a usage-derived amount. If control is briefly
    // unavailable the durable provider-attempt fence lets the stale-reservation
    // sweep capture later, so the delivered audio is still returned.
    try {
      await captureWithRetry(server.controlClient, { requestId, latencyMs: Date.now() - startedAt });
    } catch (captureError) {
      request.log.error(
        { request_id: requestId, error_type: captureError instanceof Error ? captureError.name : "control_rpc_error" },
        "speech_settlement_pending"
      );
    }

    reply.header("content-type", result.mimeType);
    return reply.send(Buffer.from(result.audioBase64, "base64"));
  });
}
