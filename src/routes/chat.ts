import type { FastifyInstance, FastifyRequest } from "fastify";
import {
  estimateChoiceOutputTokens,
  estimateInputTokenCeiling,
  estimateInputTokens,
  estimateToolInputCeiling,
  normalizeUsage,
  type TokenUsage
} from "../metering/tokens.js";
import { assertE2EESupported, estimateE2EEInputCeiling } from "../metering/e2ee.js";
import { z } from "zod";
import {
  canonicalOutputTokenLimit,
  chatCompletionRequestSchema,
  countImageParts,
  qualifiedPublicModelId,
  type ChatCompletionRequestBody,
  type ModelRecord
} from "../providers/types.js";
import { applyRoutingPreferences } from "../routing/preferences.js";
import { isAutomaticModel, selectRoutingModel } from "../routing/selector.js";
import { normalizeProviderPolicy, providerPolicyDigest } from "../providers/routing/policy.js";
import { publicPrivacyTier } from "../providers/routing/presentation.js";
import {
  attestationNoteFor,
  attestationView,
  buildAttestationExpectations,
  e2eeProtocolFor,
  endpointIdentityFor
} from "../providers/attestation/index.js";
import { AppError, ProviderError } from "../security/errors.js";
import { rawStreamCorsHeaders } from "../httpBase.js";
import type {
  AuthorizeRpcResult,
  ControlClient,
  ProviderAttemptOutcome,
  ProviderRoutingMetadata,
  RedeemResult,
  RelayModel,
  SettleRpcRequest,
  SettleRpcResponse
} from "../inference/rpc.js";
import type { InferenceRateLimitResult } from "../rate-limit/limiter.js";
import type { UsageStatus } from "../metering/usage.js";
import { parseBody } from "./helpers.js";
import { abortOnClientDisconnect, isAbortError } from "../inference/disconnect.js";
import { finalizeThenWriteDone, writeWithBackpressure } from "../inference/backpressure.js";
import {
  providerReasoningFields,
  reasoningSelectionKey,
  resolveReasoningSelection,
  NO_REASONING_CAPABILITIES,
  type ModelReasoningCapabilities,
  type ReasoningSelection
} from "../inference/reasoning.js";
import { relayIngressContext } from "../relay/ingress.js";
import { hasOutputBearingOpenAiDelta } from "../inference/streamTiming.js";
import { isTerminalProviderCode } from "../inference/rejectionTaxonomy.js";
import { reportProviderRejection } from "../inference/rejectionReporting.js";
import { newOpaqueReceiptId } from "../inference/contentReceipts.js";

const TICKET_HEADER = "x-anonrouter-ticket";
// The opaque settlement receipt id, returned to the caller so it can fetch the
// exact-wire binding from the content plane. The binding itself never leaves
// this trust domain; this id is the only handle to it that does.
const RECEIPT_HEADER = "x-anonrouter-receipt";
const ANONROUTER_E2EE_PROVIDER_HEADER = "x-anonrouter-e2ee-provider";
const NEAR_CLIENT_KEY_HEADER = "x-client-pub-key";
const NEAR_MODEL_KEY_HEADER = "x-model-pub-key";
const NEAR_SIGNING_ALGO_HEADER = "x-signing-algo";
const NEAR_ENCRYPTION_VERSION_HEADER = "x-encryption-version";
// Backward-compatible Venice client vocabulary. These are accepted only for a
// Venice-bound ticket and translated to the provider's existing header names.
const VENICE_CLIENT_KEY_HEADER = "x-venice-tee-client-pub-key";
const VENICE_MODEL_KEY_HEADER = "x-venice-tee-model-pub-key";
const VENICE_SIGNING_ALGO_HEADER = "x-venice-tee-signing-algo";
// Uncapped sentinel: the control plane caps the E2EE ceiling at the model's real
// context window (the relay has no catalog).
const RELAY_CONTEXT_CEILING = 100_000_000;

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

interface E2eeHeaderSelection {
  providerName: "near-ai" | "venice";
  upstreamHeaders: Record<string, string>;
}

function hasAnyHeader(request: FastifyRequest, names: readonly string[]): boolean {
  return names.some((name) => headerValue(request.headers[name]) !== undefined);
}

/**
 * Select one documented E2EE protocol without reading ciphertext. All values
 * are validated at the public edge and rewritten to a fixed provider header
 * map; arbitrary client headers can never cross the worker boundary.
 */
export function extractE2eeHeaders(request: FastifyRequest): E2eeHeaderSelection | null {
  const explicitProvider = headerValue(request.headers[ANONROUTER_E2EE_PROVIDER_HEADER]);
  if (explicitProvider !== undefined && explicitProvider !== "near-ai" && explicitProvider !== "venice") {
    throw new AppError(400, "e2ee_provider_unsupported", "The selected E2EE provider is not supported");
  }

  const nearNames = [NEAR_CLIENT_KEY_HEADER, NEAR_MODEL_KEY_HEADER, NEAR_SIGNING_ALGO_HEADER, NEAR_ENCRYPTION_VERSION_HEADER] as const;
  const veniceNames = [VENICE_CLIENT_KEY_HEADER, VENICE_MODEL_KEY_HEADER, VENICE_SIGNING_ALGO_HEADER] as const;
  const hasNear = hasAnyHeader(request, nearNames);
  const hasVenice = hasAnyHeader(request, veniceNames);
  if (!explicitProvider && !hasNear && !hasVenice) return null;
  if (hasNear && hasVenice) {
    throw new AppError(400, "e2ee_header_conflict", "Headers from multiple E2EE protocols cannot be combined");
  }

  const providerName = explicitProvider ?? (hasNear ? "near-ai" : "venice");
  if (providerName === "near-ai") {
    if (hasVenice) throw new AppError(400, "e2ee_header_conflict", "Venice E2EE headers do not match the selected provider");
    const client = headerValue(request.headers[NEAR_CLIENT_KEY_HEADER]);
    const model = headerValue(request.headers[NEAR_MODEL_KEY_HEADER]);
    const algo = headerValue(request.headers[NEAR_SIGNING_ALGO_HEADER]);
    const version = headerValue(request.headers[NEAR_ENCRYPTION_VERSION_HEADER]);
    if (!client || !algo || !version) {
      throw new AppError(400, "e2ee_headers_incomplete", "NEAR direct E2EE requires client key, signing algorithm, and encryption version");
    }
    if (model !== undefined) {
      throw new AppError(400, "e2ee_model_key_not_accepted", "NEAR direct E2EE derives the model key from attestation; X-Model-Pub-Key is gateway-only");
    }
    if (!/^[0-9a-f]{64}$/i.test(client)) {
      throw new AppError(400, "e2ee_invalid_key", "The NEAR client public key must be a 32-byte hex Ed25519 key");
    }
    if (algo !== "ed25519" || version !== "2") {
      throw new AppError(400, "e2ee_protocol_unsupported", "NEAR E2EE requires ed25519 encryption version 2");
    }
    return {
      providerName,
      upstreamHeaders: {
        "X-Signing-Algo": algo,
        "X-Client-Pub-Key": client,
        "X-Encryption-Version": version
      }
    };
  }

  if (hasNear) throw new AppError(400, "e2ee_header_conflict", "NEAR E2EE headers do not match the selected provider");
  const client = headerValue(request.headers[VENICE_CLIENT_KEY_HEADER]);
  const model = headerValue(request.headers[VENICE_MODEL_KEY_HEADER]);
  if (!client || !model) {
    throw new AppError(400, "e2ee_headers_incomplete", "Venice E2EE requires client and model public keys");
  }
  const algo = headerValue(request.headers[VENICE_SIGNING_ALGO_HEADER]) ?? "ecdsa";
  return {
    providerName,
    upstreamHeaders: {
      "X-Venice-TEE-Client-Pub-Key": client,
      "X-Venice-TEE-Model-Pub-Key": model,
      "X-Venice-TEE-Signing-Algo": algo
    }
  };
}

function applyRateLimitHeaders(reply: { header(name: string, value: string): unknown }, limits: InferenceRateLimitResult) {
  reply.header("x-ratelimit-limit-requests", String(limits.requests.limit));
  reply.header("x-ratelimit-remaining-requests", String(limits.requests.remaining));
  reply.header("x-ratelimit-reset-requests", String(Math.ceil(limits.requests.resetMs / 1000)));
  reply.header("x-ratelimit-limit-tokens", String(limits.tokens.limit));
  reply.header("x-ratelimit-remaining-tokens", String(limits.tokens.remaining));
  reply.header("x-ratelimit-reset-tokens", String(Math.ceil(limits.tokens.resetMs / 1000)));
}

function estimateResponseOutputTokens(response: unknown) {
  if (!response || typeof response !== "object") return 0;
  const choices = (response as { choices?: Array<{ message?: { content?: unknown } }> }).choices;
  if (!Array.isArray(choices)) return 0;
  return choices.reduce((total, choice) => total + estimateChoiceOutputTokens(choice.message), 0);
}

/**
 * Normalize provider extensions at the public OpenAI boundary.
 *
 * Venice currently returns `name: null` on assistant tool-call messages. The
 * official JS SDK preserves that field when callers append the returned
 * message to the next request, while OpenAI's request shape allows `name` only
 * as a string. Passing the provider response through verbatim therefore makes
 * a normal JS tool loop fail our own request validation on its second turn.
 *
 * Tool-only assistant messages are also canonicalized to `content: null` when
 * the provider uses an empty string. That is the OpenAI response shape coding
 * agents expect and is already what our mock provider emits. Non-null provider
 * extensions, including reasoning_content, remain untouched.
 */
/**
 * Correct a streamed `finish_reason` when the stream carried tool calls.
 *
 * The OpenAI schema says a turn that produces tool calls finishes with
 * "tool_calls". Venice, and DeepInfra's mistral-nemo, stream a correct
 * tool_calls delta and then close with "stop". A coding agent that branches on
 * finish_reason — which the spec entitles it to do — sees an ordinary
 * completion, never executes the tool, and stalls mid-task. Nothing errors: the
 * status is 200, the SSE is well formed, and no log records a problem.
 *
 * This is a string rewrite on the frame, matching how the relay already rewrites
 * the model id inline, so it does not introduce frame rewriting to a path that
 * was otherwise byte-verbatim.
 *
 * DELIBERATELY NARROW. It fires only when a tool-call delta was actually seen
 * earlier in the same stream, and only on "stop". A "length" finish is left
 * alone: a truncated tool call is a real truncation and an agent needs to know
 * that rather than be told the call completed.
 */
export function correctStreamedFinishReason(chunk: string, toolCallsSeen: boolean): string {
  if (!toolCallsSeen) return chunk;
  if (!chunk.includes('"finish_reason":"stop"')) return chunk;
  return chunk.split('"finish_reason":"stop"').join('"finish_reason":"tool_calls"');
}

/** True when an SSE frame carries a tool-call delta. */
export function frameHasToolCallDelta(chunk: string): boolean {
  return chunk.includes('"tool_calls"');
}

export function publicModelResponse(response: unknown, requestedModel: string) {
  if (!response || typeof response !== "object" || Array.isArray(response)) return response;

  const record = response as Record<string, unknown>;
  const choices = Array.isArray(record.choices)
    ? record.choices.map((choice) => {
        if (!choice || typeof choice !== "object" || Array.isArray(choice)) return choice;
        const choiceRecord = choice as Record<string, unknown>;
        if (!choiceRecord.message || typeof choiceRecord.message !== "object" || Array.isArray(choiceRecord.message)) {
          return choice;
        }

        const message = { ...(choiceRecord.message as Record<string, unknown>) };
        if (message.name === null) delete message.name;
        if (message.reasoning_content === null) delete message.reasoning_content;
        const hasToolCalls = Array.isArray(message.tool_calls) && message.tool_calls.length > 0;
        if (message.content === "" && hasToolCalls) {
          message.content = null;
        }
        // SPEC CORRECTION, and it is not cosmetic.
        //
        // When a model returns tool calls the OpenAI schema requires
        // finish_reason "tool_calls". Venice and DeepInfra's mistral-nemo both
        // return "stop" while supplying a correct tool_calls array, measured on
        // the live deployment. A client that reads message.tool_calls copes; a
        // coding agent that branches on finish_reason — which the spec says it
        // may — sees an ordinary completion, never executes the tool, and stalls
        // mid-task with no error anywhere.
        //
        // Only ever tightened toward the spec, and only when tool calls are
        // actually present, so a genuine "stop" or "length" is untouched.
        if (hasToolCalls && choiceRecord.finish_reason !== "tool_calls") {
          return { ...choiceRecord, message, finish_reason: "tool_calls" };
        }
        return { ...choiceRecord, message };
      })
    : record.choices;

  return { ...record, ...(choices === undefined ? {} : { choices }), model: requestedModel };
}

/**
 * Surface the AnonRouter-charged cost inline as usage.cost (USD), mirroring
 * OpenRouter. Metadata only: no content is inspected. Returns the response
 * unchanged when it carries no usage object.
 */
export function withUsageCost(response: unknown, chargedUsd: number): unknown {
  if (!response || typeof response !== "object" || Array.isArray(response)) return response;
  const record = response as Record<string, unknown>;
  const usage = record.usage;
  if (!usage || typeof usage !== "object") return response;
  return { ...record, usage: { ...(usage as Record<string, unknown>), cost: chargedUsd } };
}

/**
 * Classify a pre-output provider failure into a sanitized fallback outcome, or
 * null when the failure is NOT eligible for a transparent fallback (client
 * cancellation, or an ambiguous error we treat conservatively). Never inspects
 * provider response bodies.
 */
function providerFallbackOutcome(error: unknown): ProviderAttemptOutcome | null {
  if (error instanceof ProviderError) {
    // An explicit provider policy/moderation rejection is TERMINAL: it must not
    // transparently retry through another provider. (No text provider surfaces
    // such a code today; this guards the moment one is added to the allowlist.)
    if (isTerminalProviderCode(error.providerCode)) return null;
    const status = error.providerStatusCode;
    if (status === 429) return "rate_limited";
    if (error.code === "provider_unavailable") return "provider_unavailable";
    if (error.code === "provider_timeout") return "network_error";
    if (error.code === "provider_invalid_json" || error.code === "provider_no_stream") return "invalid_response";
    if (typeof status === "number" && status >= 400) return "provider_rejected";
    return null;
  }
  if (error instanceof AppError && error.code === "provider_unavailable") return "provider_unavailable";
  // A transport failure before any output is eligible; the delivery/attempt
  // fences below still govern conservative billing on the last attempt.
  if (error instanceof TypeError && (error.message === "fetch failed" || error.message === "terminated")) {
    return "network_error";
  }
  if (error instanceof DOMException && (error.name === "NetworkError" || error.name === "TimeoutError")) {
    return "network_error";
  }
  return null;
}

/** Content-free transparency headers describing the route that actually served. */
function providerTransparencyHeaders(
  servingModel: RelayModel,
  automatic: boolean,
  attempts: number,
  fellBack: boolean,
  routing?: ProviderRoutingMetadata
): Record<string, string> {
  const privacyClass = servingModel.privacyClass ?? routing?.effectivePrivacyClass ?? "";
  return {
    "x-anonrouter-provider": servingModel.providerName,
    "x-anonrouter-routing": automatic ? "auto" : "exact",
    "x-anonrouter-provider-attempts": String(attempts),
    "x-anonrouter-provider-fallback": fellBack ? "true" : "false",
    ...(privacyClass ? { "x-anonrouter-privacy-class": publicPrivacyTier(privacyClass) } : {})
  };
}

function usageStatusForError(error: unknown): "failed" | "rate_limited" | "insufficient_balance" {
  if (error instanceof AppError && error.statusCode === 402) return "insufficient_balance";
  if (error instanceof AppError && (error.code === "rate_limited" || error.code === "concurrency_limited")) {
    return "rate_limited";
  }
  return "failed";
}

/**
 * Build the upstream provider body. The canonical reasoning fields
 * (`reasoning`, `reasoning_effort`, legacy `disable_thinking`) are consumed by
 * the resolution/validation layer and replaced with the exact translated
 * provider fields; presentation-only `strip_thinking_response` passes through.
 */
/** Venice rejects `strict: null` inside a function definition with a 400 (the
 *  Vercel AI SDK emits `strict: null` for "unset"). Null is semantically
 *  absent, so the key is dropped before the body reaches the provider. */
export function normalizedProviderTools(tools: ChatCompletionRequestBody["tools"]) {
  if (!Array.isArray(tools)) return tools;
  return tools.map((tool) => {
    if (tool.function.strict === null) {
      const { strict: _unsetStrict, ...fn } = tool.function;
      return { ...tool, function: fn };
    }
    return tool;
  });
}

function providerBody(
  body: ChatCompletionRequestBody,
  selectedModel: string,
  reasoning: ReasoningSelection,
  capabilities: ModelReasoningCapabilities
): Record<string, unknown> {
  const { provider: _provider, routing: _routing, reasoning: _reasoning, reasoning_effort: _effort, venice_parameters, ...rest } = body;
  const { disable_thinking: _legacyDisable, ...passthroughVeniceParameters } = venice_parameters ?? {};
  return {
    ...rest,
    ...(rest.tools ? { tools: normalizedProviderTools(rest.tools) } : {}),
    ...(venice_parameters ? { venice_parameters: passthroughVeniceParameters } : {}),
    ...providerReasoningFields(reasoning, capabilities),
    model: selectedModel
  };
}

async function withRoutingTimeout<T>(promise: Promise<T>, timeoutMs: number) {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new AppError(503, "router_timeout", "Automatic routing timed out")), timeoutMs);
      })
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

/**
 * The auto-routing candidate pool, read from the control plane's content-free
 * catalog RPC and cached on the server instance. Selection runs here, so the
 * catalog has to be here too.
 */
async function routingCandidates(server: FastifyInstance, signal: AbortSignal): Promise<ModelRecord[]> {
  const cache = server.routingCatalog;
  if (!cache) throw new AppError(503, "router_unavailable", "Automatic routing is not enabled");
  try {
    return await withRoutingTimeout(cache.candidates(signal), server.config.routing.timeoutMs);
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(503, "router_unavailable", "Automatic routing is unavailable");
  }
}

/**
 * Refuse a route that cannot serve what this request actually contains.
 *
 * The control plane used to make this call, from the `requiresTools` and
 * `requiresVision` booleans the relay sent it. Those are derived from request
 * content and no longer cross, so the check moved here, to the process that can
 * see the tools array and the image parts directly. The error codes are the ones
 * the control plane used to raise, so a caller cannot tell the check moved.
 *
 * Returns null when the route is acceptable.
 */
function capabilityRefusal(
  model: RelayModel,
  needs: { tools: boolean; vision: boolean }
): AppError | null {
  if (needs.tools && model.supportsTools === false) {
    return new AppError(400, "tools_not_supported", "The selected model does not support tool calling");
  }
  if (needs.vision && model.supportsVision === false) {
    return new AppError(400, "model_not_vision", "The selected model does not support image input");
  }
  return null;
}

async function settleWithRetry(
  controlClient: ControlClient,
  request: SettleRpcRequest,
  attempts = 2
): Promise<SettleRpcResponse> {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await controlClient.settle(request);
    } catch (error) {
      lastError = error;
      if (attempt + 1 < attempts) {
        await new Promise((resolve) => setTimeout(resolve, 50 * (attempt + 1)));
      }
    }
  }
  throw lastError;
}

/**
 * The relay. It holds request content and an opaque ticket redemption, but no DB,
 * Redis, auth, payment, or Venice credential. Account-scoped decisions go to the
 * control plane over RPC (ceilings + classifier metadata only, never content);
 * inference goes to the venice worker over RPC. The relay never learns the
 * account behind a ticket, redemption, or request id.
 */
const attestationSchema = z
  .object({
    // A single-use, model-bound attestation ticket issued by the control plane.
    // Split production presents this in x-anonrouter-ticket so it can be
    // redeemed before body parsing. The body field remains dev-monolith
    // compatible until the experimental E2EE client surface is finalized.
    ticket: z.string().min(1).max(256).optional(),
    // Client nonce: exactly 32 bytes as 64 hex characters.
    nonce: z.string().regex(/^[0-9a-fA-F]{64}$/)
  })
  .strict();

export async function registerChatRoutes(server: FastifyInstance) {
  const allowInline = server.config.internal.allowInlineTicket;

  // Attestation relay for every attestable route, TEE and E2EE alike.
  //
  // The client first obtains a route-bound, single-use attestation ticket from
  // control, then presents it here with a fresh 32-byte nonce. The relay redeems
  // the ticket (single-use, replay-safe), the credential-isolated worker fetches
  // the enclave evidence, and the relay returns it for the client to verify
  // INDEPENDENTLY. The relay holds no provider credential, never inspects the
  // evidence, and attests only the exact route the ticket is bound to.
  //
  // NO STABLE CREDENTIAL REACHES THIS ROUTE. It authenticates the opaque ticket
  // and nothing else: the browser sends it with `credentials: "omit"`, and the
  // CVM edge strips Authorization and Cookie before the relay sees the request.
  // That is the whole reason attestation moved here from the credentialed GET on
  // control — control cannot serve it, because control deliberately has no
  // provider credential and no route to a provider worker.
  server.post("/v1/tee/attestation", async (request, reply) => {
    const ingress = relayIngressContext(request);
    const signal = ingress?.signal ?? abortOnClientDisconnect(request, reply);
    const body = parseBody(attestationSchema, request.body);
    const headerTicket = headerValue(request.headers[TICKET_HEADER]);
    if (headerTicket && body.ticket && headerTicket !== body.ticket) {
      throw new AppError(400, "conflicting_ticket", "Ticket header and body do not match");
    }
    const redeemed = ingress?.attestationRedemption
      ?? (headerTicket || body.ticket
        ? await server.controlClient.redeemAttestation(headerTicket ?? body.ticket!, signal)
        : null);
    if (!redeemed) throw new AppError(401, "invalid_attestation_ticket", "Attestation ticket is invalid, expired, or already used");
    signal.throwIfAborted();
    // Bound at mint time by control, which is the only party with a catalog.
    // Never inferred here, and never defaulted to the stronger claim.
    const privacyModality: "tee" | "e2ee" = redeemed.privacyClass === "tee" ? "tee" : "e2ee";
    const evidence = await server.workerClient.attestation({
      providerName: redeemed.providerName,
      externalModelId: redeemed.externalModelId,
      dispatchToken: redeemed.dispatchToken,
      nonce: body.nonce,
      privacyModality
    }, signal);

    // Enrich the response BACKWARD-COMPATIBLY: keep `evidence` (existing callers
    // read only that) and add sanitized route-bound metadata.
    //
    // WHAT THE CLIENT DOES WITH IT DEPENDS ON THE CLIENT, and this route must not
    // assume the stronger case. The browser-encrypted chat path re-checks the raw
    // evidence itself before encrypting and never trusts this verdict alone. The
    // read-only attestation panel renders this verdict and offers the evidence
    // for OFFLINE checking; it verifies nothing in the browser. Both get the same
    // response, and neither is privileged by it. The relay has no database,
    // so it runs only the PURE verifier with the in-code pinned measurement/
    // endpoint policy (never a DB read); the raw evidence is still returned
    // verbatim for the browser's own binding checks.
    const provider = redeemed.providerName;
    const upstreamModel = redeemed.externalModelId;
    // The E2EE wire protocol is only meaningful for a client-opaque request. A
    // TEE ticket must not advertise one: a client reading `protocol` as
    // "encrypt to this" would build a request this route never authorized.
    const protocol = privacyModality === "e2ee" ? e2eeProtocolFor(provider) : null;
    const verifier = server.verifierRegistry?.forProvider(provider);
    let attestation: ReturnType<typeof attestationView> | undefined;
    if (verifier) {
      const now = Date.now();
      const endpointIdentity = endpointIdentityFor(server.config, provider, upstreamModel);
      const expectations = buildAttestationExpectations({
        provider,
        upstreamModel,
        canonicalModel: redeemed.canonicalModelId,
        routeId: redeemed.routeId,
        endpointIdentity,
        nonce: body.nonce,
        privacyModality,
        now
      });
      attestation = attestationView(
        verifier.verifyAttestation({ fetchedAtMs: now, endpointIdentity, payload: evidence }, expectations)
      );
    }
    return {
      evidence,
      provider,
      upstream_model: upstreamModel,
      // Route identity and the honest caveat, so a read-only verification panel
      // renders the same thing here as it did on the control GET. All of it is
      // catalog fact bound into the ticket at mint time; none of it is derived
      // from a database this process does not have, and none of it names an
      // account. `model` and `route_id` are omitted rather than invented when an
      // older ticket did not carry them.
      ...(redeemed.canonicalModelId ? { model: redeemed.canonicalModelId } : {}),
      ...(redeemed.routeId ? { route_id: redeemed.routeId } : {}),
      privacy_class: privacyModality,
      note: attestationNoteFor(privacyModality),
      ...(protocol ? { protocol } : {}),
      ...(attestation ? { attestation } : {})
    };
  });

  server.post("/v1/chat/completions", async (request, reply) => {
    const startedAt = Date.now();
    const requestId = request.id;
    const ingress = relayIngressContext(request);
    const signal = ingress?.signal ?? abortOnClientDisconnect(request, reply);
    let body = parseBody(chatCompletionRequestSchema, request.body) as ChatCompletionRequestBody;

    // Cross-model fallback (`models`) is orchestrated by re-minting a ticket per
    // model, which only the compatibility broker (or a future native-ticket
    // binding) can do. The single-ticket relay path cannot honor it, so reject it
    // here rather than silently serve only the primary model.
    if (Array.isArray(body.models) && body.models.length > 0) {
      throw new AppError(
        400,
        "models_fallback_unsupported_here",
        "The models fallback array is supported only via the OpenAI-compatibility endpoint"
      );
    }

    const e2eeSelection = extractE2eeHeaders(request);
    const isE2EE = e2eeSelection !== null;
    // Content-free capability signal: whether any message carries an image part.
    // The image bytes/URLs themselves never leave the relay's request path.
    const requiresVision = body.messages.some((message) => countImageParts(message.content) > 0);
    const requestedAutomatic = isAutomaticModel(body.model);
    if (isE2EE && requestedAutomatic) {
      throw new AppError(400, "e2ee_requires_explicit_model", "E2EE requests must name an explicit E2EE model");
    }

    // Canonical reasoning selection for this body (400 on conflicting flat /
    // nested / legacy signals). Capability validation happens at the control
    // plane; the relay only needs the digest for the ticket-binding check.
    const reasoningSelection = resolveReasoningSelection(body);
    const reasoningKey = reasoningSelectionKey(reasoningSelection);

    const requestedMaxOutputTokens = canonicalOutputTokenLimit(body);

    // Obtain a ticket redemption. Production relay requests MUST present a ticket
    // (fail closed). The inline identity path is a weaker dev-only mode.
    let redeemed: RedeemResult;
    const ticketId = headerValue(request.headers[TICKET_HEADER]);
    if (ingress?.chatRedemption) {
      redeemed = ingress.chatRedemption;
    } else if (ticketId) {
      const result = await server.controlClient.redeem(ticketId, signal);
      if (!result) throw new AppError(401, "invalid_ticket", "Inference ticket is invalid or expired");
      redeemed = result;
    } else if (allowInline && request.server.inlineTicketIssuer) {
      // Dev-only. The capability is registered by the monolith and is ABSENT on
      // the relay, so this branch cannot execute on the content tier even if
      // the flag were somehow set. See src/inference/inlineTicket.ts.
      redeemed = await request.server.inlineTicketIssuer(request, {
        requestedModel: body.model,
        providerPolicy: body.provider,
        maxOutputTokens: requestedMaxOutputTokens ?? null,
        automatic: requestedAutomatic,
        operation: "chat",
        reasoning: reasoningSelection,
        // Inline (dev) path: the relay already knows the E2EE modality from the
        // TEE headers, so bind it directly.
        e2ee: isE2EE
      });
    } else {
      throw new AppError(401, "ticket_required", "An inference ticket is required");
    }
    if ((redeemed.constraints.operation ?? "chat") !== "chat") {
      throw new AppError(409, "ticket_operation_mismatch", "Ticket is not valid for chat");
    }
    const testMockProtocol = server.config.env === "test" && redeemed.constraints.providerName === "mock";
    if (e2eeSelection && e2eeSelection.providerName !== redeemed.constraints.providerName && !testMockProtocol) {
      throw new AppError(409, "ticket_e2ee_provider_mismatch", "E2EE provider does not match the issued ticket");
    }
    if (!redeemed.constraints.automatic && body.model !== redeemed.constraints.requestedModel) {
      throw new AppError(409, "ticket_model_mismatch", "Model does not match the issued ticket");
    }
    // The provider routing policy is part of what the ticket authorized. A body
    // that changes the policy after issuance is rejected before any provider work.
    // (invalid_provider_policy / provider_policy_conflict surface here on a bad body.)
    const providerPolicyKey = providerPolicyDigest(normalizeProviderPolicy(body.provider));
    if (redeemed.constraints.providerPolicyKey && providerPolicyKey !== redeemed.constraints.providerPolicyKey) {
      throw new AppError(409, "ticket_provider_policy_mismatch", "Provider policy does not match the issued ticket");
    }
    // The reasoning configuration is part of what the ticket authorized. A body
    // that drifts from the issued digest — in either direction, off-to-max or
    // max-to-off — is rejected before any reservation or provider work.
    if (reasoningKey !== (redeemed.constraints.reasoningKey ?? "default")) {
      throw new AppError(409, "ticket_reasoning_mismatch", "Reasoning configuration does not match the issued ticket");
    }

    // Trial-funded tickets authorize a text-only surface: no tool calling and
    // no image content. The control plane cannot see content, so the relay is
    // the enforcement point, failing closed before any reservation.
    if (redeemed.constraints.trial) {
      if (body.tools !== undefined || body.tool_choice !== undefined || body.parallel_tool_calls !== undefined) {
        throw new AppError(400, "trial_tools_unsupported", "Trial chat does not support tool calling");
      }
      if (requiresVision) {
        throw new AppError(400, "trial_text_only", "Trial chat supports text messages only");
      }
    }

    const automatic = redeemed.constraints.automatic;
    if (
      requestedMaxOutputTokens !== undefined
      && (redeemed.constraints.maxOutputTokens === null
        || requestedMaxOutputTokens > redeemed.constraints.maxOutputTokens)
    ) {
      throw new AppError(409, "ticket_output_limit_mismatch", "Requested output-token limit exceeds the issued ticket");
    }

    // Measure the input ceiling from content the relay holds. For E2EE the ceiling
    // comes from ciphertext length; the control plane caps it at the real context.
    let inputCeiling: number;
    if (isE2EE) {
      // Tool calling is not part of the E2EE launch surface. Fail closed FIRST
      // (before any model check) rather than forward tools the client believes
      // are private-sealed. Do not silently claim tool support for E2EE.
      if (body.tools !== undefined || body.tool_choice !== undefined || body.parallel_tool_calls !== undefined) {
        throw new AppError(400, "e2ee_tools_unsupported", "E2EE requests do not support tool calling");
      }
      // Vision is not part of the E2EE launch surface either: image parts are
      // plaintext content, so fail closed before any model check rather than
      // forward images the client believes are private-sealed.
      if (requiresVision) {
        throw new AppError(400, "e2ee_vision_unsupported", "E2EE requests do not support image content");
      }
      if (redeemed.constraints.privacyClass !== "e2ee") {
        throw new AppError(400, "model_not_e2ee", "TEE headers were sent for a model that is not E2EE-capable");
      }
      if (requestedMaxOutputTokens === undefined) {
        throw new AppError(400, "e2ee_requires_max_tokens", "E2EE requests require an explicit output-token limit");
      }
      assertE2EESupported({
        messages: body.messages,
        stream: Boolean(body.stream),
        maxOutputTokens: requestedMaxOutputTokens,
        protocol: e2eeSelection?.providerName === "near-ai" ? "near-v2" : "venice-legacy"
      });
      inputCeiling = estimateE2EEInputCeiling(
        body.messages,
        RELAY_CONTEXT_CEILING,
        e2eeSelection?.providerName === "near-ai" ? "near-v2" : "venice-legacy"
      );
    } else {
      // A tool-bearing request adds the serialized tool definitions + tool_choice
      // to the conservative admission ceiling.
      inputCeiling = estimateInputTokenCeiling(body.messages) + estimateToolInputCeiling(body.tools, body.tool_choice);
    }

    // Automatic routing runs END TO END in the content plane: classify the
    // prompt here, and pick the model here too. The classifier output used to be
    // sent to the control plane, which did the selecting; CONTROL_RPC_CONTRACT.md
    // removes it, because "this is a coding request" and "this looked sensitive"
    // are statements about the prompt. Neither the classification nor the
    // capability requirements it is combined with leave this process — only the
    // resolved model id does, and the control plane re-validates that against
    // its own catalog, policy and privacy gates.
    const requiresTools = Array.isArray(body.tools) && body.tools.length > 0;
    let selectedAutomaticModel: string | undefined;
    if (automatic) {
      body = applyRoutingPreferences(body, redeemed.constraints.routingPreferences);
      if (!server.requestClassifier) throw new AppError(503, "router_unavailable", "Automatic routing is not enabled");
      let classification;
      try {
        classification = await withRoutingTimeout(server.requestClassifier.classify(body.messages), server.config.routing.timeoutMs);
      } catch (error) {
        if (error instanceof AppError) throw error;
        throw new AppError(503, "router_unavailable", "Automatic routing is unavailable");
      }
      const decision = selectRoutingModel({
        models: await routingCandidates(server, signal),
        // The ticket's requested model may be a wildcard pattern; the selector
        // consumes it through the same routing allow/exclude path the control
        // plane used, so the candidate pool is constrained identically.
        body: { ...body, model: redeemed.constraints.requestedModel },
        classification,
        inputTokens: inputCeiling,
        ...(requestedMaxOutputTokens === undefined ? {} : { requestedMaxOutputTokens }),
        requiresTools,
        requiresVision
      });
      selectedAutomaticModel = decision.model.canonicalModelId ?? decision.model.publicModelId;
    }

    signal.throwIfAborted();
    let authorization: AuthorizeRpcResult;
    try {
      authorization = await server.controlClient.authorize({
        redemption: redeemed.redemption,
        requestId,
        operation: "chat",
        // For automatic routing this is the model THIS process selected, not the
        // ticket's wildcard: selection happens here now. The control plane
        // re-validates it against the enabled catalog, the effective provider
        // policy, auto-routability and the privacy-tier gate.
        modelPublicId: automatic ? selectedAutomaticModel! : redeemed.constraints.publicModelId,
        automatic,
        stream: Boolean(body.stream),
        routing: body.routing,
        inputCeiling,
        ...(requestedMaxOutputTokens === undefined ? {} : { requestedMaxOutputTokens }),
        reasoningKey,
        providerPolicyKey,
        // The E2EE modality is derived from the TEE headers, cross-checked against
        // the ticket, and used to partition provider routes.
        e2ee: isE2EE
      }, signal);
    } catch (error) {
      // Do not pass the already-aborted downstream signal to compensation. The
      // abort RPC writes a cancellation tombstone even when authorize has not
      // created its reservation yet, closing the abort-before-create race.
      await server.controlClient
        .abort({ requestId, status: usageStatusForError(error), latencyMs: Date.now() - startedAt })
        .catch(() => undefined);
      if (signal.aborted || isAbortError(error)) return reply;
      throw error;
    }
    if (signal.aborted) {
      await server.controlClient.abort({ requestId, status: "failed", latencyMs: Date.now() - startedAt }).catch(() => undefined);
      signal.throwIfAborted();
    }
    applyRateLimitHeaders(reply, authorization.rateLimits);
    const model = authorization.model;
    const outputCeiling = authorization.effectiveMaxOutputTokens;
    body = { ...body, max_tokens: outputCeiling, max_completion_tokens: outputCeiling };

    if (model.modelType !== "text") {
      await server.controlClient.abort({ requestId, status: "failed", latencyMs: Date.now() - startedAt }).catch(() => undefined);
      throw new AppError(400, "model_not_chat", "Model is not a chat model; use its generation endpoint instead");
    }
    if (body.stream && !model.supportsStreaming) {
      await server.controlClient.abort({ requestId, status: "failed", latencyMs: Date.now() - startedAt }).catch(() => undefined);
      throw new AppError(400, "streaming_not_supported", "Model does not support streaming");
    }
    const capabilityNeeds = { tools: requiresTools, vision: requiresVision };
    const primaryRefusal = capabilityRefusal(model, capabilityNeeds);
    if (primaryRefusal) {
      // Zero charge: nothing was dispatched, so the reservation is released in
      // full, exactly as for the streaming/chat-model refusals above.
      await server.controlClient.abort({ requestId, status: "failed", latencyMs: Date.now() - startedAt }).catch(() => undefined);
      throw primaryRefusal;
    }

    // Transparent bounded fallback: the reservation already covers the plan's
    // worst-case attempt, so a pre-output provider failure can advance to the next
    // attempt. E2EE is provider-bound and never transparently switches. Fallback
    // is only ever attempted BEFORE any output is committed (non-stream: before
    // the JSON is returned; stream: before the SSE headers are written).
    let servingModel: RelayModel = authorization.model;
    let servingToken = authorization.dispatchToken;
    let servingCeiling = outputCeiling;
    let servingRouting = authorization.routing;
    let attempts = 1;
    let fellBack = false;
    const fallbackEnabled =
      !isE2EE
      && Boolean(authorization.routing?.fallbackAvailable)
      && typeof server.controlClient.authorizeNextProviderAttempt === "function";
    const buildWorkerRequest = (m: RelayModel, token: string, ceiling: number) => ({
      dispatchToken: token,
      requestId,
      providerName: m.providerName,
      externalModelId: m.externalModelId,
      reasoningKey,
      body: providerBody(
        { ...body, max_tokens: ceiling, max_completion_tokens: ceiling },
        m.publicModelId,
        reasoningSelection,
        m.reasoningCapabilities ?? NO_REASONING_CAPABILITIES
      ),
      ...(isE2EE && e2eeSelection ? { e2eeHeaders: e2eeSelection.upstreamHeaders } : {})
    });
    // Request the next attempt's dispatch capability. Returns false when the
    // caller should surface the original error; throws a stable routing error
    // when the plan is exhausted after a fallback, or when E2EE forbids one.
    const advanceToNextAttempt = async (error: unknown): Promise<boolean> => {
      if (signal.aborted || isAbortError(error)) return false;
      // Client cancellation is handled above; anything not classifiable as a
      // pre-output provider failure surfaces unchanged.
      const outcome = providerFallbackOutcome(error);
      if (!outcome) return false;
      // E2EE is enclave-bound: never transparently switch providers. Surface a
      // clear retry error (the client must re-attest before retrying).
      if (isE2EE) {
        throw new AppError(
          503,
          "provider_fallback_not_supported_for_e2ee",
          "E2EE is enclave-bound and cannot transparently switch providers; retry with a fresh attestation"
        );
      }
      if (!fallbackEnabled) return false;
      // Walk forward until an attempt can actually serve this request. The
      // control plane builds the plan without knowing whether the request
      // carries tools or images, so a plan may contain a route that cannot serve
      // it; skipping such an attempt costs nothing, because no dispatch happened
      // and the reservation already covers the plan's worst case.
      for (;;) {
        const next = await server.controlClient.authorizeNextProviderAttempt!(
          { requestId, previousOutcome: outcome, latencyMs: Date.now() - startedAt },
          signal
        );
        if (!next) {
          // The plan is exhausted. If we already fell back at least once, surface a
          // stable exhaustion error; otherwise let the original provider error show.
          if (fellBack) {
            throw new AppError(503, "provider_fallback_exhausted", "Every permitted provider attempt failed before output");
          }
          return false;
        }
        if (capabilityRefusal(next.model, capabilityNeeds)) continue;
        servingModel = next.model;
        servingToken = next.dispatchToken;
        servingCeiling = next.effectiveMaxOutputTokens;
        servingRouting = next.routing;
        attempts = next.attemptIndex + 1;
        fellBack = true;
        return true;
      }
    };

    // Capability enforcement moved here with the tools/vision signals that may no
    // longer cross to control (O13). Control constrains the plan by policy,
    // privacy tier and price; only this plane knows the request needs tools or
    // vision, so only this plane can refuse an incapable route. Skip forward
    // through the bounded plan rather than dispatching a request the provider is
    // guaranteed to reject.
    const routeSatisfiesCapabilities = (m: RelayModel) =>
      (!requiresTools || m.supportsTools) && (!requiresVision || m.supportsVision);
    while (!routeSatisfiesCapabilities(servingModel)) {
      const next = fallbackEnabled
        ? await server.controlClient.authorizeNextProviderAttempt!(
            { requestId, previousOutcome: "provider_rejected", latencyMs: Date.now() - startedAt },
            signal
          )
        : null;
      if (!next) {
        await server.controlClient
          .abort({ requestId, status: "failed", latencyMs: Date.now() - startedAt })
          .catch(() => undefined);
        throw requiresTools && !servingModel.supportsTools
          ? new AppError(400, "tools_not_supported", "The selected model does not support tool calling")
          : new AppError(400, "model_not_vision", "The selected model does not support image input");
      }
      servingModel = next.model;
      servingToken = next.dispatchToken;
      servingCeiling = next.effectiveMaxOutputTokens;
      servingRouting = next.routing;
      attempts = next.attemptIndex + 1;
      fellBack = true;
    }

    // Record an exact-wire signature binding in THIS plane and hand control only
    // the resulting opaque receipt id. The hashes never cross (D29).
    const recordSettlementReceipt = (binding: {
      providerRequestId: string;
      requestHash: string;
      responseHash: string;
      model: RelayModel;
    }): { opaqueReceiptId: string } | Record<string, never> => {
      if (!server.contentReceipts) return {};
      return {
        opaqueReceiptId: server.contentReceipts.record({
          providerName: binding.model.providerName,
          externalModelId: binding.model.externalModelId,
          routeId: binding.model.publicModelId,
          providerRequestId: binding.providerRequestId,
          requestHash: binding.requestHash,
          responseHash: binding.responseHash
        })
      };
    };

    try {
      reply.header("x-anonrouter-routing", automatic ? "auto" : "exact");

      if (!body.stream) {
        for (;;) {
          try {
            const result = await server.workerClient.chat(buildWorkerRequest(servingModel, servingToken, servingCeiling), signal);
            const fallbackUsage: TokenUsage = {
              inputTokens: inputCeiling,
              outputTokens: Math.max(1, estimateResponseOutputTokens(result.response)),
              cachedTokens: 0
            };
            const usage = normalizeUsage(result.usage, fallbackUsage);
            const hasExactSignatureBinding = server.verifierRegistry?.forProvider(servingModel.providerName)?.supportsSignatures === true
              && typeof result.providerRequestId === "string"
              && /^[0-9a-f]{64}$/.test(result.exactRequestHash ?? "")
              && /^[0-9a-f]{64}$/.test(result.exactResponseHash ?? "");
            // The exact wire hashes stay HERE. Only a fresh random 128-bit
            // receipt id crosses to the control plane, which can join it to this
            // settlement and learn nothing else from it.
            const opaqueReceiptId = hasExactSignatureBinding
              ? server.contentReceipts?.record({
                providerName: servingModel.providerName,
                externalModelId: servingModel.externalModelId,
                routeId: servingModel.publicModelId,
                canonicalModelId: servingModel.canonicalModelId,
                providerRequestId: result.providerRequestId!,
                requestHash: result.exactRequestHash!,
                responseHash: result.exactResponseHash!
              })
              : undefined;
            const settlement = await server.controlClient.settle({
              requestId,
              usage,
              latencyMs: Date.now() - startedAt,
              ...(opaqueReceiptId ? { opaqueReceiptId } : {})
            });
            if (opaqueReceiptId) {
              reply.header(RECEIPT_HEADER, opaqueReceiptId);
              // A receipt the control plane did not record means the customer's
              // later lookup will find the binding here with no matching
              // settlement marker. Non-fatal, but a defect worth seeing rather
              // than discovering when someone goes looking for a receipt.
              if (settlement.receiptRecorded === false) {
                request.log.warn({ request_id: requestId }, "settlement_receipt_not_recorded");
              }
            }
            reply.header("x-anonrouter-selected-model", qualifiedPublicModelId(servingModel.providerName, servingModel.publicModelId));
            for (const [name, value] of Object.entries(
              providerTransparencyHeaders(servingModel, automatic, attempts, fellBack, servingRouting)
            )) {
              reply.header(name, value);
            }
            return withUsageCost(
              publicModelResponse(result.response, servingModel.canonicalModelId ?? servingModel.publicModelId),
              settlement.chargedUsd
            );
          } catch (error) {
            // Content-free ledger record for this failed attempt (best-effort).
            // attempts is 1-based; attemptIndex is the 0-based plan cursor.
            await reportProviderRejection(server.controlClient, {
              requestId, attemptIndex: attempts - 1, automatic, error, signal, startedAt
            });
            if (!(await advanceToNextAttempt(error))) throw error;
          }
        }
      }

      // Streaming: fallback is only safe before the SSE headers are committed.
      // Once the stream is returned and headers are written, terminate on the
      // serving provider and settle conservatively (no mid-stream switch).
      let streamResult: Awaited<ReturnType<typeof server.workerClient.stream>>;
      for (;;) {
        try {
          streamResult = await server.workerClient.stream(buildWorkerRequest(servingModel, servingToken, servingCeiling), signal);
          break;
        } catch (error) {
          // Pre-output stream failure: record this attempt (best-effort) before
          // deciding fallback. Mid-stream failures (after headers) are ambiguous
          // and deliberately NOT recorded as rejections.
          await reportProviderRejection(server.controlClient, {
            requestId, attemptIndex: attempts - 1, automatic, error, signal, startedAt
          });
          if (!(await advanceToNextAttempt(error))) throw error;
        }
      }
      const selectedModel = qualifiedPublicModelId(servingModel.providerName, servingModel.publicModelId);
      // Minted BEFORE the headers go out, because SSE headers are written before
      // the first chunk and the response hash does not exist until the last one.
      // The id is random either way, so nothing about it depends on the response.
      const streamReceiptId = server.contentReceipts ? newOpaqueReceiptId() : undefined;
      reply.raw.writeHead(200, {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-transform",
        connection: "keep-alive",
        "x-accel-buffering": "no",
        // Raw socket write: Fastify's CORS hook does not run on this path, so
        // the browser would receive a perfect 200 SSE stream it is not allowed
        // to read. This is the path the first-party chat UI streams on.
        ...rawStreamCorsHeaders(request.headers.origin, server.config),
        "x-anonrouter-selected-model": selectedModel,
        ...(streamReceiptId ? { [RECEIPT_HEADER]: streamReceiptId } : {}),
        ...providerTransparencyHeaders(servingModel, automatic, attempts, fellBack, servingRouting),
        "x-ratelimit-limit-requests": String(authorization.rateLimits.requests.limit),
        "x-ratelimit-remaining-requests": String(authorization.rateLimits.requests.remaining),
        "x-ratelimit-reset-requests": String(Math.ceil(authorization.rateLimits.requests.resetMs / 1000)),
        "x-ratelimit-limit-tokens": String(authorization.rateLimits.tokens.limit),
        "x-ratelimit-remaining-tokens": String(authorization.rateLimits.tokens.remaining),
        "x-ratelimit-reset-tokens": String(Math.ceil(authorization.rateLimits.tokens.resetMs / 1000))
      });
      let deliveryStarted = false;
      let firstTokenLatencyMs: number | undefined;
      // Whether this stream has produced a tool call, so the terminal frame can
      // be corrected to the finish_reason the schema requires.
      let toolCallsSeen = false;
      try {
        const externalId = servingModel.externalModelId;
        const publicId = servingModel.canonicalModelId ?? servingModel.publicModelId;
        const rewriteModel = externalId !== publicId;
        for await (const chunk of streamResult.stream) {
          // Defense in depth for in-process/custom workers. The credential
          // worker consumes provider [DONE], but the relay is the sole owner of
          // the public completion marker and emits it only after settlement.
          if (chunk.trim() === "data: [DONE]") continue;
          // TTFT is the relay-observed time until Venice yields its first real
          // output-bearing delta. Empty role/usage frames do not count. Capture
          // before the durable delivery fence so DB/RPC overhead and slow client
          // backpressure are not mislabeled as model response time.
          if (firstTokenLatencyMs === undefined && hasOutputBearingOpenAiDelta(chunk)) {
            firstTokenLatencyMs = Date.now() - startedAt;
          }
          if (!deliveryStarted) {
            // The durable fence must commit before any model output is written.
            // If this RPC fails, no content has reached the caller; the earlier
            // worker-side provider-attempt fence still governs conservative
            // capture because upstream work may already have been billed.
            await server.controlClient.markDeliveryStarted({ requestId });
            deliveryStarted = true;
          }
          if (frameHasToolCallDelta(chunk)) toolCallsSeen = true;
          const modelRewritten = rewriteModel
            ? chunk.split(`"model":"${externalId}"`).join(`"model":"${publicId}"`)
            : chunk;
          const publicChunk = correctStreamedFinishReason(modelRewritten, toolCallsSeen);
          await writeWithBackpressure(reply.raw, publicChunk, signal);
        }
        const providerUsage = await streamResult.usage;
        const usage = normalizeUsage(providerUsage, { inputTokens: inputCeiling, outputTokens: 1, cachedTokens: 0 });
        const streamSignatureBinding = await streamResult.signatureBinding?.catch(() => undefined);
        const hasStreamSignatureBinding = server.verifierRegistry?.forProvider(servingModel.providerName)?.supportsSignatures === true
          && typeof streamSignatureBinding?.providerRequestId === "string"
          && /^[0-9a-f]{64}$/.test(streamSignatureBinding.exactRequestHash)
          && /^[0-9a-f]{64}$/.test(streamSignatureBinding.exactResponseHash);
        // A public [DONE] promises both a complete provider stream and durable
        // billing settlement. The worker's provider [DONE] is consumed before
        // its usage + terminal sidebands and is never forwarded directly.
        await finalizeThenWriteDone(
          reply.raw,
          () => settleWithRetry(server.controlClient, {
            requestId,
            usage,
            firstTokenLatencyMs,
            latencyMs: Date.now() - startedAt,
            // The receipt id was minted and sent in the SSE headers before the
            // first chunk; the response hash only exists now, at the end of the
            // stream, so the binding is filled in under that id here.
            ...(hasStreamSignatureBinding && streamReceiptId && server.contentReceipts
              ? (server.contentReceipts.recordUnder(streamReceiptId, {
                providerName: servingModel.providerName,
                externalModelId: servingModel.externalModelId,
                routeId: servingModel.publicModelId,
                canonicalModelId: servingModel.canonicalModelId,
                providerRequestId: streamSignatureBinding!.providerRequestId,
                requestHash: streamSignatureBinding!.exactRequestHash,
                responseHash: streamSignatureBinding!.exactResponseHash
              }), { opaqueReceiptId: streamReceiptId })
              : {})
          }),
          signal
        );
        if (!reply.raw.destroyed && !reply.raw.writableEnded) reply.raw.end();
      } catch (error) {
        const disconnected = signal.aborted || isAbortError(error);
        let durablyFinalized = false;
        if (deliveryStarted && error instanceof AppError && error.code === "provider_stream_incomplete" && !disconnected) {
          // The caller already received partial output and Venice may charge for
          // it. Settle input plus the provider-side output estimate captured
          // before the missing terminal marker; never grant a free partial stream.
          const partialProviderUsage = await streamResult.usage.catch(() => undefined);
          const partialUsage = normalizeUsage(partialProviderUsage, {
            inputTokens: inputCeiling,
            outputTokens: 1,
            cachedTokens: 0
          });
          try {
            await settleWithRetry(server.controlClient, {
              requestId,
              usage: partialUsage,
              firstTokenLatencyMs,
              latencyMs: Date.now() - startedAt
            });
            durablyFinalized = true;
          } catch {
            // Fall through to conservative ceiling capture below.
          }
        }
        if (deliveryStarted && !durablyFinalized) {
          // Output was already delivered, so a zero-charge abort is forbidden.
          // Capture is idempotent with a settle whose response was lost. If the
          // control plane is unavailable, the durable delivery marker makes the
          // stale-reservation sweeper perform the same capture later.
          try {
            await server.controlClient.capture({ requestId, firstTokenLatencyMs, latencyMs: Date.now() - startedAt });
            durablyFinalized = true;
          } catch (captureError) {
            request.log.error(
              { request_id: requestId, error_type: captureError instanceof Error ? captureError.name : "control_rpc_error" },
              "stream_settlement_pending"
            );
          }
        } else if (!deliveryStarted) {
          try {
            // Nothing reached the caller. A provider/server fault releases the
            // hold in full even though the provider-attempt fence committed (an
            // upstream rejection is not billable output); a client disconnect
            // is NOT attested, so a fenced disconnect still captures.
            await server.controlClient.abort({
              requestId,
              status: "failed",
              providerRejected: !disconnected,
              latencyMs: Date.now() - startedAt
            });
            durablyFinalized = true;
          } catch (abortError) {
            request.log.error(
              { request_id: requestId, error_type: abortError instanceof Error ? abortError.name : "control_rpc_error" },
              "stream_settlement_pending"
            );
          }
        }
        if (!disconnected && durablyFinalized && !reply.raw.destroyed) {
          try {
            await writeWithBackpressure(
              reply.raw,
              `data: ${JSON.stringify({ error: { message: "Stream failed", type: "provider_stream_error", request_id: requestId } })}\n\n`,
              signal
            );
            await writeWithBackpressure(reply.raw, "data: [DONE]\n\n", signal);
            if (!reply.raw.destroyed && !reply.raw.writableEnded) reply.raw.end();
          } catch (writeError) {
            if (!signal.aborted && !isAbortError(writeError)) {
              request.log.warn(
                { request_id: requestId, error_type: writeError instanceof Error ? writeError.name : "stream_write_error" },
                "stream_error_delivery_failed"
              );
            }
          }
          request.log.warn(
            { request_id: requestId, error_type: error instanceof Error ? error.name : "provider_stream_error" },
            "stream_failed"
          );
        } else if (!disconnected && !durablyFinalized && !reply.raw.destroyed) {
          // Close without a terminal marker. A public [DONE] is a durable
          // completion promise and must never be emitted while settlement is
          // pending; the client will treat EOF as an incomplete response.
          reply.raw.destroy();
        }
      }
      return reply;
    } catch (error) {
      const clientGone = signal.aborted || isAbortError(error);
      await server.controlClient
        .abort({
          requestId,
          status: usageStatusForError(error),
          // Server/provider faults with zero delivery release the fenced hold;
          // client disconnects keep the conservative capture.
          providerRejected: !clientGone,
          latencyMs: Date.now() - startedAt
        })
        .catch(() => undefined);
      // A closed downstream socket cannot receive an error body. Treat this as
      // normal cancellation instead of generating a noisy server error log.
      if (clientGone) return reply;
      throw error;
    }
  });
}
