// The compat broker. It terminates static-key OpenAI-compatible requests on the
// control/identity side of the split, mints a fresh single-use ticket through
// the narrow control RPC (never sending prompt content there), then forwards the
// UNCHANGED body to the relay with x-anonrouter-ticket and streams the SSE
// response straight back. It holds no DB, provider credential, or payment
// access, calls no billing RPC, and never logs Authorization, cookies, the ar_
// key, tickets, or request/response content.
//
// It is a faithful passthrough: it validates nothing the relay would accept and
// strips nothing the relay needs. Whatever the underlying chat/embeddings
// contract supports (tool calling is NOT accepted at the request layer today —
// see docs/SDK_COMPATIBILITY.md) the broker supports identically; unsupported
// requests get the same OpenAI-shaped error the native ticket flow returns.

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { AppError } from "../security/errors.js";
import { rawStreamCorsHeaders } from "../httpBase.js";
import { abortOnClientDisconnect, isAbortError } from "../inference/disconnect.js";
import { writeWithBackpressure } from "../inference/backpressure.js";
import { RelayIngressGuard, relayClientAddress, type RelayIngressLimits } from "../relay/ingress.js";
import { CompatControlClient } from "./controlClient.js";
import { openAiErrorFromUnknown } from "./openaiErrors.js";

declare module "fastify" {
  interface FastifyInstance {
    compatControlClient: CompatControlClient;
  }
}

const CHAT_PATH = "/v1/chat/completions";
const EMBEDDINGS_PATH = "/v1/embeddings";
const COMPLETIONS_PATH = "/v1/completions";
const MODELS_PATH = "/v1/models";
const COMPAT_PATHS = new Set([CHAT_PATH, EMBEDDINGS_PATH, COMPLETIONS_PATH]);
const TICKET_HEADER = "x-anonrouter-ticket";

// Response headers the relay sets that are safe and useful to relay back. No
// Set-Cookie, no internal RPC headers, no content.
const PASSTHROUGH_HEADERS = [
  "x-anonrouter-selected-model",
  "x-anonrouter-routing",
  "x-ratelimit-limit-requests",
  "x-ratelimit-remaining-requests",
  "x-ratelimit-reset-requests",
  "x-ratelimit-limit-tokens",
  "x-ratelimit-remaining-tokens",
  "x-ratelimit-reset-tokens"
] as const;

function bearerToken(header: string | string[] | undefined): string | undefined {
  const value = Array.isArray(header) ? header[0] : header;
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed.toLowerCase().startsWith("bearer ")) return undefined;
  const token = trimmed.slice("bearer ".length).trim();
  return token.length > 0 ? token : undefined;
}

/**
 * Pick ONLY the top-level routing metadata the ticket binds. Never reads
 * `messages`/`input`/tool arguments. venice_parameters is narrowed to
 * `disable_thinking` (the only reasoning-relevant field) so the control mint
 * schema accepts it while the relay still recomputes the same reasoning digest
 * from the full forwarded body.
 */
function extractMintMetadata(body: Record<string, unknown>, operation: "chat" | "embeddings") {
  const meta: Record<string, unknown> = { operation, model: body.model };
  // The ticket binds a normalized provider-policy digest, and the relay
  // recomputes that digest from the forwarded body. Omitting `provider` here
  // bound the default policy while the relay computed the caller's, so every
  // compat request carrying a provider policy failed with a 409
  // ticket_provider_policy_mismatch. Forward it verbatim; control validates it
  // through the same providerRoutingPolicySchema as the native ticket route.
  if (body.provider !== undefined) meta.provider = body.provider;
  if (operation === "embeddings") return meta;
  if (body.max_tokens !== undefined) meta.max_tokens = body.max_tokens;
  if (body.max_completion_tokens !== undefined) meta.max_completion_tokens = body.max_completion_tokens;
  if (body.reasoning_effort !== undefined) meta.reasoning_effort = body.reasoning_effort;
  if (body.reasoning !== undefined) meta.reasoning = body.reasoning;
  const veniceParameters = body.venice_parameters;
  if (
    veniceParameters
    && typeof veniceParameters === "object"
    && !Array.isArray(veniceParameters)
    && "disable_thinking" in veniceParameters
  ) {
    meta.venice_parameters = { disable_thinking: (veniceParameters as { disable_thinking?: unknown }).disable_thinking };
  }
  return meta;
}

// The ordered model candidates for a request: the primary `model` first, then
// the OpenRouter-style `models` fallbacks (chat only). Fallbacks must be concrete
// ids (globs/pools are primary-only), bounded, de-duped. A malformed `models`
// value degrades to just the primary, so this never widens or errors on junk.
function resolveCandidateModels(body: Record<string, unknown>, operation: "chat" | "embeddings"): string[] {
  const primary = typeof body.model === "string" ? body.model.trim() : "";
  const base = primary ? [primary] : [];
  if (operation !== "chat" || !Array.isArray(body.models)) return base;
  const fallbacks = body.models
    .filter((m): m is string => typeof m === "string" && m.trim().length > 0 && m.length <= 256 && !m.includes("*"))
    .map((m) => m.trim())
    .slice(0, 4);
  const ordered = [...base, ...fallbacks];
  return ordered.filter((m, index) => ordered.indexOf(m) === index);
}

// Errors that mean "this model could not serve you before any output", so the
// next candidate model is worth trying. These are all pre-output on the relay
// (forwardToRelay only throws before it writes any bytes), and the relay has
// already released this model's reservation, so re-minting the next model never
// double-holds balance. Auth/scope/validation and infra (relay_unavailable)
// errors are intentionally excluded: another model would fail the same way.
const CROSS_MODEL_FALLBACK_CODES = new Set([
  "model_not_found",
  "model_not_chat",
  "model_unpriced",
  "no_provider_route",
  "no_provider_route_meets_privacy",
  "no_provider_route_meets_price",
  "provider_fallback_exhausted",
  "provider_unavailable",
  "rate_limited",
  "router_timeout",
  "router_unavailable",
  "insufficient_balance"
]);

function isCrossModelFallbackEligible(error: unknown): boolean {
  return error instanceof AppError && CROSS_MODEL_FALLBACK_CODES.has(error.code);
}

function copyPassthroughHeaders(upstream: Response, reply: FastifyReply) {
  for (const name of PASSTHROUGH_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) reply.header(name, value);
  }
}

/** Translate the relay's AnonRouter-coded error body into an AppError the compat
 *  error handler maps to the OpenAI envelope. Preserves any Retry-After. */
function relayErrorToAppError(status: number, bodyText: string, retryAfter: string | null): AppError {
  let code = "relay_error";
  let message = "The request could not be completed.";
  try {
    const parsed = JSON.parse(bodyText) as { error?: { type?: string; message?: string } };
    if (parsed.error?.type) code = parsed.error.type;
    if (parsed.error?.message) message = parsed.error.message;
  } catch {
    // keep defaults; never echo a raw upstream body
  }
  const error = new AppError(status, code, message) as AppError & { retryAfterSeconds?: number };
  const seconds = retryAfter ? Number(retryAfter) : Number.NaN;
  if (Number.isFinite(seconds) && seconds > 0) error.retryAfterSeconds = seconds;
  return error;
}

async function streamRelayResponse(
  request: FastifyRequest,
  reply: FastifyReply,
  signal: AbortSignal,
  upstream: Response
): Promise<FastifyReply> {
  const headers: Record<string, string> = {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive",
    "x-accel-buffering": "no",
    "x-request-id": request.id,
    // Written HERE because this is a raw socket write: it bypasses Fastify's
    // reply lifecycle, so @fastify/cors never runs and the response would
    // otherwise carry no Access-Control-Allow-Origin at all. A browser then
    // discards a complete, correct, 200 SSE stream.
    ...rawStreamCorsHeaders(request.headers.origin, request.server.config)
  };
  for (const name of PASSTHROUGH_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) headers[name] = value;
  }
  reply.raw.writeHead(200, headers);

  const reader = upstream.body?.getReader();
  if (!reader) {
    if (!reply.raw.writableEnded) reply.raw.end();
    return reply;
  }
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      // Pass relay bytes through verbatim (backpressure-aware). The relay owns
      // the settlement-gated public `data: [DONE]`; the broker adds/removes
      // nothing so SSE framing is preserved exactly.
      if (value && value.length) await writeWithBackpressure(reply.raw, value, signal);
    }
    if (!reply.raw.writableEnded) reply.raw.end();
  } catch {
    // Client disconnect or an upstream stream fault. NEVER fabricate a terminal
    // [DONE] — that would falsely promise a complete, settled stream. Close the
    // socket; the client treats EOF-without-[DONE] as incomplete, and the relay's
    // own abort/capture compensation has already fired from its closed socket.
    await reader.cancel().catch(() => undefined);
    if (!reply.raw.destroyed && !reply.raw.writableEnded) reply.raw.destroy();
  }
  return reply;
}

async function forwardToRelay(
  server: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  signal: AbortSignal,
  path: string,
  ticket: string,
  clientIp: string,
  body: unknown
): Promise<FastifyReply | unknown> {
  const url = `${server.config.internal.relayIngressUrl}${path}`;
  let upstream: Response;
  // Deadline for RESPONSE HEADERS only, cleared as soon as they arrive, so a
  // long streamed generation is never truncated by it. There was previously no
  // deadline here at all, which was survivable while the broker and the relay
  // shared a Docker bridge; across a WAN a black-holed connection would hold a
  // broker slot until the client gave up.
  const deadline = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    deadline.abort(new DOMException("Relay did not respond in time", "TimeoutError"));
  }, server.config.internal.relayForwardTimeoutMs);
  try {
    upstream = await fetch(url, {
      method: "POST",
      // Build headers from scratch: the caller's Authorization and Cookie are
      // NEVER forwarded to the content tier. The relay authenticates only the
      // opaque single-use ticket.
      headers: {
        "content-type": "application/json",
        "x-anonrouter-ticket": ticket,
        "x-forwarded-for": clientIp
      },
      body: JSON.stringify(body),
      signal: AbortSignal.any([signal, deadline.signal])
    });
  } catch (error) {
    // A client disconnect stays a disconnect. Only our own deadline becomes a
    // service error, and it is deliberately the same code a dead relay yields
    // so the caller cannot distinguish the two.
    if (!signal.aborted && timedOut) {
      throw new AppError(504, "relay_unavailable", "The inference service did not respond in time");
    }
    if (signal.aborted || isAbortError(error)) return reply;
    throw new AppError(502, "relay_unavailable", "The inference service is unavailable");
  } finally {
    clearTimeout(timer);
  }

  if (!upstream.ok) {
    const text = await upstream.text().catch(() => "");
    throw relayErrorToAppError(upstream.status, text, upstream.headers.get("retry-after"));
  }

  const contentType = upstream.headers.get("content-type") ?? "";
  if (contentType.includes("text/event-stream")) {
    return streamRelayResponse(request, reply, signal, upstream);
  }

  copyPassthroughHeaders(upstream, reply);
  reply.header("x-request-id", request.id);
  let payload: unknown;
  try {
    payload = await upstream.json();
  } catch (error) {
    if (signal.aborted || isAbortError(error)) return reply;
    throw new AppError(502, "provider_stream_error", "Malformed upstream response");
  }
  reply.status(upstream.status);
  return payload;
}

async function handleCompatInference(
  server: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  operation: "chat" | "embeddings",
  path: string
): Promise<FastifyReply | unknown> {
  const signal = abortOnClientDisconnect(request, reply);
  // Independent broker-side kill switch (control's mint RPC enforces the same
  // flag). Reject before touching the body, the key, or any mint round-trip.
  if (!server.config.internal.allowCompatMode) {
    throw new AppError(403, "compat_unavailable", "Compatibility mode is not available");
  }
  // Fail closed on an ambiguous request that carries BOTH a static key and a
  // single-use ticket. The broker mints its own ticket; a caller-supplied ticket
  // is never honored, so we reject rather than silently pick a credential path.
  if (request.headers[TICKET_HEADER] !== undefined) {
    throw new AppError(400, "conflicting_credentials", "A compatibility request must not carry a ticket");
  }
  const token = bearerToken(request.headers.authorization);
  if (!token) throw new AppError(401, "unauthorized", "Missing API key");

  const body = request.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new AppError(400, "invalid_request", "Request body must be a JSON object");
  }

  const clientIp = request.ip;
  const rawBody = body as Record<string, unknown>;
  const candidates = resolveCandidateModels(rawBody, operation);
  if (candidates.length === 0) {
    throw new AppError(400, "invalid_request", "Request must name a model");
  }

  // Cross-model fallback by re-minting: try each candidate in order, minting a
  // fresh single-use ticket (and thus a fresh worst-case reservation) per model.
  // forwardToRelay throws only before any bytes reach the client, so a caught
  // error here means nothing was delivered and the relay already released this
  // model's reservation; only then do we advance to the next model.
  let lastError: unknown;
  for (let i = 0; i < candidates.length; i += 1) {
    const isLast = i === candidates.length - 1;
    // Forward a clean single-model body: pin the attempted model and drop the
    // fallback array so the relay serves exactly one model and never re-loops.
    const attemptBody: Record<string, unknown> = { ...rawBody, model: candidates[i] };
    delete attemptBody.models;
    const meta = extractMintMetadata(attemptBody, operation);
    try {
      const minted = await server.compatControlClient.mint({ apiKey: token, ...meta } as never, clientIp, signal);
      return await forwardToRelay(server, request, reply, signal, path, minted.ticket, clientIp, attemptBody);
    } catch (error) {
      lastError = error;
      if (isLast || signal.aborted || isAbortError(error) || !isCrossModelFallbackEligible(error)) {
        throw error;
      }
    }
  }
  throw lastError;
}

export async function registerCompatRoutes(server: FastifyInstance) {
  server.post(CHAT_PATH, (request, reply) => handleCompatInference(server, request, reply, "chat", CHAT_PATH));
  server.post(EMBEDDINGS_PATH, (request, reply) => handleCompatInference(server, request, reply, "embeddings", EMBEDDINGS_PATH));
  // Legacy Completions has no handler anywhere in AnonRouter. Return a clean
  // OpenAI-shaped unsupported error rather than a 404 fallthrough.
  server.post(COMPLETIONS_PATH, async () => {
    throw new AppError(404, "unsupported_endpoint", "The /v1/completions endpoint is not supported. Use /v1/chat/completions.");
  });

  // Model discovery. Every stock OpenAI client calls this, and without it the
  // confidential origin answered 404 because the route belongs to the
  // api/control role, which sits outside the trust domain in the split
  // topology.
  //
  // The caller is still authenticated here, so an unauthenticated stranger
  // cannot enumerate the catalog through the TEE origin. What does NOT happen is
  // forwarding their credential onward: the broker asks control with its own
  // service token, because a catalog listing needs no user identity and sending
  // the key across another hop would widen its exposure for nothing.
  server.get(MODELS_PATH, {
    preHandler: async (request) => {
      if (!server.config.internal.allowCompatMode) {
        throw new AppError(403, "compat_unavailable", "Compatibility mode is not available");
      }
      const token = bearerToken(request.headers.authorization);
      if (!token) throw new AppError(401, "unauthorized", "Missing API key");
      // Presence is NOT validity. This used to stop here, so any ar_-prefixed
      // string enumerated the catalogue; the token is now carried to control and
      // resolved there through the same path the chat mint uses.
      (request as { compatApiKey?: string }).compatApiKey = token;
    }
  }, async (request, reply) => server.compatControlClient.models(
    (request as { compatApiKey?: string }).compatApiKey,
    abortOnClientDisconnect(request, reply)
  ));
}

/** OpenAI-shaped error handler passed to createBaseServer (set once, no
 *  override). Logs metadata only — never a message, body, or credential. */
export function compatErrorHandler(error: unknown, request: FastifyRequest, reply: FastifyReply) {
  const mapped = openAiErrorFromUnknown(error);
  request.log.warn(
    {
      request_id: request.id,
      error_type: error instanceof AppError ? error.code : "internal_error",
      status_code: mapped.status
    },
    "request_error"
  );
  if (mapped.retryAfterSeconds && mapped.retryAfterSeconds > 0) {
    reply.header("retry-after", String(Math.ceil(mapped.retryAfterSeconds)));
  }
  reply.header("x-request-id", request.id);
  reply.status(mapped.status).send(mapped.body);
}

/**
 * Dependency-free flood/concurrency guard for the pre-ticket compat path,
 * reusing the relay's HMAC-keyed guard (no ticket redemption). Runs in
 * onRequest before body parse or any mint RPC, so a saturating client cannot
 * turn compat into unbounded ticket-mint + relay load.
 */
export function registerCompatIngressGuard(
  server: FastifyInstance,
  options: Partial<RelayIngressLimits> = {}
): RelayIngressGuard {
  const guard = new RelayIngressGuard(options);
  server.server.maxConnections = options.maxConnections ?? 512;
  const releases = new WeakMap<FastifyRequest, () => void>();

  server.addHook("onRequest", async (request, reply) => {
    const path = request.url.split("?", 1)[0];
    if (!COMPAT_PATHS.has(path)) return;
    const release = guard.admit(relayClientAddress(request));
    releases.set(request, release);
    request.raw.once("aborted", release);
    reply.raw.once("close", release);
  });
  const release = (request: FastifyRequest) => {
    releases.get(request)?.();
    releases.delete(request);
  };
  server.addHook("onResponse", async (request) => release(request));
  server.addHook("onError", async (request) => release(request));
  return guard;
}
