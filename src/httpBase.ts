import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
// Side-effect import: declares the content-plane Fastify decorations for every
// role built through this module. See src/contentDecorators.ts (D-22).
import "./contentDecorators.js";
import type { AppConfig } from "./config.js";
import type { ContentPlaneConfig } from "./contentPlaneConfig.js";
import { createLoggerOptions } from "./logger.js";
import { newId } from "./ids.js";
import { ProviderError, publicErrorBody } from "./security/errors.js";
import { registerLeanHealthRoutes } from "./routes/healthLean.js";
import { isPrivateProxyAddress } from "./relay/ingress.js";

/**
 * Error handler for the credential-isolated provider workers. Identical to the
 * default, except that a ProviderError additionally carries a sanitized,
 * content-free `provider` block (status / request id / machine code) so the relay
 * can reconstruct the real provider outcome across the worker RPC boundary. This
 * block is emitted ONLY on the internal worker->relay channel; the customer-facing
 * relay never adds it (publicErrorBody is unchanged), so no upstream metadata
 * leaks to callers. It never contains a body, message, prompt, or credential.
 */
export function workerErrorHandler(error: unknown, request: FastifyRequest, reply: FastifyReply) {
  const errorRecord = error as { statusCode?: unknown; code?: unknown; providerStatusCode?: unknown };
  const statusCode = typeof errorRecord.statusCode === "number" ? errorRecord.statusCode : 500;
  request.log.warn(
    {
      request_id: request.id,
      error_type: typeof errorRecord.code === "string" ? errorRecord.code : "internal_error",
      status_code: statusCode,
      ...(typeof errorRecord.providerStatusCode === "number" ? { provider_status: errorRecord.providerStatusCode } : {})
    },
    "request_error"
  );
  const retryAfterSeconds = (error as { retryAfterSeconds?: unknown }).retryAfterSeconds;
  if (typeof retryAfterSeconds === "number" && retryAfterSeconds > 0) {
    reply.header("retry-after", String(Math.ceil(retryAfterSeconds)));
  }
  const body = publicErrorBody(error, request.id) as Record<string, unknown>;
  if (error instanceof ProviderError) {
    body.provider = {
      status: error.providerStatusCode ?? null,
      request_id: error.providerRequestId ?? null,
      code: error.providerCode ?? null
    };
  }
  reply.status(statusCode).send(body);
}

/**
 * Response headers the browser is allowed to read cross-origin from the content
 * tier. Without an explicit list the browser exposes only the CORS-safelisted
 * headers, so every one of these reads as null and the UI silently degrades:
 * the provider badge, the Auto-vs-exact indicator, the transparent-fallback
 * disclosure, the privacy chip, the selected-model label, the image moderation
 * flags, and rate-limit backoff all disappear.
 *
 * This is an allowlist on purpose. Nothing content-derived belongs here.
 */
export const CONTENT_TIER_EXPOSED_HEADERS = [
  "x-request-id",
  "x-anonrouter-provider",
  "x-anonrouter-routing",
  "x-anonrouter-provider-attempts",
  "x-anonrouter-provider-fallback",
  "x-anonrouter-privacy-class",
  "x-anonrouter-selected-model",
  "x-anonrouter-provider-blurred",
  "x-anonrouter-provider-content-violation",
  "retry-after",
  "x-ratelimit-limit-requests",
  "x-ratelimit-remaining-requests",
  "x-ratelimit-reset-requests",
  "x-ratelimit-limit-tokens",
  "x-ratelimit-remaining-tokens",
  "x-ratelimit-reset-tokens"
] as const;

/**
 * Request headers a cross-origin browser client may send to the content tier:
 * the single-use ticket plus the documented E2EE protocol headers, which are
 * already re-validated against a strict allowlist in src/routes/chat.ts.
 */
export const CONTENT_TIER_ALLOWED_HEADERS = [
  "content-type",
  "accept",
  // REQUIRED, and its absence was a real browser blocker.
  //
  // The ticket path below is what the first-party chat UI uses, so the list was
  // built around it and `authorization` was never added. But the SAME origin
  // also serves the OpenAI-compatible surface, where every stock client sends
  // `Authorization: Bearer ar_...`. A browser preflighting that request got a
  // 204 with an Access-Control-Allow-Headers list that omitted `authorization`,
  // refused to send the POST at all, and surfaced it as "Failed to fetch" -- an
  // error with no status, no body and nothing in any server log, because the
  // request never arrived.
  //
  // Allowing the header grants nothing: `credentials: false` below still stops
  // the browser attaching cookies, and the server still authenticates the key.
  // What it permits is a browser-based OpenAI client working at all.
  "authorization",
  "x-anonrouter-ticket",
  "x-anonrouter-e2ee-provider",
  "x-signing-algo",
  "x-client-pub-key",
  "x-model-pub-key",
  "x-encryption-version",
  "x-venice-tee-client-pub-key",
  "x-venice-tee-model-pub-key",
  "x-venice-tee-signing-algo",
  "x-chutes-instance-id",
  "x-chutes-e2e-nonce"
] as const;

/**
 * The CORS response headers for a RAW (hijacked) streaming write.
 *
 * WHY THIS HAS TO EXIST SEPARATELY.
 *
 * SSE responses are written with `reply.raw.writeHead(...)`, straight to the
 * socket. That bypasses Fastify's reply lifecycle entirely, so @fastify/cors's
 * hook never runs and the response goes out with NO
 * Access-Control-Allow-Origin. Helmet's headers survive the same write because
 * it sets them earlier via `setHeader` on the raw response, which is exactly why
 * the failure looked so strange: the streaming response carried
 * Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy but not ACAO.
 *
 * The symptom is brutal to diagnose. The preflight passes, the POST returns 200,
 * the SSE body is complete and correct, the provider header is right, the
 * receipt is present -- and the browser still refuses to hand any of it to the
 * page, because a cross-origin read needs ACAO on the ACTUAL response, not only
 * on the preflight. Every server-side check passes; only a browser sees it.
 *
 * This mirrors contentTierCorsOptions rather than inventing a second policy: the
 * SAME explicit allowlist decides, so a raw write can never be more permissive
 * than the configured origins. An origin that is not allowed gets no header at
 * all, which is what makes the browser refuse it.
 */
export function rawStreamCorsHeaders(
  requestOrigin: string | undefined,
  config: ContentPlaneConfig
): Record<string, string> {
  if (!requestOrigin) return {};
  const allowed = config.env === "production"
    ? config.server.corsOrigin.split(",").map((o) => o.trim()).filter(Boolean)
    : null;
  // null means "not production": reflect, matching `origin: true` below.
  if (allowed !== null && !allowed.includes(requestOrigin)) return {};
  return {
    "access-control-allow-origin": requestOrigin,
    // Without this the page can read the body but none of the routing,
    // provider or rate-limit headers the UI displays.
    "access-control-expose-headers": [...CONTENT_TIER_EXPOSED_HEADERS].join(", "),
    // The allowed origin varies per request, so any cache must key on it.
    vary: "Origin"
  };
}

/**
 * CORS for the content tier.
 *
 * Two deliberate differences from the control plane:
 *
 *  - `credentials: false`. The content tier authenticates ONLY the opaque
 *    single-use ticket. Never returning Access-Control-Allow-Credentials means
 *    a browser will refuse to attach cookies here even if a future call site
 *    forgets `credentials: "omit"`. That turns a code-review invariant into a
 *    browser-enforced one.
 *  - An explicit exposed/allowed header list and a preflight cache. Every chat
 *    POST is non-simple, so without `maxAge` each send costs an extra full
 *    OPTIONS round trip to the enclave.
 */
export function contentTierCorsOptions(config: ContentPlaneConfig) {
  return {
    origin: config.env === "production" ? config.server.corsOrigin.split(",") : true,
    credentials: false,
    exposedHeaders: [...CONTENT_TIER_EXPOSED_HEADERS],
    allowedHeaders: [...CONTENT_TIER_ALLOWED_HEADERS],
    maxAge: 600
  };
}

/**
 * Shared HTTP scaffolding for the lean split roles (relay, venice-worker,
 * compat): a hardened Fastify instance with metadata-only logging, the standard
 * error handler, security headers, and a health route — but none of the
 * data-plane decorations (db, redis, auth) that those roles must not have.
 *
 * A role may supply its own error handler (the compat broker emits OpenAI-shaped
 * envelopes instead of the AnonRouter shape); it is set ONCE so no override
 * warning fires.
 */
export async function createBaseServer(
  config: AppConfig,
  options: { errorHandler?: (error: unknown, request: FastifyRequest, reply: FastifyReply) => void } = {}
): Promise<FastifyInstance> {
  const server = Fastify({
    logger: createLoggerOptions(config),
    genReqId: () => newId("req"),
    bodyLimit: config.server.bodyLimitBytes,
    // Split roles trust one forwarding hop only when the socket peer is on the
    // private Docker proxy path. A direct public/loopback caller cannot make
    // Fastify accept a forged forwarding chain.
    trustProxy: config.server.trustProxyHops === 1
      ? (address, hop) => hop === 0 && isPrivateProxyAddress(address)
      : false,
    disableRequestLogging: true
  });

  server.decorate("config", config);

  await server.register(helmet, { global: true });
  await server.register(cors, contentTierCorsOptions(config));

  server.addHook("onResponse", async (request, reply) => {
    request.log.info(
      {
        request_id: request.id,
        method: request.method,
        route: request.routeOptions.url,
        status_code: reply.statusCode,
        latency_ms: reply.elapsedTime
      },
      "request_complete"
    );
  });

  server.setErrorHandler(options.errorHandler ?? ((error, request, reply) => {
    const errorRecord = error as { statusCode?: unknown; code?: unknown; providerStatusCode?: unknown };
    const statusCode = typeof errorRecord.statusCode === "number" ? errorRecord.statusCode : 500;
    request.log.warn(
      {
        request_id: request.id,
        error_type: typeof errorRecord.code === "string" ? errorRecord.code : "internal_error",
        status_code: statusCode,
        // Content-free upstream status for provider failures: without it a
        // provider 4xx rejection and a provider outage are indistinguishable.
        ...(typeof errorRecord.providerStatusCode === "number" ? { provider_status: errorRecord.providerStatusCode } : {})
      },
      "request_error"
    );
    const retryAfterSeconds = (error as { retryAfterSeconds?: unknown }).retryAfterSeconds;
    if (typeof retryAfterSeconds === "number" && retryAfterSeconds > 0) {
      reply.header("retry-after", String(Math.ceil(retryAfterSeconds)));
    }
    reply.status(statusCode).send(publicErrorBody(error, request.id));
  }));

  // Lean roles get /healthz only. See registerLeanHealthRoutes for why.
  await registerLeanHealthRoutes(server);
  return server;
}
