import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
// Side-effect import: declares the content-plane Fastify decorations for every
// role built through this module. See src/contentDecorators.ts (D-22).
import "./contentDecorators.js";
import { corsAllowlist } from "./config.js";
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
 * THE POLICY SPLIT. Two browser-visible surfaces share this origin, they
 * authenticate in two different ways, and they therefore need two different CORS
 * policies. The role decides which; nothing else can.
 *
 *   RUNTIME_ROLE=relay   the TICKETED surface. Authenticates an opaque,
 *                        session-derived, single-use ticket. Keeps the strict
 *                        CORS_ORIGIN allowlist.
 *   RUNTIME_ROLE=compat  the OpenAI-COMPATIBLE surface. Authenticates only a
 *                        `Authorization: Bearer ar_...` header the customer
 *                        pasted into a third-party app themselves.
 *                        `Access-Control-Allow-Origin: *`, never credentials.
 *
 * WHY `*` IS SAFE ON THE SECOND AND NOT THE FIRST. CORS exists to stop a hostile
 * page spending a victim's AMBIENT credentials -- cookies, HTTP auth, TLS client
 * certs -- which the browser attaches on the page's behalf and without its
 * knowledge. The compat surface has none: it has no cookie parser, no session
 * reader and no account module in its module closure, the edge strips Cookie
 * before the content tier sees it, and the only credential it accepts is one the
 * caller had to hold and type. A hostile page does not have a stranger's `ar_`
 * key, and a page that DID hold one would not need a victim's browser to spend
 * it -- it could call the API from its own server, as every non-browser client
 * already does. So the wildcard grants a hostile origin exactly one capability:
 * calling an API with a key it already has.
 *
 * The ticketed surface is the opposite case and keeps the allowlist, because a
 * ticket IS obtained through the victim's session at the control plane.
 *
 * WHY THE ROLE AND NOT A CONFIG VALUE. A setting that must be right on exactly
 * one of two roles is the ALLOW_COMPAT_MODE defect with a new name: that flag
 * was on for one role and off for another, and the deployment looked healthy
 * while `/v1/models` worked and every chat call was refused. Deriving the policy
 * from RUNTIME_ROLE removes the possibility instead of documenting it. There is
 * no environment value anywhere that can make a relay permissive.
 */
const PUBLIC_CORS_ROLE = "compat";

/** True for the one role whose browser policy is public. */
export function servesPublicCors(config: Pick<ContentPlaneConfig, "runtimeRole">): boolean {
  return config.runtimeRole === PUBLIC_CORS_ROLE;
}

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
  // THE COMPAT ROLE'S RAW WRITE MIRRORS ITS PREFLIGHT, from the same role
  // decision, for exactly the reason this function exists at all: a policy that
  // is answered on the preflight and forgotten on the streamed response
  // produces a complete, correct, settled 200 SSE stream the browser refuses to
  // hand to the page. Both halves derive from `servesPublicCors`, so they cannot
  // disagree.
  //
  // Unconditional, with no dependence on the request's Origin, because
  // @fastify/cors emits `Access-Control-Allow-Origin: *` on every response under
  // this policy whether an Origin was sent or not. A non-browser client ignores
  // the header; a browser needs it. No `Vary: Origin`, because the value does
  // not vary. No Access-Control-Allow-Credentials, here or anywhere on this
  // policy.
  if (servesPublicCors(config)) {
    return {
      "access-control-allow-origin": "*",
      "access-control-expose-headers": [...CONTENT_TIER_EXPOSED_HEADERS].join(", ")
    };
  }
  if (!requestOrigin) return {};
  const allowed = config.env === "production" ? corsAllowlist(config.server.corsOrigin) : null;
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
 * CORS for the TICKETED content tier: relay, workers, gateway attestation.
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
    // Trimmed for the same reason as the control plane's list: the comparison
    // against an Origin header is byte-exact, and an untrimmed split silently
    // produces an entry that matches nothing.
    origin: config.env === "production" ? corsAllowlist(config.server.corsOrigin) : true,
    credentials: false,
    exposedHeaders: [...CONTENT_TIER_EXPOSED_HEADERS],
    allowedHeaders: [...CONTENT_TIER_ALLOWED_HEADERS],
    maxAge: 600
  };
}

/**
 * CORS for the OpenAI-compatible broker: any origin, never credentials.
 *
 * ASSERTED, NOT BRANCHED ON. Calling this for any other role throws rather than
 * returning something narrower, so a future caller cannot quietly hand the
 * permissive policy to the ticket-only relay by passing it the wrong config.
 * `corsOptionsForRole` below is the only intended caller.
 */
export function compatTierCorsOptions(config: ContentPlaneConfig) {
  if (!servesPublicCors(config)) {
    throw new Error(
      `compatTierCorsOptions is for RUNTIME_ROLE=${PUBLIC_CORS_ROLE} only; `
      + `refusing to build a public CORS policy for role '${String(config.runtimeRole)}'`
    );
  }
  return {
    // The LITERAL wildcard, not a reflection of the caller's Origin. Two
    // reasons. It is cacheable without Vary, so one preflight answer is reusable
    // across origins. And it is structurally incompatible with credentials:
    // every browser rejects `*` paired with Access-Control-Allow-Credentials:
    // true, so the permissive policy cannot quietly become a credentialed one.
    origin: "*",
    // NEVER true on this policy, ever. The wildcard is defensible only because
    // no ambient credential exists on this surface.
    credentials: false,
    exposedHeaders: [...CONTENT_TIER_EXPOSED_HEADERS],
    // `allowedHeaders` IS DELIBERATELY ABSENT, which makes @fastify/cors reflect
    // Access-Control-Request-Headers and add `Vary: Access-Control-Request-Headers`.
    // Omitted rather than set to undefined: the plugin's default is `null` and
    // it tests `=== null`, so an explicit undefined would emit the literal
    // string "undefined" as the header value.
    //
    // TWO REASONS, and the first one is a bug this policy had when it was a
    // copy of the ticketed list.
    //
    // 1. A FIXED LIST IS PER-CLIENT MAINTENANCE, which is the thing this whole
    //    change exists to abolish. The official OpenAI SDK sends
    //    `X-Stainless-Retry-Count` on EVERY request (openai/client.js) plus
    //    `X-Stainless-Timeout` whenever a timeout is set. Those are
    //    CORS-unsafe, so a browser names them in the preflight, and a fixed
    //    allowlist that omits them makes the browser refuse to send the
    //    request -- the exact failure this change is fixing, reintroduced one
    //    client later. Reflecting means a client we have never heard of, using
    //    headers we have never heard of, works without a release.
    //
    // 2. IT CLOSES A CORS-PREFLIGHT-CACHE CROSSOVER ONTO THE TICKETED SURFACE.
    //    The browser's preflight cache is keyed on (origin, url, credentials)
    //    and stores one entry per ALLOWED HEADER NAME, for max-age seconds. It
    //    does not consult Vary. So while this policy advertised the ticketed
    //    list, one compat preflight cached an `x-anonrouter-ticket` entry for
    //    that origin -- and for the next 600 seconds a hostile page could send
    //    a ticket-bearing request with NO further preflight, skipping the edge
    //    matcher that exists to route exactly that request to the relay.
    //    Reflecting makes that unreachable BY CONSTRUCTION: this policy can
    //    only ever cache header names the caller asked for, and a preflight
    //    that asks for `x-anonrouter-ticket` is excluded by the edge matcher
    //    and never reaches this policy at all.
    //
    // Reflection grants nothing: Allow-Headers permits a page to SEND a header
    // name, the browser's own forbidden-header list still blocks Cookie, Host,
    // Origin and the rest so they can never appear in the request list, and the
    // broker ignores every header it does not read. The ticketed policy keeps
    // its explicit list, because there the question is which ORIGINS may speak
    // at all and the answer is a short, known list.
    maxAge: 600
  };
}

/**
 * The one selector. `createBaseServer` calls this and nothing else registers a
 * CORS policy on a content role, so "which surface got which policy" is decided
 * in exactly one place, from RUNTIME_ROLE.
 */
export function corsOptionsForRole(
  config: ContentPlaneConfig
): ReturnType<typeof contentTierCorsOptions> | ReturnType<typeof compatTierCorsOptions> {
  return servesPublicCors(config) ? compatTierCorsOptions(config) : contentTierCorsOptions(config);
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
/**
 * `observe` runs against the bare instance BEFORE any route is registered.
 *
 * It exists for one caller: the front-door route inventory, which installs an
 * `onRoute` hook. That hook only fires for routes registered after it, so an
 * observer handed the finished server would report a shorter table than the
 * server actually serves, which is the precise failure the inventory exists to
 * prevent. Reading the router afterwards is not an alternative:
 * `printRoutes({ commonPrefix: false })` still emits a prefix TREE, so a child
 * segment appears without its full path and a parser silently drops routes.
 *
 * It is deliberately not a hook and not a decoration: nothing in the request
 * path can reach it, and a caller that does not pass it changes nothing.
 */
export interface BaseServerOptions {
  errorHandler?: (error: unknown, request: FastifyRequest, reply: FastifyReply) => void;
  observe?: (server: FastifyInstance) => void;
}

export async function createBaseServer(
  config: AppConfig,
  options: BaseServerOptions = {}
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

  options.observe?.(server);

  server.decorate("config", config);

  await server.register(helmet, { global: true });
  // The policy comes from the ROLE, not from a setting. See corsOptionsForRole.
  await server.register(cors, corsOptionsForRole(config));

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
