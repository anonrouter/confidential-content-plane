// Structural, allowlist-based logging.
//
// The previous control was pino's `redact`, which is a decoy for this threat
// model: its paths are exact-match and non-recursive, so `{ body: { messages } }`
// or `{ err }` sail straight past a `messages` / `prompt` path. It protected
// nothing that call sites were not already avoiding by discipline.
//
// The confidential data plane cannot rely on discipline. dstack collects
// container stdout, and container logs are not end-to-end encrypted even when
// `public_logs` is false, so stdout must be treated as platform-visible
// unconditionally. What protects it is this file, not the flag.
//
// Two structural controls, applied in ONE place so no call site can opt out:
//
//   1. `formatters.log` drops every field that is not on an explicit allowlist.
//      A new field is invisible until someone adds it here, which is a
//      deliberate review checkpoint rather than a silent leak.
//   2. `serializers.err` reduces any Error to a type and a code. Never a
//      message, never a stack, never `cause`. `pg` errors carry `detail` and
//      `where` that echo row values; `oidc-provider` messages embed parameter
//      echoes; provider SDK errors can embed response bodies. All neutralized
//      at once, without having to find and fix every `{ err }` call site.
//
// `redact` is kept underneath as defense in depth for the allowlisted fields.
//
// See docs/PHALA_CONFIDENTIAL_DATA_PLANE.md section 7.

import pino, { type LoggerOptions } from "pino";
import type { ContentPlaneConfig } from "./contentPlaneConfig.js";

/**
 * Every field name any log line in this codebase may emit.
 *
 * Rules for adding one:
 *   - It must be a bounded scalar: an id, an enum, a count, a duration, a
 *     status code. Never free text, never a caller-supplied string.
 *   - It must not be derived from request or response content, and must not
 *     narrow a user to a small cohort.
 *   - If you are unsure, it does not go here.
 */
export const LOGGED_FIELD_ALLOWLIST: ReadonlySet<string> = new Set([
  // Correlation and routing. Route is the Fastify template, never a URL, so
  // query strings and path parameters cannot arrive through it.
  "request_id",
  "method",
  "route",
  "path",
  "status_code",
  "latency_ms",

  // Sanitized error identity. `err` is reduced by the serializer below.
  "err",
  "error_type",
  "error_code",
  "provider_status",

  // Catalog, model, and provider metadata (public identifiers).
  "model_id",
  "provider",
  "outcome",

  // Health probing.
  "probed",
  "ok",
  "failed",
  "failures",
  "provider_errors",

  // Billing, payments, and reconciliation bookkeeping. Order and refund ids are
  // opaque internal identifiers, and these lines run only on the accounts host.
  "order_id",
  "refund_request_id",
  "manual_review",
  "attached",
  "awaiting_settlement_webhook",
  "budget_exhausted",
  "capped_dropped",
  "concurrent_advance",
  "cursor_rebootstrapped",
  "delivered",
  "duplicate_events",
  "events_ignored",
  "events_processed",
  "events_purged",
  "events_visited",
  "expired",
  "bootstrap_pages",
  "pages_listed",
  "payment_pending",
  "quarantined_events",
  "rollups_purged",
  "buckets_flushed",

  // Transactional email. `email_purpose` is a fixed enum of template names.
  "email_purpose"
]);

/**
 * Bindings the root logger may carry.
 *
 * Applied by `formatters.bindings` to `base` and to pino's own `pid`/`hostname`.
 *
 * LIMITATION, stated rather than glossed: pino does NOT run this formatter over
 * bindings passed to `logger.child({...})`, so a child binding is not filtered
 * here. Today only Fastify creates children, and it passes exactly `reqId`. The
 * gap is closed by a test that fails if any source file calls `.child(` at all
 * (tests/unit/logger-allowlist.test.ts), which is enforceable in a way a
 * runtime filter is not.
 */
const BINDING_ALLOWLIST: ReadonlySet<string> = new Set([
  "pid",
  "hostname",
  "service",
  "reqId",
  ...LOGGED_FIELD_ALLOWLIST
]);

/**
 * Event names any log line may use as its message.
 *
 * The message argument does not pass through `formatters.log` either, so
 * `logger.info({}, prompt)` printed the prompt verbatim. Every message in this
 * codebase is already a static snake_case event name; this makes that a rule
 * rather than a habit. Third-party messages are permitted only by explicit
 * pattern below.
 */
export const LOGGED_MESSAGE_ALLOWLIST: ReadonlySet<string> = new Set([
  "account_discovery_internal_failure",
  "account_restriction_expiry_failed",
  "account_restrictions_expired",
  "admin_refund_reconciliation_state_failed",
  "auth_email_delivery_failed",
  "auth_email_outbox_failed",
  "auth_email_outbox_processed",
  "authorize_disconnect_compensation_failed",
  "auto_top_up_attempts_processed",
  "auto_top_up_setup_failed",
  "auto_top_up_worker_failed",
  "catalog_metadata_push_failed",
  "crypto_checkout_failed",
  "crypto_orders_quarantined_for_review",
  "crypto_orders_reconciled",
  "crypto_orders_settled_without_webhook",
  "crypto_reconciliation_failed",
  "crypto_reconciliation_provider_errors",
  "dstack_guest_agent_unreachable",
  "embedded_payment_failed",
  "gateway_attestation_degraded",
  "gateway_attestation_failed",
  "image_settlement_pending",
  "model_health_probe_pass",
  "model_health_probe_pass_failed",
  "model_health_probe_record_failed",
  "operational_alert_delivery_failed",
  "operational_alert_delivery_processed",
  "operational_metrics_collection_failed",
  "payment_checkout_failed",
  "provider_rejection_record_failed",
  "rejection_purge_batch_capped",
  "rejection_purge_failed",
  "rejection_rollup_coverage_capped",
  "rejection_rollup_flush_failed",
  "request_complete",
  "request_error",
  "scaleway_webhook_processed",
  "server_start_failed",
  "stale_inference_reservations_released",
  "stale_reservation_recovery_failed",
  "standard_auth_handler_failed",
  "stream_error_delivery_failed",
  "stream_failed",
  "stream_settlement_pending",
  "stripe_reconciliation_failed",
  "stripe_reconciliation_processed",
  "tee_verification_cache_write_failed",
  "venice_key_manifest_registration_failed"
]);

/**
 * Third-party messages we accept verbatim. Deliberately a tiny, anchored list:
 * Fastify's boot line carries a bind address, which is operational rather than
 * content. Anything not matched here and not in the allowlist is replaced.
 */
const PERMITTED_MESSAGE_PATTERNS: readonly RegExp[] = [
  /^Server listening at (https?:\/\/|unix:)[A-Za-z0-9._:/\-[\]]{1,120}$/
];

export const UNALLOWLISTED_MESSAGE = "unallowlisted_message";

/**
 * Emitted when a log call passes fields that are not allowlisted, so a missing
 * entry is immediately visible instead of the field vanishing silently.
 */
const DROPPED_COUNT_KEY = "dropped_fields";
const DROPPED_NAMES_KEY = "dropped_field_names";
const DROPPED_MESSAGE_KEY = "dropped_message";
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const MAX_REPORTED_NAMES = 8;
/** Bound on any allowlisted string value, so a long field cannot become a channel. */
const MAX_VALUE_CHARS = 256;

/**
 * Reduce any thrown value to a content-free identity.
 *
 * Deliberately NOT pino's stdSerializers.err, which emits `message`, `stack`,
 * and `cause`. `code` is included because AnonRouter's own AppError and
 * ProviderError codes are a fixed, reviewed vocabulary; anything non-string is
 * dropped rather than coerced.
 */
export function safeErrorSerializer(value: unknown): { type: string; code?: string } {
  // Idempotent. `formatters.log` reduces `err` before pino applies serializers,
  // so this runs a second time over its own output; without this guard the
  // second pass would see a plain object and report `{ type: "object" }`,
  // silently discarding the error class that makes the line useful.
  if (
    value !== null
    && typeof value === "object"
    && !(value instanceof Error)
    && typeof (value as { type?: unknown }).type === "string"
    && Object.keys(value).every((key) => key === "type" || key === "code")
  ) {
    const reduced = value as { type: string; code?: unknown };
    return {
      type: IDENTIFIER.test(reduced.type) ? reduced.type : "Error",
      ...(typeof reduced.code === "string" && IDENTIFIER.test(reduced.code) ? { code: reduced.code } : {})
    };
  }
  if (value instanceof Error) {
    const code = (value as { code?: unknown }).code;
    // Prefer the constructor name: AnonRouter's error subclasses do not set
    // `name`, so `value.name` collapses every one of them to "Error" and loses
    // the only useful distinction the type carries.
    const constructorName = value.constructor?.name;
    const type = constructorName && constructorName !== "Object" ? constructorName : (value.name || "Error");
    return {
      type: IDENTIFIER.test(type) ? type : "Error",
      ...(typeof code === "string" && IDENTIFIER.test(code) ? { code } : {})
    };
  }
  return { type: typeof value === "string" ? "string" : typeof value };
}

/**
 * Coerce an allowlisted value to a safe scalar.
 *
 * An allowlisted KEY does not make its VALUE safe. `{ request_id: { toJSON:
 * () => prompt } }` passed the key filter and then serialized the prompt, so
 * only bounded scalars survive. The two structured exceptions are values this
 * module produced itself: the reduced `err` object, and the dropped-names array.
 */
function safeValue(key: string, value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") {
    return value.length > MAX_VALUE_CHARS ? `${value.slice(0, MAX_VALUE_CHARS)}...` : value;
  }
  // pino runs `formatters.log` BEFORE `serializers`, so this sees the raw
  // thrown value, and whatever it returns is then handed to the serializer.
  // Reducing it here (rather than duplicating the logic) keeps one definition,
  // and safeErrorSerializer is idempotent so the second pass is a no-op.
  if (key === "err" || key === "error") return safeErrorSerializer(value);
  return "[unserializable]";
}

/**
 * Drop every non-allowlisted field. Exported so tests can assert the filter
 * directly rather than only through captured stdout.
 */
export function filterLoggedFields(object: Record<string, unknown>): Record<string, unknown> {
  const kept: Record<string, unknown> = {};
  const dropped: string[] = [];
  for (const key of Object.keys(object)) {
    if (LOGGED_FIELD_ALLOWLIST.has(key)) {
      kept[key] = safeValue(key, object[key]);
    } else {
      // Key names are authored in source, not caller-supplied, but guard the
      // pathological case rather than assume it.
      dropped.push(IDENTIFIER.test(key) ? key : "invalid");
    }
  }
  if (dropped.length > 0) {
    kept[DROPPED_COUNT_KEY] = dropped.length;
    kept[DROPPED_NAMES_KEY] = dropped.slice(0, MAX_REPORTED_NAMES);
  }
  return kept;
}

/** The same filter for child-logger bindings, which bypass formatters.log. */
export function filterLoggedBindings(bindings: Record<string, unknown>): Record<string, unknown> {
  const kept: Record<string, unknown> = {};
  for (const key of Object.keys(bindings)) {
    if (BINDING_ALLOWLIST.has(key)) kept[key] = safeValue(key, bindings[key]);
  }
  return kept;
}

/** True when a message is a reviewed event name or a permitted third-party line. */
export function isAllowlistedLogMessage(message: unknown): message is string {
  if (typeof message !== "string") return false;
  if (LOGGED_MESSAGE_ALLOWLIST.has(message)) return true;
  return PERMITTED_MESSAGE_PATTERNS.some((pattern) => pattern.test(message));
}

/**
 * Normalize a log call before pino sees it.
 *
 * Closes the two channels that never touch `formatters.log`:
 *
 *   1. The MESSAGE argument. `logger.info({}, prompt)` printed the prompt
 *      verbatim. Anything not on the message allowlist becomes a placeholder.
 *   2. Printf-style INTERPOLATION. `logger.info({}, "m %s", prompt)` spliced the
 *      prompt into the message. Extra arguments are discarded outright; there is
 *      no legitimate use of them here.
 */
export function normalizeLogArguments(args: unknown[]): unknown[] {
  const [first, second] = args;
  const mergingObject = first !== null && typeof first === "object" ? first : undefined;
  const rawMessage = mergingObject ? second : first;

  if (isAllowlistedLogMessage(rawMessage)) {
    return mergingObject ? [mergingObject, rawMessage] : [rawMessage];
  }
  const flagged = { ...(mergingObject as Record<string, unknown> | undefined), [DROPPED_MESSAGE_KEY]: true };
  return [flagged, UNALLOWLISTED_MESSAGE];
}

const redactedPaths = [
  "req.headers.authorization",
  "req.headers.cookie",
  "req.headers['set-cookie']",
  "req.headers['x-api-key']",
  "res.headers['set-cookie']",
  "headers.authorization",
  "headers.cookie",
  "headers['set-cookie']",
  "headers['x-api-key']",
  "authorization",
  "cookie",
  "api_key",
  "apiKey",
  "password",
  "recovery_seed_phrase",
  "recoverySeedPhrase",
  "messages",
  "prompt",
  "completion",
  "provider_payload",
  "providerPayload",
  "request_body",
  "response_body"
];

export function createLogger(config: ContentPlaneConfig) {
  return pino(createLoggerOptions(config));
}

export function createLoggerOptions(config: ContentPlaneConfig): LoggerOptions {
  return {
    level: config.logging.level,
    // Defense in depth beneath the allowlist, not the primary control.
    redact: {
      paths: redactedPaths,
      censor: "[REDACTED]",
      remove: false
    },
    serializers: {
      err: safeErrorSerializer,
      error: safeErrorSerializer
    },
    formatters: {
      // Applied to the merged object of every log call.
      log: filterLoggedFields,
      // Applied to `base` and pino's own pid/hostname, which do not pass
      // through `log`. Not applied by pino to `logger.child({...})`; see the
      // note on BINDING_ALLOWLIST for how that gap is covered instead.
      bindings: filterLoggedBindings
    },
    hooks: {
      // Runs before pino processes the call, and is the only place that can see
      // the MESSAGE argument and any printf-style interpolation arguments.
      // Neither reaches `formatters.log`.
      logMethod(args, method) {
        return method.apply(this, normalizeLogArguments(args as unknown[]) as never);
      }
    },
    base: {
      service: "anonrouter"
    },
    messageKey: "message"
  };
}
