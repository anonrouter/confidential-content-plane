// Single-use inference tickets (control-plane owned).
//
// A ticket is a random, 30-second, single-use credential the control plane
// issues after authenticating an account. It binds the public constraints of a
// request — model, privacy tier, and maximum output tokens — plus the private
// account binding needed later to reserve credit. The relay only ever holds the
// opaque ticket id; the account binding is read exclusively by the control plane
// (see src/inference/controlPlane.ts). Lifecycle, enforced atomically in Redis:
//
//   issued ──redeem──▶ redeemed ──reserve──▶ consumed
//
// Single-use is enforced at redeem: only the first caller may move issued →
// redeemed. Replay after redeem fails closed.

import type { Redis } from "ioredis";
import { newId } from "../ids.js";
import { VALKEY_LUA_WRITE_CAPACITY_FUNCTION } from "../observability/valkey.js";
import { randomToken } from "../security/crypto.js";
import { AppError } from "../security/errors.js";
import { AUTO_PROVIDER_POLICY, providerPolicyDigest } from "../providers/routing/policy.js";

/** Digest of the Auto default policy; the fallback for legacy tickets. */
const AUTO_PROVIDER_POLICY_KEY = providerPolicyDigest(AUTO_PROVIDER_POLICY);
const AUTO_PROVIDER_POLICY_JSON = JSON.stringify(AUTO_PROVIDER_POLICY);

export const TICKET_TTL_SECONDS = 30;
/** Grace window between redeem and reserve so the relay can measure the body. */
const REDEEMED_TTL_MS = 60_000;

const issueScript = `${VALKEY_LUA_WRITE_CAPACITY_FUNCTION}
if not valkey_has_write_capacity() then
  return -1
end

redis.call('HSET', KEYS[1], unpack(ARGV, 2, #ARGV))
redis.call('EXPIRE', KEYS[1], ARGV[1])
return 1
`;

export type TicketStatus = "issued" | "redeemed" | "consumed";
export type InferenceOperation = "chat" | "embeddings" | "image" | "speech";

/**
 * The content-free speech work parameters a ticket binds. `inputChars` is the
 * exact length of the text the caller will send: it is the priced unit, so
 * binding it is what makes the reservation exact. It is a count, never text.
 */
export interface SpeechWorkParameters {
  inputChars: number;
  voice: string | null;
  responseFormat: string;
}

export interface TicketBinding {
  /** Private: only the control plane reads these. */
  accountId: string;
  accountType: "registered" | "private";
  authType: "session" | "api_key" | "management_key" | "connected_app";
  apiKeyId: string | null;
  apiKeyCreditLimitUsd: number | null;
  connectedGrantId?: string | null;
  /** Public operation binding; prevents cross-endpoint ticket reuse. */
  operation?: InferenceOperation;
  /** Public constraints the relay is allowed to learn. */
  providerName: string;
  publicModelId: string;
  /** Canonical creator/model slug shared by every provider route for the model. */
  canonicalModelId: string;
  /** The originally requested model or wildcard pattern (e.g. "mock/*"). */
  requestedModel: string;
  privacyClass: string;
  /** Public, content-free model context bound at issuance. Needed by a
   * whole-body ciphertext relay, which cannot estimate plaintext input size. */
  contextWindow?: number;
  /**
   * Canonical digest of the normalized (request-level) provider routing policy,
   * bound at issue time. The relay recomputes it from the redeemed body; a
   * mismatch is a `ticket_provider_policy_mismatch`. Tickets issued before this
   * field exists parse as the Auto default digest.
   */
  providerPolicyKey: string;
  /** The normalized request-level provider policy as JSON, re-evaluated at authorize. */
  providerPolicyJson: string;
  /**
   * The bound E2EE serving modality. E2EE (client-attested ciphertext) is a
   * distinct modality from plaintext, so a canonical model may carry both an e2ee
   * and a plaintext route; this records which one the ticket authorized. The
   * relay's TEE-header signal must match at redemption. Legacy tickets parse false.
   */
  e2ee: boolean;
  /** Null only for /auto when the caller omitted a limit. */
  maxOutputTokens: number | null;
  /** Distinguishes caller intent from an exact model's derived authorization maximum. */
  maxOutputTokensExplicit: boolean;
  /**
   * Image-only provider-work parameters bound at issue time so a redeeming body
   * cannot change the authorized size or output format (both change provider
   * cost/work). Null for non-image operations. Content-free scalars only.
   */
  imageWidth: number | null;
  imageHeight: number | null;
  imageResponseFormat: string | null;
  /**
   * Speech-only provider-work parameters bound at issue time, mirroring the
   * image fields. `speechCharacterCount` is the EXACT character count the caller
   * will send: text-to-speech is priced per character, so the count is what
   * makes the reservation exact (reserve == settle, as for a flat-priced
   * image). It is a content-free scalar — a length, never the text. Null for
   * non-speech operations.
   */
  speechCharacterCount: number | null;
  speechVoice: string | null;
  speechResponseFormat: string | null;
  /**
   * Canonical reasoning selection digest ("default" | "disabled" |
   * "effort:<level>", see src/inference/reasoning.ts). Bound at issue time so a
   * redeeming request cannot escalate or change the authorized reasoning
   * configuration. Tickets issued before this field exist parse as "default".
   */
  reasoningKey: string;
  /** Snapshot of the usage plan resolved at issue time (JSON). */
  planJson: string;
  /** Account routing defaults for /auto, resolved at issue time (JSON). */
  routingPreferencesJson: string;
  /**
   * Whether this request is funded by the account's model-locked trial
   * entitlement rather than wallet balance. Bound at issue time so authorize
   * reserves against the entitlement and the relay enforces the trial's
   * text-only surface. Tickets issued before this field exists parse false.
   */
  trial?: boolean;
}

/** The subset of a ticket the relay is permitted to see. */
export interface TicketPublicConstraints {
  operation: InferenceOperation;
  providerName: string;
  publicModelId: string;
  privacyClass: string;
  maxOutputTokens: number | null;
  reasoningKey: string;
  imageWidth: number | null;
  imageHeight: number | null;
  imageResponseFormat: string | null;
  speechCharacterCount: number | null;
  speechVoice: string | null;
  speechResponseFormat: string | null;
}

const redeemScript = `
local key = KEYS[1]
local grace_ttl_ms = tonumber(ARGV[1])
if redis.call('EXISTS', key) == 0 then return {} end
local status = redis.call('HGET', key, 'status')
if status ~= 'issued' then return {} end
redis.call('HSET', key, 'status', 'redeemed')
redis.call('PEXPIRE', key, grace_ttl_ms)
return redis.call('HGETALL', key)
`;

const consumeScript = `
local key = KEYS[1]
if redis.call('EXISTS', key) == 0 then return {} end
local status = redis.call('HGET', key, 'status')
if status ~= 'redeemed' then return {} end
redis.call('DEL', key)
return {}
`;

const consumeIntoStateScript = `${VALKEY_LUA_WRITE_CAPACITY_FUNCTION}
-- ticket_to_redemption
if not valkey_has_write_capacity() then
  return -1
end

local source = KEYS[1]
local destination = KEYS[2]
if redis.call('HGET', source, 'status') ~= 'redeemed' then return 0 end
local written = redis.call('SET', destination, ARGV[1], 'EX', ARGV[2], 'NX')
if not written then return -1 end
redis.call('DEL', source)
return 1
`;

function ticketKey(ticketId: string) {
  return `tkt:${ticketId}`;
}

function parseHash(flat: unknown): Record<string, string> | null {
  if (!Array.isArray(flat) || flat.length === 0) return null;
  const record: Record<string, string> = {};
  for (let i = 0; i + 1 < flat.length; i += 2) {
    record[String(flat[i])] = String(flat[i + 1]);
  }
  return record;
}

function bindingFromHash(hash: Record<string, string>): TicketBinding {
  return {
    accountId: hash.accountId,
    accountType: hash.accountType === "private" ? "private" : "registered",
    authType: hash.authType === "api_key" || hash.authType === "management_key" || hash.authType === "connected_app"
      ? hash.authType
      : "session",
    apiKeyId: hash.apiKeyId === "" ? null : hash.apiKeyId,
    apiKeyCreditLimitUsd: hash.apiKeyCreditLimitUsd === "" ? null : Number(hash.apiKeyCreditLimitUsd),
    connectedGrantId: hash.connectedGrantId ? hash.connectedGrantId : null,
    operation: hash.operation === "embeddings"
      ? "embeddings"
      : hash.operation === "image"
        ? "image"
        : hash.operation === "speech"
          ? "speech"
          : "chat",
    providerName: hash.providerName,
    publicModelId: hash.publicModelId,
    canonicalModelId: hash.canonicalModelId || hash.publicModelId,
    requestedModel: hash.requestedModel ?? hash.publicModelId,
    privacyClass: hash.privacyClass,
    contextWindow: Number.isSafeInteger(Number(hash.contextWindow)) && Number(hash.contextWindow) > 0
      ? Number(hash.contextWindow)
      : 0,
    providerPolicyKey: hash.providerPolicyKey || AUTO_PROVIDER_POLICY_KEY,
    providerPolicyJson: hash.providerPolicyJson || AUTO_PROVIDER_POLICY_JSON,
    e2ee: hash.e2ee === "true",
    maxOutputTokens: hash.maxOutputTokens === "" || hash.maxOutputTokens === undefined
      ? null
      : Number(hash.maxOutputTokens),
    maxOutputTokensExplicit: hash.maxOutputTokensExplicit === "true"
      || (hash.maxOutputTokensExplicit === undefined && hash.maxOutputTokens !== ""),
    imageWidth: hash.imageWidth === "" || hash.imageWidth === undefined ? null : Number(hash.imageWidth),
    imageHeight: hash.imageHeight === "" || hash.imageHeight === undefined ? null : Number(hash.imageHeight),
    imageResponseFormat: hash.imageResponseFormat === "" || hash.imageResponseFormat === undefined
      ? null
      : hash.imageResponseFormat,
    speechCharacterCount: hash.speechCharacterCount === "" || hash.speechCharacterCount === undefined
      ? null
      : Number(hash.speechCharacterCount),
    speechVoice: hash.speechVoice === "" || hash.speechVoice === undefined ? null : hash.speechVoice,
    speechResponseFormat: hash.speechResponseFormat === "" || hash.speechResponseFormat === undefined
      ? null
      : hash.speechResponseFormat,
    reasoningKey: hash.reasoningKey || "default",
    planJson: hash.planJson ?? "{}",
    routingPreferencesJson: hash.routingPreferencesJson ?? "{}",
    trial: hash.trial === "true"
  };
}

/** Issue a fresh single-use ticket and return its opaque id. */
export async function issueTicket(redis: Redis, binding: TicketBinding): Promise<string> {
  const ticketId = newId("tkt") + "_" + randomToken(18);
  const key = ticketKey(ticketId);
  const issued = Number(await redis.eval(
    issueScript,
    1,
    key,
    TICKET_TTL_SECONDS,
    "accountId", binding.accountId,
    "accountType", binding.accountType,
    "authType", binding.authType,
    "apiKeyId", binding.apiKeyId ?? "",
    "apiKeyCreditLimitUsd", binding.apiKeyCreditLimitUsd === null ? "" : String(binding.apiKeyCreditLimitUsd),
    "connectedGrantId", binding.connectedGrantId ?? "",
    "operation", binding.operation ?? "chat",
    "providerName", binding.providerName,
    "publicModelId", binding.publicModelId,
    "canonicalModelId", binding.canonicalModelId,
    "requestedModel", binding.requestedModel,
    "privacyClass", binding.privacyClass,
    "contextWindow", String(binding.contextWindow ?? 0),
    "providerPolicyKey", binding.providerPolicyKey,
    "providerPolicyJson", binding.providerPolicyJson,
    "e2ee", String(binding.e2ee),
    "maxOutputTokens", binding.maxOutputTokens === null ? "" : String(binding.maxOutputTokens),
    "maxOutputTokensExplicit", String(binding.maxOutputTokensExplicit),
    "imageWidth", binding.imageWidth === null ? "" : String(binding.imageWidth),
    "imageHeight", binding.imageHeight === null ? "" : String(binding.imageHeight),
    "imageResponseFormat", binding.imageResponseFormat ?? "",
    "speechCharacterCount", binding.speechCharacterCount === null ? "" : String(binding.speechCharacterCount),
    "speechVoice", binding.speechVoice ?? "",
    "speechResponseFormat", binding.speechResponseFormat ?? "",
    "reasoningKey", binding.reasoningKey,
    "planJson", binding.planJson,
    "routingPreferencesJson", binding.routingPreferencesJson,
    "trial", String(binding.trial ?? false),
    "status", "issued" satisfies TicketStatus
  ));
  if (issued !== 1) {
    throw new AppError(503, "protection_state_unavailable", "Protection state is temporarily unavailable");
  }
  return ticketId;
}

/**
 * Atomically redeem a ticket (issued → redeemed, single-use). Returns the full
 * binding to the control plane, or null if the ticket is missing, expired, or
 * already used.
 */
export async function redeemTicket(redis: Redis, ticketId: string): Promise<TicketBinding | null> {
  const flat = await redis.eval(redeemScript, 1, ticketKey(ticketId), REDEEMED_TTL_MS);
  const hash = parseHash(flat);
  if (!hash || !hash.accountId) return null;
  return bindingFromHash(hash);
}

/** Finalize a redeemed ticket after its reservation is created (single-use end). */
export async function consumeTicket(redis: Redis, ticketId: string): Promise<void> {
  await redis.eval(consumeScript, 1, ticketKey(ticketId));
}

/**
 * Atomically replace a redeemed ticket with its opaque control-plane state.
 * At high Valkey utilization the transition is read-only and fails closed: the
 * ticket remains redeemed until its short grace TTL, and no partial redemption
 * capability is published.
 */
export async function consumeTicketIntoState(
  redis: Redis,
  ticketId: string,
  destinationKey: string,
  value: string,
  ttlSeconds: number
): Promise<void> {
  const result = Number(await redis.eval(
    consumeIntoStateScript,
    2,
    ticketKey(ticketId),
    destinationKey,
    value,
    ttlSeconds
  ));
  if (result === -1) {
    throw new AppError(503, "protection_state_unavailable", "Protection state is temporarily unavailable");
  }
  if (result !== 1) {
    throw new AppError(409, "ticket_not_redeemable", "Inference ticket is not redeemable");
  }
}
