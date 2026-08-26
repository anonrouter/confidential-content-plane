// Centralized, tested translation from AnonRouter AppError codes / HTTP statuses
// to the OpenAI error envelope that OpenAI-compatible clients parse:
//
//   { "error": { "message", "type", "param", "code" } }
//
// Clients (the official OpenAI SDK and AnonRouter's own SDK) classify primarily
// by HTTP status, so the STATUS is authoritative; `type`/`code` add fidelity.
// Server-class errors (`api_error`) always carry a generic message so no
// internal service name, provider body, account id, key hash, ticket id, or
// stack ever reaches a client. Ambiguous internal-invariant failures (a ticket
// binding conflict that parity should make impossible) are sanitized to a
// generic server error rather than surfaced as a confusing 4xx.

import { AppError } from "../security/errors.js";

export interface OpenAiErrorEnvelope {
  error: {
    message: string;
    type: string;
    param: string | null;
    code: string | null;
  };
}

export interface OpenAiError {
  status: number;
  body: OpenAiErrorEnvelope;
  retryAfterSeconds?: number;
}

interface Mapping {
  status: number;
  type: string;
  code: string | null;
  param?: string | null;
  /** Override message; otherwise the incoming message is used for 4xx and a
   *  generic message for server-class (`api_error`) responses. */
  message?: string;
}

const GENERIC_SERVER_MESSAGE = "The server had an error while processing your request.";

// Keyed on the AnonRouter AppError.code. Anything not listed falls back by HTTP
// status. model_not_chat / model_not_embedding collapse to model_not_found so an
// incompatible model reads as a single OpenAI-canonical "model does not exist".
const CODE_MAP: Record<string, Mapping> = {
  // Authentication — the caller's ar_ key.
  unauthorized: { status: 401, type: "authentication_error", code: "invalid_api_key", message: "Invalid API key provided." },
  invalid_api_key: { status: 401, type: "authentication_error", code: "invalid_api_key", message: "Invalid API key provided." },

  // Permission — the key or the deployment is not enabled for compat.
  compat_scope_required: {
    status: 403,
    type: "permission_error",
    code: "compat_scope_required",
    message: "This API key is not enabled for OpenAI-compatible tool access. Enable it in the dashboard, or use the private ticket flow."
  },
  compat_unavailable: {
    status: 403,
    type: "permission_error",
    code: "compat_unavailable",
    message: "OpenAI-compatible access is not available."
  },
  insufficient_scope: { status: 403, type: "permission_error", code: "insufficient_scope", message: "This API key does not have the required scope." },

  // Model — unknown, disabled, or incompatible for the operation.
  model_not_found: { status: 404, type: "invalid_request_error", code: "model_not_found", param: "model" },
  model_not_chat: { status: 404, type: "invalid_request_error", code: "model_not_found", param: "model", message: "The requested model is not a chat model." },
  model_not_embedding: { status: 404, type: "invalid_request_error", code: "model_not_found", param: "model", message: "The requested model is not an embeddings model." },

  // Malformed request.
  invalid_request: { status: 400, type: "invalid_request_error", code: null },
  conflicting_output_token_limits: { status: 400, type: "invalid_request_error", code: "conflicting_output_token_limits", param: "max_tokens" },
  reasoning_conflict: { status: 400, type: "invalid_request_error", code: "reasoning_conflict", param: "reasoning" },
  reasoning_requires_explicit_model: { status: 400, type: "invalid_request_error", code: "reasoning_requires_explicit_model", param: "model" },
  max_output_tokens_exceeds_model_limit: { status: 400, type: "invalid_request_error", code: "max_tokens_exceeded", param: "max_tokens" },
  streaming_not_supported: { status: 400, type: "invalid_request_error", code: "streaming_not_supported", param: "stream" },
  model_not_e2ee: { status: 400, type: "invalid_request_error", code: "invalid_request_error" },
  unsupported_endpoint: { status: 404, type: "invalid_request_error", code: "unsupported_endpoint" },
  // Tool calling.
  tools_not_supported: { status: 400, type: "invalid_request_error", code: "tools_not_supported", param: "tools", message: "The requested model does not support tool calling." },
  no_tools_capable_model: { status: 400, type: "invalid_request_error", code: "no_tools_capable_model", param: "tools", message: "No tools-capable model is available for automatic routing." },
  e2ee_tools_unsupported: { status: 400, type: "invalid_request_error", code: "e2ee_tools_unsupported", param: "tools" },
  // Vision (image input).
  model_not_vision: { status: 400, type: "invalid_request_error", code: "model_not_vision", param: "messages", message: "The requested model does not support image input." },
  no_vision_capable_model: { status: 400, type: "invalid_request_error", code: "no_vision_capable_model", param: "messages", message: "No vision-capable model is available for automatic routing." },
  e2ee_vision_unsupported: { status: 400, type: "invalid_request_error", code: "e2ee_vision_unsupported", param: "messages" },
  // A compat (static-key) request must never also carry a ticket; the broker
  // mints its own. Fail closed rather than pick a credential path.
  conflicting_credentials: { status: 400, type: "invalid_request_error", code: "conflicting_credentials", param: null, message: "A request must present either a static API key or a single-use ticket, not both." },

  // Quota / balance.
  insufficient_balance: { status: 402, type: "insufficient_quota", code: "insufficient_quota", message: "You have insufficient credits for this request." },
  credit_limit_exceeded: { status: 402, type: "insufficient_quota", code: "insufficient_quota", message: "This API key has reached its credit limit." },

  // Rate / concurrency.
  rate_limited: { status: 429, type: "rate_limit_error", code: "rate_limit_exceeded", message: "Rate limit reached. Please slow down." },
  concurrency_limited: { status: 429, type: "rate_limit_error", code: "rate_limit_exceeded", message: "Too many concurrent requests." },

  // Provider / upstream availability — generic server errors.
  router_unavailable: { status: 503, type: "api_error", code: "server_error" },
  router_timeout: { status: 503, type: "api_error", code: "server_error" },
  relay_unavailable: { status: 502, type: "api_error", code: "server_error" },
  provider_stream_error: { status: 502, type: "api_error", code: "server_error" },
  provider_stream_incomplete: { status: 502, type: "api_error", code: "server_error" },

  // Internal-only signals that must never reveal the split to a client. A wrong
  // service token, or a ticket-binding conflict that parity should prevent, is a
  // server fault — sanitize to a generic 5xx, never a confusing 401/409.
  service_unauthorized: { status: 500, type: "api_error", code: "server_error" },
  invalid_ticket: { status: 503, type: "api_error", code: "server_error" },
  ticket_required: { status: 503, type: "api_error", code: "server_error" },
  ticket_operation_mismatch: { status: 500, type: "api_error", code: "server_error" },
  ticket_model_mismatch: { status: 500, type: "api_error", code: "server_error" },
  ticket_reasoning_mismatch: { status: 500, type: "api_error", code: "server_error" },
  ticket_output_limit_mismatch: { status: 500, type: "api_error", code: "server_error" },
  control_rpc_timeout: { status: 503, type: "api_error", code: "server_error" },
  control_authorize_timeout: { status: 503, type: "api_error", code: "server_error" }
};

function fallbackByStatus(status: number): Mapping {
  if (status === 400) return { status: 400, type: "invalid_request_error", code: null };
  if (status === 401) return { status: 401, type: "authentication_error", code: "invalid_api_key", message: "Invalid API key provided." };
  if (status === 402) return { status: 402, type: "insufficient_quota", code: "insufficient_quota" };
  if (status === 403) return { status: 403, type: "permission_error", code: null };
  if (status === 404) return { status: 404, type: "invalid_request_error", code: null };
  if (status === 409) return { status: 500, type: "api_error", code: "server_error" };
  if (status === 429) return { status: 429, type: "rate_limit_error", code: "rate_limit_exceeded" };
  // Any other 4xx is treated as a request problem; 5xx (and unknown) as a server error.
  if (status >= 400 && status < 500) return { status, type: "invalid_request_error", code: null };
  return { status: status >= 500 ? status : 500, type: "api_error", code: "server_error" };
}

function resolveMessage(mapping: Mapping, incomingMessage: string): string {
  if (mapping.message) return mapping.message;
  if (mapping.type === "api_error") return GENERIC_SERVER_MESSAGE;
  return incomingMessage.trim() || "The request could not be completed.";
}

/** Build an OpenAI envelope from an explicit AnonRouter (status, code, message). */
export function toOpenAiError(status: number, code: string, message: string, retryAfterSeconds?: number): OpenAiError {
  const mapping = CODE_MAP[code] ?? fallbackByStatus(status);
  return {
    status: mapping.status,
    body: {
      error: {
        message: resolveMessage(mapping, message),
        type: mapping.type,
        param: mapping.param ?? null,
        code: mapping.code
      }
    },
    ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {})
  };
}

/** Map any thrown value (AppError, RelayLimitError, unknown) to an OpenAI error. */
export function openAiErrorFromUnknown(error: unknown): OpenAiError {
  if (error instanceof AppError) {
    const retryAfterSeconds = (error as AppError & { retryAfterSeconds?: number }).retryAfterSeconds;
    return toOpenAiError(error.statusCode, error.code, error.message, typeof retryAfterSeconds === "number" ? retryAfterSeconds : undefined);
  }
  return {
    status: 500,
    body: { error: { message: GENERIC_SERVER_MESSAGE, type: "api_error", param: null, code: "server_error" } }
  };
}
