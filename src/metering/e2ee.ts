// Credit reservation for Venice E2EE requests.
//
// The relay never sees plaintext for an E2EE request, so it must NOT reuse the
// ordinary plaintext estimator (src/metering/tokens.ts). Instead it bounds the
// input from the ciphertext length, per the locked formula
// (docs/HIGH_PRIVACY_INFERENCE_IMPLEMENTATION_PLAN.md §6.3):
//
//   input ceiling = Σ_messages max(0, decodedContentBytes − protocolOverhead)
//                   + 128 tokens per message (framing)
//                   + 512 request-level safety tokens
//   capped at the model context window.
//
// Venice legacy overhead is 93 bytes (65-byte uncompressed ephemeral public
// key + 12-byte GCM nonce + 16-byte tag). NEAR v2 overhead is 72 bytes (32-byte
// ephemeral X25519 key + 24-byte XChaCha20 nonce + 16-byte Poly1305 tag). The
// remaining ciphertext payload equals the plaintext byte length, and a token
// encodes at least one byte, so this is a rigorous upper bound and therefore
// billing-safe (over-reservation is refunded on settlement).

import { AppError } from "../security/errors.js";
import type { ChatMessage } from "../providers/types.js";

export type E2eeProtocol = "near-v2" | "venice-legacy";

/** NEAR v2: ephemeral X25519 key + XChaCha20 nonce + Poly1305 tag. */
export const NEAR_V2_E2EE_PROTOCOL_OVERHEAD_BYTES = 32 + 24 + 16;
/** Venice legacy: uncompressed secp256k1 key + AES-GCM nonce + tag. */
export const VENICE_E2EE_PROTOCOL_OVERHEAD_BYTES = 65 + 12 + 16;
/** Backward-compatible export for the original Venice-only estimator. */
export const E2EE_PROTOCOL_OVERHEAD_BYTES = VENICE_E2EE_PROTOCOL_OVERHEAD_BYTES;
export const E2EE_PER_MESSAGE_FRAMING_TOKENS = 128;
export const E2EE_REQUEST_SAFETY_TOKENS = 512;

function protocolOverhead(protocol: E2eeProtocol): number {
  return protocol === "near-v2"
    ? NEAR_V2_E2EE_PROTOCOL_OVERHEAD_BYTES
    : VENICE_E2EE_PROTOCOL_OVERHEAD_BYTES;
}

function isHexString(value: string): boolean {
  return value.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(value);
}

/** Decoded byte length of a hex string without allocating the buffer. */
function decodedHexBytes(value: string): number {
  return Math.floor(value.length / 2);
}

/**
 * Validate that an E2EE request only carries the supported surface:
 * `user`/`system`/`assistant` text messages (assistant turns are conversation
 * history the client re-sends each turn, exactly like any stateless chat API),
 * streaming, and a bounded `max_tokens`. Anything else (tools, files, images, web
 * search, non-hex content) fails closed. The input ceiling is derived from the
 * ciphertext length of every message (see estimateE2EEInputCeiling), so multi-turn
 * history is metered correctly without the relay ever seeing plaintext.
 */
export function assertE2EESupported(params: {
  messages: ChatMessage[];
  stream: boolean;
  maxOutputTokens: number;
  protocol?: E2eeProtocol;
}): void {
  if (!params.stream) {
    throw new AppError(400, "e2ee_requires_streaming", "E2EE requests must use streaming");
  }
  if (!Number.isInteger(params.maxOutputTokens) || params.maxOutputTokens <= 0) {
    throw new AppError(400, "e2ee_requires_max_tokens", "E2EE requests must set a bounded max_tokens");
  }
  for (const message of params.messages) {
    if (message.role !== "user" && message.role !== "system" && message.role !== "assistant") {
      throw new AppError(400, "e2ee_unsupported_role", "E2EE accepts only user, system, and assistant messages");
    }
    if (message.tool_call_id !== undefined) {
      throw new AppError(400, "e2ee_tools_unsupported", "E2EE does not support tool messages");
    }
    if (typeof message.content !== "string" || !isHexString(message.content)) {
      throw new AppError(400, "e2ee_invalid_ciphertext", "E2EE message content must be hex ciphertext");
    }
    const minEncryptedHexLength = (protocolOverhead(params.protocol ?? "venice-legacy") + 1) * 2;
    if (message.content.length < minEncryptedHexLength) {
      throw new AppError(400, "e2ee_invalid_ciphertext", "E2EE ciphertext is shorter than the protocol minimum");
    }
  }
}

/**
 * Conservative input-token ceiling for an E2EE request, derived only from
 * ciphertext lengths (never from plaintext). Assumes messages have already
 * passed {@link assertE2EESupported}.
 */
export function estimateE2EEInputCeiling(
  messages: ChatMessage[],
  contextWindow: number,
  protocol: E2eeProtocol = "venice-legacy"
): number {
  let ceiling = E2EE_REQUEST_SAFETY_TOKENS;
  for (const message of messages) {
    const content = typeof message.content === "string" ? message.content : "";
    const payloadBytes = Math.max(0, decodedHexBytes(content) - protocolOverhead(protocol));
    ceiling += payloadBytes + E2EE_PER_MESSAGE_FRAMING_TOKENS;
  }
  return Math.min(ceiling, Math.max(1, contextWindow));
}
