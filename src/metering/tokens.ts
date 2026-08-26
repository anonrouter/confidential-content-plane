import { countImageParts, type ChatMessage } from "../providers/types.js";
import { toolCallBytes, toolDefinitionBytes, type ToolDefinition } from "../providers/tools.js";

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  cachedTokens: number;
  /**
   * Provider-reported prompt tokens written to cache. Optional on the wire so
   * rolling deployments remain compatible with older workers; normalization
   * and persistence treat an omitted value as zero.
   */
  cacheWriteTokens?: number;
}

/**
 * Admission uses a deliberately conservative ceiling instead of a tokenizer
 * guess. Modern LLM tokenizers can always fall back to byte-level tokens, so a
 * UTF-8 byte may cost one token in the worst case. Counting bytes prevents
 * multi-byte Unicode (emoji, combining text, unusual scripts) from being
 * admitted under the much smaller `string.length / 4` English-text estimate.
 *
 * The per-message and request allowances cover chat-template/framing tokens.
 * Provider-owned system prompts are disabled by the Venice adapter; allowing
 * an unbounded hidden provider prompt would make a local upper bound impossible.
 */
export const INPUT_CEILING_PER_MESSAGE_TOKENS = 128;
export const INPUT_CEILING_REQUEST_SAFETY_TOKENS = 512;
/**
 * Conservative admission surcharge per image content part. Vision models bill
 * an image as prompt tokens the relay cannot compute locally (it depends on the
 * provider's tiling), so each image reserves this flat ceiling; settlement
 * still prefers the provider's actual usage. Image bytes are NEVER counted as
 * text and never leave the request path.
 */
export const INPUT_CEILING_PER_IMAGE_TOKENS = 2_000;

function utf8Bytes(value: string | undefined): number {
  return value ? Buffer.byteLength(value, "utf8") : 0;
}

export function estimateTextTokens(text: string) {
  if (!text) {
    return 0;
  }
  return Math.max(1, Math.ceil(text.length / 4));
}

/**
 * Billing-safe upper bound for the prompt tokens attributable to a request.
 * This is used only for admission, rate limiting, and reserving the maximum
 * possible charge. Settlement continues to prefer the provider's actual usage.
 */
export function estimateInputTokenCeiling(messages: ChatMessage[]) {
  let ceiling = INPUT_CEILING_REQUEST_SAFETY_TOKENS;
  for (const message of messages) {
    ceiling += INPUT_CEILING_PER_MESSAGE_TOKENS;
    ceiling += utf8Bytes(message.role);
    ceiling += utf8Bytes(messageText(message.content));
    ceiling += utf8Bytes(message.name);
    ceiling += utf8Bytes(message.tool_call_id);
    // Assistant tool-call names + JSON argument strings and tool-result content
    // (counted above via message.content for role:"tool") are billable input on
    // the next turn. A tool-call turn is never zero-cost input.
    ceiling += toolCallBytes(message.tool_calls);
    // Image parts are excluded from the text flattening above; each one adds a
    // flat conservative surcharge instead of its (much larger) data-URL bytes.
    ceiling += countImageParts(message.content) * INPUT_CEILING_PER_IMAGE_TOKENS;
  }
  return ceiling;
}

/**
 * Extra conservative input-token ceiling for the request's tool definitions and
 * tool_choice. A UTF-8 byte can cost a token in the worst case, so a large tool
 * schema raises the reservation and can never be admitted as zero-cost input.
 */
export function estimateToolInputCeiling(tools: ToolDefinition[] | undefined, toolChoice: unknown): number {
  return toolDefinitionBytes(tools, toolChoice);
}

/**
 * Fallback output-token estimate for one choice's generated output: assistant
 * text PLUS tool-call names and JSON argument strings. Used only when the
 * provider omits usage; provider-reported usage always wins. A tool-only
 * response (content null, tool_calls present) is therefore never zero output.
 * Accepts a `delta` (streaming) or `message` (non-streaming) shape.
 */
export function estimateChoiceOutputTokens(source: { content?: unknown; tool_calls?: unknown } | undefined): number {
  if (!source) return 0;
  let tokens = typeof source.content === "string" ? estimateTextTokens(source.content) : 0;
  if (Array.isArray(source.tool_calls)) {
    for (const call of source.tool_calls) {
      const fn = (call as { function?: { name?: unknown; arguments?: unknown } })?.function;
      if (typeof fn?.name === "string") tokens += estimateTextTokens(fn.name);
      if (typeof fn?.arguments === "string") tokens += estimateTextTokens(fn.arguments);
    }
  }
  return tokens;
}

export function messageText(content: unknown): string {
  if (typeof content === "string") {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (part && typeof part === "object" && "text" in part && typeof part.text === "string") {
          return part.text;
        }
        // Non-text parts (image_url) carry no billable text; the admission
        // ceiling accounts for images via a flat per-image surcharge instead.
        return "";
      })
      .join(" ");
  }
  return "";
}

export function estimateInputTokens(messages: ChatMessage[]) {
  const contentTokens = messages.reduce((total, message) => total + estimateTextTokens(messageText(message.content)), 0);
  return contentTokens + messages.length * 4;
}

export function normalizeUsage(usage: Partial<TokenUsage> | undefined, fallback: TokenUsage): TokenUsage {
  return {
    inputTokens: Number.isFinite(usage?.inputTokens) ? Math.max(0, Math.floor(usage?.inputTokens ?? 0)) : fallback.inputTokens,
    outputTokens: Number.isFinite(usage?.outputTokens) ? Math.max(0, Math.floor(usage?.outputTokens ?? 0)) : fallback.outputTokens,
    cachedTokens: Number.isFinite(usage?.cachedTokens) ? Math.max(0, Math.floor(usage?.cachedTokens ?? 0)) : fallback.cachedTokens,
    cacheWriteTokens: Number.isFinite(usage?.cacheWriteTokens)
      ? Math.max(0, Math.floor(usage?.cacheWriteTokens ?? 0))
      : (fallback.cacheWriteTokens ?? 0)
  };
}
