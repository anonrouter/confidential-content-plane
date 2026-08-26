import { estimateChoiceOutputTokens } from "../metering/tokens.js";
import type { TokenUsage } from "../metering/tokens.js";
import { ProviderError } from "../security/errors.js";

export interface SseParseResult {
  usage?: TokenUsage;
  estimatedOutputTokens: number;
  providerRequestId?: string;
}

export function openAiUsageToInternal(usage: unknown): TokenUsage | undefined {
  if (!usage || typeof usage !== "object") {
    return undefined;
  }
  const candidate = usage as {
    prompt_tokens?: unknown;
    completion_tokens?: unknown;
    total_tokens?: unknown;
    prompt_tokens_details?: {
      cached_tokens?: unknown;
      cache_creation_input_tokens?: unknown;
      cache_write_tokens?: unknown;
    };
  };
  const inputTokens = Number(candidate.prompt_tokens ?? 0);
  const outputTokens = Number(candidate.completion_tokens ?? 0);
  const cachedTokens = Number(candidate.prompt_tokens_details?.cached_tokens ?? 0);
  const cacheWriteTokens = Number(
    candidate.prompt_tokens_details?.cache_creation_input_tokens
      ?? candidate.prompt_tokens_details?.cache_write_tokens
      ?? 0
  );

  if (!Number.isFinite(inputTokens) && !Number.isFinite(outputTokens)) {
    return undefined;
  }

  return {
    inputTokens: Math.max(0, Math.floor(inputTokens)),
    outputTokens: Math.max(0, Math.floor(outputTokens)),
    cachedTokens: Math.max(0, Math.floor(cachedTokens)),
    cacheWriteTokens: Math.max(0, Math.floor(cacheWriteTokens))
  };
}

function contentDeltaTokens(value: unknown) {
  if (!value || typeof value !== "object") {
    return 0;
  }
  const choices = (value as { choices?: Array<{ delta?: unknown; message?: unknown }> }).choices;
  if (!Array.isArray(choices)) {
    return 0;
  }
  // Content AND tool-call deltas are generated output. Argument strings stream in
  // fragments across chunks; each fragment's estimate accumulates the total, so a
  // tool-only stream is never billed as zero output when the provider omits usage.
  return choices.reduce(
    (total, choice) => total + estimateChoiceOutputTokens((choice.delta ?? choice.message) as { content?: unknown; tool_calls?: unknown } | undefined),
    0
  );
}

/** True when any choice carries a terminal finish_reason (stop/length/tool_calls…). */
function hasFinishReason(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const choices = (value as { choices?: Array<{ finish_reason?: unknown }> }).choices;
  return Array.isArray(choices) && choices.some((choice) => choice != null && choice.finish_reason != null);
}

export async function* proxyOpenAiSse(
  body: ReadableStream<Uint8Array>,
  onDone: (result: SseParseResult) => void,
  // Some OpenAI-compatible providers (AWS Bedrock Mantle) terminate their SSE by
  // closing the connection after the final finish_reason/usage chunk WITHOUT the
  // `[DONE]` sentinel. `acceptEofAfterFinish` treats a clean EOF that follows a
  // terminal finish_reason as a valid completion, while still failing closed on a
  // genuine mid-stream truncation (EOF before any finish_reason arrived).
  options: { acceptEofAfterFinish?: boolean } = {}
): AsyncIterable<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let usage: TokenUsage | undefined;
  let estimatedOutputTokens = 0;
  let terminalDone = false;
  let sawFinishReason = false;
  let providerRequestId: string | undefined;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        const terminated = terminalDone || (options.acceptEofAfterFinish === true && sawFinishReason);
        if (!terminated) {
          throw new ProviderError(
            "provider_stream_incomplete",
            "Provider stream ended before its terminal marker",
            502
          );
        }
        return;
      }
      buffer += decoder.decode(value, { stream: true });
      buffer = buffer.replace(/\r\n/g, "\n");

      let boundary = buffer.indexOf("\n\n");
      while (boundary !== -1) {
        const event = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const dataLines = event
          .split(/\r?\n/)
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trimStart());

        for (const data of dataLines) {
          if (data === "[DONE]") {
            terminalDone = true;
            // [DONE] is a provider-to-worker terminal marker, not yet a public
            // completion promise. The relay emits its own [DONE] only after the
            // usage sideband has arrived and durable settlement succeeds.
            return;
          }
          try {
            const parsed = JSON.parse(data) as { id?: unknown; usage?: unknown };
            if (!providerRequestId && typeof parsed.id === "string" && parsed.id.length <= 256) {
              providerRequestId = parsed.id;
            }
            usage = openAiUsageToInternal(parsed.usage) ?? usage;
            estimatedOutputTokens += contentDeltaTokens(parsed);
            if (hasFinishReason(parsed)) sawFinishReason = true;
          } catch {
            // Forward provider-compatible SSE even if an extension event is not JSON.
          }
          yield `data: ${data}\n\n`;
        }

        boundary = buffer.indexOf("\n\n");
      }
    }
  } finally {
    await reader.cancel().catch(() => undefined);
    onDone({ usage, estimatedOutputTokens, providerRequestId });
  }
}
