/**
 * Return true only when an OpenAI-compatible SSE chunk contains generated
 * output. Role-only, finish, usage, malformed, and [DONE] frames are not a
 * token boundary and must not make the dashboard look faster than it is.
 *
 * Parsing is transient: the caller stores only elapsed milliseconds, never the
 * parsed value or raw model output.
 */
export function hasOutputBearingOpenAiDelta(chunk: string): boolean {
  const dataLines = chunk
    .replaceAll("\r\n", "\n")
    .split("\n")
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trimStart());

  for (const data of dataLines) {
    if (!data || data === "[DONE]") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      continue;
    }
    if (!parsed || typeof parsed !== "object") continue;
    const choices = (parsed as { choices?: unknown }).choices;
    if (!Array.isArray(choices)) continue;

    for (const choice of choices) {
      if (!choice || typeof choice !== "object") continue;
      const delta = (choice as { delta?: unknown }).delta;
      if (!delta || typeof delta !== "object") continue;
      const output = delta as Record<string, unknown>;
      if (
        meaningful(output.content)
        || meaningful(output.reasoning_content)
        || meaningful(output.reasoning)
        || meaningful(output.refusal)
        || meaningful(output.tool_calls)
        || meaningful(output.function_call)
        || meaningful(output.audio)
      ) {
        return true;
      }
    }
  }
  return false;
}

function meaningful(value: unknown): boolean {
  if (typeof value === "string") return value.length > 0;
  if (Array.isArray(value)) return value.some(meaningful);
  if (value && typeof value === "object") return Object.values(value).some(meaningful);
  return false;
}
