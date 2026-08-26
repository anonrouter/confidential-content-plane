// OpenAI Chat Completions tool-calling transport contract.
//
// AnonRouter TRANSPORTS the tool protocol; it never executes tools. OpenCode (or
// any client) owns tool/MCP execution locally. This module validates only the
// wire SHAPE and enforces defensible BOUNDS so a tool-bearing request cannot
// smuggle unbounded input past admission, and never validates the caller's
// function-argument contents against their own JSON Schema (that is the client's
// job). Everything here is content-shape only; nothing is logged or persisted.

import { z } from "zod";

/** Defensible bounds. Total request size is separately capped by the edge/body
 *  limit; these prevent a single field from dominating that budget or nesting
 *  without bound. */
export const TOOL_BOUNDS = {
  maxTools: 128,
  maxToolNameLength: 64,
  maxDescriptionBytes: 8 * 1024,
  maxToolCallIdLength: 128,
  maxArgumentsBytes: 256 * 1024,
  maxParametersSchemaBytes: 64 * 1024,
  maxParametersSchemaDepth: 12,
  maxTotalToolDefinitionBytes: 600 * 1024,
  maxToolCallsPerMessage: 64
} as const;

// OpenAI function-name grammar. Bounds length and character set so a name can
// never carry an oversized or structurally surprising payload.
export const TOOL_NAME_PATTERN = /^[a-zA-Z0-9_.-]{1,64}$/;

export function utf8ByteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

/** Maximum nesting depth of a JSON value (object/array), 1 for a scalar. */
export function jsonValueDepth(value: unknown, current = 1): number {
  if (current > TOOL_BOUNDS.maxParametersSchemaDepth + 1) return current; // short-circuit runaway
  if (Array.isArray(value)) {
    let max = current;
    for (const item of value) max = Math.max(max, jsonValueDepth(item, current + 1));
    return max;
  }
  if (value && typeof value === "object") {
    let max = current;
    for (const nested of Object.values(value as Record<string, unknown>)) {
      max = Math.max(max, jsonValueDepth(nested, current + 1));
    }
    return max;
  }
  return current;
}

/** A JSON Schema object for `function.parameters`. Its contents are opaque to
 *  AnonRouter; only serialized size and nesting depth are bounded. */
const parametersSchema = z.record(z.unknown()).superRefine((value, ctx) => {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "function.parameters must be JSON-serializable" });
    return;
  }
  if (utf8ByteLength(serialized) > TOOL_BOUNDS.maxParametersSchemaBytes) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "function.parameters exceeds the maximum JSON Schema size" });
  }
  if (jsonValueDepth(value) > TOOL_BOUNDS.maxParametersSchemaDepth) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "function.parameters exceeds the maximum JSON Schema nesting depth" });
  }
});

/** A single function tool definition. */
export const toolDefinitionSchema = z
  .object({
    type: z.literal("function"),
    function: z
      .object({
        name: z.string().regex(TOOL_NAME_PATTERN, "tool function name is invalid or too long"),
        description: z
          .string()
          .refine((value) => utf8ByteLength(value) <= TOOL_BOUNDS.maxDescriptionBytes, "tool description is too large")
          .optional(),
        parameters: parametersSchema.optional(),
        strict: z.boolean().nullable().optional()
      })
      .strict()
  })
  .strict();

export type ToolDefinition = z.infer<typeof toolDefinitionSchema>;

/** Top-level `tools`: a bounded array of function definitions whose combined
 *  serialized size is capped. */
export const toolsSchema = z
  .array(toolDefinitionSchema)
  .min(1)
  .max(TOOL_BOUNDS.maxTools)
  .superRefine((tools, ctx) => {
    let total = 0;
    for (const tool of tools) total += utf8ByteLength(JSON.stringify(tool));
    if (total > TOOL_BOUNDS.maxTotalToolDefinitionBytes) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "tool definitions exceed the maximum combined size" });
    }
  });

/** `tool_choice`: "auto" | "none" | "required" | a named function selection. */
export const toolChoiceSchema = z.union([
  z.enum(["auto", "none", "required"]),
  z
    .object({
      type: z.literal("function"),
      function: z.object({ name: z.string().regex(TOOL_NAME_PATTERN) }).strict()
    })
    .strict()
]);

/** A single assistant tool call on the wire. `arguments` stays a JSON STRING and
 *  is NEVER parsed, joined, reordered, or validated against the tool schema. */
export const toolCallSchema = z
  .object({
    id: z.string().min(1).max(TOOL_BOUNDS.maxToolCallIdLength),
    type: z.literal("function"),
    function: z
      .object({
        name: z.string().regex(TOOL_NAME_PATTERN),
        arguments: z
          .string()
          .refine((value) => utf8ByteLength(value) <= TOOL_BOUNDS.maxArgumentsBytes, "tool call arguments are too large")
      })
      .strict()
  });

// Deliberately do not make the outer wrapper strict. OpenCode preserves a
// provider `cache_control` extension on assistant tool-call items when it sends
// the local tool result back. The extension is not part of the OpenAI transport
// contract AnonRouter forwards, so Zod strips it while the security-relevant
// id/type/function fields above remain fully validated and bounded.

export type ToolCall = z.infer<typeof toolCallSchema>;

/** UTF-8 bytes attributable to a set of tool definitions + tool_choice, used to
 *  raise the conservative input-token ceiling (a byte can cost a token). */
export function toolDefinitionBytes(tools: ToolDefinition[] | undefined, toolChoice: unknown): number {
  let bytes = 0;
  if (tools) for (const tool of tools) bytes += utf8ByteLength(JSON.stringify(tool));
  if (toolChoice !== undefined) bytes += utf8ByteLength(JSON.stringify(toolChoice));
  return bytes;
}

/** UTF-8 bytes attributable to a message's assistant tool calls (names + the
 *  argument strings), used for input ceiling and fallback output accounting. */
export function toolCallBytes(toolCalls: ToolCall[] | undefined): number {
  if (!toolCalls) return 0;
  let bytes = 0;
  for (const call of toolCalls) {
    bytes += utf8ByteLength(call.id) + utf8ByteLength(call.function.name) + utf8ByteLength(call.function.arguments);
  }
  return bytes;
}
