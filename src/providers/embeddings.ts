import { z } from "zod";
import type { TokenUsage } from "../metering/tokens.js";
import type { ModelRecord, ProviderDispatchAuthorization } from "./types.js";
import { ProviderError } from "../security/errors.js";

const embeddingTextSchema = z.string().min(1).max(200_000);

/**
 * Public OpenAI-compatible embedding subset. Token-id arrays are intentionally
 * not accepted: AnonRouter cannot conservatively validate their tokenizer or
 * provider-specific token vocabulary at the relay boundary.
 */
export const embeddingRequestSchema = z
  .object({
    model: z.string().min(1).max(256),
    input: z.union([
      embeddingTextSchema,
      z.array(embeddingTextSchema).min(1).max(2_048)
    ]),
    encoding_format: z.enum(["float", "base64"]).optional().default("float"),
    dimensions: z.number().int().positive().max(65_536).optional(),
    // Venice documents this as an unused OpenAI-compatibility field.
    user: z.string().max(256).optional()
  })
  .strict();

export type EmbeddingRequestBody = z.infer<typeof embeddingRequestSchema>;
export type EmbeddingOperation = "embeddings";

export function embeddingInputs(input: EmbeddingRequestBody["input"]): string[] {
  return typeof input === "string" ? [input] : input;
}

/**
 * UTF-8 bytes are a tokenizer-independent upper bound for ordinary text
 * tokenizers. The small fixed/per-item allowance covers special tokens and
 * framing while keeping reservation strictly content-free.
 */
export function estimateEmbeddingInputTokenCeiling(input: EmbeddingRequestBody["input"]): number {
  const values = embeddingInputs(input);
  return 32 + values.length * 8 + values.reduce((sum, value) => sum + Buffer.byteLength(value, "utf8"), 0);
}

export function estimateEmbeddingInputTokens(input: EmbeddingRequestBody["input"]): number {
  return embeddingInputs(input).reduce((sum, value) => sum + Math.max(1, Math.ceil(value.length / 4)), 0);
}

export interface EmbeddingProviderRequest {
  requestId: string;
  model: ModelRecord;
  body: EmbeddingRequestBody;
  signal?: AbortSignal;
  onProviderAttempt?: () => Promise<ProviderDispatchAuthorization | void>;
}

export interface EmbeddingItem {
  object: "embedding";
  index: number;
  embedding: number[] | string;
}

export interface EmbeddingResponse {
  object: "list";
  data: EmbeddingItem[];
  model: string;
  usage: {
    prompt_tokens: number;
    total_tokens: number;
  };
}

export interface EmbeddingProviderResult {
  response: EmbeddingResponse;
  usage: TokenUsage;
  providerRequestId?: string;
}

function invalidProviderResponse(): never {
  throw new ProviderError("provider_invalid_json", "Provider returned an invalid embedding response", 502);
}

function finiteFloatVector(value: unknown, expectedDimensions?: number): value is number[] {
  return Array.isArray(value)
    && value.length > 0
    && (expectedDimensions === undefined || value.length === expectedDimensions)
    && value.every((entry) => typeof entry === "number" && Number.isFinite(entry));
}

function base64VectorDimensions(value: unknown): number | null {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return null;
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length === 0 || bytes.length % Float32Array.BYTES_PER_ELEMENT !== 0) return null;
  for (let offset = 0; offset < bytes.length; offset += Float32Array.BYTES_PER_ELEMENT) {
    if (!Number.isFinite(bytes.readFloatLE(offset))) return null;
  }
  return bytes.length / Float32Array.BYTES_PER_ELEMENT;
}

/**
 * Validate and normalize the provider response before it crosses the worker
 * boundary. Only the OpenAI response contract and numeric vectors survive;
 * provider extensions and malformed values are dropped by failing closed.
 */
export function normalizeEmbeddingResponse(
  raw: unknown,
  request: Pick<EmbeddingRequestBody, "input" | "encoding_format" | "dimensions">,
  fallbackModel: string
): { response: EmbeddingResponse; usage: TokenUsage } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) invalidProviderResponse();
  const record = raw as Record<string, unknown>;
  const expectedCount = embeddingInputs(request.input).length;
  if (record.object !== "list" || !Array.isArray(record.data) || record.data.length !== expectedCount) {
    invalidProviderResponse();
  }

  const byIndex = new Map<number, EmbeddingItem>();
  let vectorDimensions = request.dimensions;
  for (const rawItem of record.data) {
    if (!rawItem || typeof rawItem !== "object" || Array.isArray(rawItem)) invalidProviderResponse();
    const item = rawItem as Record<string, unknown>;
    const index = item.index;
    if (!Number.isInteger(index) || (index as number) < 0 || (index as number) >= expectedCount || byIndex.has(index as number)) {
      invalidProviderResponse();
    }
    const embedding = item.embedding;
    const dimensions = request.encoding_format === "base64"
      ? base64VectorDimensions(embedding)
      : finiteFloatVector(embedding) ? embedding.length : null;
    if (
      item.object !== "embedding"
      || dimensions === null
      || (vectorDimensions !== undefined && dimensions !== vectorDimensions)
    ) invalidProviderResponse();
    vectorDimensions ??= dimensions;
    byIndex.set(index as number, { object: "embedding", index: index as number, embedding: embedding as number[] | string });
  }
  const data = Array.from({ length: expectedCount }, (_unused, index) => byIndex.get(index));
  if (data.some((item) => !item)) invalidProviderResponse();

  const rawUsage = record.usage;
  if (!rawUsage || typeof rawUsage !== "object" || Array.isArray(rawUsage)) invalidProviderResponse();
  const promptTokens = (rawUsage as Record<string, unknown>).prompt_tokens;
  const totalTokens = (rawUsage as Record<string, unknown>).total_tokens;
  if (
    !Number.isInteger(promptTokens) || (promptTokens as number) < 0
    || !Number.isInteger(totalTokens) || (totalTokens as number) < (promptTokens as number)
  ) invalidProviderResponse();

  const response: EmbeddingResponse = {
    object: "list",
    data: data as EmbeddingItem[],
    model: typeof record.model === "string" && record.model.length > 0 ? record.model : fallbackModel,
    usage: { prompt_tokens: promptTokens as number, total_tokens: totalTokens as number }
  };
  return {
    response,
    usage: { inputTokens: promptTokens as number, outputTokens: 0, cachedTokens: 0 }
  };
}
