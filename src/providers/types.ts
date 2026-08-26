import { z } from "zod";
import type { TokenUsage } from "../metering/tokens.js";
import {
  reasoningEffortWireSchema,
  reasoningRequestSchema,
  type ModelReasoningCapabilities
} from "../inference/reasoning.js";
import { TOOL_BOUNDS, toolCallSchema, toolChoiceSchema, toolsSchema } from "./tools.js";
import { providerRoutingPolicySchema } from "./routing/policy.js";
import { AppError } from "../security/errors.js";
import type { EmbeddingProviderRequest, EmbeddingProviderResult } from "./embeddings.js";

/** Canonical image dimension bounds shared by mint, relay, and monolith routes. */
export const IMAGE_MIN_DIMENSION = 128;
export const IMAGE_MAX_DIMENSION = 2048;
export const IMAGE_DEFAULT_SIZE = "1024x1024";
export const IMAGE_DEFAULT_RESPONSE_FORMAT = "b64_json";

/**
 * Parse an OpenAI-style "WIDTHxHEIGHT" size into bounded integer dimensions.
 * Every image surface (ticket mint, relay body validation, monolith route)
 * must derive width/height with this exact function so a bound ticket and a
 * redeemed body can never disagree on the authorized (priced) provider work.
 */
export function parseImageSize(size: string): { width: number; height: number } {
  const [width, height] = size.split("x").map(Number);
  if (
    !Number.isInteger(width)
    || !Number.isInteger(height)
    || width < IMAGE_MIN_DIMENSION
    || height < IMAGE_MIN_DIMENSION
    || width > IMAGE_MAX_DIMENSION
    || height > IMAGE_MAX_DIMENSION
  ) {
    throw new AppError(400, "invalid_size", `Size must be between ${IMAGE_MIN_DIMENSION}x${IMAGE_MIN_DIMENSION} and ${IMAGE_MAX_DIMENSION}x${IMAGE_MAX_DIMENSION}`);
  }
  return { width, height };
}

export const chatRoleSchema = z.enum(["system", "user", "assistant", "tool"]);

// OpenAI messages may send `content` as a plain string OR an array of typed
// parts. opencode, the OpenAI SDK, and other agent clients use the array form
// (e.g. on tool turns). AnonRouter accepts text parts and forwards them verbatim
// to the provider; metering flattens the text via messageText(), so array
// content is billed identically to the equivalent string. Image parts are
// accepted on USER messages only (enforced per role in the superRefine below);
// other non-text parts (audio/file) are not accepted over this contract.
const textContentPartSchema = z
  .object({
    type: z.literal("text"),
    text: z.string().max(200_000),
    // Venice supports Anthropic-compatible explicit cache breakpoints on text
    // content. Only the documented ephemeral marker is forwarded.
    cache_control: z.object({ type: z.literal("ephemeral") }).strict().optional()
  })
  .strict();

/** Bounds for image (vision) content parts. */
export const IMAGE_HTTPS_URL_MAX_CHARS = 2_048;
// A data: URL up to ~5MB of image bytes once base64 overhead is included.
export const IMAGE_DATA_URL_MAX_CHARS = 7_000_000;
export const MAX_IMAGE_PARTS_PER_MESSAGE = 10;

const IMAGE_DATA_URL_PATTERN = /^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/]+={0,2}$/;

const imageContentPartSchema = z
  .object({
    type: z.literal("image_url"),
    image_url: z
      .object({
        // Either a bounded https: URL or a bounded base64 data: URL for the
        // supported image types. Image bytes are request content: forwarded
        // verbatim to the provider, never logged or persisted.
        url: z
          .string()
          .max(IMAGE_DATA_URL_MAX_CHARS)
          .superRefine((url, ctx) => {
            if (url.startsWith("data:")) {
              if (!IMAGE_DATA_URL_PATTERN.test(url)) {
                ctx.addIssue({
                  code: z.ZodIssueCode.custom,
                  message: "image data URLs must be base64-encoded png, jpeg, webp, or gif"
                });
              }
            } else if (!url.startsWith("https://") || url.length > IMAGE_HTTPS_URL_MAX_CHARS) {
              ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: `image URLs must use https: and be at most ${IMAGE_HTTPS_URL_MAX_CHARS} characters`
              });
            }
          }),
        detail: z.enum(["auto", "low", "high"]).optional()
      })
      .strict()
  })
  .strict();

const contentPartSchema = z.union([textContentPartSchema, imageContentPartSchema]);

/** Content-free count of image parts in one message's content. */
export function countImageParts(content: unknown): number {
  if (!Array.isArray(content)) return 0;
  let count = 0;
  for (const part of content) {
    if (part && typeof part === "object" && (part as { type?: unknown }).type === "image_url") count += 1;
  }
  return count;
}

const messageContentSchema = z.union([
  z.string().max(200_000),
  z.null(),
  // Empty arrays are allowed: the OpenAI SDK sends `content: []` on an
  // assistant message that carries only tool_calls, and a tool result may be
  // empty. The per-role superRefine below enforces "must have content".
  z.array(contentPartSchema).max(256)
]);

export const chatMessageSchema = z
  .object({
    role: chatRoleSchema,
    // Assistant messages may carry null content when tool_calls are present.
    // user/system/tool messages must carry text content (a string or text parts).
    // The superRefine below enforces the role-specific transport shape.
    content: messageContentSchema.optional(),
    name: z.string().max(128).optional(),
    tool_call_id: z.string().min(1).max(TOOL_BOUNDS.maxToolCallIdLength).optional(),
    tool_calls: z.array(toolCallSchema).min(1).max(TOOL_BOUNDS.maxToolCallsPerMessage).optional()
  })
  // Unknown message fields (refusal, annotations, audio, reasoning, …) are
  // stripped rather than rejected: real OpenAI clients attach extras we do not
  // need, and only the known fields above are ever forwarded to the provider.
  .superRefine((message, ctx) => {
    const hasContent =
      typeof message.content === "string" || Array.isArray(message.content);
    // Image parts ride only on user messages (matching the OpenAI vision
    // contract); system/assistant/tool content stays text-only.
    const imageParts = countImageParts(message.content);
    if (imageParts > 0 && message.role !== "user") {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["content"], message: `${message.role} messages cannot contain image content` });
    }
    if (imageParts > MAX_IMAGE_PARTS_PER_MESSAGE) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["content"], message: `a message may carry at most ${MAX_IMAGE_PARTS_PER_MESSAGE} image parts` });
    }
    if (message.role === "user" || message.role === "system") {
      if (!hasContent) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["content"], message: `${message.role} message content must be text` });
      }
      if (message.tool_calls) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["tool_calls"], message: `${message.role} messages cannot contain tool_calls` });
      }
      if (message.tool_call_id !== undefined) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["tool_call_id"], message: `${message.role} messages cannot reference a tool_call_id` });
      }
    } else if (message.role === "tool") {
      if (message.tool_call_id === undefined) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["tool_call_id"], message: "tool messages require tool_call_id" });
      }
      if (!hasContent) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["content"], message: "tool message content must be text" });
      }
      if (message.tool_calls) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["tool_calls"], message: "tool messages cannot contain tool_calls" });
      }
    } else {
      // assistant: normal content, tool calls, or both. An assistant turn cannot
      // be empty (no text content AND no tool calls).
      const hasToolCalls = Array.isArray(message.tool_calls) && message.tool_calls.length > 0;
      if (!hasContent && !hasToolCalls) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["content"], message: "assistant messages must have text content or tool_calls" });
      }
      if (message.tool_call_id !== undefined) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["tool_call_id"], message: "assistant messages cannot reference a tool_call_id" });
      }
    }
  });

/**
 * Cost-neutral Venice extensions exposed by AnonRouter.
 *
 * Search, scraping, X search, characters, and arbitrary future keys are not
 * accepted here: they can add unmetered provider work or hidden prompt tokens.
 * Venice's own system prompt must remain disabled so the admission layer can
 * place a local upper bound on input tokens.
 */
export const veniceParametersSchema = z
  .object({
    strip_thinking_response: z.boolean().optional(),
    disable_thinking: z.boolean().optional(),
    include_venice_system_prompt: z.literal(false).optional()
  })
  .strict();

/**
 * A caller-supplied output limit is optional intent, not an AnonRouter product
 * ceiling.  Keep the wire value inside JavaScript's exact integer range; the
 * selected provider model and remaining context are validated later.
 */
export const outputTokenLimitSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);

export function canonicalOutputTokenLimit(body: {
  max_tokens?: number;
  max_completion_tokens?: number;
}): number | undefined {
  const legacy = body.max_tokens;
  const completion = body.max_completion_tokens;
  if (legacy !== undefined && completion !== undefined && legacy !== completion) {
    throw new Error("max_tokens and max_completion_tokens must match when both are provided");
  }
  return completion ?? legacy;
}

function requireMatchingOutputTokenAliases(
  body: { max_tokens?: number; max_completion_tokens?: number },
  context: z.RefinementCtx
) {
  if (
    body.max_tokens !== undefined
    && body.max_completion_tokens !== undefined
    && body.max_tokens !== body.max_completion_tokens
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["max_completion_tokens"],
      message: "max_tokens and max_completion_tokens must match when both are provided"
    });
  }
}

/**
 * OpenAI-style structured-output control, forwarded to the provider verbatim.
 * AnonRouter validates only shape + bounds; the provider enforces the schema.
 * `.passthrough()` keeps provider-specific extras. Honoring this needs no logging
 * and no ticket binding: it does not affect routing/pricing/privacy, it simply
 * rides inside the request body the relay already forwards (and stays end-to-end
 * encrypted on tee/e2ee routes).
 */
export const responseFormatSchema = z
  .object({
    type: z.enum(["text", "json_object", "json_schema"]),
    json_schema: z
      .object({
        name: z.string().min(1).max(128),
        description: z.string().max(2048).optional(),
        schema: z.record(z.string(), z.unknown()).optional(),
        strict: z.boolean().nullish()
      })
      .passthrough()
      .optional()
  })
  .passthrough()
  .refine((value) => value.type !== "json_schema" || value.json_schema !== undefined, {
    message: "response_format.json_schema is required when type is 'json_schema'"
  });

// Effective routing policy (allow/exclude globs, strategy, privacy floor). SHARED
// between the client-facing chat request schema and the internal control-plane
// authorize RPC so the two can never drift. This bound is load-bearing: allow/
// exclude counts feed the O(n*m) glob matcher run per enabled model, so the
// control plane must re-validate this field with these exact limits rather than
// trust the (assume-breach) relay to have bounded it — an unbounded pattern count
// is an event-loop DoS of the control tier.
export const routingConfigSchema = z
  .object({
    allow: z.array(z.string().min(1).max(256)).min(1).max(32).optional(),
    exclude: z.array(z.string().min(1).max(256)).max(32).optional(),
    strategy: z.enum(["cost", "balanced", "quality"]).optional(),
    max_cost_usd: z.number().positive().max(1000).optional(),
    privacy_classes: z
      .array(z.enum(["anonymous", "private", "tee", "e2ee", "unknown"]))
      .min(1)
      .max(5)
      .optional()
  })
  .strict();

export const chatCompletionRequestSchema = z
  .object({
    model: z.string().min(1).max(256),
    /**
     * OpenRouter-style cross-model fallback list. `model` is the primary; each
     * entry is tried in order when the current model cannot serve BEFORE any
     * output (rate-limited, capacity, no eligible route, etc.). Honored by the
     * OpenAI-compatibility broker, which re-mints a fresh single-use ticket (and
     * thus a fresh worst-case reservation, released on pre-output failure) per
     * model, so at most one model's cost is ever held. The native relay path
     * rejects it for now. Bounded to 4 fallbacks.
     */
    models: z.array(z.string().min(1).max(256)).max(4).optional(),
    /**
     * Provider routing. A bare string is an exact provider pin (no fallback); an
     * object is a full provider policy (order/only/ignore/sort/minimum_privacy/
     * max_price/…). Omit for Auto: privacy-first, price-tiebroken. Deeper semantic
     * validation happens in normalizeProviderPolicy. See docs/PROVIDER_ROUTING.md.
     */
    provider: providerRoutingPolicySchema.optional(),
    messages: z.array(chatMessageSchema).min(1).max(256),
    stream: z.boolean().optional().default(false),
    // OpenAI streaming usage opt-in (opencode and other SDKs send this). Bounded
    // and forwarded unchanged.
    stream_options: z.object({ include_usage: z.boolean().optional() }).strict().optional(),
    temperature: z.number().min(0).max(2).optional(),
    top_p: z.number().min(0).max(1).optional(),
    max_tokens: outputTokenLimitSchema.optional(),
    max_completion_tokens: outputTokenLimitSchema.optional(),
    stop: z.union([z.string().max(256), z.array(z.string().max(256)).max(8)]).optional(),
    presence_penalty: z.number().min(-2).max(2).optional(),
    frequency_penalty: z.number().min(-2).max(2).optional(),
    seed: z.number().int().optional(),
    user: z.string().max(256).optional(),
    // OpenAI structured outputs (json_object / json_schema). Validated for shape
    // only and forwarded to the provider verbatim via providerBody (...rest);
    // AnonRouter never enforces the schema itself. See responseFormatSchema.
    response_format: responseFormatSchema.optional(),
    /**
     * Reasoning controls (documented fields only). Semantic resolution —
     * flat/nested agreement, disable signals, legacy `disable_thinking` — and
     * per-model validation happen in src/inference/reasoning.ts; the schema
     * only bounds the accepted shapes and enum values.
     */
    reasoning_effort: reasoningEffortWireSchema.optional(),
    reasoning: reasoningRequestSchema.optional(),
    // OpenAI tool-calling transport. AnonRouter validates only shape + bounds and
    // forwards these unchanged; it never executes tools (see src/providers/tools.ts
    // and docs/COMPAT_MODE.md). Legacy `functions`/`function_call` are unsupported:
    // they are stripped (not forwarded), so use `tools`/`tool_choice` instead.
    tools: toolsSchema.optional(),
    tool_choice: toolChoiceSchema.optional(),
    parallel_tool_calls: z.boolean().optional(),
    // Venice/OpenAI cache-affinity and retention controls. These affect only
    // prompt-cache routing/lifetime; cache write/read work is metered from the
    // provider's returned usage details.
    prompt_cache_key: z.string().min(1).max(256).optional(),
    prompt_cache_retention: z.enum(["default", "extended", "24h"]).optional(),
    venice_parameters: veniceParametersSchema.optional(),
    routing: routingConfigSchema.optional()
  })
  // Strip unknown top-level fields (response_format, logprobs, n, prediction, …)
  // instead of rejecting. Only the fields defined above are ever forwarded to the
  // provider, so accepting-and-dropping unknowns is safe and lets standard OpenAI
  // clients (opencode, Cursor, the OpenAI SDK) work without per-field allowlisting.
  .superRefine(requireMatchingOutputTokenAliases);

export type ChatCompletionRequestBody = z.infer<typeof chatCompletionRequestSchema>;
export type ChatMessage = z.infer<typeof chatMessageSchema>;

/** Provider-qualified display/header id without duplicating an existing prefix. */
export function qualifiedPublicModelId(providerName: string, publicModelId: string): string {
  const prefix = `${providerName}/`;
  return publicModelId.startsWith(prefix) ? publicModelId : `${prefix}${publicModelId}`;
}

export interface ModelRecord {
  id: string;
  providerId: string;
  providerName: string;
  providerStatus: string;
  providerPrivacyClass: string;
  publicModelId: string;
  /** One creator/model slug shared by every provider route for the model. */
  canonicalModelId?: string;
  externalModelId: string;
  displayName: string;
  /** Inference surface this route serves. */
  modelType: "text" | "image" | "tts" | "embedding";
  /** Flat per-unit price for media routes (per image / per 1M TTS characters). */
  unitPriceUsd: number | null;
  contextWindow: number;
  /** Provider-advertised generation maximum. Positive for callable text routes. */
  maxOutputTokens: number | null;
  inputPricePerMillion: number;
  outputPricePerMillion: number;
  /** Discounted price for provider-reported cached prompt tokens, when published. */
  cacheReadPricePerMillion?: number | null;
  /** Price for provider-reported cache creation tokens, when separately published. */
  cacheWritePricePerMillion?: number | null;
  privacyClass: string;
  supportsStreaming: boolean;
  supportsTools: boolean;
  /** Vision (image input) capability; absent on legacy rows = fail closed. */
  supportsVision?: boolean;
  /** Provider-attested per-request image cap; 0 when vision is unsupported. */
  maxImages?: number;
  routingEnabled: boolean;
  qualityTier: number;
  routingTasks: string[];
  /** Catalog moderation posture ("uncensored" | "moderated" | "unknown"); absent on legacy rows. */
  moderation?: string;
  supportsWeb: boolean;
  expectedLatencyMs: number | null;
  /** Sanitized reasoning-control capabilities (fail closed when unsynced). */
  reasoningCapabilities: ModelReasoningCapabilities;
}

export interface ProviderRequest {
  requestId: string;
  model: ModelRecord;
  body: ChatCompletionRequestBody;
  inputTokens: number;
  /**
   * Provider-canonical E2EE headers selected from a strict allowlist at relay
   * ingress. Adapters must still validate their own exact header vocabulary
   * before forwarding it to an enclave.
   */
  e2eeHeaders?: Record<string, string>;
  /**
   * In-memory cancellation only. It is never serialized into a worker RPC or
   * retained after the request and lets a downstream disconnect stop provider
   * work promptly.
   */
  signal?: AbortSignal;
  /**
   * Worker-only durable dispatch fence. Adapters must await this immediately
   * before the first upstream fetch. The relay deliberately cannot invoke it:
   * a worker transport failure before this callback remains a zero-cost abort.
   * The control plane's response may name which provider credential this
   * dispatch must use; the secret itself never crosses the fence.
   */
  onProviderAttempt?: () => Promise<ProviderDispatchAuthorization | void>;
}

/** Content-free facts the control plane returns from the dispatch fence. */
export interface ProviderDispatchAuthorization {
  /** Venice keyset id selected for this dispatch; null/absent = default key. */
  providerKeyId?: string | null;
}

export interface ProviderChatResult {
  response: unknown;
  usage?: TokenUsage;
  providerRequestId?: string;
  /** Content-free SHA-256 digests of the exact provider wire bytes. Present only
   * for signature-capable, non-streaming adapters that retain those boundaries. */
  exactRequestHash?: string;
  exactResponseHash?: string;
}

/** Content-free lookup facts retained for a provider response-signature API. */
export interface ProviderSignatureBinding {
  providerRequestId: string;
  exactRequestHash: string;
  exactResponseHash: string;
}

export interface ProviderStreamResult {
  stream: AsyncIterable<string>;
  usage: Promise<TokenUsage | undefined>;
  providerRequestId?: string;
  /** Resolves only after a complete provider stream. Undefined when the
   * provider exposes no response receipt or the stream carried no request id. */
  signatureBinding?: Promise<ProviderSignatureBinding | undefined>;
}

export type ProviderOpaqueE2eeProtocol = "chutes-mlkem-v1";

export interface ProviderOpaqueE2eeRequest {
  requestId: string;
  model: ModelRecord;
  protocol: ProviderOpaqueE2eeProtocol;
  /** Exact encrypted application bytes. Never decoded, parsed, or logged. */
  ciphertext: Uint8Array;
  /** Provider-specific routing/crypto metadata from a strict edge allowlist. */
  headers: Record<string, string>;
  signal?: AbortSignal;
  onProviderAttempt?: () => Promise<ProviderDispatchAuthorization | void>;
}

export interface ProviderOpaqueE2eeResult {
  statusCode: number;
  contentType: string;
  /** Exact encrypted provider response bytes. */
  body: Uint8Array;
  /** Strictly allowlisted cryptographic response headers only. */
  responseHeaders: Record<string, string>;
  usage?: TokenUsage;
}

export const imageGenerationRequestSchema = z
  .object({
    model: z.string().min(1).max(256),
    prompt: z.string().min(1).max(10_000),
    /** "WIDTHxHEIGHT", e.g. 1024x1024. */
    size: z
      .string()
      .regex(/^\d{3,4}x\d{3,4}$/)
      .optional()
      .default("1024x1024"),
    response_format: z.literal("b64_json").optional().default("b64_json")
  })
  .strict();

export type ImageGenerationRequestBody = z.infer<typeof imageGenerationRequestSchema>;

export const speechRequestSchema = z
  .object({
    model: z.string().min(1).max(256),
    input: z.string().min(1).max(20_000),
    voice: z.string().min(1).max(64).optional(),
    response_format: z.literal("mp3").optional().default("mp3")
  })
  .strict();

export type SpeechRequestBody = z.infer<typeof speechRequestSchema>;

export interface ImageProviderRequest {
  requestId: string;
  model: ModelRecord;
  prompt: string;
  width: number;
  height: number;
  /** In-memory cancellation only; aborts the upstream fetch on disconnect/timeout. */
  signal?: AbortSignal;
  /**
   * Worker-only durable dispatch fence. The adapter MUST await this immediately
   * before the upstream image fetch. The relay cannot invoke it: a worker
   * transport failure before this callback remains a zero-cost abort. The
   * response may name which provider credential this dispatch must use.
   */
  onProviderAttempt?: () => Promise<ProviderDispatchAuthorization | void>;
}

export interface ImageProviderResult {
  /** Base64 image bytes (no data: prefix). */
  base64: string;
  mimeType: string;
  /** Provider moderation metadata only; never derived from or stores image content. */
  blurred?: boolean;
  contentViolation?: boolean;
}

export interface SpeechProviderRequest {
  requestId: string;
  model: ModelRecord;
  input: string;
  voice?: string;
}

export interface SpeechProviderResult {
  audio: Buffer;
  mimeType: string;
}

export interface ProviderAdapter {
  name: string;
  chat(request: ProviderRequest): Promise<ProviderChatResult>;
  stream(request: ProviderRequest): Promise<ProviderStreamResult>;
  opaqueE2ee?(request: ProviderOpaqueE2eeRequest): Promise<ProviderOpaqueE2eeResult>;
  /** OpenAI-compatible text embeddings; absent when unsupported. */
  embeddings?(request: EmbeddingProviderRequest): Promise<EmbeddingProviderResult>;
  /** Image generation for model_type=image routes; absent when unsupported. */
  generateImage?(request: ImageProviderRequest): Promise<ImageProviderResult>;
  /** Text-to-speech for model_type=tts routes; absent when unsupported. */
  speech?(request: SpeechProviderRequest): Promise<SpeechProviderResult>;
  /**
   * Provider-neutral TEE attestation fetch. Present only on providers that expose
   * a verifiable enclave quote/evidence for a model + fresh caller nonce. Runs
   * ONLY on the credential-isolated worker (the provider secret never leaves it);
   * the returned evidence is opaque and independently verified by the provider's
   * TeeVerifier (src/providers/attestation) and by advanced clients. Absent =>
   * the route exposes no attestation (e.g. Fireworks/DeepInfra).
   */
  fetchAttestation?(
    externalModelId: string,
    nonce: string,
    signal?: AbortSignal,
    providerKeyId?: string | null
  ): Promise<unknown>;
  /**
   * Modality-specific attestation used before a client-opaque request. Providers
   * may expose a different attested encryption/signing key than their general
   * TEE report (NEAR v2 requires an Ed25519 key). Absent means the normal
   * attestation method is also the E2EE key report.
   */
  fetchE2eeAttestation?(
    externalModelId: string,
    nonce: string,
    signal?: AbortSignal,
    providerKeyId?: string | null
  ): Promise<unknown>;
  /**
   * Provider-neutral per-request signature fetch, keyed by the provider request
   * id captured during inference. Present only on providers that expose a
   * verifiable per-request signature (for example NEAR AI or Venice). Absent => the caller must
   * return a structured `tee_signature_not_supported`, never a fabricated one.
   */
  fetchSignature?(
    providerRequestId: string,
    externalModelId: string,
    signal?: AbortSignal,
    providerKeyId?: string | null
  ): Promise<unknown>;
}
