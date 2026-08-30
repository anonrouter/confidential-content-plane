import { z } from "zod";
import {
  IMAGE_DEFAULT_RESPONSE_FORMAT,
  outputTokenLimitSchema,
  SPEECH_DEFAULT_RESPONSE_FORMAT,
  SPEECH_MAX_INPUT_CHARS,
  SPEECH_MAX_VOICE_CHARS
} from "../providers/types.js";
import { providerRoutingPolicySchema } from "../providers/routing/policy.js";
import { reasoningEffortWireSchema, reasoningRequestSchema } from "./reasoning.js";

// The ticket request contract.
//
// SPLIT OUT OF `ticketFromRequest.ts` FOR D-22.
//
// `ticketFromRequest.ts` also ISSUES tickets, which is control-plane work: it
// takes an `AuthContext`, consults the account, and mints against a balance. It
// is not in the content plane's runtime closure and does not belong in the
// public repository.
//
// The SCHEMA is different. It is the shape of what a caller may ask for, it is
// extended by the compat mint contract, and D-22 requires the boundary contract
// be publishable so a reviewer can check what crosses. Keeping the two in one
// file meant publishing the contract required publishing the issuer, and
// through it the account-identity types.

/**
 * The exact routing-metadata surface a ticket binds. Deliberately mirrors the
 * chat/embeddings body so a caller (or the broker) can bind precisely what it
 * will redeem. It carries NO messages/embeddings input — only scalars the
 * ticket is bound to. `.strict()` rejects unknown fields fail-closed.
 */
export const ticketRequestSchema = z
  .object({
    model: z.string().min(1).max(256),
    /**
     * Provider routing policy bound into the ticket. A bare string pins an exact
     * provider; an object is a full policy. Omission selects Auto. The bound
     * policy digest must match what the redeeming body normalizes to.
     */
    provider: providerRoutingPolicySchema.optional(),
    /**
     * Request the E2EE (client-attested ciphertext) serving modality. Only needed
     * to disambiguate a DUAL model that has both an e2ee and a plaintext route; an
     * e2ee-only model is inferred. The chat request must then carry TEE headers.
     */
    e2ee: z.boolean().optional(),
    operation: z.enum(["chat", "embeddings", "image", "speech"]).optional().default("chat"),
    max_tokens: outputTokenLimitSchema.optional(),
    max_completion_tokens: outputTokenLimitSchema.optional(),
    // Image-only, content-free provider-work parameters. The ticket binds them
    // so a redeeming body cannot change the authorized (priced) size or format.
    size: z.string().regex(/^\d{3,4}x\d{3,4}$/).optional(),
    // Output container. Constrained per operation by the issuer: b64_json for
    // image, mp3 for speech. A value from the wrong operation is a 400, never
    // silently coerced, so a bound ticket always names the format its endpoint
    // will serve.
    response_format: z.enum([IMAGE_DEFAULT_RESPONSE_FORMAT, SPEECH_DEFAULT_RESPONSE_FORMAT]).optional(),
    // Speech-only, content-free provider-work parameters. `input_chars` is the
    // EXACT length of the text the caller will send — a count, never the text.
    // Speech is priced per character, so binding the count is what lets control
    // reserve the exact amount it will settle, as the flat unit price does for
    // an image.
    input_chars: z.number().int().positive().max(SPEECH_MAX_INPUT_CHARS).optional(),
    voice: z.string().min(1).max(SPEECH_MAX_VOICE_CHARS).optional(),
    // Reasoning surface mirrors the chat body so a caller can bind the exact
    // configuration it will redeem with. The relay rejects any drift.
    reasoning_effort: reasoningEffortWireSchema.optional(),
    reasoning: reasoningRequestSchema.optional(),
    venice_parameters: z.object({ disable_thinking: z.boolean().optional() }).strict().optional()
  })
  .strict();
export type TicketRequestBody = z.infer<typeof ticketRequestSchema>;
