// Internal RPC contracts between the three inference roles.
//
//   relay  → control : redeem, authorize, settle, abort   (no content, no account back)
//   relay  → worker  : attestation, chat, stream          (no account, no billing)
//   worker → control : provider-attempt fence             (single-use, bound grant)
//
// Relay-facing types deliberately carry NO stable account identity: a redemption
// handle and a request id are opaque, and a compromised relay cannot resolve
// either back to an account (that mapping lives only in the control plane).

import type { TokenUsage } from "../metering/tokens.js";
import type { InferenceRateLimitResult } from "../rate-limit/limiter.js";
import type { RoutingPreferences } from "../routing/preferences.js";
import type { ChatCompletionRequestBody, ModelRecord, ProviderSignatureBinding } from "../providers/types.js";
import type { EmbeddingRequestBody, EmbeddingResponse } from "../providers/embeddings.js";
import type { ModelReasoningCapabilities } from "./reasoning.js";
import type { InferenceOperation } from "./tickets.js";

/** Public constraints the relay may learn about a redeemed ticket. */
export interface RelayTicketConstraints {
  operation?: InferenceOperation;
  requestedModel: string;
  automatic: boolean;
  providerName: string;
  publicModelId: string;
  /** Canonical creator/model slug returned to callers regardless of provider. */
  canonicalModelId: string;
  /** Canonical digest of the ticket-bound provider policy (relay early mismatch check). */
  providerPolicyKey: string;
  /** Whether the ticket was bound as an E2EE (ciphertext) request. */
  e2ee?: boolean;
  privacyClass: string;
  /** Content-free route context bound by control at ticket issuance. */
  contextWindow?: number;
  /** Null means /auto may derive a candidate-specific model/context maximum. */
  maxOutputTokens: number | null;
  /** Canonical reasoning digest bound at issue time ("default" when absent). */
  reasoningKey?: string;
  /** Image-only: bound provider-work parameters the relay validates the body against. */
  imageWidth?: number | null;
  imageHeight?: number | null;
  imageResponseFormat?: string | null;
  /** Speech-only: bound provider-work parameters the relay validates the body against. */
  speechCharacterCount?: number | null;
  speechVoice?: string | null;
  speechResponseFormat?: string | null;
  routingPreferences: RoutingPreferences;
  /** Trial-entitlement-funded request: the relay enforces the text-only surface. */
  trial?: boolean;
}

export interface RedeemResult {
  /** Opaque handle; not derivable to an account by the relay. */
  redemption: string;
  constraints: RelayTicketConstraints;
}

export interface AuthorizeRpcRequest {
  redemption: string;
  requestId: string;
  operation?: InferenceOperation;
  /** For an exact request: the ticket-bound model id. Ignored for automatic. */
  modelPublicId: string;
  automatic: boolean;
  stream: boolean;
  /** Effective routing policy (metadata only) for automatic selection. */
  routing?: ChatCompletionRequestBody["routing"];
  /**
   * Prompt classification used to live here. It is content-derived — a task
   * label, a complexity tier and a "maybe sensitive" bit describe what the
   * customer asked for — so O13 removed it from this boundary entirely.
   * Classification AND canonical-model selection now run in the content plane,
   * which sends the model it chose as `modelPublicId` even when `automatic` is
   * true. See docs/architecture/confidential-backend/CONTROL_RPC_CONTRACT.md.
   */
  inputCeiling: number;
  /** Optional caller intent from the chat body; never a fabricated relay cap. */
  requestedMaxOutputTokens?: number;
  /**
   * The relay's canonical reasoning digest for the request body. The control
   * plane cross-checks it against the ticket-bound digest and re-validates it
   * against the resolved model; a mismatch fails before any reservation.
   */
  reasoningKey?: string;
  /**
   * The relay's canonical provider-policy digest for the request body. The control
   * plane cross-checks it against the ticket-bound digest; a mismatch is a
   * `ticket_provider_policy_mismatch` before any reservation.
   */
  providerPolicyKey?: string;
  /**
   * Whether this is an E2EE request (derived by the relay from the TEE headers).
   * The control plane cross-checks it against the ticket-bound modality and uses
   * it to partition the provider routes; a plaintext request never selects an
   * e2ee route and an E2EE request selects only e2ee routes.
   */
  e2ee?: boolean;
  /**
   * True only for a whole-body ciphertext transport whose token-bearing JSON is
   * intentionally unreadable to the relay. Control reserves the model's full
   * context at the most expensive token rate and binds the worker grant to this
   * transport, rather than trusting client-declared token counts hidden inside
   * the ciphertext.
   */
  opaqueE2ee?: boolean;
  // `classification`, `requiresTools` and `requiresVision` are deliberately
  // absent. All three are derived from request content, and all three moved
  // into the content plane: it classifies, it filters candidates by capability,
  // and it sends the control plane only the model it resolved. See
  // AUTHORIZE_DENIED_CONTENT_DERIVED_FIELDS in routes/internal/rpcSchemas.ts.
}

/** Public model metadata the relay needs to drive the worker — no pricing. */
export interface RelayModel {
  providerName: string;
  publicModelId: string;
  /** Shared creator/model slug returned to callers regardless of provider. */
  canonicalModelId?: string;
  externalModelId: string;
  /** Route effective privacy class; drives the x-anonrouter-privacy-class header. */
  privacyClass?: string;
  supportsStreaming: boolean;
  /**
   * Public catalog capability facts, returned so the content plane can enforce
   * a tools/vision requirement it may no longer disclose to control. Travelling
   * control -> content, they reveal nothing about the request.
   */
  supportsTools: boolean;
  supportsVision: boolean;
  contextWindow: number;
  maxOutputTokens: number | null;
  modelType: "text" | "image" | "tts" | "embedding";
  /** Public capability data so the relay can translate the validated canonical
   *  reasoning selection into exact provider fields. */
  reasoningCapabilities?: ModelReasoningCapabilities;
}

export interface AuthorizeRpcResult {
  /** Opaque, single-use capability consumed by the credential worker. */
  dispatchToken: string;
  model: RelayModel;
  /** Exact provider maximum authorized, reserved, and sent upstream. */
  effectiveMaxOutputTokens: number;
  rateLimits: InferenceRateLimitResult;
  /** Provider-routing plan metadata (content-free) for transparency + fallback. */
  routing?: ProviderRoutingMetadata;
}

/** Content-free description of the bounded provider plan behind an authorization. */
export interface ProviderRoutingMetadata {
  /** Whether provider selection was Auto (policy is the default) or explicit. */
  mode: "auto" | "exact";
  /** Number of bounded attempts the plan permits (>=1). */
  attemptsPlanned: number;
  /** Whether a transparent fallback attempt is available. */
  fallbackAvailable: boolean;
  /** Strongest privacy class the plan may select (the primary attempt). */
  effectivePrivacyClass: string;
  /** Weakest privacy class any attempt could select: the honest guarantee. */
  minimumPrivacyClass: string;
}

/**
 * Request a single-use dispatch capability for the NEXT provider attempt after
 * the relay reported a sanitized outcome for the previous one. The reservation
 * made at first authorization already covers the plan's worst-case attempt, so no
 * re-reservation happens here; the serving route recorded on the reservation is
 * updated to the newly-selected route so settlement bills the actual provider.
 */
export interface AuthorizeNextAttemptRpcRequest {
  requestId: string;
  /** Content-free category of why the previous attempt failed. */
  previousOutcome: ProviderAttemptOutcome;
  latencyMs: number;
}

export type ProviderAttemptOutcome =
  | "provider_unavailable"
  | "rate_limited"
  | "provider_rejected"
  | "network_error"
  | "invalid_response";

export interface AuthorizeNextAttemptRpcResult {
  dispatchToken: string;
  model: RelayModel;
  effectiveMaxOutputTokens: number;
  /** 1-based index of this new attempt within the plan. */
  attemptIndex: number;
  routing: ProviderRoutingMetadata;
}

/**
 * Content-free dispatch facts derived by the credential worker from the exact
 * request it is about to send upstream. Control consumes the opaque token and
 * requires every fact to match the grant minted during authorization.
 */
export interface ProviderDispatchAttempt {
  dispatchToken: string;
  requestId: string;
  operation: InferenceOperation;
  providerName: string;
  externalModelId: string;
  stream: boolean;
  effectiveMaxOutputTokens: number;
  /** Ticket-bound canonical reasoning digest carried through by the relay. */
  reasoningKey: string;
  /** Digest derived by the worker from the actual provider-bound body. */
  providerReasoningKey: string;
  /** Distinguishes the whole-body ciphertext RPC from the normal JSON path. */
  opaqueE2ee?: boolean;
  /**
   * Image-only content-free provider-work facts the worker derives from the
   * exact request it is about to send upstream. Undefined for chat/embeddings.
   * Control matches these against the grant so a relay cannot change the
   * authorized (and priced) size or output format after authorization.
   */
  imageWidth?: number;
  imageHeight?: number;
  imageResponseFormat?: string;
  /**
   * Speech-only equivalents. `speechCharacterCount` is the exact character count the
   * worker is about to send upstream, which is the priced unit — matching it
   * against the grant is what stops a post-authorization change to the charge.
   */
  speechCharacterCount?: number;
  speechVoice?: string;
  speechResponseFormat?: string;
}

export interface SettleRpcRequest {
  requestId: string;
  usage: TokenUsage;
  /** Request receipt until the first streamed provider output chunk. */
  firstTokenLatencyMs?: number;
  /** Request receipt until the request reached its terminal outcome. */
  latencyMs: number;
  /**
   * Opaque 128-bit join handle minted in the content plane when a provider
   * receipt exists for this request. It replaces the `teeSignatureBinding`
   * object, whose `requestHash`/`responseHash` are now retained only inside the
   * attested workload. See inference/contentReceipts.ts.
   */
  opaqueReceiptId?: string;
}

/**
 * Settlement result returned to the relay so it can surface the charged cost
 * inline (as usage.cost). Carries only the settled amount, never content.
 */
export interface SettleRpcResponse {
  /** AnonRouter-charged amount in USD for this request. */
  chargedUsd: number;
  /**
   * Whether the opaque receipt was durably recorded. Absent when no receipt was
   * sent. False is non-fatal — billing never depends on a transparency row — but
   * it is reported so the relay, which has a logger, can say so.
   */
  receiptRecorded?: boolean;
}

export interface DeliveryStartedRpcRequest {
  requestId: string;
}

/**
 * Content-free report of a rejected provider attempt for the inference rejection
 * ledger. The relay derives these sanitized facts from the ProviderError (or a
 * transport failure) it caught; the control plane resolves the account from the
 * reservation and classifies. It carries NO prompt/response, raw body, message,
 * or credential — only a sanitized code, an allowlisted request id/machine code,
 * a status, and an attempt index.
 */
export interface RecordProviderRejectionRpcRequest {
  requestId: string;
  /** 0-based index of the failed provider attempt within the bounded plan. */
  attemptIndex: number;
  /** Whether the request used automatic routing. */
  automatic: boolean;
  /** The relay's sanitized fallback outcome when there is no ProviderError. */
  relayOutcome?: ProviderAttemptOutcome;
  /** AnonRouter's sanitized error code (ProviderError.code). */
  anonrouterCode?: string;
  /** The provider's own HTTP status, when known (ProviderError.providerStatusCode). */
  providerStatus?: number;
  /** Sanitized, allowlisted-header provider request id. */
  providerRequestId?: string;
  // `providerCode` is gone. The allowlist that admitted it included Venice's
  // image `content_violation`, which reports a moderation verdict on the
  // caller's prompt: content-derived by any reading. The generic
  // relayOutcome/anonrouterCode pair carries everything refund conservation
  // needs.
  latencyMs: number;
}

/**
 * Single-use, model-bound capability minted only after the public attestation
 * ticket is redeemed. The relay may carry this opaque token, but it cannot use
 * it to recover an account or provider credential.
 */
export interface AttestationRedemption {
  /** Exact provider route bound when the attestation ticket was issued. */
  providerName: string;
  externalModelId: string;
  dispatchToken: string;
  /**
   * The modality this ticket was minted for. CATALOG FACT, not account state:
   * the same value is on the public GET /v1/models. The content plane has no
   * database and cannot look it up, and it must not GUESS — labelling a TEE
   * route `e2ee` would tell a customer their prompt stayed opaque to AnonRouter
   * when it did not. Optional so a ticket minted just before a deploy still
   * redeems; absent is read as `e2ee`, which is the only thing the previous
   * mint could issue.
   */
  privacyClass?: "tee" | "e2ee";
  /** Public catalog id of the bound route, for labelling the verdict. */
  canonicalModelId?: string;
  /** Provider-qualified route id of the bound route. */
  routeId?: string;
}

export interface WorkerAttestationRequest {
  providerName: string;
  externalModelId: string;
  dispatchToken: string;
  nonce: string;
  /**
   * Which evidence the worker must fetch. Some providers publish a DIFFERENT
   * report for a client-opaque request than for general enclave verification
   * (NEAR reports an Ed25519 encryption key for E2EE and an ECDSA one
   * otherwise), so this cannot be inferred from the provider name. Absent is
   * read as `e2ee` to match the pre-generalization relay.
   */
  privacyModality?: "tee" | "e2ee";
}

export interface CaptureRpcRequest {
  requestId: string;
  firstTokenLatencyMs?: number;
  latencyMs: number;
}

export interface AbortRpcRequest {
  requestId: string;
  status: "failed" | "rate_limited" | "insufficient_balance";
  /** True when the request failed upstream/server-side before any delivery
   *  (e.g. a provider HTTP rejection). NEVER set for client disconnects: a
   *  disconnect after provider dispatch still captures conservatively. */
  providerRejected?: boolean;
  firstTokenLatencyMs?: number;
  latencyMs: number;
}

/** The control plane as seen by the relay. Never returns account identity. */
export interface ControlClient {
  redeem(ticketId: string, signal?: AbortSignal): Promise<RedeemResult | null>;
  authorize(request: AuthorizeRpcRequest, signal?: AbortSignal): Promise<AuthorizeRpcResult>;
  /**
   * Authorize the next bounded provider attempt after a sanitized failure of the
   * previous one. Returns null when the plan is exhausted (fallback complete).
   */
  authorizeNextProviderAttempt?(
    request: AuthorizeNextAttemptRpcRequest,
    signal?: AbortSignal
  ): Promise<AuthorizeNextAttemptRpcResult | null>;
  /** Persisted before the relay writes the first streamed response byte. */
  markDeliveryStarted(request: DeliveryStartedRpcRequest, signal?: AbortSignal): Promise<void>;
  /**
   * Best-effort, content-free record of a provider-attempt rejection for the
   * rejection ledger. NEVER affects billing or the actual rejection response; the
   * relay swallows any failure. Optional so alternate control clients need not
   * implement it.
   */
  recordProviderRejection?(request: RecordProviderRejectionRpcRequest, signal?: AbortSignal): Promise<void>;
  settle(request: SettleRpcRequest, signal?: AbortSignal): Promise<SettleRpcResponse>;
  /**
   * Content-free public catalog rows the content plane needs to run automatic
   * model selection locally. Optional so alternate clients need not implement
   * it; automatic routing fails closed when it is absent.
   */
  routingCatalog?(signal?: AbortSignal): Promise<ModelRecord[]>;
  /** Capture the authorized ceiling after delivery when exact settle is unavailable. */
  capture(request: CaptureRpcRequest, signal?: AbortSignal): Promise<void>;
  abort(request: AbortRpcRequest, signal?: AbortSignal): Promise<void>;
  /** Single-use redemption of a model-bound attestation ticket. */
  redeemAttestation(ticket: string, signal?: AbortSignal): Promise<AttestationRedemption | null>;
  /**
   * The enabled catalog rows automatic routing selects from. Control → content,
   * content-free, and takes no request: the content plane classifies and selects
   * locally so no classifier output has to cross the other way. Optional so an
   * alternate control client that never serves /auto need not implement it.
   */
  fetchRoutingCandidates?(signal?: AbortSignal): Promise<ModelRecord[]>;
}

export interface WorkerChatRequest {
  dispatchToken: string;
  requestId: string;
  providerName: string;
  externalModelId: string;
  /** Canonical ticket-bound digest; the worker separately derives the body digest. */
  reasoningKey: string;
  /** Inference body; content is opaque to the relay (ciphertext for E2EE). */
  body: Record<string, unknown>;
  /**
   * Provider-canonical E2EE headers selected from a strict client-header
   * allowlist. The relay never interprets the ciphertext fields themselves.
   */
  e2eeHeaders?: Record<string, string>;
}

export interface WorkerStreamResult {
  stream: AsyncIterable<string>;
  usage: Promise<TokenUsage | undefined>;
  signatureBinding?: Promise<ProviderSignatureBinding | undefined>;
}

export interface WorkerChatResult {
  response: unknown;
  usage?: TokenUsage;
  providerRequestId?: string;
  exactRequestHash?: string;
  exactResponseHash?: string;
}

export type OpaqueE2eeProtocol = "chutes-mlkem-v1";

/** Whole-body ciphertext request. The body is base64 only for the authenticated
 * relay -> worker JSON transport; neither process decodes it as application
 * data. The worker restores the exact bytes before provider dispatch. */
export interface WorkerOpaqueE2eeRequest {
  dispatchToken: string;
  requestId: string;
  providerName: string;
  externalModelId: string;
  reasoningKey: string;
  effectiveMaxOutputTokens: number;
  protocol: OpaqueE2eeProtocol;
  headers: Record<string, string>;
  ciphertextBase64: string;
}

export interface WorkerOpaqueE2eeResult {
  statusCode: number;
  contentType: string;
  bodyBase64: string;
  /** Strictly allowlisted cryptographic response headers only. */
  responseHeaders: Record<string, string>;
  usage?: TokenUsage;
}

export interface WorkerEmbeddingRequest {
  dispatchToken: string;
  requestId: string;
  providerName: string;
  externalModelId: string;
  body: EmbeddingRequestBody;
}

export interface WorkerEmbeddingResult {
  response: EmbeddingResponse;
  usage: TokenUsage;
}

/**
 * Tagged, operation-specific image request. It carries only the prompt and the
 * content-free provider-work parameters the ticket bound — it deliberately does
 * NOT reuse chat token/output semantics. The relay holds the prompt and forwards
 * it here; the prompt never reaches the control plane.
 */
export interface WorkerImageRequest {
  dispatchToken: string;
  requestId: string;
  providerName: string;
  externalModelId: string;
  width: number;
  height: number;
  responseFormat: string;
  prompt: string;
}

export interface WorkerImageResult {
  /** Base64 image bytes (no data: prefix). Never crosses to the control plane. */
  base64: string;
  mimeType: string;
  /** Provider moderation metadata only; never derived from image content. */
  blurred?: boolean;
  contentViolation?: boolean;
}

/**
 * Tagged, operation-specific speech request. Like image it carries only the
 * content (here the input text) and the ticket-bound provider-work parameters,
 * and reuses no chat token/output semantics. The relay holds the text and
 * forwards it here; the text never reaches the control plane.
 */
export interface WorkerSpeechRequest {
  dispatchToken: string;
  requestId: string;
  providerName: string;
  externalModelId: string;
  input: string;
  voice?: string;
  responseFormat: string;
}

export interface WorkerSpeechResult {
  /** Base64 audio bytes (no data: prefix). Never crosses to the control plane. */
  audioBase64: string;
  mimeType: string;
}

/**
 * Synthetic health probe: a one-token inference sent purely to confirm a model
 * responds. It carries no ticket, no dispatch fence, and no billing — the whole
 * point is a cheap liveness signal for models that get little real traffic.
 */
export interface WorkerProbeRequest {
  requestId: string;
  providerName: string;
  externalModelId: string;
}

export interface WorkerProbeResult {
  ok: boolean;
  latencyMs: number;
  /** Upstream/provider HTTP status when the probe failed, if known. */
  statusCode?: number;
  /** Allowlisted provider error code on failure (e.g. provider_timeout). */
  errorCode?: string;
}

/** The Venice worker as seen by the relay. Holds the Venice credential. */
export interface WorkerClient {
  attestation(request: WorkerAttestationRequest, signal?: AbortSignal): Promise<unknown>;
  chat(request: WorkerChatRequest, signal?: AbortSignal): Promise<WorkerChatResult>;
  embeddings?(request: WorkerEmbeddingRequest, signal?: AbortSignal): Promise<WorkerEmbeddingResult>;
  generateImage?(request: WorkerImageRequest, signal?: AbortSignal): Promise<WorkerImageResult>;
  generateSpeech?(request: WorkerSpeechRequest, signal?: AbortSignal): Promise<WorkerSpeechResult>;
  stream(request: WorkerChatRequest, signal?: AbortSignal): Promise<WorkerStreamResult>;
  /** Whole-body client ciphertext relay. Optional so workers that do not expose
   * a native opaque transport fail closed instead of accepting a JSON fallback. */
  opaqueE2ee?(request: WorkerOpaqueE2eeRequest, signal?: AbortSignal): Promise<WorkerOpaqueE2eeResult>;
  /** Synthetic health probe (in-process workers only; the relay never probes). */
  probe?(request: WorkerProbeRequest, signal?: AbortSignal): Promise<WorkerProbeResult>;
  /**
   * Provider-neutral, read-only TEE attestation fetch for the public TEE API
   * (GET /v1/tee/attestation). Runs on the credential-isolated worker so the
   * provider secret never leaves it; returns the raw enclave evidence for the
   * provider's TeeVerifier to check. No dispatch fence and no billing: it fetches
   * a quote, it does not run inference. Absent on relay clients that route by
   * provider (they delegate). Throws a provider-neutral error when the resolved
   * provider exposes no attestation.
   */
  attestationForModel?(providerName: string, externalModelId: string, nonce: string, signal?: AbortSignal): Promise<unknown>;
  /**
   * Provider-neutral per-request signature fetch, keyed by the provider request
   * id captured during inference. Throws `tee_signature_not_supported` when the
   * provider exposes none (never fabricated).
   */
  signatureForRequest?(providerName: string, externalModelId: string, providerRequestId: string, signal?: AbortSignal): Promise<unknown>;
}
