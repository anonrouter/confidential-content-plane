// Canonical reasoning/thinking configuration.
//
// This is the ONE module that interprets reasoning controls. The public request
// schema, ticket issuance, relay redemption checks, control-plane validation,
// and provider forwarding all normalize through here so no component can
// interpret `reasoning_effort` / `reasoning` / legacy `disable_thinking`
// differently from another.
//
// A request resolves to exactly one of three canonical states:
//   - default   : no override; the provider's own default behavior applies
//   - disabled  : reasoning must be off (only valid where the model can disable)
//   - effort L  : a specific effort level (only valid where the model lists L)
//
// Precedence and conflicts are strict, never silent: contradictory signals are
// a 400 (`reasoning_conflict`), and an unsupported setting for the resolved
// model is a 400 — nothing is downgraded or quietly dropped.
//
// Capability semantics (verified against docs.venice.ai and the live
// `GET /models` catalog, 2026-07):
//   - `supportsReasoning`        : the model may reason and emit `reasoning_content`
//   - `supportsReasoningEffort`  : the model accepts a `reasoning_effort` parameter
//   - `reasoningEffortOptions`   : the exact accepted values, including "none"
//                                  when the provider supports disabling
//   - `defaultReasoningEffort`   : the provider default level
// These are independent capabilities; none is inferred from another. Venice
// does not auto-map unsupported values (they 400), so validation is anchored on
// the catalog-attested option list and fails closed when data is missing.
//
// Wire translation: an effort level forwards as top-level `reasoning_effort`
// (the OpenAI-compatible form; Venice gives it precedence over nested
// `reasoning.effort`). Disabling forwards as `reasoning_effort: "none"`, the
// mechanism whose per-model validity the catalog attests via
// `reasoningEffortOptions`. Legacy `venice_parameters.disable_thinking` is
// absorbed into the canonical state here and never forwarded upstream.
// `strip_thinking_response` only hides returned reasoning text — it does NOT
// disable reasoning and is deliberately not part of this configuration.

import { z } from "zod";
import { AppError } from "../security/errors.js";

/** Requestable effort levels in canonical (ascending) order. "none" is not a
 *  level — it is the wire form of the disabled state. */
export const REASONING_EFFORT_LEVELS = ["minimal", "low", "medium", "high", "xhigh", "max"] as const;
export type ReasoningEffortLevel = (typeof REASONING_EFFORT_LEVELS)[number];

export const reasoningEffortLevelSchema = z.enum(REASONING_EFFORT_LEVELS);

/** Public wire enum for `reasoning_effort` / `reasoning.effort`. */
export const reasoningEffortWireSchema = z.enum(["none", ...REASONING_EFFORT_LEVELS]);
export type ReasoningEffortWire = z.infer<typeof reasoningEffortWireSchema>;

/**
 * Nested `reasoning` request object. Only documented, cost-relevant fields are
 * accepted: `enabled` and `effort`. (`reasoning.summary` and provider-specific
 * extensions are rejected by strictness — fail closed.)
 */
export const reasoningRequestSchema = z
  .object({
    enabled: z.boolean().optional(),
    effort: reasoningEffortWireSchema.optional()
  })
  .strict();
export type ReasoningRequestObject = z.infer<typeof reasoningRequestSchema>;

export type ReasoningSelection =
  | { mode: "default" }
  | { mode: "disabled" }
  | { mode: "effort"; effort: ReasoningEffortLevel };

export const DEFAULT_REASONING_SELECTION: ReasoningSelection = { mode: "default" };

/** The reasoning-relevant surface of a chat/ticket request body. */
export interface ReasoningRequestFields {
  reasoning_effort?: ReasoningEffortWire;
  reasoning?: ReasoningRequestObject;
  venice_parameters?: { disable_thinking?: boolean };
}

function conflict(detail: string): AppError {
  return new AppError(400, "reasoning_conflict", `Conflicting reasoning parameters: ${detail}`);
}

/**
 * Resolve the request's reasoning surface to one canonical selection.
 * Deterministic rules (documented in docs/SDK_COMPATIBILITY.md):
 *   - `reasoning_effort` and `reasoning.effort` must agree when both are sent.
 *   - "none" (either form), `reasoning.enabled: false`, and legacy
 *     `venice_parameters.disable_thinking: true` all mean disabled and must not
 *     be combined with an effort level.
 *   - `reasoning.enabled: true` is a no-op confirmation: alone it keeps the
 *     provider default; with an effort it selects that effort; with any disable
 *     signal it conflicts.
 * Contradictions are a 400, never silent precedence.
 */
export function resolveReasoningSelection(fields: ReasoningRequestFields): ReasoningSelection {
  const flat = fields.reasoning_effort;
  const nested = fields.reasoning?.effort;
  const enabled = fields.reasoning?.enabled;
  const legacyDisable = fields.venice_parameters?.disable_thinking === true;

  if (flat !== undefined && nested !== undefined && flat !== nested) {
    throw conflict(`reasoning_effort "${flat}" does not match reasoning.effort "${nested}"`);
  }
  const effort = flat ?? nested;

  const disableSignal = effort === "none" || enabled === false || legacyDisable;
  if (disableSignal) {
    if (effort !== undefined && effort !== "none") {
      throw conflict(`reasoning cannot be disabled and set to effort "${effort}" at once`);
    }
    if (enabled === true) {
      throw conflict('reasoning.enabled: true contradicts a disable signal ("none" or disable_thinking)');
    }
    return { mode: "disabled" };
  }

  if (effort !== undefined) {
    return { mode: "effort", effort };
  }
  return { mode: "default" };
}

/** Stable, deterministic digest of a selection. Bound into single-use tickets
 *  so issuance and redemption cannot disagree ("default" | "disabled" | "effort:high"). */
export function reasoningSelectionKey(selection: ReasoningSelection): string {
  if (selection.mode === "effort") return `effort:${selection.effort}`;
  return selection.mode;
}

/** Inverse of {@link reasoningSelectionKey}. Absent or unrecognized keys parse
 *  as the default selection (a ticket issued before this feature carries none). */
export function parseReasoningSelectionKey(key: string | null | undefined): ReasoningSelection {
  if (!key || key === "default") return { mode: "default" };
  if (key === "disabled") return { mode: "disabled" };
  if (key.startsWith("effort:")) {
    const effort = key.slice("effort:".length);
    if ((REASONING_EFFORT_LEVELS as readonly string[]).includes(effort)) {
      return { mode: "effort", effort: effort as ReasoningEffortLevel };
    }
  }
  return { mode: "default" };
}

/**
 * Sanitized per-model reasoning capabilities. Sourced from the normalized
 * catalog (see src/providers/catalog/normalize.ts); every field is independent:
 *   - supported          : may reason / may emit reasoning_content
 *   - effortConfigurable : accepts at least one requestable effort level
 *   - supportedEfforts   : the exact accepted levels (canonical order)
 *   - canDisable         : provider attests reasoning can be turned off
 *   - defaultEffort      : provider default level when published and valid
 *   - alwaysOn           : reasons unconditionally (supported and not disableable)
 */
export interface ModelReasoningCapabilities {
  supported: boolean;
  effortConfigurable: boolean;
  supportedEfforts: ReasoningEffortLevel[];
  canDisable: boolean;
  defaultEffort: ReasoningEffortLevel | null;
  alwaysOn: boolean;
}

/** Fail-closed capabilities: not a reasoning model, nothing configurable. */
export const NO_REASONING_CAPABILITIES: ModelReasoningCapabilities = {
  supported: false,
  effortConfigurable: false,
  supportedEfforts: [],
  canDisable: false,
  defaultEffort: null,
  alwaysOn: false
};

/**
 * Defensively decode capabilities from storage (jsonb column / RPC payload).
 * Anything missing or malformed fails closed to {@link NO_REASONING_CAPABILITIES}
 * so a stale or tampered row can only withhold options, never invent them.
 */
export function decodeReasoningCapabilities(value: unknown): ModelReasoningCapabilities {
  if (!value || typeof value !== "object" || Array.isArray(value)) return { ...NO_REASONING_CAPABILITIES, supportedEfforts: [] };
  const record = value as Record<string, unknown>;
  if (record.supported !== true) return { ...NO_REASONING_CAPABILITIES, supportedEfforts: [] };
  const rawEfforts = Array.isArray(record.supportedEfforts) ? record.supportedEfforts : [];
  const supportedEfforts = REASONING_EFFORT_LEVELS.filter((level) => rawEfforts.includes(level));
  const canDisable = record.canDisable === true;
  const defaultEffort =
    typeof record.defaultEffort === "string" && (supportedEfforts as string[]).includes(record.defaultEffort)
      ? (record.defaultEffort as ReasoningEffortLevel)
      : null;
  return {
    supported: true,
    effortConfigurable: record.effortConfigurable === true && supportedEfforts.length > 0,
    supportedEfforts,
    canDisable,
    defaultEffort,
    alwaysOn: !canDisable
  };
}

/**
 * Validate a canonical selection against the resolved model's capabilities.
 * Fail closed with a clear 4xx; nothing unsupported may reach the provider and
 * nothing is silently downgraded.
 *
 * One deliberate compatibility carve-out: disabling reasoning on a model that
 * is not reasoning-capable is a satisfied no-op (nothing to disable, nothing is
 * forwarded). This keeps long-standing clients that sprinkle the legacy
 * `disable_thinking: true` over non-reasoning models working. Disabling a
 * reasoning model that cannot stop reasoning is rejected — the request cannot
 * be honored.
 */
export function validateReasoningSelection(
  selection: ReasoningSelection,
  capabilities: ModelReasoningCapabilities,
  modelId: string
): void {
  if (selection.mode === "default") return;

  if (selection.mode === "disabled") {
    if (!capabilities.supported) return; // no-op: nothing to disable
    if (!capabilities.canDisable) {
      throw new AppError(
        400,
        "reasoning_not_disableable",
        `Model ${modelId} always reasons; reasoning cannot be disabled`
      );
    }
    return;
  }

  if (!capabilities.supported) {
    throw new AppError(400, "reasoning_not_supported", `Model ${modelId} does not support reasoning`);
  }
  if (!capabilities.effortConfigurable) {
    throw new AppError(
      400,
      "reasoning_effort_not_configurable",
      `Model ${modelId} does not accept a configurable reasoning effort`
    );
  }
  if (!capabilities.supportedEfforts.includes(selection.effort)) {
    throw new AppError(
      400,
      "reasoning_effort_unsupported",
      `Model ${modelId} does not support reasoning effort "${selection.effort}" (supported: ${capabilities.supportedEfforts.join(", ")})`
    );
  }
}

/**
 * Translate a validated canonical selection into the exact Venice-compatible
 * provider fields. Assumes {@link validateReasoningSelection} passed for this
 * model. The default selection adds nothing (no accidental override); the
 * disabled selection forwards the catalog-attested `"none"` value, and is a
 * forwarded no-op for models that never reason.
 */
export function providerReasoningFields(
  selection: ReasoningSelection,
  capabilities: ModelReasoningCapabilities
): { reasoning_effort?: ReasoningEffortWire } {
  if (selection.mode === "effort") return { reasoning_effort: selection.effort };
  if (selection.mode === "disabled" && capabilities.supported && capabilities.canDisable) {
    return { reasoning_effort: "none" };
  }
  return {};
}
