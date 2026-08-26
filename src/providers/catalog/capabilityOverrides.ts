/**
 * Observed capability corrections, where a provider's advertised metadata is
 * contradicted by what the model actually does.
 *
 * WHY THIS EXISTS. Tool support is taken from the provider's own catalogue tags,
 * which is right by default — we should not second-guess an upstream that knows
 * its own models. But a tag is a claim, and a coding agent does not consume
 * claims, it consumes behaviour. When the two disagree the agent is the one that
 * breaks, halfway through a task, with a 200 and nothing in any log.
 *
 * The bar for an entry here is deliberately high: a reproducible observation
 * against the live provider, recorded with what was seen. This is not a place to
 * encode preferences or to disable a model somebody dislikes.
 *
 * A correction may only ever REMOVE a capability. Granting one the provider does
 * not advertise would be inventing a claim rather than correcting one, and would
 * fail in exactly the same way it is meant to prevent.
 */

export interface CapabilityOverride {
  /** providers.providers.name */
  provider: string;
  /** The provider-native model id, as the normalizer sees it. */
  modelId: string;
  /** Only ever false: a correction removes a capability, never adds one. */
  supportsTools?: false;
  /** What was observed, and when. Kept so a future reviewer can re-test. */
  evidence: string;
}

export const CAPABILITY_OVERRIDES: readonly CapabilityOverride[] = [
  {
    provider: "deepinfra",
    modelId: "mistralai/Mistral-Nemo-Instruct-2407",
    supportsTools: false,
    evidence:
      "2026-08-24, live against the deployment with an explicit tool_choice. Tool "
      + "calling is INTERMITTENT rather than absent: one attempt returned a correct "
      + "structured tool_call, the next leaked the model's internal '[TOOL_CALLS]' "
      + "sentinel into message.content as prose with finish_reason=stop and an empty "
      + "tool_calls array. Unreliable structured output is worse for an agent than no "
      + "support at all, because the agent cannot detect the failure: it receives "
      + "plausible text where it expected a call, and stalls. DeepInfra tags this "
      + "model 'tools'."
  }
];

/**
 * Apply any correction for one route.
 *
 * Matching is case-insensitive on the native id because providers are not
 * consistent about casing between their list and detail endpoints, and a
 * correction that silently stops matching is worse than no correction: the
 * capability would quietly revert with nothing to show it had.
 */
export function applyCapabilityOverride<T extends { supportsTools: boolean }>(
  provider: string,
  modelId: string,
  route: T
): T {
  const override = CAPABILITY_OVERRIDES.find(
    (entry) => entry.provider === provider
      && entry.modelId.toLowerCase() === modelId.toLowerCase()
  );
  if (!override) return route;
  return { ...route, ...(override.supportsTools === false ? { supportsTools: false } : {}) };
}
