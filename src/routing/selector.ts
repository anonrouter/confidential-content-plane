import { calculateCostUsd } from "../metering/billing.js";
import type { TokenUsage } from "../metering/tokens.js";
import type { ChatCompletionRequestBody, ModelRecord } from "../providers/types.js";
import { AppError } from "../security/errors.js";
import type { RoutingClassification, RoutingTask } from "./classifier.js";

export interface RoutingDecision {
  model: ModelRecord;
  classification: RoutingClassification;
  estimatedCostUsd: number;
  effectiveMaxOutputTokens: number;
}

export function isAutomaticModel(model: string) {
  return model === "auto" || model === "/auto" || model === "anonrouter/auto" || model.includes("*");
}

// Cap wildcards per pattern. Legitimate routing globs carry one or two "*"
// (venice/*, *llama*, openai/gpt-*); anything past this is abuse, not a real
// allow/exclude rule. Enforced here so every caller is protected, not only the
// HTTP route (a saved preference or a raw request routing field passes through
// the same matcher).
const MAX_GLOB_WILDCARDS = 8;

// Case-insensitive glob match with linear time. "*" matches any run of
// characters including empty, every other character is literal, and the whole
// value must be consumed (equivalent to the old ^...$ anchoring). This is a
// greedy two-pointer scan with bounded backtrack (O(n*m) worst case): it never
// compiles a RegExp from caller input, so a pattern of many "*" cannot trigger
// catastrophic backtracking.
function globMatches(pattern: string, value: string) {
  let wildcards = 0;
  for (let i = 0; i < pattern.length; i += 1) {
    if (pattern[i] === "*") wildcards += 1;
  }
  if (wildcards > MAX_GLOB_WILDCARDS) return false;

  const p = pattern.toLowerCase();
  const v = value.toLowerCase();
  let pi = 0;
  let vi = 0;
  let star = -1;
  let mark = 0;
  while (vi < v.length) {
    if (pi < p.length && p[pi] === "*") {
      star = pi;
      mark = vi;
      pi += 1;
    } else if (pi < p.length && p[pi] === v[vi]) {
      pi += 1;
      vi += 1;
    } else if (star !== -1) {
      // The last "*" absorbs one more character of the value, then retry.
      pi = star + 1;
      mark += 1;
      vi = mark;
    } else {
      return false;
    }
  }
  // A fully consumed value matches only if the pattern tail is all "*".
  while (pi < p.length && p[pi] === "*") pi += 1;
  return pi === p.length;
}

function modelMatches(pattern: string, model: ModelRecord) {
  const canonical = `${model.providerName}/${model.publicModelId}`;
  return globMatches(pattern, canonical) || globMatches(pattern, model.publicModelId);
}

function privacyPolicyAllows(model: ModelRecord, privacyClasses: Set<string>) {
  if (!privacyClasses.has(model.privacyClass)) return false;
  if (privacyClasses.has(model.providerPrivacyClass)) return true;
  // A provider-wide private posture can carry a stricter model-specific route
  // (for example a Venice TEE/E2EE model) or a less-private explicitly allowed route.
  return model.providerPrivacyClass === "private" || model.providerPrivacyClass === "tee" || model.providerPrivacyClass === "e2ee";
}

export function filterRoutingPolicyModels(
  models: ModelRecord[],
  policy: Pick<ChatCompletionRequestBody, "model" | "routing">
) {
  const routing = policy.routing ?? {};
  const privacyClasses = new Set(routing.privacy_classes ?? ["private", "tee", "e2ee"]);
  const explicitModelPattern = policy.model.includes("*") ? policy.model : null;
  const allowPatterns = routing.allow === undefined ? ["*"] : routing.allow;
  const excludePatterns = routing.exclude ?? [];

  return models
    .filter((model) => model.routingEnabled)
    .filter((model) => !explicitModelPattern || modelMatches(explicitModelPattern, model))
    .filter((model) => allowPatterns.some((pattern) => modelMatches(pattern, model)))
    .filter((model) => !excludePatterns.some((pattern) => modelMatches(pattern, model)))
    .filter((model) => privacyPolicyAllows(model, privacyClasses));
}

/**
 * The quality floor each strategy aims for. "cost" is the budget mode: small and
 * cheap models are fair game. "balanced" (the default) targets frontier-class
 * models (tier 4: GLM 5, Kimi, DeepSeek V4, GPT-5 class) for the majority of
 * requests, stepping up to tier 5 for high-complexity work. "quality" always
 * demands tier 5. The floor is a preference, not a hard gate: selection relaxes
 * it tier by tier when nothing in the allowed pool satisfies it.
 */
function requiredQualityTier(classification: RoutingClassification, strategy: "cost" | "balanced" | "quality") {
  if (strategy === "cost") {
    const specializedTask = ["coding", "math", "research"].includes(classification.effectiveTask);
    let tier = classification.complexity === "high" ? 3 : specializedTask ? 2 : 1;
    if (classification.abstained) tier = Math.max(tier, 2);
    return tier;
  }
  if (strategy === "quality") return 5;
  return classification.complexity === "high" ? 5 : 4;
}

function isTaskCapable(model: ModelRecord, task: RoutingTask) {
  return model.routingTasks.includes(task);
}

function isSpecialist(model: ModelRecord, task: RoutingTask) {
  return model.routingTasks.includes(task) && model.routingTasks.length <= 2;
}

export interface RoutingCandidate {
  model: ModelRecord;
  effectiveMaxOutputTokens: number;
  estimatedCostUsd: number;
}

function isUncensored(model: ModelRecord) {
  return model.moderation === "uncensored";
}

/**
 * Rank every feasible candidate for a classified request, best first. The
 * quality floor relaxes tier by tier when the allowed pool cannot satisfy it,
 * so a constrained pool degrades gracefully instead of erroring. Requests
 * flagged as likely-censored steer to uncensored routes (best tier first) when
 * any exist in the pool; those routes bypass the quality floor so a mid-tier
 * uncensored model still beats a frontier refusal.
 */
export function rankRoutingCandidates(params: {
  models: ModelRecord[];
  body: ChatCompletionRequestBody;
  classification: RoutingClassification;
  inputTokens: number;
  requestedMaxOutputTokens?: number;
  /** When true, only tools-capable models are eligible. Content-free. */
  requiresTools?: boolean;
  /** When true, only vision-capable models are eligible. Content-free. */
  requiresVision?: boolean;
}): RoutingCandidate[] {
  const { models, body, classification, inputTokens, requestedMaxOutputTokens, requiresTools, requiresVision } = params;
  const routing = body.routing ?? {};
  const strategy = routing.strategy ?? "balanced";
  const preferredTier = requiredQualityTier(classification, strategy);

  const feasible = filterRoutingPolicyModels(models, body)
    .filter((model) => !body.stream || model.supportsStreaming)
    .filter((model) => !classification.needsWeb || model.supportsWeb)
    .filter((model) => !requiresTools || model.supportsTools)
    .filter((model) => !requiresVision || model.supportsVision)
    .filter((model) => isTaskCapable(model, classification.effectiveTask))
    .map((model) => {
      const advertised = model.maxOutputTokens;
      const remainingContext = model.contextWindow - inputTokens;
      if (!Number.isSafeInteger(advertised) || (advertised ?? 0) <= 0 || remainingContext <= 0) return null;
      if (requestedMaxOutputTokens !== undefined && requestedMaxOutputTokens > advertised!) return null;
      const effectiveMaxOutputTokens = requestedMaxOutputTokens ?? Math.min(advertised!, remainingContext);
      if (effectiveMaxOutputTokens > remainingContext) return null;
      const estimatedUsage: TokenUsage = { inputTokens, outputTokens: effectiveMaxOutputTokens, cachedTokens: 0 };
      return {
        model,
        effectiveMaxOutputTokens,
        estimatedCostUsd: calculateCostUsd(estimatedUsage, {
          inputPricePerMillion: model.inputPricePerMillion,
          outputPricePerMillion: model.outputPricePerMillion
        })
      };
    })
    .filter((candidate): candidate is RoutingCandidate => candidate !== null)
    .filter((candidate) => routing.max_cost_usd === undefined || candidate.estimatedCostUsd <= routing.max_cost_usd);

  // A real provider always beats the mock fixture, regardless of tier.
  const realFeasible = feasible.filter((candidate) => candidate.model.providerName !== "mock");
  const pool = realFeasible.length > 0 ? realFeasible : feasible;

  // Relax the quality floor only as far as the pool requires.
  let candidates: RoutingCandidate[] = [];
  for (let floor = preferredTier; floor >= 1 && candidates.length === 0; floor -= 1) {
    candidates = pool.filter(
      (candidate) => candidate.model.qualityTier >= floor || (classification.maybeSensitive && isUncensored(candidate.model))
    );
  }
  if (candidates.length === 0) return [];

  // Likely-censored request: hand it to the best uncensored route available.
  const sensitiveMode = classification.maybeSensitive && candidates.some((candidate) => isUncensored(candidate.model));
  if (sensitiveMode) candidates = candidates.filter((candidate) => isUncensored(candidate.model));

  candidates.sort((a, b) => {
    // Balanced and quality both rank best tier first and break ties on price:
    // "the cheapest frontier model", not "the cheapest model above the floor".
    // Only the explicit cost strategy ranks by price outright.
    if ((sensitiveMode || strategy !== "cost") && a.model.qualityTier !== b.model.qualityTier) {
      return b.model.qualityTier - a.model.qualityTier;
    }
    const shouldPreferSpecialist =
      strategy !== "cost" && ["coding", "math", "research"].includes(classification.effectiveTask);
    if (shouldPreferSpecialist) {
      const specialistDelta = Number(!isSpecialist(a.model, classification.effectiveTask)) - Number(!isSpecialist(b.model, classification.effectiveTask));
      if (specialistDelta !== 0) return specialistDelta;
    }
    if (a.estimatedCostUsd !== b.estimatedCostUsd) return a.estimatedCostUsd - b.estimatedCostUsd;
    if (a.model.qualityTier !== b.model.qualityTier) return a.model.qualityTier - b.model.qualityTier;
    return (a.model.expectedLatencyMs ?? Number.MAX_SAFE_INTEGER) - (b.model.expectedLatencyMs ?? Number.MAX_SAFE_INTEGER);
  });

  return candidates;
}

export function selectRoutingModel(params: {
  models: ModelRecord[];
  body: ChatCompletionRequestBody;
  classification: RoutingClassification;
  inputTokens: number;
  requestedMaxOutputTokens?: number;
  requiresTools?: boolean;
  requiresVision?: boolean;
}): RoutingDecision {
  const candidates = rankRoutingCandidates(params);
  if (candidates.length === 0) {
    // A tool-bearing automatic request whose pool would have candidates WITHOUT
    // the tools filter gets a stable, distinct error: the tools requirement is
    // specifically what disqualified every model. Same for the vision filter.
    if (params.requiresTools && rankRoutingCandidates({ ...params, requiresTools: false }).length > 0) {
      throw new AppError(400, "no_tools_capable_model", "No tools-capable model can satisfy the routing requirements");
    }
    if (params.requiresVision && rankRoutingCandidates({ ...params, requiresVision: false }).length > 0) {
      throw new AppError(400, "no_vision_capable_model", "No vision-capable model can satisfy the routing requirements");
    }
    throw new AppError(
      400,
      "no_routing_candidate",
      params.requestedMaxOutputTokens === undefined
        ? "No allowed model can satisfy the routing requirements"
        : "No allowed model can honor the requested output-token limit within its advertised maximum and context window"
    );
  }
  return {
    model: candidates[0].model,
    classification: params.classification,
    estimatedCostUsd: candidates[0].estimatedCostUsd,
    effectiveMaxOutputTokens: candidates[0].effectiveMaxOutputTokens
  };
}
