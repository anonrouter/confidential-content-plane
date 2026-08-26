// Canonical OpenRouter-style `creator/model` slugs derived from a provider's
// raw route id + display name. Used as the public model id so callers pass a
// clean, readable identifier (z-ai/glm-4.7) instead of the raw Venice route
// (zai-org-glm-4.7). The raw route stays as external_model_id for the provider
// call, and the gateway resolves either form.
//
// IMPORTANT: this logic is mirrored verbatim in
// site/scripts/generate-venice-catalog.mjs so the frontend catalog and the
// gateway agree on every slug. Keep the two in sync.

// Ordered: first regex (tested against `${routeId} ${displayName}` lowercased)
// wins. Falls back to "venice" for Venice-native / unknown-origin models.
const CREATOR_MATCHERS: { match: RegExp; creator: string }[] = [
  { match: /claude|anthropic/, creator: "anthropic" },
  { match: /\bnova\b/, creator: "amazon" },
  { match: /titan/, creator: "amazon" },
  { match: /deepseek/, creator: "deepseek" },
  { match: /llama/, creator: "meta-llama" },
  { match: /mistral|magistral|ministral|pixtral/, creator: "mistralai" },
  { match: /gpt|openai|sora|whisper|text-embedding-3/, creator: "openai" },
  { match: /gemma/, creator: "google" },
  { match: /gemini/, creator: "google" },
  { match: /nano-banana/, creator: "google" },
  { match: /lyria/, creator: "google" },
  { match: /\bveo/, creator: "google" },
  { match: /glm|zhipu|zai/, creator: "z-ai" },
  { match: /kimi|moonshot/, creator: "moonshotai" },
  { match: /qwen/, creator: "qwen" },
  { match: /thinkingmachines|inkling/, creator: "thinking-machines" },
  { match: /\bkling/, creator: "kuaishou" },
  { match: /grok|\bxai/, creator: "x-ai" },
  { match: /\bwan[- ]|wan2|z-image/, creator: "alibaba" },
  { match: /minimax|hailuo/, creator: "minimax" },
  { match: /pixverse/, creator: "pixverse" },
  { match: /seedream|seedance/, creator: "bytedance" },
  { match: /eleven/, creator: "elevenlabs" },
  { match: /\bluma/, creator: "luma" },
  { match: /runway/, creator: "runway" },
  { match: /ltx/, creator: "lightricks" },
  { match: /longcat/, creator: "meituan" },
  { match: /vidu/, creator: "vidu" },
  { match: /aion/, creator: "aion-labs" },
  { match: /flux/, creator: "black-forest-labs" },
  { match: /krea/, creator: "krea" },
  { match: /recraft/, creator: "recraft" },
  { match: /ideogram/, creator: "ideogram" },
  { match: /hunyuan/, creator: "tencent" },
  { match: /mercury|inception/, creator: "inception" },
  { match: /ace-step/, creator: "ace-step" },
  { match: /\bbge/, creator: "baai" },
  { match: /-e5-|\be5\b/, creator: "microsoft" },
  { match: /parakeet|nvidia|nemotron/, creator: "nvidia" },
  { match: /xiaomi|mimo/, creator: "xiaomi" },
  { match: /sd35|sdxl|stable-|stability/, creator: "stabilityai" },
  { match: /venice/, creator: "venice" }
];

export function creatorSlug(routeId: string, displayName: string): string {
  const haystack = `${routeId} ${displayName}`.toLowerCase();
  return CREATOR_MATCHERS.find((matcher) => matcher.match.test(haystack))?.creator ?? "venice";
}

export function slugifyModelName(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[\s_]+/g, "-")
    .replace(/[^a-z0-9.-]/g, "")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Base `creator/model` slug for a route. Deterministic and collision-free
 * across text (routable) models — colliding media variants are disambiguated
 * by assignCanonicalSlugs below.
 */
export function canonicalModelSlug(routeId: string, displayName: string): string {
  const creator = creatorSlug(routeId, displayName);
  let modelPart = slugifyModelName(displayName) || slugifyModelName(routeId) || "model";
  // The `-e2ee` suffix keeps the PUBLIC MODEL ID (the addressable route id) unique
  // per provider, since a provider can serve one model both plaintext and E2EE.
  // The CANONICAL grouping id (canonicalGroupId below) strips it so both routes
  // group under one model. E2EE is a serving modality, not a separate model.
  if (routeId.startsWith("e2ee-")) modelPart += "-e2ee";
  return `${creator}/${modelPart}`;
}

/**
 * The canonical creator/model grouping id for a public model slug: the id under
 * which every provider route for one model is grouped in /v1/models. It strips
 * the `-e2ee` route disambiguator so an E2EE route and its plaintext counterpart
 * (e.g. Venice GLM 5.2 with and without E2EE) share ONE canonical model. The
 * per-route `public_model_id` keeps its unique `-e2ee` form; only the grouping id
 * is stripped. E2EE is a serving modality (see docs/PROVIDER_ROUTING.md), not a
 * separate model.
 */
export function canonicalGroupId(publicModelSlug: string): string {
  return publicModelSlug.replace(/-e2ee$/, "");
}

// Modality tags appended to colliding media slugs (mirrors the frontend
// generator's VARIANT_TAGS ordering exactly).
const VARIANT_TAGS: [string, string][] = [
  ["reference-to-video", "r2v"],
  ["image-to-video", "i2v"],
  ["text-to-video", "t2v"],
  ["text-to-image", "t2i"],
  ["video-to-video", "v2v"],
  ["image-to-audio", "i2a"],
  ["text-to-audio", "t2a"],
  ["reference", "ref"],
  ["edit", "edit"]
];

function variantTag(routeId: string): string | null {
  return VARIANT_TAGS.find(([pattern]) => routeId.includes(pattern))?.[1] ?? null;
}

/** Display-name fallback used by the frontend generator; kept identical so
 *  slug computation agrees when model_spec.name is missing. */
export function titleCaseFromId(id: string): string {
  return (id.split("/").pop() ?? id)
    .split(/[-_]/)
    .map((part) => (part.length <= 3 ? part.toUpperCase() : part[0].toUpperCase() + part.slice(1)))
    .join(" ");
}

export interface SlugInput {
  routeId: string;
  displayName?: string | null;
  type?: string | null;
}

/**
 * routeId -> unique canonical slug for a full catalog snapshot. MUST be fed the
 * complete Venice model list (all types) — collision groups can span types, so
 * computing over a subset would disambiguate differently than the frontend.
 * Text models always claim the clean base slug; colliding media variants get a
 * modality/edit suffix. Mirrors site/scripts/generate-venice-catalog.mjs.
 */
export function assignCanonicalSlugs(models: SlugInput[]): Map<string, string> {
  const groups = new Map<string, SlugInput[]>();
  for (const model of models) {
    const displayName = model.displayName || titleCaseFromId(model.routeId);
    const slug = canonicalModelSlug(model.routeId, displayName);
    const group = groups.get(slug);
    if (group) group.push(model);
    else groups.set(slug, [model]);
  }
  const final = new Map<string, string>();
  for (const [slug, group] of groups) {
    if (group.length === 1) {
      final.set(group[0].routeId, slug);
      continue;
    }
    const used = new Set<string>();
    // Text first so a routable model always claims the clean base slug.
    const ordered = [...group].sort((a, b) => (a.type === "text" ? -1 : 0) - (b.type === "text" ? -1 : 0));
    for (const model of ordered) {
      const tag = variantTag(model.routeId);
      const candidate = tag && !used.has(`${slug}-${tag}`) ? `${slug}-${tag}` : slug;
      let attempt = candidate;
      let counter = 2;
      while (used.has(attempt)) {
        attempt = `${candidate === slug ? `${slug}-${slugifyModelName(model.routeId).slice(-14)}` : candidate}-${counter++}`;
      }
      used.add(attempt);
      final.set(model.routeId, attempt);
    }
  }
  return final;
}
