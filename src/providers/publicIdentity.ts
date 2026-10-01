// PUBLIC PROVIDER IDENTITY: the one mapping from an INTERNAL provider id to what
// a customer sees.
//
// Internally every provider keeps its real id: credentials, worker role, egress,
// attestation verifiers, billing rows and admin data all say `near-ai`. A
// provider can instead be PRESENTED under a public provider group. Today there is
// one group, "Other" (public slug `other`), with one member, `near-ai`: NEAR AI
// approved AnonRouter offering NEAR AI Cloud's models on the condition that they
// are listed under a provider called "Other" rather than under NEAR's name.
//
// THIS FILE IS THE SINGLE SOURCE, AND IT IS MIRRORED VERBATIM. It has no imports
// so other packages can carry byte-identical copies (npm run gen:provider-identity):
//   site/lib/provider-identity.generated.ts    the PUBLIC SECTION only. The
//       website bundle ships to browsers, so it must never contain a member's
//       internal id, operator label or concealed terms.
//   admin/src/provider-identity.generated.ts   the whole file (operator console).
// tests/unit/provider-identity-mirror.test.ts fails when either copy drifts, and
// asserts the site copy names no concealed member.
//
// The rules every surface follows:
//   - Customer-facing provider ids pass through `publicProviderSlug`, names
//     through `publicProviderName`. Nothing customer-facing prints a member id.
//   - Provider-qualified public route ids use the member's route-id namespace,
//     exactly like `chutes/<slug>` or `phala-ai/<slug>`: a NEAR route is
//     `other/<slug>`.
//   - A member id is NOT a public provider id, on input or output. A customer
//     who sends `near-ai` (as a provider pin, in order/only/ignore, in saved
//     workspace defaults, as the E2EE provider header, as an uptime filter or as
//     a `near-ai/<slug>` model id) gets exactly what any unknown provider gets:
//     it matches nothing. There is no alias, because an accepted alias lets
//     anyone confirm what "Other" is (owner decision, 2026-10-01; these routes
//     were never public, so nothing depended on one). Public input is compared
//     against the PUBLIC form of each route; internal ids never match it.
//   - Operator tools (admin console, adminctl, logs) may show
//     `operatorProviderLabel`, e.g. "Other (NEAR AI)".
//   - Attestation EVIDENCE is exempt: a verifier report necessarily names the
//     serving operator's published repositories, registry and TLS domains.
//     Our own fields and copy around it never add the member's name.
//
// Adding a member: add it to PUBLIC_PROVIDER_MEMBERS with a group, an operator
// label, a route-id namespace and its concealed terms. Public route ids must
// stay globally unique, so two members of one group need distinct namespaces
// (the mirror test enforces it) or slugs that can never collide.

// ---- BEGIN PUBLIC SECTION (mirrored to the website) ----

/** A public provider identity that one or more internal providers are shown as. */
export interface PublicProviderGroup {
  /** Public slug: catalog `provider`, response headers, routing preferences. */
  readonly slug: string;
  /** Public display name. */
  readonly displayName: string;
  /** Neutral one-line description for provider listings. Never identifies a member. */
  readonly description: string;
}

export const PUBLIC_PROVIDER_GROUPS: Readonly<Record<string, PublicProviderGroup>> = {
  other: {
    slug: "other",
    displayName: "Other",
    description: "Additional models AnonRouter serves through partner inference providers that are not listed by name."
  }
};

/** Whether a slug is a public group slug (e.g. `other`). */
export function isPublicProviderGroupSlug(slug: string): boolean {
  return Object.prototype.hasOwnProperty.call(PUBLIC_PROVIDER_GROUPS, slug);
}

/** The public group for a group slug, or null. */
export function publicProviderGroupBySlug(slug: string): PublicProviderGroup | null {
  return isPublicProviderGroupSlug(slug) ? PUBLIC_PROVIDER_GROUPS[slug] : null;
}

// ---- END PUBLIC SECTION ----

/** An internal provider presented under a public group. */
export interface PublicProviderMember {
  /** The PublicProviderGroup slug this member is shown as. */
  readonly group: string;
  /** Operator-only label (admin console, adminctl). Never customer-facing. */
  readonly operatorLabel: string;
  /** Public route-id namespace: this member's routes are `<namespace>/<slug>`. */
  readonly routeIdNamespace: string;
  /**
   * Lower-case words that identify the member. Customer-facing copy we author
   * must not contain them (whole-word, case-insensitive); the no-leak tests and
   * the public catalog read boundary enforce it. Attestation evidence is exempt.
   */
  readonly concealedTerms: readonly string[];
}

export const PUBLIC_PROVIDER_MEMBERS: Readonly<Record<string, PublicProviderMember>> = {
  "near-ai": {
    group: "other",
    operatorLabel: "Other (NEAR AI)",
    routeIdNamespace: "other",
    concealedTerms: ["near", "nearai", "near.ai", "near-ai"]
  }
};

function memberOf(internalProvider: string): PublicProviderMember | null {
  return Object.prototype.hasOwnProperty.call(PUBLIC_PROVIDER_MEMBERS, internalProvider)
    ? PUBLIC_PROVIDER_MEMBERS[internalProvider]
    : null;
}

/** The public group an internal provider is presented under, or null when it is shown as itself. */
export function publicProviderGroupFor(internalProvider: string): PublicProviderGroup | null {
  const member = memberOf(internalProvider);
  return member ? publicProviderGroupBySlug(member.group) : null;
}

/** Whether an internal provider is presented under a public group. */
export function isPublicProviderMember(internalProvider: string): boolean {
  return memberOf(internalProvider) !== null;
}

/** Customer-facing provider id for an internal provider id (identity for non-members). */
export function publicProviderSlug(internalProvider: string): string {
  return publicProviderGroupFor(internalProvider)?.slug ?? internalProvider;
}

/** Customer-facing provider name; `internalName` is used for non-members. */
export function publicProviderName(internalProvider: string, internalName: string): string {
  return publicProviderGroupFor(internalProvider)?.displayName ?? internalName;
}

/** Operator-facing provider label; `internalName` is used for non-members. */
export function operatorProviderLabel(internalProvider: string, internalName: string): string {
  return memberOf(internalProvider)?.operatorLabel ?? internalName;
}

/**
 * Internal providers a CUSTOMER-SUPPLIED public provider slug covers: a group's
 * members, otherwise the slug itself. A member id is not a public slug and
 * covers nothing, exactly like a provider that does not exist.
 */
export function internalProvidersForPublicSlug(publicSlug: string): string[] {
  const base = publicSlug.split("/")[0];
  if (isPublicProviderMember(base)) return [];
  if (!isPublicProviderGroupSlug(publicSlug)) return [publicSlug];
  return Object.keys(PUBLIC_PROVIDER_MEMBERS).filter((id) => PUBLIC_PROVIDER_MEMBERS[id].group === publicSlug);
}

/**
 * Customer-facing form of a provider-qualified route id read from STORAGE. A
 * member-namespaced id (`near-ai/<slug>`, a row written before its provider
 * moved under a group) becomes `<routeIdNamespace>/<slug>`; every other id
 * (canonical `creator/model` ids included) is returned unchanged.
 *
 * OUTPUT ONLY. Never apply this to customer input: that would turn the internal
 * namespace back into an accepted alias.
 */
export function publicRouteId(routeId: string): string {
  const slash = routeId.indexOf("/");
  if (slash <= 0) return routeId;
  const member = memberOf(routeId.slice(0, slash));
  return member ? `${member.routeIdNamespace}${routeId.slice(slash)}` : routeId;
}

/**
 * Whether a CUSTOMER-SUPPLIED model id is in a member's INTERNAL route-id
 * namespace (`near-ai/<slug>`, compared case-insensitively). Such an id is
 * refused exactly like an unknown model, before any lookup: a row still stored
 * in that format must not be reachable, or confirmable, by its internal id.
 */
export function isMemberInternalRouteId(routeId: string): boolean {
  const slash = routeId.indexOf("/");
  if (slash <= 0) return false;
  const prefix = routeId.slice(0, slash).trim().toLowerCase();
  const member = memberOf(prefix);
  return member !== null && member.routeIdNamespace !== prefix;
}

/**
 * Whether a STORED public route id of `internalProvider` predates the
 * provider's public id format: a member's rows must be `<namespace>/<slug>`.
 * Such a row (written by a normalizer from before the member moved under a
 * group) is never listed, enabled or callable; the next sync rewrites it.
 */
export function isLegacyMemberRouteId(internalProvider: string, publicModelId: string): boolean {
  const member = memberOf(internalProvider);
  return member !== null && !publicModelId.startsWith(`${member.routeIdNamespace}/`);
}

/** Public route id for one of a provider's routes: `<namespace>/<slug>` for a member, else `<provider>/<slug>`. */
export function providerQualifiedRouteId(internalProvider: string, slug: string): string {
  return `${memberOf(internalProvider)?.routeIdNamespace ?? internalProvider}/${slug}`;
}

/** Every concealed term across all members (lower-case, de-duplicated, sorted). */
export function concealedProviderTerms(): string[] {
  const terms = new Set<string>();
  for (const member of Object.values(PUBLIC_PROVIDER_MEMBERS)) {
    for (const term of member.concealedTerms) terms.add(term.toLowerCase());
  }
  return [...terms].sort();
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Whether customer-facing text names a concealed member. Whole-word and
 * case-insensitive, so "near" matches "NEAR AI", "near-ai" and "near.ai" but not
 * "linear", "nearest" or "nearly".
 */
export function mentionsConcealedProvider(text: string): boolean {
  return concealedProviderTerms().some((term) =>
    new RegExp(`(^|[^a-z0-9])${escapeRegExp(term)}($|[^a-z0-9])`, "i").test(text)
  );
}
