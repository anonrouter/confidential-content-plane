import type { FastifyReply, FastifyRequest } from "fastify";
import { AppError } from "../../security/errors.js";
import { safeEqual } from "../../security/crypto.js";

/** The presented bearer token, or "" when absent or malformed. */
export function bearerToken(request: FastifyRequest): string {
  const header = request.headers.authorization;
  return header?.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
}

/**
 * Constant-time bearer check for the internal RPC boundary. Each callee accepts
 * only its own high-entropy service token; this is the authenticated interface
 * between the relay, control-api, and venice-worker roles.
 */
export function requireServiceToken(expectedToken: string) {
  return async (request: FastifyRequest, _reply: FastifyReply) => {
    const presented = bearerToken(request);
    if (!expectedToken || !presented || !safeEqual(presented, expectedToken)) {
      throw new AppError(401, "service_unauthorized", "Service authentication required");
    }
  };
}

/**
 * Constant-time bearer check that accepts ANY one of several service tokens. The
 * worker → control metadata channel accepts the shared metadata token OR any
 * configured per-provider metadata token (AR-02). Every candidate is compared
 * (no short-circuit on a match) so acceptance never reveals which token matched.
 */
export function requireAnyServiceToken(expectedTokens: string[]) {
  const candidates = expectedTokens.filter((token) => token.length > 0);
  return async (request: FastifyRequest, _reply: FastifyReply) => {
    const presented = bearerToken(request);
    let matched = false;
    for (const token of candidates) {
      if (presented && safeEqual(presented, token)) matched = true;
    }
    if (!presented || !matched) {
      throw new AppError(401, "service_unauthorized", "Service authentication required");
    }
  };
}

/**
 * Which provider a presented token is the dedicated per-provider metadata token
 * for, or null when it is not (the shared token, or unrecognized). Control uses
 * this to bind a catalog push to exactly one provider: a per-provider token may
 * only carry a payload for its own provider (AR-02). The comparison is
 * constant-time per candidate.
 */
export function metadataProviderForToken(providerTokens: Record<string, string>, presented: string): string | null {
  if (!presented) return null;
  for (const [provider, token] of Object.entries(providerTokens)) {
    if (token && safeEqual(presented, token)) return provider;
  }
  return null;
}

export interface MetadataDeploymentScope {
  deploymentId: string;
  provider: string;
  token: string;
}

/**
 * Resolve a regional metadata capability without timing-short-circuiting the
 * candidate list. A token is unique by configuration; returning null therefore
 * means either a legacy token or an unrecognized credential.
 */
export function metadataDeploymentScopeForToken(
  scopes: MetadataDeploymentScope[],
  presented: string
): Omit<MetadataDeploymentScope, "token"> | null {
  if (!presented) return null;
  let matched: Omit<MetadataDeploymentScope, "token"> | null = null;
  for (const scope of scopes) {
    if (scope.token && safeEqual(presented, scope.token)) {
      matched = { deploymentId: scope.deploymentId, provider: scope.provider };
    }
  }
  return matched;
}

/** Bind an authenticated worker request to its declared provider/deployment. */
export function resolveMetadataRequestScope(params: {
  deploymentScopes: MetadataDeploymentScope[];
  providerTokens: Record<string, string>;
  presented: string;
  claimedProvider: string;
  claimedDeploymentId: string;
}): { provider: string | null; deploymentId: string } {
  const deploymentScope = metadataDeploymentScopeForToken(params.deploymentScopes, params.presented);
  if (deploymentScope) {
    if (deploymentScope.provider !== params.claimedProvider
      || deploymentScope.deploymentId !== params.claimedDeploymentId) {
      throw new AppError(403, "metadata_scope_forbidden", "Metadata capability does not match provider and deployment");
    }
    return deploymentScope;
  }
  const legacyProvider = metadataProviderForToken(params.providerTokens, params.presented);
  if ((legacyProvider && legacyProvider !== params.claimedProvider) || params.claimedDeploymentId !== "primary") {
    throw new AppError(403, "metadata_scope_forbidden", "Regional metadata requires a deployment-scoped capability");
  }
  // Preserve the distinction between a provider-bound legacy token and the
  // shared token. Catalog authorization relies on null here to prevent the
  // shared token from writing a provider that has its own dedicated token.
  return { provider: legacyProvider, deploymentId: "primary" };
}
