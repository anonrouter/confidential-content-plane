import { describe, expect, it } from "vitest";
import {
  metadataDeploymentScopeForToken,
  metadataProviderForToken,
  resolveMetadataRequestScope
} from "../../src/routes/internal/serviceAuth.js";

// AR-02: the worker -> control catalog push must be bound to exactly one
// provider. Control maps the PRESENTED per-provider metadata token to a provider
// and rejects any payload whose `provider` differs. This exercises that mapping
// and the cross-provider rejection decision without a DB, mirroring the guard in
// registerControlRpcRoutes (`/internal/control/catalog`).

const VENICE_TOKEN = "venice-metadata-token-0123456789abcdef0123456789";
const FIREWORKS_TOKEN = "fireworks-metadata-token-0123456789abcdef01234567";
const BEDROCK_TOKEN = "bedrock-metadata-token-0123456789abcdef0123456789";
const DEEPINFRA_TOKEN = "deepinfra-metadata-token-0123456789abcdef01234567";
const SHARED_TOKEN = "shared-metadata-token-0123456789abcdef0123456789ab";

const providerTokens: Record<string, string> = {
  venice: VENICE_TOKEN,
  fireworks: FIREWORKS_TOKEN,
  "aws-bedrock": BEDROCK_TOKEN,
  deepinfra: DEEPINFRA_TOKEN
};

// The exact decision the catalog route applies after authentication (AR-02,
// hardened fail-closed). A per-provider token may push only its own provider;
// the shared/unknown token may not push any provider that owns a dedicated
// token. Providers with no dedicated token stay in single-token mode.
function isForbiddenPush(tokens: Record<string, string>, presented: string, payloadProvider: string): boolean {
  const bound = metadataProviderForToken(tokens, presented);
  if (bound !== null) return payloadProvider !== bound;
  return Boolean(tokens[payloadProvider]);
}

describe("AR-02 catalog push provider binding", () => {
  it("maps each per-provider token to its own provider", () => {
    expect(metadataProviderForToken(providerTokens, VENICE_TOKEN)).toBe("venice");
    expect(metadataProviderForToken(providerTokens, FIREWORKS_TOKEN)).toBe("fireworks");
    expect(metadataProviderForToken(providerTokens, BEDROCK_TOKEN)).toBe("aws-bedrock");
    expect(metadataProviderForToken(providerTokens, DEEPINFRA_TOKEN)).toBe("deepinfra");
  });

  it("returns null for the shared token, an unknown token, or an empty token", () => {
    expect(metadataProviderForToken(providerTokens, SHARED_TOKEN)).toBeNull();
    expect(metadataProviderForToken(providerTokens, "not-a-real-token")).toBeNull();
    expect(metadataProviderForToken(providerTokens, "")).toBeNull();
  });

  it("rejects a cross-provider push (venice token, fireworks payload -> forbidden)", () => {
    expect(isForbiddenPush(providerTokens, VENICE_TOKEN, "fireworks")).toBe(true);
    expect(isForbiddenPush(providerTokens, VENICE_TOKEN, "aws-bedrock")).toBe(true);
    expect(isForbiddenPush(providerTokens, DEEPINFRA_TOKEN, "venice")).toBe(true);
  });

  it("allows a same-provider push (venice token, venice payload)", () => {
    expect(isForbiddenPush(providerTokens, VENICE_TOKEN, "venice")).toBe(false);
    expect(isForbiddenPush(providerTokens, FIREWORKS_TOKEN, "fireworks")).toBe(false);
    expect(isForbiddenPush(providerTokens, BEDROCK_TOKEN, "aws-bedrock")).toBe(false);
  });

  it("does not bind (no enforcement) when only the shared token is configured", () => {
    // Single-token mode: the shared token maps to no provider, so any payload is
    // accepted by this decision (the prior monolith/dev behavior is preserved).
    expect(isForbiddenPush({}, SHARED_TOKEN, "venice")).toBe(false);
    expect(isForbiddenPush({}, SHARED_TOKEN, "fireworks")).toBe(false);
  });

  it("fails closed: the shared token cannot push a provider that owns a dedicated token", () => {
    // Hardened split prod configures a distinct token for every provider, so the
    // control-only shared token can never write any provider's catalog. This is
    // what makes re-mounting the shared token onto a worker unable to reopen AR-02.
    expect(isForbiddenPush(providerTokens, SHARED_TOKEN, "venice")).toBe(true);
    expect(isForbiddenPush(providerTokens, SHARED_TOKEN, "fireworks")).toBe(true);
    expect(isForbiddenPush(providerTokens, "unrecognized-token", "aws-bedrock")).toBe(true);
  });

  it("allows single-token mode per provider during a partial rollout", () => {
    // Only venice has a dedicated token: venice is bound, but a provider without
    // its own token still accepts the shared token (staged rollout does not break).
    const partial = { venice: VENICE_TOKEN };
    expect(isForbiddenPush(partial, VENICE_TOKEN, "venice")).toBe(false);
    expect(isForbiddenPush(partial, SHARED_TOKEN, "venice")).toBe(true);
    expect(isForbiddenPush(partial, SHARED_TOKEN, "fireworks")).toBe(false);
  });
});

describe("regional metadata capability binding", () => {
  const scopes = [
    { deploymentId: "eu-ams-1", provider: "venice", token: VENICE_TOKEN },
    { deploymentId: "us-east-1", provider: "venice", token: FIREWORKS_TOKEN }
  ];

  it("resolves one token to exactly one provider and deployment", () => {
    expect(metadataDeploymentScopeForToken(scopes, VENICE_TOKEN)).toEqual({
      deploymentId: "eu-ams-1",
      provider: "venice"
    });
    expect(metadataDeploymentScopeForToken(scopes, FIREWORKS_TOKEN)).toEqual({
      deploymentId: "us-east-1",
      provider: "venice"
    });
  });

  it("does not treat a legacy, unknown, or empty token as regional authority", () => {
    expect(metadataDeploymentScopeForToken(scopes, SHARED_TOKEN)).toBeNull();
    expect(metadataDeploymentScopeForToken(scopes, "unknown")).toBeNull();
    expect(metadataDeploymentScopeForToken(scopes, "")).toBeNull();
  });

  it("rejects cross-region and cross-provider claims before dispatch", () => {
    const resolve = (token: string, provider: string, deploymentId: string) => resolveMetadataRequestScope({
      deploymentScopes: scopes,
      providerTokens,
      presented: token,
      claimedProvider: provider,
      claimedDeploymentId: deploymentId
    });
    expect(resolve(VENICE_TOKEN, "venice", "eu-ams-1")).toEqual({ provider: "venice", deploymentId: "eu-ams-1" });
    expect(() => resolve(VENICE_TOKEN, "venice", "us-east-1")).toThrow(/does not match/);
    expect(() => resolve(VENICE_TOKEN, "fireworks", "eu-ams-1")).toThrow(/does not match/);
    expect(() => resolve(SHARED_TOKEN, "venice", "eu-ams-1")).toThrow(/deployment-scoped/);
    expect(() => resolve(BEDROCK_TOKEN, "venice", "primary")).toThrow(/deployment-scoped/);
  });

  it("does not upgrade the shared legacy token into provider-bound authority", () => {
    expect(resolveMetadataRequestScope({
      deploymentScopes: scopes,
      providerTokens,
      presented: SHARED_TOKEN,
      claimedProvider: "venice",
      claimedDeploymentId: "primary"
    })).toEqual({ provider: null, deploymentId: "primary" });
    expect(resolveMetadataRequestScope({
      deploymentScopes: scopes,
      providerTokens,
      presented: VENICE_TOKEN,
      claimedProvider: "venice",
      claimedDeploymentId: "eu-ams-1"
    })).toEqual({ provider: "venice", deploymentId: "eu-ams-1" });
  });
});
