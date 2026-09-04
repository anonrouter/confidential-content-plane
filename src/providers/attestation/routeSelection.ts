// "Which route am I attesting?" answered ONCE, for every caller that asks.
//
// Three surfaces used to answer this question, and two of them answered it
// differently:
//
//   - GET /v1/tee/attestation (src/routes/tee.ts) filtered to TEE/E2EE routes
//     with a registered verifier and demanded a `provider` selector whenever the
//     model had more than one;
//   - the attestation-ticket mint (ControlPlane.issueAttestationTicket) accepted
//     `e2ee` only, and when no provider was given let `getEnabledModel` PICK the
//     best route by privacy class and price.
//
// The second behaviour is the dangerous one. "Which enclave did I just verify"
// must have exactly one answer, chosen by the caller: a silent best-route pick
// can attest Venice and then run on Tinfoil, and the customer sees a green
// verdict for an enclave their prompt never touched. So both callers now share
// this module, and an ambiguous request is a 409 asking for a selector rather
// than a guess.

import { AppError } from "../../security/errors.js";
import type { ModelRecord } from "../types.js";
import { providerExposesAttestation } from "./registry.js";

/**
 * The catalog's test-fixture provider.
 *
 * It stands in for a real provider across the split-role acceptance suite, and
 * the worker RPC already names it for the same reason
 * (`HttpWorkerClient.attestation` admits `mock` on the Venice worker). It has no
 * verifier and never will, so the verifier requirement below would otherwise
 * make the whole ticket path untestable without a live provider credential.
 */
const TEST_FIXTURE_PROVIDER = "mock";

export interface AttestableRouteOptions {
  /**
   * Whether test-fixture rows are in scope, which is the SAME flag that decides
   * whether the database returns them at all (`p.is_test_fixture = false OR
   * $2 = true`). So the fixture exemption below has two independent gates: in
   * production this is false AND no fixture row can reach the filter.
   */
  includeTestFixtures?: boolean;
}

/**
 * The genuinely attestable subset of a model's callable routes.
 *
 * `privacyClass` describes where execution happens; a registered verifier is
 * what makes the claim checkable. A `tee` row for a provider that publishes no
 * evidence is not attestable, and a `private` or `plain` row has no enclave to
 * attest at all.
 */
export function attestableRoutes(
  routes: ModelRecord[],
  options: AttestableRouteOptions = {}
): ModelRecord[] {
  return routes.filter(
    (route) =>
      (route.privacyClass === "tee" || route.privacyClass === "e2ee")
      && (providerExposesAttestation(route.providerName)
        || (options.includeTestFixtures === true && route.providerName === TEST_FIXTURE_PROVIDER))
  );
}

/**
 * Resolve exactly one attestable route, or throw an unambiguous error.
 *
 * `routes` is the full callable candidate set for the requested model; the
 * attestable filter is applied here so no caller can forget it.
 */
export function resolveExactAttestableRoute(
  routes: ModelRecord[],
  provider: string | undefined,
  requestedModel: string,
  options: AttestableRouteOptions = {}
): ModelRecord {
  const attestable = attestableRoutes(routes, options);
  if (provider) {
    const match = attestable.find((route) => route.providerName === provider);
    if (!match) {
      // Deliberately the same shape whether the provider serves this model on a
      // non-attestable class, does not serve it at all, or has no verifier. A
      // caller that named a provider gets one answer: not here.
      throw new AppError(404, "route_not_found", `No attestable ${provider} route for ${requestedModel}`);
    }
    return match;
  }
  if (attestable.length === 0) {
    throw new AppError(404, "no_tee_route", `No TEE/E2EE route is available for ${requestedModel}`);
  }
  if (attestable.length > 1) {
    const providers = attestable.map((route) => route.providerName).join(", ");
    throw new AppError(
      409,
      "provider_selector_required",
      `Model ${requestedModel} has multiple TEE routes (${providers}); specify a provider`
    );
  }
  return attestable[0];
}
