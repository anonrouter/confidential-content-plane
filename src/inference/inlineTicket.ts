// The inline (dev-only) ticket path, expressed as an INJECTED CAPABILITY rather
// than as a direct import.
//
// WHY THIS MODULE EXISTS (D-22)
//
// `src/routes/{chat,embeddings,image}.ts` run on the content tier, inside the
// TD, where they can touch prompt plaintext. They also each contained a
// dev-only branch that called `authenticateRequest` directly, which is a
// **value** import of `src/auth/authenticate.ts`. That single edge pulled the
// entire account-identity, API-key, admin and payments graph into the content
// plane's module closure.
//
// The consequence was not a plaintext leak. The branch is unreachable in
// production three times over:
//
//   1. `config.ts` hard-codes `allowInlineTicket` to false when NODE_ENV is
//      production, so the branch is never entered;
//   2. `roles.ts` never decorates `controlPlane`, so the call inside it has
//      nothing to call; and
//   3. the content-tier boundary tests assert the split.
//
// The consequence was to the AUDIT. D-22's argument is that a reviewer asking
// "what code here can see a prompt" should not first have to exclude the
// payments stack, and that publishing the plaintext-capable workload should not
// mean publishing the whole backend. A dead import still ships in the image,
// still enlarges the measured TCB, and still has to be read and dismissed.
//
// So the dependency is inverted. The monolith (`server.ts`) registers an
// implementation that does exactly what the three routes used to do inline; the
// content roles (`roles.ts`) register nothing. The routes ask the server for the
// capability and get `undefined` on the content tier, which is the same
// unreachability as before, now expressed in the type system instead of relying
// on a config flag holding.
//
// The capability is deliberately shaped as ONE call covering authenticate,
// scope check and issue-and-redeem together. Exposing the three steps
// separately would let a caller perform two of them, and "authenticated but
// unscoped" is not a state any content-tier route should be able to construct.

import type { FastifyRequest } from "fastify";
import type { InferenceOperation } from "./tickets.js";
import type { ReasoningSelection } from "./reasoning.js";
import type { RedeemResult } from "./rpc.js";
import type { ProviderRoutingPolicyInput } from "../providers/routing/policy.js";

/**
 * Exactly the parameter object the three routes previously passed to
 * `ControlPlane.issueAndRedeemInline`. Kept structurally identical so the
 * inversion cannot quietly change what is bound into a ticket.
 */
export interface InlineTicketParams {
  requestedModel: string;
  providerPolicy?: ProviderRoutingPolicyInput;
  maxOutputTokens: number | null;
  automatic: boolean;
  operation?: InferenceOperation;
  reasoning?: ReasoningSelection;
  image?: { width: number; height: number; responseFormat: string };
  /** Explicit E2EE serving modality intent (dual-privacy models). */
  e2ee?: boolean;
}

/**
 * Authenticate the caller, require the `inference` scope, then mint and redeem
 * a ticket in one step.
 *
 * Present ONLY on the monolith. On the relay, the compat broker and every
 * worker this is `undefined`, and a route that finds it absent must fail closed
 * with `ticket_required` exactly as it did when the branch was guarded by
 * `allowInlineTicket`.
 */
export type InlineTicketIssuer = (
  request: FastifyRequest,
  params: InlineTicketParams
) => Promise<RedeemResult>;

declare module "fastify" {
  interface FastifyInstance {
    /**
     * Optional by design. Its ABSENCE is what makes the content tier
     * ticket-only, and that is a stronger statement than a configuration flag
     * because it cannot be switched on by an environment variable.
     */
    inlineTicketIssuer?: InlineTicketIssuer;
  }
}
