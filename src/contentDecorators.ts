// Fastify instance decorations that the CONTENT plane relies on (D-22).
//
// These declarations previously lived in `src/server.ts`, alongside `db`,
// `redis`, `controlPlane`, `standardAuth` and `btcpay`. That was invisible until
// the content-plane export was compiled in isolation and every content file
// failed with "Property 'config' does not exist on type 'FastifyInstance'":
// the split had removed the file that told TypeScript what a server IS.
//
// It is exactly the failure WO-07 test 5 exists to catch. An export that cannot
// build alone is not the real build source, and the commit-to-digest binding
// would have been a fiction.
//
// The split is along the same line as the rest of D-22. Declared here are the
// five capabilities a content role actually uses; the control-only decorations
// stay in `server.ts`. TypeScript merges module augmentations, so the monolith
// sees the union and nothing about it changes, while the content plane sees
// only what it can legitimately reach.
//
// What is deliberately NOT here, and why it matters: `db`, `redis`,
// `controlPlane`, `rateLimiter`, `standardAuth` and `btcpay`. A content role
// that tried to reach for a database handle now fails to COMPILE rather than
// failing at runtime on a process that has none. The trust document's claim
// that the CVM holds no database and no Valkey is, for these five roles, now
// enforced by the type system.

// Side-effect import: `inlineTicket.ts` declares the optional
// `inlineTicketIssuer` decoration. The three content routes USE it without
// importing it, so without this line the declaration is absent from the
// content-plane closure and the export fails to compile.
import "./inference/inlineTicket.js";
import type { AppConfig } from "./config.js";
import type { ControlClient, WorkerClient } from "./inference/rpc.js";
import type { VerifierRegistry } from "./providers/attestation/index.js";
import type { LocalRequestClassifier } from "./routing/classifier.js";
import type { RoutingCatalogCache } from "./routing/contentPlaneCatalog.js";
import type { ContentReceiptStore } from "./inference/contentReceipts.js";

declare module "fastify" {
  interface FastifyInstance {
    /** Validated configuration. Present on every role. */
    config: AppConfig;
    /**
     * The content-free control RPC client. On the content tier this is
     * `HttpControlClient` over the route-allowlisted mTLS bridge; there is no
     * in-process control plane to wrap.
     */
    controlClient: ControlClient;
    /** Dispatches to the credential-isolated provider worker. */
    workerClient: WorkerClient;
    /** Upstream provider attestation verifiers. */
    verifierRegistry: VerifierRegistry;
    /** In-process routing classifier. Null when routing is disabled. */
    requestClassifier: LocalRequestClassifier | null;
    /**
     * Cached auto-routing candidate pool. Present wherever automatic routing can
     * run, because selection happens in the content plane now; absent when the
     * router is disabled, which is the launch configuration on `tdx.medium`.
     */
    routingCatalog?: RoutingCatalogCache;
    /**
     * Opaque settlement receipts. Holds the exact request/response hashes that
     * used to be sent to the control plane, so they stay inside the attested
     * workload and only a random 128-bit id crosses.
     */
    contentReceipts?: ContentReceiptStore;
  }
}

export {};
