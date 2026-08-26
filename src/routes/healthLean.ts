import type { FastifyInstance } from "fastify";

export { verifyValkeyWritable } from "../observability/valkey.js";

/**
 * The only health route a content or credential role serves.
 *
 * SPLIT OUT OF `health.ts` FOR D-22.
 *
 * `httpBase.ts` builds every role's Fastify instance, including the relay, the
 * compat broker and the workers, and it registers these routes. It previously
 * imported them from `health.ts`, which also serves `/v1/admin/crypto-health`
 * and therefore imports `../auth/admin.js` and `../payments/cryptoLedger.js`.
 * That one edge pulled the admin, account-identity and payments graph into the
 * content plane's module closure, so a reviewer asking "what code here can see
 * a prompt" had to read and dismiss the crypto ledger first.
 *
 * Nothing about the served routes changed. `registerHealthRoutes` still
 * registers exactly what it did, by composing this.
 *
 * The full set in `health.ts` reaches for `server.db`, `server.redis`, the admin
 * auth chain, and an outbound BTCPay fetch, none of which exist on the lean
 * roles. They only ever returned 503 there because a bare `catch` swallowed the
 * resulting TypeError, and `/v1/admin/crypto-health` would have run admin
 * authentication on a process with no database at all. Today the public Caddy
 * edge 404s those paths, but a CVM ingress must not inherit that assumption.
 */
export async function registerLeanHealthRoutes(server: FastifyInstance) {
  server.get("/healthz", async () => ({ ok: true }));
}
