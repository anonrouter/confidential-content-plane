import { existsSync } from "node:fs";
import type { FastifyInstance } from "fastify";

interface Lifecycle { draining: boolean; readyFile?: string; closing?: Promise<void> }
const lifecycles = new WeakMap<FastifyInstance, Lifecycle>();

/** Keep repeated termination signals on the same drain, without forcing exit. */
export function installServiceShutdown(server: FastifyInstance, lifecycle: {
  drain(): Promise<void>;
}): void {
  const shutdown = () => {
    void lifecycle.drain().catch(error => {
      server.log.error({ error_type: error instanceof Error ? error.name : "unknown" }, "server_drain_failed");
      process.exitCode = 1;
    });
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  server.addHook("onClose", async () => {
    process.off("SIGTERM", shutdown);
    process.off("SIGINT", shutdown);
  });
}

export function serviceIsReady(server: FastifyInstance): boolean {
  const state = lifecycles.get(server);
  return !state?.draining && (!state?.readyFile || existsSync(state.readyFile));
}

/** The file is host-owned, mounted read-only into one slot, never an HTTP control. */
export function installServiceLifecycle(server: FastifyInstance, options: {
  readyFile?: string; drainDelayMs?: number;
} = {}) {
  if (options.readyFile && !/^\/run\/anonrouter\/control-slots\/[ab]\/status\/serving$/.test(options.readyFile)) {
    throw new Error("invalid continuity readiness file");
  }
  const state: Lifecycle = { draining: false, readyFile: options.readyFile };
  lifecycles.set(server, state);
  server.addHook("onRequest", async (_request, reply) => {
    if (state.draining) reply.header("connection", "close");
  });
  server.addHook("onSend", async (_request, reply, payload) => {
    // This includes requests admitted before draining began.
    if (state.draining) reply.header("connection", "close");
    return payload;
  });
  server.addHook("onResponse", async () => {
    // Raw streaming replies bypass onSend. Reap only idle sockets after their
    // response completes; never destroy a socket carrying an active response.
    if (state.draining) setImmediate(() => server.server.closeIdleConnections?.());
  });
  return {
    drain(): Promise<void> {
      if (state.closing) return state.closing;
      state.draining = true;
      state.closing = (async () => {
        // Keep accepting during the proxy's health-observation interval. Then
        // Fastify closes idle connections and waits for admitted requests.
        await new Promise(resolve => setTimeout(resolve, options.drainDelayMs ?? 5_000));
        await server.close();
      })();
      return state.closing;
    }
  };
}
