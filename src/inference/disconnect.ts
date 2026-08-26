import type { FastifyReply, FastifyRequest } from "fastify";

/**
 * Convert an inbound HTTP disconnect into a reusable AbortSignal.
 *
 * A completed response also emits `close`, so only treat it as cancellation
 * while the response is still unfinished. The signal contains no request
 * content or client identifier and is never persisted.
 */
export function abortOnClientDisconnect(request: FastifyRequest, reply: FastifyReply): AbortSignal {
  const controller = new AbortController();

  const abort = () => {
    if (!controller.signal.aborted) {
      controller.abort(new DOMException("Client disconnected", "AbortError"));
    }
  };
  const onResponseClose = () => {
    if (!reply.raw.writableEnded) abort();
    cleanup();
  };
  const cleanup = () => {
    request.raw.off("aborted", abort);
    reply.raw.off("close", onResponseClose);
    reply.raw.off("finish", cleanup);
  };

  request.raw.once("aborted", abort);
  reply.raw.once("close", onResponseClose);
  reply.raw.once("finish", cleanup);
  return controller.signal;
}

export function isAbortError(error: unknown): boolean {
  if (error instanceof DOMException) return error.name === "AbortError";
  if (!error || typeof error !== "object") return false;
  const candidate = error as { name?: unknown; code?: unknown };
  return candidate.name === "AbortError" || candidate.code === "ABORT_ERR";
}
