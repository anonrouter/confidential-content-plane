/**
 * Minimal writable surface shared by Node's ServerResponse and focused tests.
 * Backpressure is part of the inference security boundary: continuing to pull a
 * provider stream after write() returns false lets a slow caller grow process
 * memory without bound.
 */
export interface BackpressureWritable {
  write(chunk: string | Uint8Array): boolean;
  once(event: "drain", listener: () => void): unknown;
  once(event: "close", listener: () => void): unknown;
  once(event: "error", listener: (error: Error) => void): unknown;
  removeListener(event: "drain", listener: () => void): unknown;
  removeListener(event: "close", listener: () => void): unknown;
  removeListener(event: "error", listener: (error: Error) => void): unknown;
  destroyed?: boolean;
  writableEnded?: boolean;
}

function closedWritableError() {
  return new DOMException("Downstream stream closed", "AbortError");
}

/** Write one chunk and stop pulling upstream until the socket drains. */
export async function writeWithBackpressure(
  writable: BackpressureWritable,
  chunk: string | Uint8Array,
  signal?: AbortSignal
): Promise<void> {
  signal?.throwIfAborted();
  if (writable.destroyed || writable.writableEnded) throw closedWritableError();
  if (writable.write(chunk)) return;

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      writable.removeListener("drain", onDrain);
      writable.removeListener("close", onClose);
      writable.removeListener("error", onError);
      signal?.removeEventListener("abort", onAbort);
    };
    const finish = (action: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      action();
    };
    const onDrain = () => finish(resolve);
    const onClose = () => finish(() => reject(closedWritableError()));
    const onError = (error: Error) => finish(() => reject(error));
    const onAbort = () => finish(() => reject(signal?.reason ?? closedWritableError()));

    writable.once("drain", onDrain);
    writable.once("close", onClose);
    writable.once("error", onError);
    signal?.addEventListener("abort", onAbort, { once: true });

    // Close/abort may race the listener installation after write() returned.
    if (signal?.aborted) onAbort();
    else if (writable.destroyed || writable.writableEnded) onClose();
  });
}

/**
 * Emit the OpenAI-compatible terminal marker only after the supplied durable
 * finalizer succeeds. A rejection leaves the stream without [DONE].
 */
export async function finalizeThenWriteDone<T>(
  writable: BackpressureWritable,
  finalize: () => Promise<T>,
  signal?: AbortSignal
): Promise<T> {
  const result = await finalize();
  await writeWithBackpressure(writable, "data: [DONE]\n\n", signal);
  return result;
}
