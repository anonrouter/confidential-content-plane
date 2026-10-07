import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

describe("content process termination", () => {
  it("keeps a hijacked SSE response alive through SIGTERM and completes before exiting", async () => {
    const child = spawn(process.execPath, ["--import", "tsx", fileURLToPath(new URL("../fixtures/content-drain-process.ts", import.meta.url))], {
      stdio: ["ignore", "ignore", "pipe", "ipc"]
    });
    const events: string[] = [];
    let stderr = "";
    child.stderr?.on("data", chunk => { stderr += String(chunk); });
    type Message = { event: string; port?: number; counts?: Record<string, number> };
    const messages: Message[] = [];
    const waiters = new Map<string, (message: Message) => void>();
    child.on("message", value => {
      const message = value as Message;
      messages.push(message);
      events.push(message.event);
      waiters.get(message.event)?.(message);
    });
    const exit = new Promise<{ code: number | null; signal: string | null }>(resolve => child.once("exit", (code, signal) => resolve({ code, signal })));
    const wait = async (event: string): Promise<Message> => {
      const seen = messages.find(message => message.event === event);
      if (seen) return seen;
      let timer!: ReturnType<typeof setTimeout>;
      try {
        return await Promise.race([
          new Promise<Message>(resolve => waiters.set(event, resolve)),
          exit.then(() => { throw new Error(`child exited before ${event}: ${stderr}`); }),
          new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error(`missing child event: ${event}`)), 5_000); })
        ]);
      } finally { clearTimeout(timer); waiters.delete(event); }
    };
    try {
      const { port } = await wait("ready");
      const admitted = wait("admitted");
      const response = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
        method: "POST", signal: AbortSignal.timeout(5_000),
        headers: { "content-type": "application/json", "x-anonrouter-ticket": "tkt_local" },
        body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "local synthetic test" }], stream: true, max_tokens: 32 })
      });
      expect(response.status).toBe(200);
      await admitted;
      const reader = response.body!.getReader();
      const first = await reader.read();
      expect(new TextDecoder().decode(first.value)).toContain('"content":"started"');
      const draining = wait("draining");
      child.kill("SIGTERM");
      await draining;
      await new Promise(resolve => setTimeout(resolve, 75));
      expect(events).not.toContain("closed");
      expect(child.exitCode).toBeNull();
      child.send("finish");
      await wait("settling");
      let nextResolved = false;
      const next = reader.read().then(chunk => { nextResolved = true; return chunk; });
      await new Promise(resolve => setTimeout(resolve, 50));
      expect(nextResolved).toBe(false); // No [DONE] before settlement.
      expect(events).not.toContain("closed");
      child.send("settle");
      let tail = "";
      let chunk = await next;
      for (;;) {
        if (chunk.done) break;
        tail += new TextDecoder().decode(chunk.value);
        chunk = await reader.read();
      }
      expect(tail).toBe("data: [DONE]\n\n");
      expect(await exit, stderr).toEqual({ code: 0, signal: null });
      expect(events).toEqual(["ready", "admitted", "draining", "settling", "settled", "closed"]);
      expect(messages.find(message => message.event === "closed")?.counts).toEqual({
        redemption: 1, authorization: 1, dispatch: 1, settlement: 1, capture: 0, abort: 0
      });
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      await exit;
    }
  }, 10_000);
});
