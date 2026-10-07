import Fastify from "fastify";
import { installServiceLifecycle, installServiceShutdown } from "../../src/operations/serviceLifecycle.js";
import { registerChatRoutes } from "../../src/routes/chat.js";
import type { AppConfig } from "../../src/config.js";
import type { ControlClient, WorkerClient } from "../../src/inference/rpc.js";

// Synthetic local stream; no provider, ticket, database or production endpoint.
const server = Fastify();
const lifecycle = installServiceLifecycle(server, { drainDelayMs: 10 });
installServiceShutdown(server, lifecycle);
let finish!: () => void;
let settle!: () => void;
const completion = new Promise<void>(resolve => { finish = resolve; });
const settlement = new Promise<void>(resolve => { settle = resolve; });
const counts = { redemption: 0, authorization: 0, dispatch: 0, settlement: 0, capture: 0, abort: 0 };
process.on("message", message => {
  if (message === "finish") finish();
  if (message === "settle") settle();
});
process.on("SIGTERM", () => process.send?.({ event: "draining" }));
const control: ControlClient = {
  redeem: async () => {
    counts.redemption++;
    return { redemption: "red_local", constraints: {
      requestedModel: "test-model", automatic: false, providerName: "venice",
      publicModelId: "test-model", canonicalModelId: "test-model",
      providerPolicyKey: "", privacyClass: "private", maxOutputTokens: 64,
      routingPreferences: { pool_mode: "all", model_patterns: [], strategy: "balanced", privacy_level: "balanced" }
    } };
  },
  authorize: async () => {
    counts.authorization++;
    return { dispatchToken: "dsp_local", model: {
      providerName: "venice", publicModelId: "test-model", externalModelId: "test-model",
      supportsStreaming: true, supportsTools: false, supportsVision: false,
      contextWindow: 32768, maxOutputTokens: 4096, modelType: "text"
    }, effectiveMaxOutputTokens: 64, rateLimits: {
      requests: { limit: 30, remaining: 29, resetMs: 1000 },
      tokens: { limit: 250000, remaining: 249000, resetMs: 1000 }
    } };
  },
  markDeliveryStarted: async () => undefined,
  settle: async () => {
    counts.settlement++;
    process.send?.({ event: "settling" });
    await settlement;
    process.send?.({ event: "settled" });
    return { chargedUsd: 0 };
  },
  capture: async () => { counts.capture++; },
  abort: async () => { counts.abort++; },
  redeemAttestation: async () => null
};
const worker: WorkerClient = {
  attestation: async () => ({}), chat: async () => ({ response: {} }),
  stream: async () => {
    counts.dispatch++;
    return { stream: (async function* () {
      process.send?.({ event: "admitted" });
      yield `data: ${JSON.stringify({ choices: [{ delta: { content: "started" } }] })}\n\n`;
      await completion;
      yield "data: [DONE]\n\n";
    })(), usage: Promise.resolve({ inputTokens: 1, outputTokens: 1, cachedTokens: 0 }) };
  }
};
server.decorate("config", { internal: { allowInlineTicket: false } } as AppConfig);
server.decorate("controlClient", control);
server.decorate("workerClient", worker);
server.decorate("requestClassifier", null);
await registerChatRoutes(server);
server.addHook("onClose", async () => {
  process.send?.({ event: "closed", counts });
  process.disconnect?.();
});
await server.listen({ host: "127.0.0.1", port: 0 });
const address = server.server.address();
if (!address || typeof address === "string") throw new Error("missing listener");
process.send?.({ event: "ready", port: address.port });
