import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { AppError } from "../../security/errors.js";
import { parseBody } from "../helpers.js";
import { serializeWorkerStream } from "../../inference/workerClient.js";
import type { WorkerChatRequest } from "../../inference/rpc.js";
import type {
  WorkerEmbeddingRequest,
  WorkerImageRequest,
  WorkerOpaqueE2eeRequest,
  WorkerSpeechRequest
} from "../../inference/rpc.js";
import { embeddingRequestSchema } from "../../providers/embeddings.js";
import {
  IMAGE_MAX_DIMENSION,
  IMAGE_MIN_DIMENSION,
  SPEECH_DEFAULT_RESPONSE_FORMAT,
  SPEECH_MAX_INPUT_CHARS,
  SPEECH_MAX_VOICE_CHARS
} from "../../providers/types.js";
import { requireServiceToken } from "./serviceAuth.js";
import { abortOnClientDisconnect, isAbortError } from "../../inference/disconnect.js";
import { writeWithBackpressure } from "../../inference/backpressure.js";
import { KEY_ID_PATTERN, veniceKeyFingerprint } from "../../providers/veniceKeys.js";

const attestationSchema = z
  .object({
    providerName: z.string().min(1).max(64),
    externalModelId: z.string().min(1).max(256),
    dispatchToken: z.string().min(1).max(256),
    nonce: z.string().min(1).max(256)
  })
  .strict();

// Provider-neutral read-only TEE attestation / signature fetch for the public TEE
// API. No dispatch token / fence: the worker fetches a quote or signature with its
// isolated credential and returns the raw evidence for verification upstream.
const teeAttestationSchema = z
  .object({
    providerName: z.string().min(1).max(64),
    externalModelId: z.string().min(1).max(256),
    nonce: z.string().regex(/^[0-9a-f]{32,128}$/i)
  })
  .strict();

const teeSignatureSchema = z
  .object({
    providerName: z.string().min(1).max(64),
    externalModelId: z.string().min(1).max(256),
    providerRequestId: z.string().min(1).max(256)
  })
  .strict();

const chatSchema = z
  .object({
    dispatchToken: z.string().min(1).max(256),
    requestId: z.string().min(1).max(256),
    providerName: z.string().min(1).max(64),
    externalModelId: z.string().min(1).max(256),
    reasoningKey: z.string().min(1).max(32),
    body: z.record(z.unknown()),
    e2eeHeaders: z.record(z.string()).optional()
  })
  .strict();

const opaqueE2eeSchema = z.object({
  dispatchToken: z.string().min(1).max(256),
  requestId: z.string().min(1).max(256),
  providerName: z.string().min(1).max(64),
  externalModelId: z.string().min(1).max(256),
  reasoningKey: z.string().min(1).max(32),
  effectiveMaxOutputTokens: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  protocol: z.literal("chutes-mlkem-v1"),
  headers: z.record(z.string()),
  // The HTTP body limit remains the authoritative byte cap; this secondary cap
  // prevents an accidentally raised global limit from becoming unbounded here.
  ciphertextBase64: z.string().min(4).max(64 * 1024 * 1024)
}).strict();

const embeddingsSchema = z.object({
  dispatchToken: z.string().min(1).max(256),
  requestId: z.string().min(1).max(256),
  providerName: z.string().min(1).max(64),
  externalModelId: z.string().min(1).max(256),
  body: embeddingRequestSchema
}).strict();

const imageSchema = z.object({
  dispatchToken: z.string().min(1).max(256),
  requestId: z.string().min(1).max(256),
  providerName: z.string().min(1).max(64),
  externalModelId: z.string().min(1).max(256),
  width: z.number().int().min(IMAGE_MIN_DIMENSION).max(IMAGE_MAX_DIMENSION),
  height: z.number().int().min(IMAGE_MIN_DIMENSION).max(IMAGE_MAX_DIMENSION),
  responseFormat: z.literal("b64_json"),
  // The prompt is the only content the worker receives; it never reaches control.
  prompt: z.string().min(1).max(10_000)
}).strict();

const speechSchema = z.object({
  dispatchToken: z.string().min(1).max(256),
  requestId: z.string().min(1).max(256),
  providerName: z.string().min(1).max(64),
  externalModelId: z.string().min(1).max(256),
  voice: z.string().min(1).max(SPEECH_MAX_VOICE_CHARS).optional(),
  responseFormat: z.literal(SPEECH_DEFAULT_RESPONSE_FORMAT),
  // The input text is the only content the worker receives; it never reaches
  // control. The same bound the public route enforces is re-applied here so a
  // compromised relay cannot enlarge the priced character count.
  input: z.string().min(1).max(SPEECH_MAX_INPUT_CHARS)
}).strict();

/**
 * Venice worker internal RPC. Authenticated by the worker service token. Holds
 * ONLY the Venice credential; it has no DB, Redis, account, auth, or payment
 * access. It forwards inference/attestation work and streams responses back.
 */
export async function registerWorkerRpcRoutes(server: FastifyInstance) {
  const guard = requireServiceToken(server.config.internal.workerRpcToken);
  const workerProvider = server.config.internal.role === "fireworks-worker"
    ? "fireworks"
    : server.config.internal.role === "bedrock-worker"
      ? "aws-bedrock"
      : server.config.internal.role === "deepinfra-worker"
        ? "deepinfra"
        : server.config.internal.role === "chutes-worker"
          ? "chutes"
          : server.config.internal.role === "tinfoil-worker"
            ? "tinfoil"
            : server.config.internal.role === "near-worker"
              ? "near-ai"
              : "venice";
  const workerBase = `/internal/${workerProvider}`;

  server.post(`${workerBase}/attestation`, { preHandler: guard }, async (request, reply) => {
    const signal = abortOnClientDisconnect(request, reply);
    const body = parseBody(attestationSchema, request.body);
    assertWorkerProvider(body.providerName);
    const evidence = await server.workerClient.attestation(body, signal);
    return { evidence };
  });

  // Provider-neutral TEE attestation: this worker holds only its own credential,
  // so it may attest only its own provider's models.
  server.post(`${workerBase}/tee-attestation`, { preHandler: guard }, async (request, reply) => {
    const signal = abortOnClientDisconnect(request, reply);
    const body = parseBody(teeAttestationSchema, request.body);
    assertWorkerProvider(body.providerName);
    if (!server.workerClient.attestationForModel) {
      throw new AppError(503, "attestation_unsupported", "Attestation is unavailable on this worker");
    }
    const evidence = await server.workerClient.attestationForModel(body.providerName, body.externalModelId, body.nonce, signal);
    return { evidence };
  });

  server.post(`${workerBase}/tee-signature`, { preHandler: guard }, async (request, reply) => {
    const signal = abortOnClientDisconnect(request, reply);
    const body = parseBody(teeSignatureSchema, request.body);
    assertWorkerProvider(body.providerName);
    if (!server.workerClient.signatureForRequest) {
      throw new AppError(503, "tee_signature_not_supported", "Signatures are unavailable on this worker");
    }
    const evidence = await server.workerClient.signatureForRequest(body.providerName, body.externalModelId, body.providerRequestId, signal);
    return { evidence };
  });

  // In production each worker is locked to its configured provider. Mock
  // routing exists only for dev/test split harnesses and the monolith.
  const assertWorkerProvider = (providerName: string) => {
    if (server.config.env === "production" && providerName !== workerProvider) {
      throw new AppError(400, "worker_provider_forbidden", `This worker accepts only the ${workerProvider} provider`);
    }
  };

  server.post(`${workerBase}/chat`, { preHandler: guard }, async (request, reply) => {
    const signal = abortOnClientDisconnect(request, reply);
    const body = parseBody(chatSchema, request.body) as WorkerChatRequest;
    assertWorkerProvider(body.providerName);
    return server.workerClient.chat(body, signal);
  });

  server.post(`${workerBase}/opaque-e2ee`, { preHandler: guard }, async (request, reply) => {
    const signal = abortOnClientDisconnect(request, reply);
    const body = parseBody(opaqueE2eeSchema, request.body) as WorkerOpaqueE2eeRequest;
    assertWorkerProvider(body.providerName);
    if (!server.workerClient.opaqueE2ee) {
      throw new AppError(501, "e2ee_transport_not_supported", "Whole-body E2EE is unavailable on this worker");
    }
    return server.workerClient.opaqueE2ee(body, signal);
  });

  server.post(`${workerBase}/embeddings`, { preHandler: guard }, async (request, reply) => {
    const signal = abortOnClientDisconnect(request, reply);
    const body = parseBody(embeddingsSchema, request.body) as WorkerEmbeddingRequest;
    assertWorkerProvider(body.providerName);
    if (!server.workerClient.embeddings) {
      throw new AppError(503, "provider_unavailable", "Embedding worker is unavailable");
    }
    return server.workerClient.embeddings(body, signal);
  });

  server.post(`${workerBase}/image`, { preHandler: guard }, async (request, reply) => {
    const signal = abortOnClientDisconnect(request, reply);
    const body = parseBody(imageSchema, request.body) as WorkerImageRequest;
    assertWorkerProvider(body.providerName);
    if (!server.workerClient.generateImage) {
      throw new AppError(503, "provider_unavailable", "Image worker is unavailable");
    }
    // The base64 result is returned as a JSON reply; it is never logged and
    // never crosses the worker -> control fence.
    return server.workerClient.generateImage(body, signal);
  });

  server.post(`${workerBase}/speech`, { preHandler: guard }, async (request, reply) => {
    const signal = abortOnClientDisconnect(request, reply);
    const body = parseBody(speechSchema, request.body) as WorkerSpeechRequest;
    assertWorkerProvider(body.providerName);
    if (!server.workerClient.generateSpeech) {
      throw new AppError(503, "provider_unavailable", "Speech worker is unavailable");
    }
    // Base64 audio is returned as a JSON reply, exactly as image bytes are: it
    // is never logged and never crosses the worker -> control fence.
    return server.workerClient.generateSpeech(body, signal);
  });

  // Operator key lifecycle. Only this credential-holding process ever touches
  // the secret: control forwards it through one POST body and stores nothing
  // but id/label/fingerprint. The overlay file is the durable record.
  const keyUpsertSchema = z
    .object({
      id: z.string().regex(KEY_ID_PATTERN),
      label: z.string().trim().min(1).max(120).optional(),
      key: z.string().trim().min(1).max(512)
    })
    .strict();

  server.post("/internal/venice/keys", { preHandler: guard }, async (request) => {
    // CLOSED in capability mode. This route is the legacy direction: a bearer
    // token authorizes the control plane to PUSH a provider secret into the
    // worker, which makes the control plane a credential custodian.
    // CONTROL_RPC_CONTRACT.md forbids that at launch. The replacement is
    // POST /internal/credentials/secret, where a signed single-use capability
    // authorizes and the secret comes straight from the operator's verifying
    // client. Refusing here rather than deleting the route means an operator
    // running the old procedure gets told why, instead of a 404 they might read
    // as a deployment fault.
    if (server.config.internal.credentialAdmin.mode === "capability") {
      throw new AppError(
        410,
        "credential_push_disabled",
        "Provider credentials are no longer pushed from the control plane. Use the attested capability flow at POST /internal/credentials/secret."
      );
    }
    if (workerProvider !== "venice") throw new AppError(404, "worker_route_unavailable", "Venice key management is unavailable on this provider worker");
    const store = server.veniceKeyStore;
    if (!store) throw new AppError(503, "worker_admin_unavailable", "Key lifecycle is unavailable on this worker");
    const body = parseBody(keyUpsertSchema, request.body);
    // Live check against Venice before accepting the credential. Skipped for
    // tests and the mock provider; a network failure is not proof of an
    // invalid key, so only an explicit 401 rejects.
    if (server.config.env !== "test" && server.config.providers.defaultProvider !== "mock") {
      let response: Response;
      try {
        response = await fetch(`${server.config.providers.veniceBaseUrl}/api_keys/rate_limits`, {
          headers: { authorization: `Bearer ${body.key}` },
          signal: AbortSignal.timeout(10_000)
        });
      } catch {
        throw new AppError(503, "venice_key_verification_unavailable", "Venice could not be reached to verify the credential");
      }
      await response.body?.cancel().catch(() => undefined);
      if (response.status === 401) {
        throw new AppError(400, "venice_key_invalid", "Venice rejected the credential");
      }
    }
    store.addKey({ id: body.id, label: body.label ?? null, key: body.key });
    return { id: body.id, label: body.label ?? null, fingerprint: veniceKeyFingerprint(body.key) };
  });

  server.delete("/internal/venice/keys/:id", { preHandler: guard }, async (request) => {
    if (server.config.internal.credentialAdmin.mode === "capability") {
      throw new AppError(
        410,
        "credential_push_disabled",
        "Provider credentials are no longer removed from the control plane. Use the attested capability flow at POST /internal/credentials/revoke."
      );
    }
    if (workerProvider !== "venice") throw new AppError(404, "worker_route_unavailable", "Venice key management is unavailable on this provider worker");
    const store = server.veniceKeyStore;
    if (!store) throw new AppError(503, "worker_admin_unavailable", "Key lifecycle is unavailable on this worker");
    const idResult = z.string().regex(KEY_ID_PATTERN).safeParse(String((request.params as { id: string }).id));
    if (!idResult.success) throw new AppError(400, "invalid_venice_key_id", "Venice key id is invalid");
    const id = idResult.data;
    if (store.isLastRemaining(id)) {
      throw new AppError(409, "venice_key_last_remaining", "Refusing to remove the last remaining Venice credential");
    }
    if (!store.removeKey(id)) {
      throw new AppError(404, "venice_key_not_found", "Venice key is not present in the effective keyset");
    }
    return { ok: true };
  });

  // On-demand catalog refresh: control's admin sync route delegates here in the
  // split topology, since only the worker holds a Venice credential. The worker
  // fetches + normalizes the catalog and pushes it back to control before this
  // call returns, so the caller can read the applied result immediately after.
  server.post(`${workerBase}/catalog-sync`, { preHandler: guard }, async () => {
    const syncNow = server.catalogSyncNow;
    if (!syncNow) {
      throw new AppError(503, "catalog_sync_unavailable", "Catalog sync does not run on this worker");
    }
    try {
      await syncNow();
    } catch {
      throw new AppError(502, "pricing_sync_failed", "Provider catalog sync failed");
    }
    return { ok: true };
  });

  // Synthetic health probe. Control delegates here in the split topology (only
  // the worker holds the credential); the worker runs a one-token request via
  // the adapter and returns ok/latency. Locked to this worker's provider.
  const probeSchema = z.object({ externalModelId: z.string().min(1).max(256) }).strict();
  server.post(`${workerBase}/probe`, { preHandler: guard }, async (request, reply) => {
    const signal = abortOnClientDisconnect(request, reply);
    const body = parseBody(probeSchema, request.body);
    if (!server.workerClient.probe) {
      throw new AppError(503, "provider_unavailable", "Health probing is unavailable on this worker");
    }
    return server.workerClient.probe(
      { requestId: request.id, providerName: workerProvider, externalModelId: body.externalModelId },
      signal
    );
  });

  server.post(`${workerBase}/stream`, { preHandler: guard }, async (request, reply) => {
    const signal = abortOnClientDisconnect(request, reply);
    const body = parseBody(chatSchema, request.body) as WorkerChatRequest;
    assertWorkerProvider(body.providerName);
    const result = await server.workerClient.stream(body, signal);
    reply.raw.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no"
    });
    try {
      for await (const chunk of serializeWorkerStream(result)) {
        await writeWithBackpressure(reply.raw, chunk, signal);
      }
    } catch (error) {
      if (signal.aborted || isAbortError(error)) return reply;
      throw error;
    }
    if (!reply.raw.destroyed && !reply.raw.writableEnded) reply.raw.end();
    return reply;
  });
}
