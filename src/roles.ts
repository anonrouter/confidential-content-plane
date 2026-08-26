// Independently runnable inference roles for production.
//
//   relay           : holds request content + opaque tickets. NO db, redis,
//                     auth, payment, admin, email, or provider credentials.
//   provider worker : holds ONLY its own provider credential. NO db, redis,
//                     account, auth, or payment access.
//
// The control-api role is built by buildServer(config) with RUNTIME_ROLE=control.

import type { FastifyInstance } from "fastify";
import type { AppConfig } from "./config.js";
import { createBaseServer, workerErrorHandler } from "./httpBase.js";
import { HttpControlClient } from "./inference/controlClient.js";
import {
  HttpProviderAttemptAcknowledger,
  HttpWorkerClient,
  InProcessWorkerClient,
  RoutedWorkerClient
} from "./inference/workerClient.js";
import { LocalRequestClassifier } from "./routing/classifier.js";
import { RoutingCatalogCache } from "./routing/contentPlaneCatalog.js";
import { ContentReceiptStore } from "./inference/contentReceipts.js";
import { ethersEthMessageRecoverer, VerifierRegistry } from "./providers/attestation/index.js";
import { fetchVeniceRateLimits } from "./providers/veniceRateLimits.js";
import { veniceKeyManifest } from "./providers/veniceKeys.js";
import { VeniceKeysetStore } from "./providers/veniceKeyStore.js";
import { buildVeniceCatalogPayload, createCatalogSynchronizer } from "./providers/catalog/sync.js";
import { buildFireworksCatalogPayload } from "./providers/catalog/fireworksSync.js";
import { buildBedrockCatalogPayload } from "./providers/catalog/bedrockSync.js";
import { buildDeepInfraCatalogPayload } from "./providers/catalog/deepinfraSync.js";
import { buildChutesCatalogPayload } from "./providers/catalog/chutesSync.js";
import { buildTinfoilCatalogPayload } from "./providers/catalog/tinfoilSync.js";
import { buildNearCatalogPayload } from "./providers/catalog/nearSync.js";
import type { NormalizedCatalogPayload } from "./providers/catalog/normalized.js";
import { GatewayAttestationService } from "./gateway/service.js";
import {
  registerGatewayAttestationIngressGuard,
  registerGatewayAttestationRoutes
} from "./routes/gatewayAttestation.js";
import { registerChatRoutes } from "./routes/chat.js";
import { registerTeeReceiptRoutes } from "./routes/teeReceipt.js";
import { registerOpaqueE2eeRoutes } from "./routes/opaqueE2ee.js";
import { registerEmbeddingRoutes } from "./routes/embeddings.js";
import { registerImageRoutes } from "./routes/image.js";
import { registerDisabledImageRoute } from "./routes/mediaDisabled.js";
import { registerWorkerRpcRoutes } from "./routes/internal/worker.js";
import { registerCredentialAdminRoutes } from "./routes/internal/credentialAdmin.js";
import { registerRelayIngressGuard } from "./relay/ingress.js";
import { CompatControlClient } from "./compat/controlClient.js";
import { compatErrorHandler, registerCompatIngressGuard, registerCompatRoutes } from "./compat/broker.js";

/** The relay: only the chat route, talking to control + worker over RPC. */
export async function buildRelayServer(config: AppConfig): Promise<FastifyInstance> {
  const server = await createBaseServer(config);
  // The relay verifies provider attestation evidence and decides whether a
  // per-request signature binding exists. Without this decoration
  // `server.verifierRegistry?.forProvider(...)` in src/routes/chat.ts is
  // undefined in split production, which silently (a) drops the `attestation`
  // field from POST /v1/tee/attestation so the browser E2EE gate fails closed,
  // and (b) never sends teeSignatureBinding to settle, leaving
  // providers.tee_signature_bindings empty. The registry is pure and holds no
  // credential, DB handle, or account identity, so it belongs on the relay.
  server.decorate("verifierRegistry", new VerifierRegistry({ ethRecoverer: ethersEthMessageRecoverer }));
  // Deadlines are configurable because the same code now runs both same-host
  // (sub-millisecond RPC) and cross-host (WAN RTT plus TLS). See
  // experiments/tee-gateway-bench/RESULTS.md for the measured cost per hop.
  const workerTimeoutMs = config.internal.workerRpcTimeoutMs;
  const controlClient = new HttpControlClient(
    config.internal.controlRpcUrl,
    config.internal.relayRpcToken,
    config.internal.controlRpcTimeoutMs
  );
  server.decorate("controlClient", controlClient);
  server.decorate("workerClient", new RoutedWorkerClient(
    new HttpWorkerClient(config.internal.workerRpcUrl, config.internal.workerRpcToken, "venice", workerTimeoutMs),
    new HttpWorkerClient(config.internal.fireworksWorkerRpcUrl, config.internal.workerRpcToken, "fireworks", workerTimeoutMs),
    new HttpWorkerClient(config.internal.bedrockWorkerRpcUrl, config.internal.workerRpcToken, "aws-bedrock", workerTimeoutMs),
    new HttpWorkerClient(config.internal.deepinfraWorkerRpcUrl, config.internal.workerRpcToken, "deepinfra", workerTimeoutMs),
    new HttpWorkerClient(config.internal.chutesWorkerRpcUrl, config.internal.workerRpcToken, "chutes", workerTimeoutMs),
    new HttpWorkerClient(config.internal.tinfoilWorkerRpcUrl, config.internal.workerRpcToken, "tinfoil", workerTimeoutMs),
    new HttpWorkerClient(config.internal.nearWorkerRpcUrl, config.internal.workerRpcToken, "near-ai", workerTimeoutMs)
  ));

  // Dependency-free protection for the content tier. This hook runs before
  // Fastify body parsing and before any internal RPC. It also redeems the opaque
  // single-use ticket before request content is parsed.
  registerRelayIngressGuard(server);

  // The relay runs the classifier locally (it has content); the model itself is
  // a local artifact with no secret or DB dependency.
  let requestClassifier: LocalRequestClassifier | null = null;
  if (config.routing.enabled) {
    requestClassifier = new LocalRequestClassifier({
      cacheDir: config.routing.modelCacheDir,
      artifactMetadataPath: config.routing.artifactPath,
      allowRemoteModels: config.routing.allowRemoteModels,
      maxInputChars: config.routing.maxInputChars,
      confidenceThreshold: config.routing.confidenceThreshold,
      queueTimeoutMs: config.routing.timeoutMs,
      maxQueue: config.routing.maxQueue
    });
    await requestClassifier.initialize();
  }
  server.decorate("requestClassifier", requestClassifier);
  // Automatic routing selects the model HERE. The candidate pool comes from
  // the control plane's content-free catalog RPC; only the resolved model id
  // goes back. Decorated only when the router is enabled, so a CVM running
  // with ROUTER_ENABLED=false never opens the catalog channel at all.
  if (requestClassifier) {
    server.decorate("routingCatalog", new RoutingCatalogCache({
      fetchRoutingCandidates: (signal) => server.controlClient.fetchRoutingCandidates!(signal)
    }));
  }
  // The exact request/response hashes stay in this process. See
  // inference/contentReceipts.ts.
  server.decorate("contentReceipts", new ContentReceiptStore());

  // Gateway self-attestation. Registered on the content tier because the point
  // is that the process holding the plaintext attests itself; a quote produced
  // by any other process would prove nothing about this one. Credential-free
  // (a client verifies before it trusts the endpoint with anything), stateless,
  // and reports a specific 503 rather than a 404 when no enclave is present.
  const gatewayAttestation = config.internal.gatewayAttestation.enabled
    ? await GatewayAttestationService.create({
      origin: config.internal.gatewayAttestation.publicOrigin,
      releaseId: config.internal.gatewayAttestation.releaseId,
      transport: config.internal.gatewayAttestation.transport,
      tlsTerminator: config.internal.gatewayAttestation.tlsTerminator,
      dstackEndpoint: config.internal.gatewayAttestation.dstackEndpoint
    })
    : null;
  server.decorate("gatewayAttestation", gatewayAttestation);
  if (config.internal.gatewayAttestation.enabled) {
    if (!gatewayAttestation) {
      server.log.warn(
        { error_type: "dstack_guest_agent_unreachable" },
        "gateway_attestation_degraded"
      );
    }
    await registerGatewayAttestationRoutes(server);
  }

  await registerChatRoutes(server);
  // Receipt lookup is served where the hashes are: inside the TD.
  await registerTeeReceiptRoutes(server);
  await registerOpaqueE2eeRoutes(server);
  await registerEmbeddingRoutes(server);
  // Split image generation: the relay holds the prompt + opaque ticket, reserves
  // the flat price at control, and dispatches to the credential-isolated worker.
  // Enabled only when the split image flag is on; otherwise fails closed with 503.
  if (config.internal.imageGenerationEnabled) {
    await registerImageRoutes(server);
  } else {
    await registerDisabledImageRoute(server);
  }
  return server;
}

/**
 * The compat broker: static-key OpenAI-compatibility on the identity side of the
 * split. It mints a single-use ticket at control over the authenticated compat
 * RPC and forwards content to the relay. Like the relay it is DB-less and holds
 * no provider credential; unlike the relay it legitimately handles the caller's
 * ar_ key (the acknowledged identity+content join for compat traffic). It reaches
 * ONLY control (mint) and the relay (forward) — never the DB, provider egress,
 * payments, or admin.
 */
export async function buildCompatServer(config: AppConfig): Promise<FastifyInstance> {
  // OpenAI-shaped error envelope for every failure (set once by createBaseServer).
  const server = await createBaseServer(config, { errorHandler: compatErrorHandler });
  server.decorate(
    "compatControlClient",
    new CompatControlClient(config.internal.controlRpcUrl, config.internal.compatRpcToken, config.internal.controlRpcTimeoutMs)
  );
  registerCompatIngressGuard(server);
  await registerCompatRoutes(server);
  return server;
}

/**
 * The gateway attestation service: the ONLY process that mounts
 * /var/run/dstack.sock.
 *
 * The guest agent is an app-wide key oracle. Any container that can reach the
 * socket can call getKey for any path and receive the same bytes any other
 * component would, and can mint a quote over arbitrary report data. Isolating
 * it here means the relay, which is the component most exposed to hostile
 * input, holds neither capability. The CVM's L7 edge routes
 * /v1/gateway/attestation to this service and nothing else reaches it.
 *
 * It has no DB, no Valkey, no provider credential, no account identity, and it
 * never receives request content. Its single route is credential-free by
 * design: a client verifies the enclave BEFORE trusting it with anything.
 */
export async function buildGatewayAttestationServer(config: AppConfig): Promise<FastifyInstance> {
  const server = await createBaseServer(config);
  // The flood guard is not optional here. Every call makes the guest agent mint
  // a fresh TDX quote, and that socket is a single serialized resource: an
  // unauthenticated caller could otherwise starve attestation for everyone.
  // The relay registers the same guard, but in the CVM the relay does not serve
  // this route, so without this the guard would exist only where the route does
  // not. Tightened well below the relay's chat budget: attestation is a
  // once-per-session call, not a per-request one.
  registerGatewayAttestationIngressGuard(server);
  const service = await GatewayAttestationService.create({
    origin: config.internal.gatewayAttestation.publicOrigin,
    releaseId: config.internal.gatewayAttestation.releaseId,
    transport: config.internal.gatewayAttestation.transport,
    tlsTerminator: config.internal.gatewayAttestation.tlsTerminator,
    dstackEndpoint: config.internal.gatewayAttestation.dstackEndpoint
  });
  if (!service) {
    // Fail loudly in the log but still serve, so the route returns the specific
    // 503 rather than the container crash-looping with no diagnosis.
    server.log.warn({ error_type: "dstack_guest_agent_unreachable" }, "gateway_attestation_degraded");
  }
  server.decorate("gatewayAttestation", service);
  await registerGatewayAttestationRoutes(server);
  return server;
}

/** A credential-isolated provider worker (Venice, Fireworks, or Bedrock). */
export async function buildWorkerServer(config: AppConfig): Promise<FastifyInstance> {
  // The worker error handler serializes a sanitized provider block so the relay
  // can reconstruct the provider outcome (status/request-id/machine-code) for the
  // rejection ledger across the RPC boundary.
  const server = await createBaseServer(config, { errorHandler: workerErrorHandler });
  // Map this worker's role to its canonical provider name (the DB/registry key).
  const providerLabel = config.internal.role === "fireworks-worker" ? "fireworks"
    : config.internal.role === "bedrock-worker" ? "aws-bedrock"
      : config.internal.role === "deepinfra-worker" ? "deepinfra"
        : config.internal.role === "chutes-worker" ? "chutes"
          : config.internal.role === "tinfoil-worker" ? "tinfoil"
            : config.internal.role === "near-worker" ? "near-ai"
              : "venice";
  const isVeniceWorker = providerLabel === "venice";
  // Fetch + normalize this worker's own catalog (each build fn fails closed
  // without the provider credential and never clobbers last-known-good on error).
  const buildCatalogPayload = () => {
    switch (providerLabel) {
      case "fireworks": return buildFireworksCatalogPayload(config, { log: server.log });
      case "aws-bedrock": return buildBedrockCatalogPayload(config, { log: server.log });
      case "deepinfra": return buildDeepInfraCatalogPayload(config, { log: server.log });
      case "chutes": return buildChutesCatalogPayload(config, { log: server.log });
      case "tinfoil": return buildTinfoilCatalogPayload(config, { log: server.log });
      case "near-ai": return buildNearCatalogPayload(config, { log: server.log });
      default: return buildVeniceCatalogPayload(config, { log: server.log });
    }
  };
  // Present this worker's own per-provider metadata token when configured, so
  // control can bind both the dispatch fence and the catalog push to exactly one
  // provider (AR-02). Falls back to the shared token in single-token deployments.
  const workerMetadataToken = config.internal.workerMetadataToken;
  const providerAttemptAcknowledger = new HttpProviderAttemptAcknowledger(
    config.internal.controlMetadataUrl,
    workerMetadataToken,
    config.internal.confidentialDeploymentId
  );
  // Durable keyset overlay: boot keys plus operator add/remove actions on the
  // worker's one writable mount. Dispatch and the manifest push both read the
  // live effective keyset, so lifecycle changes apply without a restart.
  const veniceKeyStore = isVeniceWorker
    ? new VeniceKeysetStore(config.providers.veniceKeys, config.providers.veniceKeysetOverlayFile)
    : undefined;
  if (veniceKeyStore) server.decorate("veniceKeyStore", veniceKeyStore);
  server.decorate(
    "workerClient",
    new InProcessWorkerClient(
      config,
      (attempt, signal) => providerAttemptAcknowledger.authorizeDispatch(attempt, signal),
      (dispatchToken, providerName, externalModelId, signal) =>
        providerAttemptAcknowledger.authorizeAttestation(dispatchToken, providerName, externalModelId, signal),
      veniceKeyStore
    )
  );
  await registerWorkerRpcRoutes(server);
  // Provider-credential administration that terminates HERE, in the attested
  // workload, rather than in a control plane that would then be holding the
  // secret. Registers only in capability mode.
  await registerCredentialAdminRoutes(server);

  // Scoped worker → control metadata push: the credential-bearing worker fetches
  // + normalizes the Venice catalog into a versioned, sanitized payload and pushes
  // ONLY that (plus rate limits) to control, which has no Venice key. Never content
  // or identity. Resilient fetch, single-flight, jittered interval; CATALOG_SYNC_
  // ENABLED gates which worker polls when the service is scaled.
  const deliverCatalog = async (payload: NormalizedCatalogPayload) => {
    const rateLimits = isVeniceWorker ? await fetchVeniceRateLimits(config) : null;
    const response = await fetch(`${config.internal.controlMetadataUrl}/internal/control/catalog`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${workerMetadataToken}` },
      body: JSON.stringify({
        deploymentId: config.internal.confidentialDeploymentId,
        payload,
        rateLimits: rateLimits ?? undefined,
        // Content-free keyset descriptors (id/label/fingerprint) so control
        // can offer per-key routing controls without ever holding a secret.
        // Read from the overlay store so operator-added keys are included.
        veniceKeys: veniceKeyStore ? veniceKeyManifest(veniceKeyStore.effectiveKeys()) : undefined
      })
    });
    if (!response.ok) {
      server.log.warn({ status_code: response.status }, "catalog_metadata_push_failed");
      throw new Error(`catalog_metadata_push_failed_${response.status}`);
    }
  };
  const synchronizer = createCatalogSynchronizer({
    buildPayload: buildCatalogPayload,
    deliver: deliverCatalog,
    intervalSeconds: config.internal.catalogSyncIntervalSeconds,
    enabled: config.internal.catalogSyncEnabled,
    log: server.log,
    provider: providerLabel
  });
  // On-demand refresh for the control-plane admin RPC: same build + push path as
  // the scheduled poller, but failures propagate to the caller instead of being
  // swallowed by the timer loop.
  server.decorate("catalogSyncNow", async () => {
    const payload = await buildCatalogPayload();
    if (!payload) throw new Error("catalog_fetch_failed");
    await deliverCatalog(payload);
  });
  if (config.env !== "test") {
    await synchronizer.start();
    server.addHook("onClose", async () => synchronizer.stop());
  }
  return server;
}
