// Independently runnable inference roles for production.
//
//   relay           : holds request content + opaque tickets. NO db, redis,
//                     auth, payment, admin, email, or provider credentials.
//   provider worker : holds ONLY its own provider credential. NO db, redis,
//                     account, auth, or payment access.
//   pool worker     : a provider worker for SEVERAL providers at once. Holds
//                     each listed provider's credential and nothing else.
//   release-collateral : makes the pool's release-authority lookups (GitHub,
//                     Base). NO provider credential, NO request content, and no
//                     token but the one that admits its caller.
//
// The control-api role is built by buildServer(config) with RUNTIME_ROLE=control.

import type { FastifyInstance } from "fastify";
import { performance } from "node:perf_hooks";
import { workerProbeLeaseBudget } from "./providers/health/probeLeaseBudget.js";
import type { AppConfig } from "./config.js";
import { createBaseServer, workerErrorHandler, type BaseServerOptions } from "./httpBase.js";
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
import { configuredVeniceKeysetStore } from "./providers/veniceKeyStore.js";
import {
  isPoolWorkerRole,
  workerMetadataTokenFor,
  workerProvidersForRole,
  type WorkerProviderName
} from "./providers/workerProviders.js";
import { buildVeniceCatalogPayload, createCatalogSynchronizer } from "./providers/catalog/sync.js";
import { buildFireworksCatalogPayload } from "./providers/catalog/fireworksSync.js";
import { buildBedrockCatalogPayload } from "./providers/catalog/bedrockSync.js";
import { buildDeepInfraCatalogPayload } from "./providers/catalog/deepinfraSync.js";
import { buildChutesCatalogPayload } from "./providers/catalog/chutesSync.js";
import { buildTinfoilCatalogPayload } from "./providers/catalog/tinfoilSync.js";
import { buildNearCatalogPayload } from "./providers/catalog/nearSync.js";
import { buildPhalaAiCatalogPayload } from "./providers/catalog/phalaAiSync.js";
import type { NormalizedCatalogPayload } from "./providers/catalog/normalized.js";
import { newId } from "./ids.js";
import {
  workerHealthTargetsResponseSchema,
  type WorkerHealthCheck,
  type WorkerHealthTarget
} from "./providers/health/workerMetadata.js";
import { AppError } from "./security/errors.js";
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
import { registerSpeechRoutes } from "./routes/speech.js";
import { registerDisabledImageRoute, registerDisabledSpeechRoute } from "./routes/mediaDisabled.js";
import { registerWorkerRpcRoutes } from "./routes/internal/worker.js";
import {
  registerCredentialAdminRoutes,
  registerPooledCredentialAdminRoutes
} from "./routes/internal/credentialAdmin.js";
import { registerRelayIngressGuard } from "./relay/ingress.js";
import { CompatControlClient } from "./compat/controlClient.js";
import { releaseCollateralClientFor } from "./releaseCollateral/client.js";
import {
  ReleaseCollateralAdmission,
  releaseCollateralErrorHandler,
  releaseCollateralSources,
  registerReleaseCollateralRoutes,
  type ReleaseCollateralSources
} from "./releaseCollateral/server.js";
import { compatErrorHandler, registerCompatIngressGuard, registerCompatRoutes } from "./compat/broker.js";

/** The relay: only the chat route, talking to control + worker over RPC. */
export async function buildRelayServer(
  config: AppConfig,
  options: BaseServerOptions = {}
): Promise<FastifyInstance> {
  const server = await createBaseServer(config, options);
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
    new HttpWorkerClient(config.internal.nearWorkerRpcUrl, config.internal.workerRpcToken, "near-ai", workerTimeoutMs),
    new HttpWorkerClient(config.internal.phalaAiWorkerRpcUrl, config.internal.workerRpcToken, "phala-ai", workerTimeoutMs)
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
      origins: config.internal.gatewayAttestation.publicOrigins,
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
  // Split text-to-speech: identical boundary to image. Independently flagged so
  // either media surface can be rolled back without the other.
  if (config.internal.speechGenerationEnabled) {
    await registerSpeechRoutes(server);
  } else {
    await registerDisabledSpeechRoute(server);
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
export async function buildCompatServer(
  config: AppConfig,
  options: BaseServerOptions = {}
): Promise<FastifyInstance> {
  // OpenAI-shaped error envelope for every failure (set once by createBaseServer).
  const server = await createBaseServer(config, { ...options, errorHandler: compatErrorHandler });
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
export async function buildGatewayAttestationServer(
  config: AppConfig,
  options: BaseServerOptions = {}
): Promise<FastifyInstance> {
  const server = await createBaseServer(config, options);
  // The flood guard is not optional here. Every call makes the guest agent mint
  // a fresh TDX quote, and that socket is a single serialized resource: an
  // unauthenticated caller could otherwise starve attestation for everyone.
  // The relay registers the same guard, but in the CVM the relay does not serve
  // this route, so without this the guard would exist only where the route does
  // not. Tightened well below the relay's chat budget: attestation is a
  // once-per-session call, not a per-request one.
  registerGatewayAttestationIngressGuard(server);
  const service = await GatewayAttestationService.create({
    origins: config.internal.gatewayAttestation.publicOrigins,
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

export interface ReleaseCollateralServerOptions extends Pick<BaseServerOptions, "observe"> {
  /** The lookups. Tests pass stubbed upstreams; the role itself takes the real fetchers. */
  sources?: ReleaseCollateralSources;
  /** The role's bounds. Tests pass smaller ones and an injected clock. */
  admission?: ReleaseCollateralAdmission;
}

/**
 * The release-collateral role: the release-authority lookups a pooled worker must not
 * make itself, behind a typed contract (src/releaseCollateral/contract.ts).
 *
 * A pooled worker holds several providers' keys and every pooled prompt. What
 * it verifies a provider against is public (GitHub refs and files, a registry
 * on Base), and fetching it from that process would give every one of those
 * keys and prompts a session to github.com and a public RPC node. This process
 * makes the requests instead, and is the only one whose egress reaches those
 * hosts.
 *
 * It has no DB, no Valkey, no provider credential, no metadata token and no
 * account identity, and it never receives request content. Its caller is not
 * trusted: every rule about what may be asked is enforced here.
 */
export async function buildReleaseCollateralServer(
  config: AppConfig,
  options: ReleaseCollateralServerOptions = {}
): Promise<FastifyInstance> {
  const server = await createBaseServer(config, { observe: options.observe, errorHandler: releaseCollateralErrorHandler });
  await registerReleaseCollateralRoutes(server, {
    token: config.internal.releaseCollateralRpcToken,
    sources: options.sources ?? releaseCollateralSources(),
    admission: options.admission ?? new ReleaseCollateralAdmission()
  });
  return server;
}

// Health probes in flight at once. On a single-provider worker this bounds one
// delivery, as it always has. On the pool it bounds the WHOLE PROCESS: six
// providers each running four would be twenty-four billed requests and their
// buffers in one heap.
const HEALTH_PROBE_CONCURRENCY = 4;
// On the pool, the most one provider's delivery may hold of that budget, so a
// provider whose probes all hang cannot starve the others' out.
const POOLED_PROVIDER_PROBE_CONCURRENCY = 2;

/** At most `limit` tasks at once, first come first served. */
function createGate(limit: number) {
  let active = 0;
  const waiting: Array<() => void> = [];
  return async function run<T>(task: () => Promise<T>): Promise<T> {
    // A released slot is handed straight to the next waiter, so `active` only
    // moves when nobody is waiting.
    if (active >= limit) await new Promise<void>((resolve) => waiting.push(resolve));
    else active += 1;
    try {
      return await task();
    } finally {
      const next = waiting.shift();
      if (next) next();
      else active -= 1;
    }
  };
}

/**
 * A credential-isolated provider worker: one provider's (Venice, Fireworks,
 * Bedrock, ...), or under the pool role every provider POOL_PROVIDERS lists.
 */
export async function buildWorkerServer(
  config: AppConfig,
  // `observe` only: it sees the bare instance before any route exists, which
  // is how a route inventory is taken. The error handler is not the caller's.
  options: Pick<BaseServerOptions, "observe"> = {}
): Promise<FastifyInstance> {
  // The worker error handler serializes a sanitized provider block so the relay
  // can reconstruct the provider outcome (status/request-id/machine-code) for the
  // rejection ledger across the RPC boundary.
  const server = await createBaseServer(config, { observe: options.observe, errorHandler: workerErrorHandler });
  // The providers this process serves, by canonical name (the DB/registry key).
  // Everything below acts for a provider NAMED from this list; nothing reads
  // the role again, except to ask whether this is the pool.
  const pooled = isPoolWorkerRole(config.internal.role);
  const providers = workerProvidersForRole(config.internal.role, config.internal.poolProviders);
  // Only the pool role serves a list. Any other role with more or fewer than
  // one provider would be a pool that passed none of the pool's fences.
  if (!pooled && providers.length !== 1) throw new Error("buildWorkerServer serves exactly one provider outside the pool");
  // Durable keyset overlay: boot keys plus operator add/remove actions on the
  // worker's one writable mount. Dispatch, the catalog and rate-limit fetches,
  // and the manifest push all read the live effective keyset, so lifecycle
  // changes apply without a restart.
  //
  // ONE store per process, and only where Venice is served. Every Venice
  // consumer below is handed this same instance; no other provider's wiring
  // sees it.
  const veniceKeyStore = providers.includes("venice") ? configuredVeniceKeysetStore(config) : undefined;
  if (veniceKeyStore) server.decorate("veniceKeyStore", veniceKeyStore);

  // Where a release-collateral role is configured (the pool), a lookup it could not
  // answer leaves an authority check failing closed with nothing else to show
  // for it. One line here, naming the operation and a fixed code, never what
  // was asked.
  releaseCollateralClientFor(config)?.observeFailures((operation, code) => {
    server.log.warn({ operation, error_type: code }, "release_collateral_rpc_failed");
  });

  const probeGate = pooled ? createGate(HEALTH_PROBE_CONCURRENCY) : null;
  // Set when the pool is closing, so no provider starts another probe.
  let closing = false;

  // Everything ONE provider needs to talk to control: its metadata token, its
  // fence acknowledger, its catalog and health pushes, its synchronizer. Built
  // once per served provider. Nothing in here is shared between providers but
  // the probe gate.
  const wireProvider = (providerLabel: WorkerProviderName) => {
    // Venice's keyset store, for the Venice wiring only. Another provider's
    // catalog push must never carry the Venice key manifest.
    const keyStore = providerLabel === "venice" ? veniceKeyStore : undefined;
    // Fetch + normalize this provider's own catalog (each build fn fails closed
    // without the provider credential and never clobbers last-known-good on error).
    const buildCatalogPayload = () => {
      switch (providerLabel) {
        case "fireworks": return buildFireworksCatalogPayload(config, { log: server.log });
        case "aws-bedrock": return buildBedrockCatalogPayload(config, { log: server.log });
        case "deepinfra": return buildDeepInfraCatalogPayload(config, { log: server.log });
        case "chutes": return buildChutesCatalogPayload(config, { log: server.log });
        case "tinfoil": return buildTinfoilCatalogPayload(config, { log: server.log });
        case "near-ai": return buildNearCatalogPayload(config, { log: server.log });
        case "phala-ai": return buildPhalaAiCatalogPayload(config, { log: server.log });
        default: return buildVeniceCatalogPayload(config, { log: server.log, veniceKeyStore: keyStore });
      }
    };
    // Present this PROVIDER's metadata token: its own per-provider token when
    // configured, so control can bind the dispatch fence, the catalog push and the
    // health push to exactly one provider (AR-02). Falls back to the shared token
    // in single-token deployments; on the pool there is no fallback, and a
    // provider with no token of its own fails here, at boot. The fences and the
    // pushes below are all built on this one selection.
    const workerMetadataToken = workerMetadataTokenFor(config.internal, providerLabel);
    const acknowledger = new HttpProviderAttemptAcknowledger(
      config.internal.controlMetadataUrl,
      workerMetadataToken,
      config.internal.confidentialDeploymentId
    );
    // The catalog and health pushes, bounded by their own deadline. Without one,
    // a control plane that stops answering holds the sync open, and boot and
    // every on-demand caller with it. It is not the control RPC deadline: control
    // applies the catalog inside this request, which takes far longer than a
    // per-request RPC. What a failure means stays with each caller.
    const pushMetadata = (body: unknown) => fetch(`${config.internal.controlMetadataUrl}/internal/control/catalog`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${workerMetadataToken}`, "x-anonrouter-probe-lease": "1" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(config.internal.metadataPushTimeoutMs)
    });

    // Scoped worker → control metadata push: the credential-bearing worker fetches
    // + normalizes the provider catalog into a versioned, sanitized payload and pushes
    // ONLY that (plus rate limits) to control, which has no provider key. Never content
    // or identity. Resilient fetch, single-flight, jittered interval; CATALOG_SYNC_
    // ENABLED gates which worker polls when the service is scaled.
    const deliverHealthChecks = async (targets: WorkerHealthTarget[], lease: NonNullable<ReturnType<typeof workerProbeLeaseBudget>>) => {
      if (targets.length === 0 || !server.workerClient.probe) return;
      const checks: WorkerHealthCheck[] = [];
      let cursor = 0;
      const probeOne = async (target: WorkerHealthTarget) => {
        if (closing || !lease.permitsProbe()) return null;
        return server.workerClient.probe!({
          requestId: `probe_${newId()}`,
          providerName: providerLabel,
          externalModelId: target.externalModelId
        }, AbortSignal.timeout(25_000));
      };
      const probe = async () => {
        while (cursor < targets.length) {
          const target = targets[cursor++]!;
          // The probe's own deadline starts when it does, not while it waits
          // for a slot.
          const result = await (probeGate ? probeGate(() => probeOne(target)) : probeOne(target));
          if (!result) return;
          checks.push({
            externalModelId: target.externalModelId,
            ok: result.ok,
            latencyMs: result.latencyMs,
            ...(result.statusCode === undefined ? {} : { statusCode: result.statusCode }),
            ...(result.errorCode === undefined ? {} : { errorCode: result.errorCode })
          });
        }
      };
      const workers = pooled ? POOLED_PROVIDER_PROBE_CONCURRENCY : HEALTH_PROBE_CONCURRENCY;
      await Promise.all(Array.from({ length: Math.min(workers, targets.length) }, probe));
      // A pass cut short by shutdown is not a health report.
      if (closing || checks.length === 0) return;

      const response = await pushMetadata({
        deploymentId: config.internal.confidentialDeploymentId,
        provider: providerLabel,
        healthProbeLeaseId: lease.leaseId,
        healthChecks: checks
      });
      if (!response.ok) {
        server.log.warn({ provider: providerLabel, status_code: response.status }, "model_health_metadata_push_failed");
        return;
      }
      const acknowledgement = await response.json().catch(() => ({})) as { accepted?: unknown };
      if (acknowledgement.accepted !== checks.length) {
        server.log.warn(
          { provider: providerLabel, attempted: checks.length, accepted: acknowledgement.accepted },
          "model_health_metadata_push_incomplete"
        );
      }
    };

    const deliverCatalog = async (payload: NormalizedCatalogPayload) => {
      const rateLimits = providerLabel === "venice" ? await fetchVeniceRateLimits(config, keyStore) : null;
      const requestStartedAt = performance.now();
      const response = await pushMetadata({
        deploymentId: config.internal.confidentialDeploymentId,
        payload,
        rateLimits: rateLimits ?? undefined,
        // Content-free keyset descriptors (id/label/fingerprint) so control
        // can offer per-key routing controls without ever holding a secret.
        // Read from the overlay store so operator-added keys are included.
        veniceKeys: keyStore ? veniceKeyManifest(keyStore.effectiveKeys()) : undefined
      });
      if (!response.ok) {
        server.log.warn({ status_code: response.status }, "catalog_metadata_push_failed");
        throw new Error(`catalog_metadata_push_failed_${response.status}`);
      }
      const raw = await response.json().catch(() => ({}));
      const parsed = workerHealthTargetsResponseSchema.safeParse(raw);
      if (!parsed.success) {
        server.log.warn({ provider: providerLabel }, "model_health_targets_invalid");
        return;
      }
      // A health failure is not a catalog failure. Catalog freshness must keep
      // advancing even when a model refuses a probe; the bounded outcome is sent
      // back separately and the admission/quarantine policy decides what it means.
      const lease = workerProbeLeaseBudget(parsed.data.health_probe_lease, requestStartedAt);
      if (!lease) return;
      await deliverHealthChecks(parsed.data.health_probe_targets, lease).catch((error) => {
        server.log.warn(
          { provider: providerLabel, error_type: error instanceof Error ? error.name : "health_probe_error" },
          "model_health_metadata_push_failed"
        );
      });
    };
    const synchronizer = createCatalogSynchronizer({
      buildPayload: buildCatalogPayload,
      deliver: deliverCatalog,
      intervalSeconds: config.internal.catalogSyncIntervalSeconds,
      enabled: config.internal.catalogSyncEnabled,
      log: server.log,
      provider: providerLabel
    });
    return { provider: providerLabel, acknowledger, synchronizer };
  };

  const wired = new Map(providers.map((provider) => [provider as string, wireProvider(provider)] as const));
  const only = pooled ? undefined : wired.get(providers[0]!)!;

  // THE FENCES SELECT BY PROVIDER. An attempt is acknowledged to control under
  // the metadata token of the provider it is FOR, so on the pool the
  // acknowledger is looked up by the provider the attempt names. One that names
  // a provider this process does not serve has no acknowledger: it is refused
  // here, the adapter's fence call fails, and no provider request is made.
  //
  // A single-provider worker has one acknowledger and uses it whatever the
  // attempt names, as it always has: dev and test harnesses send the mock
  // provider through the Venice worker, and in production the route has
  // already refused any provider but the worker's own.
  const acknowledgerFor = (providerName: string) => {
    const lane = only ?? wired.get(providerName);
    if (!lane) throw new AppError(503, "provider_attempt_fence_failed", "Provider dispatch authorization failed");
    return lane.acknowledger;
  };
  server.decorate(
    "workerClient",
    new InProcessWorkerClient(
      config,
      async (attempt, signal) => acknowledgerFor(attempt.providerName).authorizeDispatch(attempt, signal),
      async (dispatchToken, providerName, externalModelId, signal) =>
        acknowledgerFor(providerName).authorizeAttestation(dispatchToken, providerName, externalModelId, signal),
      veniceKeyStore
    )
  );
  await registerWorkerRpcRoutes(server, providers);
  // Provider-credential administration that terminates HERE, in the attested
  // workload, rather than in a control plane that would then be holding the
  // secret. Registers only in capability mode. The pool mounts one route set
  // per provider under that provider's name; a single-provider worker keeps
  // its un-namespaced paths.
  if (pooled) await registerPooledCredentialAdminRoutes(server, config.internal.poolProviders);
  else await registerCredentialAdminRoutes(server, only!.provider);

  // On-demand refresh for the control-plane admin RPC: same build + push path as
  // the scheduled poller, but failures propagate to the caller instead of being
  // swallowed by the timer loop. Concurrent callers share a run (syncNow).
  server.decorate("catalogSyncNow", async (provider?: string) => {
    // Each synchronizer is one provider's. A caller naming a provider this
    // process does not serve must get a failure, not another provider's catalog
    // under its name. Only a single-provider worker has a provider to default
    // to; on the pool a caller that names none gets the same failure.
    const lane = provider === undefined ? only : wired.get(provider);
    if (!lane) throw new Error("catalog_sync_unavailable");
    await lane.synchronizer.syncNow();
  });
  if (config.env !== "test") {
    if (only) {
      await only.synchronizer.start();
      server.addHook("onClose", async () => only.synchronizer.stop());
    } else {
      // THE POOL DOES NOT WAIT. A single-provider worker boots behind its first
      // sync; six providers in a row would put every one of them behind the
      // slowest, and a provider that never answers would keep the rest from
      // ever serving. Each provider's poller starts on its own, and each one's
      // failures stay its own: start() logs and swallows a failed sync, and
      // the catch below is for anything it did not.
      server.addHook("onClose", async () => {
        closing = true;
        for (const lane of wired.values()) lane.synchronizer.stop();
      });
      for (const lane of wired.values()) {
        void lane.synchronizer.start().catch((error) => {
          server.log.warn(
            { provider: lane.provider, error_type: error instanceof Error ? error.name : "sync_error" },
            "catalog_sync_start_failed"
          );
        });
      }
    }
  }
  return server;
}
