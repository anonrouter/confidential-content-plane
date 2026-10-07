// The two places that verify a provider secret BEFORE it is installed: the
// capability route (src/routes/internal/credentialAdmin.ts) and the legacy
// bearer route (src/routes/internal/worker.ts).
//
// Both used to call global fetch with a hand-built `authorization` header and no
// redirect policy, outside src/providers where the transport's tests could not
// see them. They now go through the transport's candidate probe. These run the
// real routes against loopback stand-ins, with the live check switched on (it is
// skipped under NODE_ENV=test), and assert what the provider actually received.

import { generateKeyPairSync } from "node:crypto";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { AppConfig } from "../../src/config.js";
import type { WorkerClient } from "../../src/inference/rpc.js";
import { mintCapability, signCapability } from "../../src/providers/credentials/capability.js";
import { VeniceKeysetStore } from "../../src/providers/veniceKeyStore.js";
import { registerCredentialAdminRoutes } from "../../src/routes/internal/credentialAdmin.js";
import { registerWorkerRpcRoutes } from "../../src/routes/internal/worker.js";

const WORKER_RPC_TOKEN = "test-worker-rpc-token-0123456789abcdef0123456789";
const METADATA_TOKEN = "test-metadata-rpc-token-0123456789abcdef0123456789";
const DEPLOYMENT_ID = "unit-candidate-validation";
const SIGNER_ID = "unit-cap-signer";
const BOOT_KEYS = [{ id: "boot-primary", label: null, key: "sk-DEVDUMMY-boot-key" }];
const CANDIDATE = "sk-DEVDUMMY-candidate-secret-7b1e";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const rawPublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
const rawPrivateKey = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex");

interface Seen {
  method: string | undefined;
  path: string;
  authorization: string | undefined;
  body: string;
}

type ProviderAnswer = "accept" | "reject" | "redirect";

let stateDir = "";
let venice: http.Server;
let elsewhere: http.Server;
let control: http.Server;
let legacy: FastifyInstance;
let capability: FastifyInstance;
let legacyStore: VeniceKeysetStore;
let capabilityStore: VeniceKeysetStore;
let providerAnswer: ProviderAnswer = "accept";
let elsewhereOrigin = "";
const veniceSeen: Seen[] = [];
const elsewhereSeen: Seen[] = [];
const controlSeen: Seen[] = [];

function listen(server: http.Server): Promise<string> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => {
    resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  }));
}

function record(seen: Seen[], respond: () => { status: number; headers?: Record<string, string> }): http.Server {
  return http.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      seen.push({
        method: request.method,
        path: request.url ?? "",
        authorization: request.headers.authorization,
        body: Buffer.concat(chunks).toString("utf8")
      });
      const answer = respond();
      response.writeHead(answer.status, { "content-type": "application/json", ...(answer.headers ?? {}) });
      response.end("{}");
    });
  });
}

function signedCapability(credentialId: string) {
  return signCapability(
    mintCapability({
      operatorId: "opa-unit-000001",
      provider: "venice",
      credentialId,
      action: "register",
      deploymentId: DEPLOYMENT_ID,
      now: Math.floor(Date.now() / 1000)
    }),
    rawPrivateKey,
    SIGNER_ID
  );
}

describe("candidate secret validation goes through the provider transport", () => {
  beforeAll(async () => {
    stateDir = mkdtempSync(join(tmpdir(), "anonrouter-candidate-"));
    elsewhere = record(elsewhereSeen, () => ({ status: 200 }));
    elsewhereOrigin = await listen(elsewhere);
    venice = record(veniceSeen, () => providerAnswer === "accept"
      ? { status: 200 }
      : providerAnswer === "reject"
        ? { status: 401 }
        : { status: 302, headers: { location: `${elsewhereOrigin}/collect` } });
    const veniceOrigin = await listen(venice);
    control = record(controlSeen, () => ({ status: 200 }));
    const controlOrigin = await listen(control);

    // `development`, not `test`: the live check is skipped under test.
    const providers = {
      defaultProvider: "venice",
      veniceBaseUrl: `${veniceOrigin}/api/v1`,
      veniceInferenceKey: BOOT_KEYS[0]!.key,
      veniceKeys: BOOT_KEYS
    };

    legacyStore = new VeniceKeysetStore(BOOT_KEYS, join(stateDir, "legacy-overlay.json"));
    legacy = Fastify({ logger: false });
    legacy.decorate("config", {
      env: "development",
      providers,
      internal: { role: "venice-worker", workerRpcToken: WORKER_RPC_TOKEN, credentialAdmin: { mode: "legacy" } }
    } as unknown as AppConfig);
    legacy.decorate("workerClient", {} as WorkerClient);
    legacy.decorate("veniceKeyStore", legacyStore);
    await registerWorkerRpcRoutes(legacy);

    capabilityStore = new VeniceKeysetStore(BOOT_KEYS, join(stateDir, "capability-overlay.json"));
    capability = Fastify({ logger: false });
    capability.decorate("config", {
      env: "development",
      providers,
      internal: {
        role: "venice-worker",
        confidentialDeploymentId: DEPLOYMENT_ID,
        controlMetadataUrl: controlOrigin,
        // The parts the worker selects its metadata token from. With no
        // deployment or per-provider token, the shared one is what it presents.
        deploymentMetadataToken: "",
        providerMetadataTokens: {},
        metadataRpcToken: METADATA_TOKEN,
        credentialAdmin: {
          mode: "capability",
          capabilitySigners: `${SIGNER_ID}:${rawPublicKey}`,
          tlsSpkiSha256: "7c".repeat(32),
          consumedCapabilityFile: join(stateDir, "consumed.json")
        }
      }
    } as unknown as AppConfig);
    capability.decorate("veniceKeyStore", capabilityStore);
    await registerCredentialAdminRoutes(capability);
  });

  afterAll(async () => {
    await legacy?.close();
    await capability?.close();
    for (const server of [venice, elsewhere, control]) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    rmSync(stateDir, { recursive: true, force: true });
  });

  beforeEach(() => {
    providerAnswer = "accept";
    veniceSeen.length = 0;
    elsewhereSeen.length = 0;
    controlSeen.length = 0;
  });

  const routes = [
    {
      name: "legacy bearer route",
      install: (credentialId: string) => legacy.inject({
        method: "POST",
        url: "/internal/venice/keys",
        headers: { authorization: `Bearer ${WORKER_RPC_TOKEN}` },
        payload: { id: credentialId, key: CANDIDATE }
      }),
      store: () => legacyStore,
      rejectedCode: "venice_key_invalid",
      unavailableCode: "venice_key_verification_unavailable"
    },
    {
      name: "capability route",
      install: (credentialId: string) => capability.inject({
        method: "POST",
        url: "/internal/credentials/secret",
        payload: { capability: signedCapability(credentialId), secret: CANDIDATE }
      }),
      store: () => capabilityStore,
      rejectedCode: "credential_rejected_by_provider",
      unavailableCode: "credential_verification_unavailable"
    }
  ];

  describe.each(routes)("$name", (route) => {
    it("sends the candidate to Venice's own origin as a bare GET, then installs it", async () => {
      const response = await route.install("accepted-01");
      expect(response.statusCode).toBe(200);

      expect(veniceSeen).toEqual([
        { method: "GET", path: "/api/v1/api_keys/rate_limits", authorization: `Bearer ${CANDIDATE}`, body: "" }
      ]);
      expect(route.store().keyById("accepted-01")).toBe(CANDIDATE);
    });

    it("does not install a candidate the provider rejects", async () => {
      providerAnswer = "reject";
      const response = await route.install("rejected-01");
      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({ code: route.rejectedCode });
      expect(veniceSeen).toHaveLength(1);
      expect(route.store().keyById("rejected-01")).toBeNull();
    });

    it("does not follow a redirect: the candidate reaches no other origin and is not installed", async () => {
      providerAnswer = "redirect";
      const response = await route.install("redirected-01");

      // A refused redirect is a failed verification, not proof of a bad key.
      expect(response.statusCode).toBe(503);
      expect(response.json()).toMatchObject({ code: route.unavailableCode });
      expect(veniceSeen).toHaveLength(1);
      expect(elsewhereSeen).toEqual([]);
      expect(route.store().keyById("redirected-01")).toBeNull();
    });
  });

  it("never puts the candidate in the outcome it reports to control", async () => {
    await capability.inject({
      method: "POST",
      url: "/internal/credentials/secret",
      payload: { capability: signedCapability("reported-01"), secret: CANDIDATE }
    });
    expect(controlSeen).toHaveLength(1);
    // The service token authenticates the report; the provider secret is nowhere in it.
    expect(controlSeen[0]!.authorization).toBe(`Bearer ${METADATA_TOKEN}`);
    expect(controlSeen[0]!.body).not.toContain(CANDIDATE);
  });
});
