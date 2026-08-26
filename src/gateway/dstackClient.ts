// Narrow, fail-closed wrapper around the dstack guest agent.
//
// Only the confidential gateway-attestation service talks to this. Everything
// else in the process must be unable to reach the guest agent socket, which is
// why deploy/phala mounts /var/run/dstack.sock into exactly one container.
//
// Three properties matter here:
//
//   1. Absence is not an error at import time. Control, the site, and local
//      development have no socket; constructing the SDK client throws when the
//      socket is missing, so construction is deferred and guarded and the route
//      reports a clean 503 instead of crashing a role that never needed it.
//   2. The surface is deliberately three calls wide (info, quote, key). The
//      wrapper does not expose sign/emitEvent/getTlsKey generically, so a future
//      caller cannot extend RTMR3 or mint signatures by accident.
//   3. Nothing here logs. The guest agent responses contain measurements and
//      public keys, not content, but they are also never written to a log line.

import type { DstackClient, GetQuoteResponse, InfoResponse, TcbInfoV05x } from "@phala/dstack-sdk";

/** Where the app key is derived from. Stable for one app id across restarts. */
export const GATEWAY_KEY_PATH = "anonrouter/gateway/transport";
export const GATEWAY_KEY_PURPOSE = "gateway-attestation";

export interface DstackGateway {
  info(): Promise<InfoResponse<TcbInfoV05x>>;
  getQuote(reportData: Buffer): Promise<GetQuoteResponse>;
  /** Deterministic application key. Same app id + path always yields the same key. */
  getAppKey(): Promise<Uint8Array>;
}

class SdkDstackGateway implements DstackGateway {
  constructor(private readonly client: DstackClient<TcbInfoV05x>) {}

  info(): Promise<InfoResponse<TcbInfoV05x>> {
    return this.client.info();
  }

  getQuote(reportData: Buffer): Promise<GetQuoteResponse> {
    // The guest agent caps report_data at 64 bytes; the binding digest is
    // exactly 64. Assert rather than truncate: a silently shortened digest
    // would still verify against a shortened recomputation and weaken the bind.
    if (reportData.length !== 64) {
      throw new Error(`report_data must be exactly 64 bytes, got ${reportData.length}`);
    }
    return this.client.getQuote(reportData);
  }

  async getAppKey(): Promise<Uint8Array> {
    // DEFAULT algorithm (secp256k1) on purpose. Asking for "ed25519" makes the
    // SDK probe the guest agent's Version RPC, which requires 0.5.7; the local
    // simulator answers that probe with HTTP 400 and a PARSEABLE JSON body, so
    // the SDK RESOLVES instead of throwing and the option is silently dropped
    // on the wire. The X25519 keypair is derived from this seed by HKDF in
    // src/gateway/service.ts, which keeps the derivation under our control.
    const derived = await this.client.getKey(GATEWAY_KEY_PATH, GATEWAY_KEY_PURPOSE);
    return derived.key;
  }
}

export class DstackUnavailableError extends Error {
  constructor(reason: string) {
    super(`dstack guest agent unavailable: ${reason}`);
    this.name = "DstackUnavailableError";
  }
}

/**
 * Construct a gateway client, or return null when this process is not running
 * inside a dstack CVM (and no simulator endpoint is configured). The SDK is
 * imported dynamically so a role without the socket never pays for it and a
 * missing optional dependency cannot break startup.
 *
 * `endpoint` accepts a socket path or an http:// simulator URL. When omitted the
 * SDK probes the standard socket paths and honors DSTACK_SIMULATOR_ENDPOINT.
 */
export async function createDstackGateway(endpoint?: string): Promise<DstackGateway | null> {
  try {
    const { DstackClient: Client } = await import("@phala/dstack-sdk");
    return new SdkDstackGateway(new Client<TcbInfoV05x>(endpoint));
  } catch {
    // Missing socket, missing module, or an unreadable endpoint. All three mean
    // the same thing to a caller: there is no attestation available here.
    return null;
  }
}
