// dstack on-chain authorization: the provider's own registry of the boot
// software its KMS will release keys to.
//
// dstack's on-chain KMS model (Dstack-TEE/dstack kms/auth-eth): a KMS contract
// (`DstackKms`) lists the OS images it accepts and the apps registered with it;
// each app is a `DstackApp` contract, at the address that IS the dstack app_id,
// listing the compose hashes the app's owner authorized. The KMS releases keys
// only to a TD whose measured app-id, compose-hash and os-image-hash pass these
// lists. NEAR AI runs such a KMS on Base mainnet (research 2026-10-01): KMS
// 0x8fa1593f..d637, app 0x2c0a0c96..f91b for the GLM TDs, owner one EOA.
//
// What this proves and what it does not:
// - It proves the provider PUBLISHED (registered) this exact boot compose and
//   image, in an append-only public event history (ComposeHashAdded,
//   OsImageHashAdded), before or while the TD ran. That is the provider's
//   official channel for its boot layer: the boot compose is rendered per
//   host from a private template and is published nowhere else.
// - It does not prove anyone reviewed it. One EOA can add or remove hashes and
//   upgrade both proxies; the registry also still lists two dev images. The
//   RPC answer is unsigned: the record is as honest as the RPC endpoint and
//   the layer that relays it.
//
// The fetch layer (`DstackOnchainFetcher`) reads the three booleans with
// `eth_call` at one block; the verifier compares the record's subjects with
// the hardware-attested values (replayed RTMR3 events, MRCONFIGID).

import { check } from "../checks.js";
import type { AttestationCheck } from "../types.js";
import {
  AUTHORITY_MAX_STALE_MS,
  AuthorityCache,
  DEFAULT_AUTHORITY_BUDGET,
  authorityFetch,
  type FetchLike,
  type RequestBudget
} from "./fetchLayer.js";

export interface DstackKmsIdentity {
  /** EIP-155 chain id: 8453 is Base mainnet. */
  chainId: number;
  /** DstackKms contract, lowercase 0x-prefixed. */
  kms: string;
}

export interface DstackOnchainAuthorization {
  v: 1;
  chainId: number;
  kms: string;
  /** The JSON-RPC endpoint that answered (audit trail only). */
  rpc: string;
  blockNumber: number;
  fetchedAtMs: number;
  /** 0x + 40 hex, lowercase: the DstackApp contract = dstack app_id. */
  appId: string;
  appRegistered: boolean;
  /** 64 hex, lowercase, no 0x. */
  composeHash: string;
  composeHashAllowed: boolean;
  osImageHash: string;
  osImageAllowed: boolean;
}

const SELECTOR = {
  allowedComposeHashes: "0x2f6622e5", // allowedComposeHashes(bytes32)
  allowedOsImages: "0x9a4e1d18", // allowedOsImages(bytes32)
  registeredApps: "0xa6c4cce9" // registeredApps(address)
} as const;

const ADDRESS = /^0x[0-9a-f]{40}$/;
const HASH = /^[0-9a-f]{64}$/;

export function validOnchainAuthorization(value: unknown): value is DstackOnchainAuthorization {
  if (!value || typeof value !== "object") return false;
  const r = value as Partial<DstackOnchainAuthorization>;
  return r.v === 1 && typeof r.chainId === "number" && typeof r.kms === "string" && ADDRESS.test(r.kms)
    && typeof r.rpc === "string" && typeof r.blockNumber === "number" && typeof r.fetchedAtMs === "number"
    && typeof r.appId === "string" && ADDRESS.test(r.appId)
    && typeof r.appRegistered === "boolean"
    && typeof r.composeHash === "string" && HASH.test(r.composeHash) && typeof r.composeHashAllowed === "boolean"
    && typeof r.osImageHash === "string" && HASH.test(r.osImageHash) && typeof r.osImageAllowed === "boolean";
}

/** `authority_boot_onchain_authorized`: the provider's KMS registry lists this TD's app, compose and image. */
export function dstackOnchainCheck(input: {
  record: DstackOnchainAuthorization | undefined;
  kms: DstackKmsIdentity;
  maxAgeMs: number;
  /** From the replayed RTMR3 "app-id" event (40 hex, no 0x). */
  appId: string | null;
  /** From MRCONFIGID / the measured compose-hash event. */
  composeHash: string | null;
  /** From the replayed RTMR3 "os-image-hash" event. */
  osImageHash: string | null;
  now: number;
}): AttestationCheck {
  const name = "authority_boot_onchain_authorized";
  const { record, kms } = input;
  if (!input.appId || !input.composeHash || !input.osImageHash) {
    return check(name, false, true, "the replayed event log does not name the app, compose and image to look up");
  }
  if (!record || !validOnchainAuthorization(record)) {
    return check(name, false, true, `no on-chain authorization record from the provider's KMS ${kms.kms.slice(0, 10)}.. was supplied`);
  }
  if (record.chainId !== kms.chainId || record.kms !== kms.kms.toLowerCase()) {
    return check(name, false, true, "the on-chain record is from a different chain or KMS than the provider's");
  }
  const age = input.now - record.fetchedAtMs;
  if (!(age <= input.maxAgeMs && age >= -30_000)) {
    return check(name, false, true, "the on-chain authorization was not read recently enough to rule out a revocation");
  }
  if (record.appId !== `0x${input.appId.toLowerCase()}` || record.composeHash !== input.composeHash.toLowerCase()
    || record.osImageHash !== input.osImageHash.toLowerCase()) {
    return check(name, false, true, "the on-chain record describes a different app, compose or image than the TD measured");
  }
  const missing = [
    record.appRegistered ? null : `app ${record.appId} is not registered with the KMS`,
    record.composeHashAllowed ? null : `compose ${record.composeHash.slice(0, 16)}.. is not authorized by app ${record.appId}`,
    record.osImageAllowed ? null : `image ${record.osImageHash.slice(0, 16)}.. is not authorized by the KMS`
  ].filter((item): item is string => item !== null);
  if (missing.length > 0) return check(name, false, true, missing.join("; "));
  return check(name, true, true,
    `the provider's KMS ${record.kms.slice(0, 10)}.. on chain ${record.chainId} (block ${record.blockNumber}) registers app ${record.appId.slice(0, 10)}.., authorizes its compose ${record.composeHash.slice(0, 16)}.. and the image ${record.osImageHash.slice(0, 16)}..`);
}

export interface DstackOnchainFetcherOptions {
  kms: DstackKmsIdentity;
  /** Public JSON-RPC endpoints, tried in order. No key, ever. */
  rpcUrls: string[];
  fetch?: FetchLike;
  timeoutMs?: number;
  /** How long an all-allowed answer is reused before the registry is read again. */
  positiveTtlMs?: number;
  /** How long a not-allowed answer is reused (it fails anyway; a registration may land). */
  negativeTtlMs?: number;
  /** Oldest all-allowed answer served when every RPC endpoint fails (capped at AUTHORITY_MAX_STALE_MS). */
  maxStaleMs?: number;
  /** Most subjects held in the cache (default 1024). */
  maxCachedSubjects?: number;
  /**
   * Ask the KMS whether the app is registered BEFORE calling the app contract,
   * and call it only if it is. Off by default: a worker reads the three
   * booleans in parallel. The release-collateral role sets it, because there the
   * subject arrives from another process: without it, any address that process
   * names is called as a contract and handed the compose hash. An app the KMS
   * does not register authorizes nothing, so its compose is reported not
   * allowed without asking.
   */
  requireRegisteredApp?: boolean;
  budget?: RequestBudget;
  now?: () => number;
}

const MAX_RPC_BYTES = 64 * 1024;

type OnchainAnswer = Omit<DstackOnchainAuthorization, "fetchedAtMs">;

/**
 * Fetch layer: reads the three registry booleans with eth_call at one block.
 *
 * Keyed by the FULL subject (app, compose hash, image hash): an answer about
 * one compose is never an answer about another. A revocation has to stop
 * passing within the verifier's maxPublicationAgeMs, so an all-allowed answer
 * is re-read every 10 minutes and, when every endpoint fails, served for at
 * most AUTHORITY_MAX_STALE_MS from when it was read.
 */
export class DstackOnchainFetcher {
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;
  private readonly budget: RequestBudget;
  private readonly now: () => number;
  private readonly cache: AuthorityCache<OnchainAnswer>;

  constructor(private readonly options: DstackOnchainFetcherOptions) {
    if (!ADDRESS.test(options.kms.kms.toLowerCase())) throw new Error("kms must be an address");
    if (options.rpcUrls.length === 0 || options.rpcUrls.some((url) => !url.startsWith("https://"))) {
      throw new Error("rpcUrls must be https");
    }
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.budget = options.budget ?? DEFAULT_AUTHORITY_BUDGET;
    this.now = options.now ?? Date.now;
    const positiveTtlMs = options.positiveTtlMs ?? 10 * 60_000;
    const negativeTtlMs = options.negativeTtlMs ?? 60_000;
    this.cache = new AuthorityCache<OnchainAnswer>({
      freshMs: (answer) => (answer.appRegistered && answer.composeHashAllowed && answer.osImageAllowed ? positiveTtlMs : negativeTtlMs),
      maxStaleMs: options.maxStaleMs ?? AUTHORITY_MAX_STALE_MS
    }, { maxEntries: options.maxCachedSubjects ?? 1024, now: this.now });
  }

  async authorize(subject: { appId: string; composeHash: string; osImageHash: string }, signal?: AbortSignal): Promise<DstackOnchainAuthorization> {
    const appId = `0x${subject.appId.toLowerCase().replace(/^0x/, "")}`;
    const composeHash = subject.composeHash.toLowerCase();
    const osImageHash = subject.osImageHash.toLowerCase();
    if (!ADDRESS.test(appId) || !HASH.test(composeHash) || !HASH.test(osImageHash)) throw new Error("onchain_subject_malformed");
    const { value, fetchedAtMs } = await this.cache.get(`${appId}:${composeHash}:${osImageHash}`, async () => {
      let lastError: unknown = null;
      for (const rpc of this.options.rpcUrls) {
        try {
          const chainId = Number.parseInt(await this.rpc(rpc, "eth_chainId", []), 16);
          if (chainId !== this.options.kms.chainId) throw new Error("onchain_wrong_chain");
          const blockHex = await this.rpc(rpc, "eth_blockNumber", []);
          const kms = this.options.kms.kms.toLowerCase();
          const word = (hex: string) => hex.replace(/^0x/, "").padStart(64, "0");
          const truthy = (result: string) => /^0x0*1$/.test(result);
          let registered: string;
          let compose: string;
          let image: string;
          if (this.options.requireRegisteredApp) {
            // Both KMS answers first, at the same block as everything else.
            [registered, image] = await Promise.all([
              this.rpc(rpc, "eth_call", [{ to: kms, data: SELECTOR.registeredApps + word(appId) }, blockHex]),
              this.rpc(rpc, "eth_call", [{ to: kms, data: SELECTOR.allowedOsImages + osImageHash }, blockHex])
            ]);
            compose = truthy(registered)
              ? await this.rpc(rpc, "eth_call", [{ to: appId, data: SELECTOR.allowedComposeHashes + composeHash }, blockHex])
              : "0x0";
          } else {
            [registered, compose, image] = await Promise.all([
              this.rpc(rpc, "eth_call", [{ to: kms, data: SELECTOR.registeredApps + word(appId) }, blockHex]),
              this.rpc(rpc, "eth_call", [{ to: appId, data: SELECTOR.allowedComposeHashes + composeHash }, blockHex]),
              this.rpc(rpc, "eth_call", [{ to: kms, data: SELECTOR.allowedOsImages + osImageHash }, blockHex])
            ]);
          }
          return {
            value: {
              v: 1 as const,
              chainId,
              kms,
              rpc,
              blockNumber: Number.parseInt(blockHex, 16),
              appId,
              appRegistered: truthy(registered),
              composeHash,
              composeHashAllowed: truthy(compose),
              osImageHash,
              osImageAllowed: truthy(image)
            }
          };
        } catch (error) {
          lastError = error;
        }
      }
      throw lastError instanceof Error ? lastError : new Error("onchain_unavailable");
    }, signal);
    return { ...value, fetchedAtMs };
  }

  private async rpc(url: string, method: string, params: unknown[]): Promise<string> {
    const answer = await authorityFetch({
      url,
      method: "POST",
      accept: "application/json",
      contentType: "application/json",
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      maxBytes: MAX_RPC_BYTES,
      timeoutMs: this.timeoutMs,
      fetch: this.fetchImpl,
      budget: this.budget,
      now: this.now
    });
    if (answer.status !== 200) throw new Error(`onchain_rpc_${answer.status}`);
    const body = JSON.parse(new TextDecoder().decode(answer.body)) as { result?: unknown };
    if (typeof body.result !== "string" || !/^0x[0-9a-f]*$/i.test(body.result)) throw new Error("onchain_rpc_error");
    return body.result.toLowerCase();
  }
}
