// Everything the release-collateral role's fetchers reach, as one in-process stub:
// GitHub's ref advertisement, compare API, raw files and release listing, and
// a Base JSON-RPC node. It records every request it is sent, so "what left the
// release-collateral role" is read off one list, and "nothing left" is that list being
// empty.
//
// Nothing here opens a socket.

import { NEAR_DSTACK_KMS } from "../../src/providers/attestation/authority/near.js";

export const FILES_REPOSITORY = "nearai/cvm-compose-files";
export const RELEASES_REPOSITORY = "nearai/compose-manager";
export const KMS_ADDRESS = NEAR_DSTACK_KMS.kms;
export const BASE_RPC_HOSTS = ["mainnet.base.org", "base-rpc.publicnode.com"] as const;
export const GITHUB_HOSTS = ["github.com", "api.github.com", "raw.githubusercontent.com"] as const;

/** What a failing host answers with. Recognisable, so a test can assert nobody repeats it. */
export const UPSTREAM_ERROR_WORDS = "UPSTREAM-SAID-THIS-503";

const SELECTOR = {
  allowedComposeHashes: "0x2f6622e5",
  allowedOsImages: "0x9a4e1d18",
  registeredApps: "0xa6c4cce9"
} as const;

export interface UpstreamRequest {
  url: string;
  host: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
  /** The parsed JSON-RPC call, for a request to a Base node. */
  rpc?: { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown };
}

/** A git smart-HTTP ref advertisement for `head` on main plus lightweight tags. */
export function refAdvertisement(head: string, tags: Record<string, string> = {}): string {
  const pkt = (line: string) => (line.length + 4).toString(16).padStart(4, "0") + line;
  return pkt("# service=git-upload-pack\n") + "0000"
    + pkt(`${head} HEAD\0symref=HEAD:refs/heads/main\n`) + pkt(`${head} refs/heads/main\n`)
    + Object.entries(tags).map(([tag, commit]) => pkt(`${commit} refs/tags/${tag}\n`)).join("") + "0000";
}

const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });

const word = (flag: boolean) => `0x${"0".repeat(63)}${flag ? "1" : "0"}`;

export class FakeUpstream {
  readonly requests: UpstreamRequest[] = [];

  // --- GitHub ---
  head = "a".repeat(40);
  /** tag -> the commit it peels to. */
  tags: Record<string, string> = {};
  /** Commits the compare API reports as ancestors of `head`. */
  ancestors = new Set<string>();
  /** `<commit>/<path>` -> the bytes served. Anything else is a 404. */
  files = new Map<string, string>();
  releases: unknown[] = [{
    tag_name: "prod-20260702-8e07c35",
    draft: false,
    prerelease: false,
    author: { login: "github-actions[bot]" },
    body: `### compose-manager\n- **Digest**: \`sha256:${"6e".repeat(32)}\`\n\n### compose-manager-launcher\n- **Digest**: \`sha256:${"91".repeat(32)}\`\n`
  }];

  // --- Base ---
  chainId = "0x2105";
  blockNumber = "0x1f4a";
  /** `0x` + 40 hex, lowercase. */
  registeredApps = new Set<string>();
  /** app address -> the compose hashes it allows. */
  allowedCompose = new Map<string, Set<string>>();
  allowedImages = new Set<string>();

  /** Hosts that answer 503. */
  failing = new Set<string>();
  /** While set, no response is sent until it resolves. */
  hold: Promise<void> | null = null;

  private readonly arrivals: Array<{ count: number; resolve: () => void }> = [];

  reset(): void {
    this.requests.length = 0;
  }

  /**
   * Resolves once `count` requests have ARRIVED (been recorded), whether or
   * not they have been answered. This is how a test waits for a lookup to be
   * in flight: on the event itself, never on a duration.
   */
  whenRequests(count: number): Promise<void> {
    if (this.requests.length >= count) return Promise.resolve();
    return new Promise<void>((resolve) => {
      this.arrivals.push({ count, resolve });
    });
  }

  /** Hold every response from now on. Returns the function that lets them go. */
  holdResponses(): () => void {
    let release!: () => void;
    this.hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    return () => {
      this.hold = null;
      release();
    };
  }

  to(...hosts: readonly string[]): UpstreamRequest[] {
    return this.requests.filter((request) => hosts.includes(request.host));
  }

  urls(): string[] {
    return this.requests.map((request) => request.url);
  }

  /** Everything any request carried, as one string, for "this never left" assertions. */
  wire(): string {
    return JSON.stringify(this.requests);
  }

  readonly fetch = async (input: string, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const parsed = new URL(url);
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, name) => {
      headers[name] = value;
    });
    const body = typeof init?.body === "string" ? init.body : null;
    const request: UpstreamRequest = { url, host: parsed.host, method: init?.method ?? "GET", headers, body };
    if (body && (BASE_RPC_HOSTS as readonly string[]).includes(parsed.host)) {
      try {
        request.rpc = JSON.parse(body) as UpstreamRequest["rpc"];
      } catch {
        // Recorded as sent; answered as an error below.
      }
    }
    this.requests.push(request);
    for (const waiter of this.arrivals.splice(0)) {
      if (this.requests.length >= waiter.count) waiter.resolve();
      else this.arrivals.push(waiter);
    }
    if (this.hold) {
      const signal = init?.signal;
      await new Promise<void>((resolve, reject) => {
        signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
        void this.hold!.then(resolve);
      });
    }
    if (this.failing.has(parsed.host)) return new Response(UPSTREAM_ERROR_WORDS, { status: 503 });
    return this.answer(parsed, request);
  };

  private answer(url: URL, request: UpstreamRequest): Response {
    if (url.host === "github.com" && url.pathname === `/${FILES_REPOSITORY}.git/info/refs`) {
      return new Response(refAdvertisement(this.head, this.tags), { status: 200 });
    }
    if (url.host === "api.github.com" && url.pathname === `/repos/${RELEASES_REPOSITORY}/releases`) {
      return json(this.releases);
    }
    const compare = url.host === "api.github.com"
      ? new RegExp(`^/repos/${FILES_REPOSITORY}/compare/([0-9a-f]{40})\\.\\.\\.([0-9a-f]{40})$`).exec(url.pathname)
      : null;
    if (compare) {
      const [, base, commit] = compare;
      const ancestor = base === this.head && this.ancestors.has(commit!);
      return json(ancestor
        ? { status: "behind", merge_base_commit: { sha: commit } }
        : { status: "diverged", merge_base_commit: { sha: base } });
    }
    if (url.host === "raw.githubusercontent.com" && url.pathname.startsWith(`/${FILES_REPOSITORY}/`)) {
      const bytes = this.files.get(url.pathname.slice(`/${FILES_REPOSITORY}/`.length));
      return bytes === undefined ? new Response("", { status: 404 }) : new Response(bytes, { status: 200 });
    }
    if ((BASE_RPC_HOSTS as readonly string[]).includes(url.host) && request.rpc) return this.rpc(request.rpc);
    return new Response("", { status: 404 });
  }

  private rpc(call: NonNullable<UpstreamRequest["rpc"]>): Response {
    const reply = (result: string) => json({ jsonrpc: "2.0", id: call.id, result });
    if (call.method === "eth_chainId") return reply(this.chainId);
    if (call.method === "eth_blockNumber") return reply(this.blockNumber);
    if (call.method === "eth_call") {
      const [target] = call.params as [{ to: string; data: string }, string];
      const selector = target.data.slice(0, 10);
      const argument = target.data.slice(10);
      if (target.to === KMS_ADDRESS && selector === SELECTOR.registeredApps) {
        return reply(word(this.registeredApps.has(`0x${argument.slice(24)}`)));
      }
      if (target.to === KMS_ADDRESS && selector === SELECTOR.allowedOsImages) {
        return reply(word(this.allowedImages.has(argument)));
      }
      if (selector === SELECTOR.allowedComposeHashes) {
        return reply(word(this.allowedCompose.get(target.to)?.has(argument) ?? false));
      }
    }
    return json({ jsonrpc: "2.0", id: call.id, error: { code: -32601, message: "unsupported" } });
  }
}

/** A stand-in for the whole upstream that fails the test if it is ever called. */
export function unreachableUpstream(calls: string[]): (input: string) => Promise<Response> {
  return async (input: string) => {
    calls.push(String(input));
    throw new Error("an upstream request was attempted");
  };
}
