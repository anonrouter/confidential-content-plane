import { defaultProvider } from "@aws-sdk/credential-provider-node";
import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from "@smithy/types";
import { Hash } from "@smithy/hash-node";
import { HttpRequest } from "@smithy/protocol-http";
import { SignatureV4 } from "@smithy/signature-v4";

export type MantleFetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface BedrockMantleClientOptions {
  baseUrl: string;
  region: string;
  profile?: string;
  credentials?: AwsCredentialIdentity | AwsCredentialIdentityProvider;
  fetchImpl?: MantleFetch;
}

/** SigV4 transport for Bedrock Mantle's OpenAI-compatible `/v1` API. */
export class BedrockMantleClient {
  private readonly baseUrl: string;
  private readonly signer: SignatureV4;
  private readonly fetchImpl: MantleFetch;

  constructor(options: BedrockMantleClientOptions) {
    // Tolerate an unset base URL at construction (like the Fireworks/DeepInfra
    // adapters, which store the URL and only dereference it at request time).
    // The registry builds this adapter unconditionally; a request against an
    // empty base URL fails at fetch time, not when a partial config is loaded.
    this.baseUrl = (options.baseUrl ?? "").replace(/\/$/, "");
    const credentials = options.credentials ?? defaultProvider(
      options.profile ? { profile: options.profile } : {}
    );
    this.signer = new SignatureV4({
      credentials,
      region: options.region,
      service: "bedrock-mantle",
      sha256: Hash.bind(null, "sha256")
    });
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async request(path: string, init: RequestInit = {}, signal?: AbortSignal): Promise<Response> {
    const url = new URL(path.replace(/^\//, ""), `${this.baseUrl}/`);
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((value, key) => { headers[key] = value; });
    const body = typeof init.body === "string" || init.body instanceof Uint8Array
      ? init.body
      : undefined;
    const query = Object.fromEntries(url.searchParams.entries());
    const signed = await this.signer.sign(new HttpRequest({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port ? Number(url.port) : undefined,
      method: init.method ?? "GET",
      path: url.pathname,
      query,
      headers: { host: url.host, ...headers },
      body
    }));
    return this.fetchImpl(url, {
      ...init,
      headers: signed.headers,
      body,
      signal
    });
  }
}
