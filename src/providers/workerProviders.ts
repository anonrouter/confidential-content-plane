// Which provider a worker process acts for, and which metadata token it
// presents to control when it does.
//
// Several pieces of worker code used to answer both questions by re-deriving
// one provider from the runtime role, each with its own copy of the mapping.
// That is only correct while exactly one provider lives in a process. This file
// is the single copy, and everything that acts for a provider takes that
// provider's name from here instead of reading the role again.
//
// NO IMPORTS from the rest of the app. src/config.ts imports this file, and
// nearly everything else imports src/config.ts.

/** Runtime role -> canonical provider name (the DB, registry and RPC-path key). */
export const WORKER_PROVIDER_BY_ROLE = {
  "venice-worker": "venice",
  "fireworks-worker": "fireworks",
  "bedrock-worker": "aws-bedrock",
  "deepinfra-worker": "deepinfra",
  "chutes-worker": "chutes",
  "tinfoil-worker": "tinfoil",
  "near-worker": "near-ai",
  "phala-ai-worker": "phala-ai"
} as const;

export type WorkerRole = keyof typeof WORKER_PROVIDER_BY_ROLE;
export type WorkerProviderName = (typeof WORKER_PROVIDER_BY_ROLE)[WorkerRole];

/** The provider a runtime role serves, or null when the role is not a provider worker. */
export function workerProviderForRole(role: string | undefined): WorkerProviderName | null {
  return role !== undefined && Object.hasOwn(WORKER_PROVIDER_BY_ROLE, role)
    ? WORKER_PROVIDER_BY_ROLE[role as WorkerRole]
    : null;
}

/**
 * The one role that serves SEVERAL providers from one process
 * (PROVIDER_POOL_PLAN.md, W1b). It is deliberately absent from
 * WORKER_PROVIDER_BY_ROLE: it has no provider of its own, so nothing can ask
 * "which provider is this role" and get an answer that is true of only one of
 * them. Its providers are the configured POOL_PROVIDERS list.
 */
export const POOL_WORKER_ROLE = "pool-worker";

export function isPoolWorkerRole(role: string | undefined): boolean {
  return role === POOL_WORKER_ROLE;
}

/**
 * The providers a pool may serve: the bearer-key providers. Bedrock is absent
 * on purpose. It signs with SigV4 under a workload identity, not a bearer the
 * provider transport can bind to an origin, and it stays in its own worker.
 */
export const POOLABLE_PROVIDERS = [
  "venice",
  "fireworks",
  "deepinfra",
  "tinfoil",
  "near-ai",
  "phala-ai",
  "chutes"
] as const satisfies readonly WorkerProviderName[];

export type PoolProviderName = (typeof POOLABLE_PROVIDERS)[number];

export function isPoolableProvider(provider: string): provider is PoolProviderName {
  return (POOLABLE_PROVIDERS as readonly string[]).includes(provider);
}

/**
 * Parse POOL_PROVIDERS: a comma-separated list of canonical provider names.
 *
 * Refused, never repaired: an empty list, an empty entry (a doubled or trailing
 * comma), a repeated provider, Bedrock, and anything that is not a poolable
 * provider. A public slug such as `near` is not a canonical name and is refused
 * like any other unknown entry. A list that was quietly tidied up would serve a
 * different set of providers from the one the measured compose names.
 *
 * An entry that is not a known provider name is identified by its position and
 * never echoed: it is operator input, and this message is logged.
 */
export function parsePoolProviders(raw: string | undefined): PoolProviderName[] {
  if (raw === undefined || raw.trim() === "") {
    throw new Error(`POOL_PROVIDERS is required for RUNTIME_ROLE=${POOL_WORKER_ROLE}`);
  }
  const providers: PoolProviderName[] = [];
  for (const [index, entry] of raw.split(",").entries()) {
    const name = entry.trim();
    const position = index + 1;
    if (name === "") throw new Error(`POOL_PROVIDERS entry ${position} is empty`);
    if (name === "aws-bedrock") {
      throw new Error("POOL_PROVIDERS must not list aws-bedrock: Bedrock holds no bearer key and stays in its own worker");
    }
    if (!isPoolableProvider(name)) {
      throw new Error(`POOL_PROVIDERS entry ${position} is not a poolable provider (allowed: ${POOLABLE_PROVIDERS.join(", ")})`);
    }
    if (providers.includes(name)) throw new Error(`POOL_PROVIDERS lists ${name} more than once`);
    providers.push(name);
  }
  return providers;
}

/**
 * The providers a worker server built under this role serves.
 *
 * A single-provider role serves its own provider. A role that is not a provider
 * worker gets Venice: the worker routes have always defaulted that way, and dev
 * and test harnesses that register them without a worker role rely on it.
 *
 * The pool role is the exception to that default, and must be. It serves the
 * configured list and nothing else, and with no list it throws: answering
 * Venice there would start a pool that looks healthy and serves one provider.
 */
export function workerProvidersForRole(
  role: string | undefined,
  poolProviders: readonly WorkerProviderName[] = []
): WorkerProviderName[] {
  if (isPoolWorkerRole(role)) {
    if (poolProviders.length === 0) {
      throw new Error(`${POOL_WORKER_ROLE} has no configured provider list (POOL_PROVIDERS)`);
    }
    return [...poolProviders];
  }
  return [workerProviderForRole(role) ?? "venice"];
}

// Each provider's consumed-capability (replay) log keeps the filename its own
// worker writes today, which is keyed by the COMPOSE service key and not the
// canonical name: NEAR's is `consumed-near.json`. The pool must read and write
// these exact files, because a missing replay log reads as "nothing consumed
// yet": a pool-only filename would re-open an unexpired capability on the way
// in, and hide the pool's records from the per-provider workers on rollback.
const CONSUMED_CAPABILITY_FILE_KEY: Readonly<Record<PoolProviderName, string>> = {
  venice: "venice",
  fireworks: "fireworks",
  deepinfra: "deepinfra",
  tinfoil: "tinfoil",
  "near-ai": "near",
  "phala-ai": "phala-ai",
  chutes: "chutes"
};

/** The replay-log filename of a pooled provider, identical to its own worker's. */
export function consumedCapabilityFileName(provider: PoolProviderName): string {
  return `consumed-${CONSUMED_CAPABILITY_FILE_KEY[provider]}.json`;
}

/** The configured metadata tokens a worker's selection is made from. */
export interface WorkerMetadataTokenSources {
  /** The runtime role. Present on the loaded config; decides the pool rule below. */
  readonly role?: string;
  /** METADATA_RPC_DEPLOYMENT_TOKEN: bound by control to one (deployment, provider). */
  readonly deploymentMetadataToken: string;
  /** METADATA_RPC_TOKEN_<PROVIDER>, keyed by canonical provider name (AR-02). */
  readonly providerMetadataTokens: Readonly<Record<string, string>>;
  /** METADATA_RPC_TOKEN: the shared token of single-token deployments. */
  readonly metadataRpcToken: string;
}

/**
 * The metadata token a worker presents to control when it acts for `provider`:
 * the deployment token, else that provider's own token, else the shared token.
 *
 * Every worker-to-control metadata call selects its token here, by the provider
 * it is made for: the catalog push, the health push, the dispatch and
 * attestation fences, and the credential-outcome report. Control binds a
 * provider token to that provider (AR-02), so presenting another provider's
 * token is refused there; selecting by provider here is what keeps a process
 * from doing so by construction.
 *
 * `provider` is null for a role that serves no provider, which leaves the
 * deployment and shared tokens.
 *
 * THE POOL HAS NO FALLBACK AND NO OVERRIDE. A deployment token would be
 * presented for every pooled provider and a shared token for any provider whose
 * own was missing, and either way one provider's calls would go out under an
 * authority that is not that provider's. So under the pool role the answer is
 * the named provider's own token or a thrown error, whatever else is
 * configured and in every environment.
 */
export function workerMetadataTokenFor(sources: WorkerMetadataTokenSources, provider: string | null): string {
  if (isPoolWorkerRole(sources.role)) {
    const own = provider !== null && Object.hasOwn(sources.providerMetadataTokens, provider)
      ? sources.providerMetadataTokens[provider]
      : undefined;
    if (!own) throw new Error(`${POOL_WORKER_ROLE} has no metadata token for provider ${provider ?? "(none)"}`);
    return own;
  }
  return sources.deploymentMetadataToken
    || (provider ? sources.providerMetadataTokens[provider] : undefined)
    || sources.metadataRpcToken;
}
