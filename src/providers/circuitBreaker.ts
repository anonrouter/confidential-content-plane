import { ProviderError } from "../security/errors.js";

export interface CircuitBreakerOptions {
  consecutiveFailureThreshold?: number;
  burstFailureThreshold?: number;
  burstWindowMs?: number;
  openDurationMs?: number;
  now?: () => number;
}

export interface CircuitPermit {
  readonly halfOpenProbe: boolean;
  readonly generation: number;
}

export type VeniceCircuitOperation = "attestation" | "chat" | "stream" | "embeddings" | "image" | "speech";
export type OperationalFailureScope = "network" | "scope";

type CircuitState = "closed" | "open" | "half_open";

/**
 * Small, process-local breaker for one credential-bearing provider worker.
 * It stores only counters and timestamps; request/response content never enters
 * this object.
 */
export class OperationalCircuitBreaker {
  private readonly consecutiveFailureThreshold: number;
  private readonly burstFailureThreshold: number;
  private readonly burstWindowMs: number;
  private readonly openDurationMs: number;
  private readonly now: () => number;
  private state: CircuitState = "closed";
  private consecutiveFailures = 0;
  private recentFailures: number[] = [];
  private openedAt = 0;
  private generation = 0;
  private readonly settledPermits = new WeakSet<object>();

  constructor(options: CircuitBreakerOptions = {}) {
    this.consecutiveFailureThreshold = options.consecutiveFailureThreshold ?? 5;
    this.burstFailureThreshold = options.burstFailureThreshold ?? 10;
    this.burstWindowMs = options.burstWindowMs ?? 30_000;
    this.openDurationMs = options.openDurationMs ?? 15_000;
    this.now = options.now ?? Date.now;
  }

  acquire(): CircuitPermit {
    const now = this.now();
    if (this.state === "open" && now - this.openedAt >= this.openDurationMs) {
      this.state = "half_open";
      return { halfOpenProbe: true, generation: this.generation };
    }
    if (this.state !== "closed") {
      throw new ProviderError("provider_unavailable", "Provider is temporarily unavailable", 503);
    }
    return { halfOpenProbe: false, generation: this.generation };
  }

  recordSuccess(permit: CircuitPermit): void {
    if (!this.settle(permit)) return;
    if (permit.generation !== this.generation) return;
    const recoveredHalfOpenProbe = permit.halfOpenProbe || this.state === "half_open";
    this.state = "closed";
    this.consecutiveFailures = 0;
    // A normal success breaks a consecutive run but must not erase the separate
    // burst window ("N failures in 30s"). A successful half-open recovery starts
    // a genuinely fresh circuit generation and may clear the old outage burst.
    this.recentFailures = recoveredHalfOpenProbe
      ? []
      : this.recentFailures.filter((at) => this.now() - at <= this.burstWindowMs);
    this.openedAt = 0;
  }

  recordOperationalFailure(permit: CircuitPermit): void {
    if (!this.settle(permit)) return;
    if (permit.generation !== this.generation) return;
    const now = this.now();
    if (permit.halfOpenProbe || this.state === "half_open") {
      this.open(now);
      return;
    }
    this.consecutiveFailures += 1;
    this.recentFailures = this.recentFailures.filter((at) => now - at <= this.burstWindowMs);
    this.recentFailures.push(now);
    if (
      this.consecutiveFailures >= this.consecutiveFailureThreshold
      || this.recentFailures.length >= this.burstFailureThreshold
    ) {
      this.open(now);
    }
  }

  /**
   * A caller cancellation is neither provider health nor provider failure. If
   * it cancels the sole half-open probe, make another probe immediately eligible
   * instead of holding the breaker half-open forever.
   */
  recordNeutral(permit: CircuitPermit): void {
    if (!this.settle(permit)) return;
    if (permit.generation !== this.generation) return;
    if (permit.halfOpenProbe && this.state === "half_open") {
      this.state = "open";
      this.openedAt = this.now() - this.openDurationMs;
    }
  }

  snapshot(): { state: CircuitState; consecutiveFailures: number; recentFailures: number } {
    const now = this.now();
    return {
      state: this.state,
      consecutiveFailures: this.consecutiveFailures,
      recentFailures: this.recentFailures.filter((at) => now - at <= this.burstWindowMs).length
    };
  }

  private open(now: number): void {
    this.state = "open";
    this.openedAt = now;
    this.generation += 1;
  }

  private settle(permit: CircuitPermit): boolean {
    if (this.settledPermits.has(permit)) return false;
    this.settledPermits.add(permit);
    return true;
  }
}

/**
 * Classify failures without inspecting provider payloads. HTTP/provider-shape
 * failures are isolated to one operation + catalog model. Transport failures
 * indicate that the credential worker cannot reliably reach Venice and feed a
 * separate provider-wide network circuit.
 *
 * Caller cancellation is intentionally handled by the adapter before calling
 * this function. An otherwise unexplained AbortError while reading a provider
 * body is therefore a transport failure (including an internal deadline).
 */
export function operationalFailureScope(error: unknown): OperationalFailureScope | undefined {
  if (error instanceof ProviderError) {
    const status = error.providerStatusCode;
    if (error.code === "provider_timeout") return "network";
    if (
      error.code === "provider_invalid_json"
      || error.code === "provider_no_stream"
      || error.code === "provider_stream_incomplete"
      || status === 429
      || (typeof status === "number" && status >= 500)
    ) {
      return "scope";
    }
    return undefined;
  }
  if (error instanceof DOMException) {
    return error.name === "AbortError" || error.name === "NetworkError" || error.name === "TimeoutError"
      ? "network"
      : undefined;
  }
  if (error instanceof TypeError) {
    const causeCode = (error as TypeError & { cause?: { code?: unknown } }).cause?.code;
    return error.message === "fetch failed" || error.message === "terminated" || typeof causeCode === "string"
      ? "network"
      : undefined;
  }
  return undefined;
}

export function isOperationalProviderFailure(error: unknown): boolean {
  return operationalFailureScope(error) !== undefined;
}

export interface VeniceCircuitBreakerRegistryOptions {
  networkOptions?: CircuitBreakerOptions;
  scopedOptions?: CircuitBreakerOptions;
  maxScopedBreakers?: number;
}

/**
 * Bounded process-local Venice circuit registry.
 *
 * The only scope key is operation + provider catalog model ID. No account,
 * address, prompt, response, request ID, or other user-controlled payload is
 * retained. The LRU cap prevents a changing catalog from growing memory without
 * bound; eviction merely forgets old breaker history and never merges models.
 */
export class VeniceCircuitBreakerRegistry {
  readonly network: OperationalCircuitBreaker;
  private readonly scopedOptions: CircuitBreakerOptions;
  private readonly maxScopedBreakers: number;
  private readonly scopedBreakers = new Map<string, OperationalCircuitBreaker>();

  constructor(options: VeniceCircuitBreakerRegistryOptions = {}) {
    this.network = new OperationalCircuitBreaker(options.networkOptions);
    this.scopedOptions = options.scopedOptions ?? {};
    this.maxScopedBreakers = Math.max(1, Math.min(4_096, options.maxScopedBreakers ?? 512));
  }

  scoped(operation: VeniceCircuitOperation, externalModelId: string): OperationalCircuitBreaker {
    const key = `${operation}\u0000${externalModelId.slice(0, 256)}`;
    const existing = this.scopedBreakers.get(key);
    if (existing) {
      // Refresh insertion order so the oldest unused catalog scope is evicted.
      this.scopedBreakers.delete(key);
      this.scopedBreakers.set(key, existing);
      return existing;
    }

    if (this.scopedBreakers.size >= this.maxScopedBreakers) {
      const oldest = this.scopedBreakers.keys().next().value as string | undefined;
      if (oldest !== undefined) this.scopedBreakers.delete(oldest);
    }
    const breaker = new OperationalCircuitBreaker(this.scopedOptions);
    this.scopedBreakers.set(key, breaker);
    return breaker;
  }

  get scopedSize(): number {
    return this.scopedBreakers.size;
  }
}
