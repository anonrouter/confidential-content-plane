import { randomUUID } from "node:crypto";
import { Redis } from "ioredis";
import { assertDisposableTestRedisUrl } from "../db/localSafety.js";
import type { AppConfig } from "../config.js";
import { VALKEY_LUA_WRITE_CAPACITY_FUNCTION } from "../observability/valkey.js";
import { AppError } from "../security/errors.js";
import type { UsagePlan } from "./plans.js";

/**
 * Lua writes are not guaranteed to receive Valkey's normal `denyoom` command
 * rejection. Every protection-state script therefore checks aggregate memory
 * itself and stops allocating at 98% of maxmemory. Release/delete scripts are
 * deliberately exempt so recovery can always make progress.
 */
const bucketScript = `${VALKEY_LUA_WRITE_CAPACITY_FUNCTION}
if not valkey_has_write_capacity() then
  return { -1, '0', 0 }
end

local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_ms = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl_ms = tonumber(ARGV[5])

local data = redis.call('HMGET', key, 'tokens', 'updated_at')
local tokens = tonumber(data[1])
local updated_at = tonumber(data[2])

if tokens == nil then
  tokens = capacity
  updated_at = now_ms
end

local elapsed = math.max(0, now_ms - updated_at)
tokens = math.min(capacity, tokens + (elapsed * refill_per_ms))

local allowed = 0
local retry_after_ms = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry_after_ms = math.ceil((cost - tokens) / refill_per_ms)
end

redis.call('HMSET', key, 'tokens', tokens, 'updated_at', now_ms)
redis.call('PEXPIRE', key, ttl_ms)

return { allowed, tostring(tokens), retry_after_ms }
`;

/**
 * Evaluate a hierarchy of token buckets as one admission decision.
 *
 * No bucket is written unless every bucket can pay the request cost. This is
 * important for attacker-controlled dimensions such as addresses and login
 * subjects: once a bounded service-wide bucket is full, rotating those values
 * cannot continue minting long-lived Valkey keys. It also prevents a single
 * exhausted narrow bucket from draining the broader service allowance.
 *
 * This intentionally targets the single-node Valkey topology used by the MVP;
 * a future Redis Cluster deployment would need hash-tagged/co-located keys.
 */
const multiBucketScript = `${VALKEY_LUA_WRITE_CAPACITY_FUNCTION}
-- atomic_multi_bucket
if not valkey_has_write_capacity() then
  return { -1, '0', 0 }
end

local now_ms = tonumber(ARGV[1])
local states = {}
local rejected = 0
local retry_after_ms = 0

for i, key in ipairs(KEYS) do
  local offset = 2 + ((i - 1) * 4)
  local capacity = tonumber(ARGV[offset])
  local refill_per_ms = tonumber(ARGV[offset + 1])
  local cost = tonumber(ARGV[offset + 2])
  local ttl_ms = tonumber(ARGV[offset + 3])

  local data = redis.call('HMGET', key, 'tokens', 'updated_at')
  local tokens = tonumber(data[1])
  local updated_at = tonumber(data[2])
  if tokens == nil then
    tokens = capacity
    updated_at = now_ms
  end

  local elapsed = math.max(0, now_ms - updated_at)
  tokens = math.min(capacity, tokens + (elapsed * refill_per_ms))
  states[i] = { tokens, capacity, cost, ttl_ms }

  if tokens < cost then
    rejected = 1
    local retry = ttl_ms
    if refill_per_ms > 0 then
      retry = math.ceil((cost - tokens) / refill_per_ms)
    end
    retry_after_ms = math.max(retry_after_ms, retry)
  end
end

-- A rejection is deliberately read-only. Do not create or refresh any of the
-- high-cardinality keys for a request that cannot pass the full hierarchy.
if rejected == 1 then
  return { 0, '0', retry_after_ms }
end

local minimum_remaining = nil
local remaining_by_bucket = {}
for i, key in ipairs(KEYS) do
  local state = states[i]
  local tokens = state[1] - state[3]
  redis.call('HMSET', key, 'tokens', tokens, 'updated_at', now_ms)
  redis.call('PEXPIRE', key, state[4])
  local whole_tokens = math.floor(tokens)
  if minimum_remaining == nil or whole_tokens < minimum_remaining then
    minimum_remaining = whole_tokens
  end
  remaining_by_bucket[i] = whole_tokens
end

local response = { 1, tostring(minimum_remaining or 0), 0 }
for i = 1, #KEYS do
  table.insert(response, tostring(remaining_by_bucket[i]))
end
return response
`;

const concurrencyAcquireScript = `${VALKEY_LUA_WRITE_CAPACITY_FUNCTION}
-- concurrency_acquire
if not valkey_has_write_capacity() then
  return -1
end

local key = KEYS[1]
local lease_id = ARGV[1]
local now_ms = tonumber(ARGV[2])
local expires_at_ms = tonumber(ARGV[3])
local limit = tonumber(ARGV[4])

local function expire_with_latest_lease()
  local latest = redis.call('ZREVRANGE', key, 0, 0, 'WITHSCORES')
  if #latest == 0 then
    redis.call('DEL', key)
    return
  end
  local ttl_ms = math.max(1, math.ceil(tonumber(latest[2]) - now_ms))
  redis.call('PEXPIRE', key, ttl_ms)
end

redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms)
local count = redis.call('ZCARD', key)
if count >= limit then
  expire_with_latest_lease()
  return 0
end

redis.call('ZADD', key, expires_at_ms, lease_id)
expire_with_latest_lease()
return 1
`;

const concurrencyReleaseScript = `
-- concurrency_release
local key = KEYS[1]
local lease_id = ARGV[1]
local now_ms = tonumber(ARGV[2])

redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms)
redis.call('ZREM', key, lease_id)
local latest = redis.call('ZREVRANGE', key, 0, 0, 'WITHSCORES')
if #latest == 0 then
  redis.call('DEL', key)
else
  local ttl_ms = math.max(1, math.ceil(tonumber(latest[2]) - now_ms))
  redis.call('PEXPIRE', key, ttl_ms)
end
return 1
`;

const freeTierConsumeScript = `${VALKEY_LUA_WRITE_CAPACITY_FUNCTION}
if not valkey_has_write_capacity() then
  return { -1, 0 }
end

local used = redis.call('INCRBY', KEYS[1], ARGV[1])
if used == tonumber(ARGV[1]) then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return { 1, used }
`;

export interface BucketOptions {
  key: string;
  capacity: number;
  refillPerMinute: number;
  cost?: number;
  ttlMs?: number;
}

export interface AbuseNetworkScopes {
  exact: string;
  subnet: string;
}

export interface RateLimitWindow {
  limit: number;
  remaining: number;
  resetMs: number;
}

export interface InferenceRateLimitResult {
  requests: RateLimitWindow;
  tokens: RateLimitWindow;
}

export class RateLimitExceededError extends AppError {
  readonly retryAfterSeconds: number;

  constructor(retryAfterMs: number) {
    super(429, "rate_limited", "Rate limit exceeded");
    this.retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
  }
}

// How long a subject's recent failed-credential count is retained. This feeds
// the audit trail only. We deliberately do NOT hard-lock an account on a failure
// count: a global per-subject lock is a targeted denial-of-service vector (an
// attacker who knows a victim's identifier could lock them out). Brute force is
// contained by the per-subject and per-IP login buckets plus the proof-of-work
// challenge instead.
const AUTH_FAILURE_WINDOW_SECONDS = 15 * 60;
// Fraction of a model's provider-side rate limit a single account may consume.
// This was 0.5, which throttled a single active user to half of Venice's real
// per-model rate (e.g. GLM-5.2 publishes 100 rpm / 2M tpm -> after the 0.8
// safety margin and this halving, an account got just 40 rpm / 800k tpm) and
// made coding-agent sessions hit the wall. At 1.0 an account may use the full
// provider allowance; the shared provider-level bucket and Venice's own 429s
// still bound the aggregate across accounts. Lower this if per-account fairness
// under heavy multi-tenant load becomes the priority over single-session speed.
const ACCOUNT_MODEL_UPSTREAM_SHARE = 1.0;

export class RateLimiter {
  private readonly redis: Redis;
  private readonly config: AppConfig;
  private veniceLimits = new Map<string, { rpm?: number; tpm?: number }>();
  private veniceLimitsExpiresAt = 0;
  private veniceLimitsObservedAt = 0;

  constructor(redis: Redis, config: AppConfig) {
    this.redis = redis;
    this.config = config;
  }

  async checkBucket(options: BucketOptions) {
    const cost = options.cost ?? 1;
    const refillPerMs = options.refillPerMinute / 60_000;
    const result = (await this.redis.eval(
      bucketScript,
      1,
      `rl:${options.key}`,
      options.capacity,
      refillPerMs,
      Date.now(),
      cost,
      options.ttlMs ?? 120_000
    )) as [number, string, number];

    if (Number(result[0]) === -1) {
      throw new AppError(503, "protection_state_unavailable", "Protection state is temporarily unavailable");
    }
    const remaining = Math.max(0, Math.floor(Number(result[1])));
    const retryAfterMs = Math.max(0, Number(result[2]));
    if (Number(result[0]) !== 1) throw new RateLimitExceededError(retryAfterMs);
    return {
      limit: options.capacity,
      remaining,
      resetMs: Math.ceil(((options.capacity - remaining) / options.refillPerMinute) * 60_000)
    } satisfies RateLimitWindow;
  }

  private async evaluateBuckets(options: BucketOptions[]) {
    if (options.length === 0) return [1, "0", 0] as [number, string, number, ...string[]];

    const result = (await this.redis.eval(
      multiBucketScript,
      options.length,
      ...options.map((option) => `rl:${option.key}`),
      Date.now(),
      ...options.flatMap((option) => [
        option.capacity,
        option.refillPerMinute / 60_000,
        option.cost ?? 1,
        option.ttlMs ?? 120_000
      ])
    )) as [number, string, number, ...string[]];

    if (Number(result[0]) === -1) {
      throw new AppError(503, "protection_state_unavailable", "Protection state is temporarily unavailable");
    }
    if (Number(result[0]) !== 1) {
      throw new RateLimitExceededError(Math.max(0, Number(result[2])));
    }
    return result;
  }

  private async checkBuckets(options: BucketOptions[]) {
    await this.evaluateBuckets(options);
  }

  private async checkBucketsWithWindows(options: BucketOptions[]) {
    const result = await this.evaluateBuckets(options);
    return options.map((option, index) => {
      const remaining = Math.max(0, Math.floor(Number(result[3 + index])));
      return {
        limit: option.capacity,
        remaining,
        resetMs: Math.ceil(((option.capacity - remaining) / option.refillPerMinute) * 60_000)
      } satisfies RateLimitWindow;
    });
  }

  async acquireConcurrency(key: string, limit: number, ttlSeconds = 120, absoluteMaxSeconds = 11 * 60) {
    const redisKey = `conc:${key}`;
    const leaseId = randomUUID();
    const absoluteDeadlineMs = Date.now() + Math.max(ttlSeconds, absoluteMaxSeconds) * 1_000;
    const acquired = Number(await this.redis.eval(
      concurrencyAcquireScript,
      1,
      redisKey,
      leaseId,
      Date.now(),
      absoluteDeadlineMs,
      limit
    ));
    if (acquired === -1) {
      throw new AppError(503, "protection_state_unavailable", "Protection state is temporarily unavailable");
    }
    if (acquired !== 1) {
      throw new AppError(429, "concurrency_limited", "Too many active generations");
    }

    let released = false;
    return async () => {
      if (released) {
        return;
      }
      released = true;
      await this.redis.eval(concurrencyReleaseScript, 1, redisKey, leaseId, Date.now());
    };
  }

  async checkProviderKillSwitch(providerName: string, modelId: string) {
    const [providerKilled, modelKilled] = await Promise.all([
      this.redis.get(`kill:provider:${providerName}`),
      this.redis.get(`kill:model:${providerName}:${modelId}`)
    ]);
    if (providerKilled === "1" || modelKilled === "1") {
      throw new AppError(503, "provider_unavailable", "Provider is temporarily unavailable");
    }
  }

  async providerKillSwitchEngaged(providerName: string) {
    return (await this.redis.get(`kill:provider:${providerName}`)) === "1";
  }

  async engageProviderKillSwitch(providerName: string) {
    // No expiry: only the audited restore workflow may reopen the provider.
    await this.redis.set(`kill:provider:${providerName}`, "1");
  }

  async releaseProviderKillSwitch(providerName: string) {
    await this.redis.del(`kill:provider:${providerName}`);
  }

  async consumeDailyFreeTokens(accountId: string, estimatedTokens: number) {
    if (this.config.billing.freeTierDailyTokens <= 0 || estimatedTokens <= 0) {
      return;
    }

    const day = new Date().toISOString().slice(0, 10);
    const key = `free:${day}:${accountId}`;
    const result = await this.redis.eval(
      freeTierConsumeScript,
      1,
      key,
      estimatedTokens,
      60 * 60 * 48
    ) as [number, number];
    if (Number(result[0]) !== 1) {
      throw new AppError(503, "protection_state_unavailable", "Protection state is temporarily unavailable");
    }
    const used = Number(result[1]);
    if (used > this.config.billing.freeTierDailyTokens) {
      throw new AppError(402, "free_tier_exhausted", "Free-tier token budget exhausted");
    }
  }

  private networkBuckets(params: {
    purpose: string;
    network: AbuseNetworkScopes;
    exact: { capacity: number; refillPerMinute: number };
    subnet: { capacity: number; refillPerMinute: number };
    global?: { capacity: number; refillPerMinute: number };
    ttlMs?: number;
  }) {
    const ttlMs = params.ttlMs ?? 60 * 60 * 1_000;
    const buckets: BucketOptions[] = [
      {
        key: `abuse:${params.purpose}:exact:${params.network.exact}`,
        ...params.exact,
        ttlMs
      },
      {
        key: `abuse:${params.purpose}:subnet:${params.network.subnet}`,
        ...params.subnet,
        ttlMs
      }
    ];
    if (params.global) {
      buckets.push({
        key: `abuse:${params.purpose}:global`,
        ...params.global,
        ttlMs
      });
    }
    return buckets;
  }

  private async limitNetwork(params: Parameters<RateLimiter["networkBuckets"]>[0]) {
    await this.checkBuckets(this.networkBuckets(params));
  }

  /** Cheap, pre-auth application flood guard. Endpoint-specific limits still apply. */
  async limitIngress(network: AbuseNetworkScopes, requestClass: "api" | "auth" | "webhook") {
    const limits = requestClass === "webhook"
      ? { exact: { capacity: 1_000, refillPerMinute: 1_000 }, subnet: { capacity: 5_000, refillPerMinute: 5_000 }, global: { capacity: 20_000, refillPerMinute: 20_000 } }
      : requestClass === "auth"
        ? { exact: { capacity: 120, refillPerMinute: 120 }, subnet: { capacity: 600, refillPerMinute: 600 }, global: { capacity: 10_000, refillPerMinute: 10_000 } }
        : { exact: { capacity: 600, refillPerMinute: 600 }, subnet: { capacity: 3_000, refillPerMinute: 3_000 }, global: { capacity: 20_000, refillPerMinute: 20_000 } };
    await this.limitNetwork({ purpose: `ingress:${requestClass}`, network, ...limits, ttlMs: 5 * 60_000 });
  }

  async limitSignup(network: AbuseNetworkScopes) {
    await this.limitNetwork({
      purpose: "signup",
      network,
      exact: { capacity: 5, refillPerMinute: 0.5 },
      subnet: { capacity: 30, refillPerMinute: 3 },
      global: { capacity: 300, refillPerMinute: 30 },
      ttlMs: 24 * 60 * 60 * 1000
    });
  }

  async limitPrivateUsernameSuggestion(network: AbuseNetworkScopes) {
    await this.limitNetwork({
      purpose: "private-username-suggestion",
      network,
      exact: { capacity: 20, refillPerMinute: 5 },
      subnet: { capacity: 100, refillPerMinute: 20 },
      global: { capacity: 1_000, refillPerMinute: 200 },
      ttlMs: 60 * 60 * 1000
    });
  }

  /**
   * Bound credential lookups before they can become database work. The limits
   * are intentionally above every current paid inference plan, while materially
   * below the broad API ingress allowance used for public catalog traffic.
   */
  async limitCredentialLookup(network: AbuseNetworkScopes) {
    await this.limitNetwork({
      purpose: "credential-lookup",
      network,
      exact: { capacity: 120, refillPerMinute: 120 },
      subnet: { capacity: 600, refillPerMinute: 600 },
      global: { capacity: 5_000, refillPerMinute: 5_000 },
      ttlMs: 5 * 60_000
    });
  }

  /**
   * Protect the expensive operator Argon2 path without keying admission on the
   * submitted username. A username-scoped pre-auth bucket lets a distributed
   * attacker keep one known operator locked out indefinitely. Network and
   * service-wide buckets instead bound password work while remaining
   * self-clearing and identical for present and absent operator identities.
   */
  async limitAdminLogin(network: AbuseNetworkScopes) {
    await this.limitNetwork({
      purpose: "admin-login",
      network,
      exact: { capacity: 30, refillPerMinute: 10 },
      subnet: { capacity: 90, refillPerMinute: 30 },
      global: { capacity: 180, refillPerMinute: 60 },
      ttlMs: 15 * 60_000
    });
  }

  /**
   * Bound issuance of proof-of-work challenges per network so the challenge
   * endpoint cannot itself be turned into a cheap amplification target. Solving
   * a challenge still costs the client real CPU; this only caps how fast fresh
   * targets can be minted.
   */
  async limitCaptchaChallenge(network: AbuseNetworkScopes) {
    await this.limitNetwork({
      purpose: "captcha-challenge",
      network,
      exact: { capacity: 60, refillPerMinute: 60 },
      subnet: { capacity: 300, refillPerMinute: 300 },
      global: { capacity: 5_000, refillPerMinute: 5_000 },
      ttlMs: 60 * 60 * 1000
    });
  }

  /**
   * Increment and return a subject's short-lived failed-credential count. Feeds
   * the security_events audit trail only; it is never used to hard-lock an
   * account (see AUTH_FAILURE_WINDOW_SECONDS).
   */
  async recordAuthFailure(subjectHash: string): Promise<number> {
    const key = `authfail:${subjectHash}`;
    const count = await this.redis.incr(key);
    if (count === 1) {
      await this.redis.expire(key, AUTH_FAILURE_WINDOW_SECONDS);
    }
    return count;
  }

  async clearAuthFailures(subjectHash: string) {
    await this.redis.del(`authfail:${subjectHash}`);
  }

  async limitLogin(subjectHash: string, network: AbuseNetworkScopes) {
    await this.checkBuckets([
      ...this.networkBuckets({
        purpose: "login",
        network,
        exact: { capacity: 30, refillPerMinute: 5 },
        subnet: { capacity: 150, refillPerMinute: 25 },
        global: { capacity: 2_000, refillPerMinute: 300 },
        ttlMs: 60 * 60 * 1000
      }),
      {
        key: `abuse:login:subject:${subjectHash}`,
        capacity: 10,
        refillPerMinute: 2,
        ttlMs: 60 * 60 * 1000
      }
    ]);
  }

  async limitRecovery(usernameHash: string, network: AbuseNetworkScopes) {
    await this.checkBuckets([
      ...this.networkBuckets({
        purpose: "recover",
        network,
        exact: { capacity: 10, refillPerMinute: 1 },
        subnet: { capacity: 50, refillPerMinute: 5 },
        global: { capacity: 500, refillPerMinute: 50 },
        ttlMs: 24 * 60 * 60 * 1000
      }),
      {
        key: `abuse:recover:subject:${usernameHash}`,
        capacity: 4,
        refillPerMinute: 0.25,
        ttlMs: 24 * 60 * 60 * 1000
      }
    ]);
  }

  async limitRecoveryManagement(accountHash: string, network: AbuseNetworkScopes) {
    await this.checkBuckets([
      ...this.networkBuckets({
        purpose: "recover-manage",
        network,
        exact: { capacity: 20, refillPerMinute: 4 },
        subnet: { capacity: 100, refillPerMinute: 20 },
        global: { capacity: 1_000, refillPerMinute: 200 },
        ttlMs: 60 * 60 * 1000
      }),
      {
        key: `abuse:recover-manage:account:${accountHash}`,
        capacity: 10,
        refillPerMinute: 2,
        ttlMs: 60 * 60 * 1000
      }
    ]);
  }

  async limitStandardAuth(params: {
    action: "sign-in" | "sign-up" | "password-reset" | "verification-email" | "social" | "other";
    network: AbuseNetworkScopes;
    subjectHash?: string;
  }) {
    type Policy = {
      subject?: { capacity: number; refillPerMinute: number };
      exact: { capacity: number; refillPerMinute: number };
      subnet: { capacity: number; refillPerMinute: number };
      global: { capacity: number; refillPerMinute: number };
    };
    const policy: Policy = {
      "sign-in": { subject: { capacity: 10, refillPerMinute: 2 }, exact: { capacity: 30, refillPerMinute: 5 }, subnet: { capacity: 150, refillPerMinute: 25 }, global: { capacity: 2_000, refillPerMinute: 300 } },
      "sign-up": { subject: { capacity: 3, refillPerMinute: 0.25 }, exact: { capacity: 5, refillPerMinute: 0.5 }, subnet: { capacity: 30, refillPerMinute: 3 }, global: { capacity: 300, refillPerMinute: 30 } },
      "password-reset": { subject: { capacity: 3, refillPerMinute: 0.2 }, exact: { capacity: 10, refillPerMinute: 1 }, subnet: { capacity: 50, refillPerMinute: 5 }, global: { capacity: 500, refillPerMinute: 50 } },
      "verification-email": { subject: { capacity: 3, refillPerMinute: 0.2 }, exact: { capacity: 10, refillPerMinute: 1 }, subnet: { capacity: 50, refillPerMinute: 5 }, global: { capacity: 500, refillPerMinute: 50 } },
      // Social auth is bounded by provider/network, not an arbitrary body email.
      social: { exact: { capacity: 30, refillPerMinute: 5 }, subnet: { capacity: 150, refillPerMinute: 25 }, global: { capacity: 2_000, refillPerMinute: 300 } },
      // Unknown Better Auth routes must never create attacker-selected subject
      // keys. Their network-only state is short-lived and globally bounded.
      other: { exact: { capacity: 60, refillPerMinute: 30 }, subnet: { capacity: 300, refillPerMinute: 150 }, global: { capacity: 5_000, refillPerMinute: 2_500 } }
    }[params.action];
    const ttlMs = params.action === "other" ? 5 * 60_000 : 24 * 60 * 60_000;
    const buckets = this.networkBuckets({
      purpose: `standard-auth:${params.action}`,
      network: params.network,
      exact: policy.exact,
      subnet: policy.subnet,
      global: policy.global,
      ttlMs
    });
    if (params.subjectHash && policy.subject) {
      buckets.push({
        key: `abuse:standard-auth:${params.action}:subject:${params.subjectHash}`,
        ...policy.subject,
        ttlMs
      });
    }
    await this.checkBuckets(buckets);
  }

  async limitPurchaseCreation(accountId: string, network: AbuseNetworkScopes, rail: "stripe" | "crypto") {
    await this.checkBuckets([
      ...this.networkBuckets({
        purpose: `purchase-create:${rail}`,
        network,
        exact: { capacity: 12, refillPerMinute: 2 },
        subnet: { capacity: 60, refillPerMinute: 10 },
        global: { capacity: 300, refillPerMinute: 60 },
        ttlMs: 24 * 60 * 60_000
      }),
      {
        key: `abuse:purchase-create:account:${accountId}`,
        capacity: 6,
        refillPerMinute: 1,
        ttlMs: 24 * 60 * 60_000
      },
      {
        key: `abuse:purchase-create:account-daily:${accountId}`,
        capacity: 30,
        refillPerMinute: 30 / (24 * 60),
        ttlMs: 48 * 60 * 60_000
      }
    ]);
  }

  async limitPaymentSetup(accountId: string, network: AbuseNetworkScopes) {
    await this.checkBuckets([
      ...this.networkBuckets({
        purpose: "payment-setup",
        network,
        exact: { capacity: 10, refillPerMinute: 1 },
        subnet: { capacity: 50, refillPerMinute: 5 },
        global: { capacity: 200, refillPerMinute: 20 },
        ttlMs: 24 * 60 * 60_000
      }),
      {
        key: `abuse:payment-setup:account:${accountId}`,
        capacity: 3,
        refillPerMinute: 0.2,
        ttlMs: 24 * 60 * 60_000
      }
    ]);
  }

  /**
   * Bound promotion-code guessing and replay at independent scopes. The caller
   * supplies an HMAC of the normalized code; raw promotion codes must never be
   * included in Redis keys or logs. The account+subject scope prevents one
   * account from hammering a single candidate without throttling a legitimate
   * campaign shared by many different accounts.
   */
  async limitPromotionRedemption(
    accountId: string,
    codeSubjectHash: string,
    network: AbuseNetworkScopes
  ) {
    await this.checkBuckets([
      ...this.networkBuckets({
        purpose: "promotion-redeem",
        network,
        exact: { capacity: 20, refillPerMinute: 4 },
        subnet: { capacity: 100, refillPerMinute: 20 },
        global: { capacity: 2_000, refillPerMinute: 400 },
        ttlMs: 24 * 60 * 60_000
      }),
      {
        key: `abuse:promotion-redeem:account:${accountId}`,
        capacity: 5,
        refillPerMinute: 1,
        ttlMs: 24 * 60 * 60_000
      },
      {
        key: `abuse:promotion-redeem:account-daily:${accountId}`,
        capacity: 20,
        refillPerMinute: 20 / (24 * 60),
        ttlMs: 48 * 60 * 60_000
      },
      {
        key: `abuse:promotion-redeem:account-subject:${accountId}:${codeSubjectHash}`,
        capacity: 5,
        refillPerMinute: 0.5,
        ttlMs: 24 * 60 * 60_000
      }
    ]);
  }

  async limitApiKeyCreation(accountId: string, keyType: "api" | "management") {
    await this.checkBucket({
      key: `abuse:key-create:${keyType}:account:${accountId}`,
      capacity: keyType === "management" ? 5 : 10,
      refillPerMinute: keyType === "management" ? 0.5 : 2,
      ttlMs: 24 * 60 * 60_000
    });
  }

  private async refreshVeniceLimits() {
    if (Date.now() < this.veniceLimitsExpiresAt) return;
    const key = this.config.providers.veniceInferenceKey;
    if (!key) {
      // Split control has no Venice key; use the limits the worker published.
      try {
        const raw = await this.redis.get("venice:published:ratelimits");
        if (raw) {
          const parsed = JSON.parse(raw) as {
            observedAt?: number;
            limits?: Record<string, { rpm?: number; tpm?: number }>;
          };
          if (parsed.observedAt && parsed.limits && Date.now() - parsed.observedAt <= 10 * 60_000) {
            this.veniceLimits = new Map(Object.entries(parsed.limits));
            this.veniceLimitsObservedAt = parsed.observedAt;
          }
        }
      } catch {
        // Keep the last snapshot; conservative fallbacks apply with none.
      }
      if (Date.now() - this.veniceLimitsObservedAt > 10 * 60_000) this.veniceLimits.clear();
      this.veniceLimitsExpiresAt = Date.now() + 60_000;
      return;
    }
    try {
      const response = await fetch(`${this.config.providers.veniceBaseUrl}/api_keys/rate_limits`, {
        headers: { authorization: `Bearer ${key}` },
        signal: AbortSignal.timeout(5_000)
      });
      if (!response.ok) throw new Error(`Venice rate-limit API returned ${response.status}`);
      const payload = (await response.json()) as {
        data?: { rateLimits?: Array<{ apiModelId?: string; rateLimits?: Array<{ amount?: number; type?: string }> }> };
      };
      const next = new Map<string, { rpm?: number; tpm?: number }>();
      for (const model of payload.data?.rateLimits ?? []) {
        if (!model.apiModelId) continue;
        const limits: { rpm?: number; tpm?: number } = {};
        for (const limit of model.rateLimits ?? []) {
          if (limit.type === "RPM" && Number.isFinite(limit.amount)) limits.rpm = limit.amount;
          if (limit.type === "TPM" && Number.isFinite(limit.amount)) limits.tpm = limit.amount;
        }
        next.set(model.apiModelId, limits);
      }
      if (next.size > 0) {
        this.veniceLimits = next;
        this.veniceLimitsObservedAt = Date.now();
      }
      this.veniceLimitsExpiresAt = Date.now() + 60_000;
    } catch {
      // A stale successful snapshot is safer than replacing it with guesses.
      // With no snapshot, conservative fallback limits below remain active.
      if (Date.now() - this.veniceLimitsObservedAt > 10 * 60_000) this.veniceLimits.clear();
      this.veniceLimitsExpiresAt = Date.now() + 10_000;
    }
  }

  private async providerModelLimits(providerName: string, externalModelId: string) {
    if (providerName === "mock") return { rpm: 600, tpm: 1_000_000 };
    if (providerName === "venice") {
      await this.refreshVeniceLimits();
      const published = this.veniceLimits.get(externalModelId);
      // Published Venice limits get an 0.8 safety margin. When a model has no
      // published limit (new/unlisted — e.g. GLM-5.2), fall back to an
      // agent-friendly rate instead of a trickle. The old 12 rpm / 300k tpm
      // fallback collapsed to ~4 rpm / ~120k tpm per account after the halving
      // in limitAccountModelInference, which throttled agent workloads to a few
      // requests per minute. If Venice actually limits an unlisted model lower,
      // its own 429s surface and we back off.
      return {
        rpm: published?.rpm !== undefined ? Math.max(1, Math.floor(published.rpm * 0.8)) : 300,
        tpm: published?.tpm !== undefined ? Math.max(1_000, Math.floor(published.tpm * 0.8)) : 3_000_000
      };
    }
    return { rpm: 60, tpm: 200_000 };
  }

  /**
   * Largest input + output estimate that can ever pass every TPM bucket for a
   * fresh request. This is an admission boundary, not a generation setting:
   * callers must never silently rewrite max_tokens to fit it.
   */
  async inferenceTokenCapacity(params: {
    plan: UsagePlan;
    providerName: string;
    externalModelId: string;
  }) {
    const upstream = await this.providerModelLimits(params.providerName, params.externalModelId);
    const accountModel = Math.min(
      params.plan.tokensPerMinute,
      Math.max(20_000, Math.floor((upstream.tpm ?? 300_000) * ACCOUNT_MODEL_UPSTREAM_SHARE))
    );
    return Math.min(params.plan.tokensPerMinute, accountModel, upstream.tpm ?? Number.MAX_SAFE_INTEGER);
  }

  async providerConcurrencyLimits(providerName: string, externalModelId: string) {
    const limits = await this.providerModelLimits(providerName, externalModelId);
    if (providerName === "mock") return { provider: 100, model: 50 };
    // Venice does not publish a concurrency number. Derive a conservative
    // ceiling from its live RPM allowance so a burst cannot consume the whole
    // upstream quota. Account limits remain the user-facing constraint.
    const model = Math.max(2, Math.min(12, Math.ceil(limits.rpm / 6)));
    return { provider: 24, model };
  }

  async limitAccountInference(params: {
    accountId: string;
    apiKeyId?: string;
    plan: UsagePlan;
    estimatedTokens: number;
  }): Promise<InferenceRateLimitResult> {
    const buckets: BucketOptions[] = [
      {
        key: `inference:account:${params.accountId}:rpm`,
        capacity: params.plan.requestsPerMinute,
        refillPerMinute: params.plan.requestsPerMinute,
        ttlMs: 120_000
      },
      {
        key: `inference:account:${params.accountId}:tpm`,
        capacity: params.plan.tokensPerMinute,
        refillPerMinute: params.plan.tokensPerMinute,
        cost: Math.max(1, params.estimatedTokens),
        ttlMs: 120_000
      }
    ];
    if (params.apiKeyId) {
      buckets.push(
        {
          key: `inference:key:${params.apiKeyId}:rpm`,
          capacity: params.plan.requestsPerMinute,
          refillPerMinute: params.plan.requestsPerMinute,
          ttlMs: 120_000
        },
        {
          key: `inference:key:${params.apiKeyId}:tpm`,
          capacity: params.plan.tokensPerMinute,
          refillPerMinute: params.plan.tokensPerMinute,
          cost: Math.max(1, params.estimatedTokens),
          ttlMs: 120_000
        }
      );
    }

    const windows = await this.checkBucketsWithWindows(buckets);
    const requests = windows[0]!;
    const tokens = windows[1]!;
    return { requests, tokens };
  }

  /** Per-customer fairness within a scarce upstream model; does not debit the shared pool. */
  async limitAccountModelInference(params: {
    accountId: string;
    plan: UsagePlan;
    providerName: string;
    externalModelId: string;
    estimatedTokens: number;
  }) {
    const upstream = await this.providerModelLimits(params.providerName, params.externalModelId);
    const requestsPerMinute = Math.min(params.plan.requestsPerMinute, Math.max(2, Math.floor(upstream.rpm * ACCOUNT_MODEL_UPSTREAM_SHARE)));
    const tokensPerMinute = Math.min(params.plan.tokensPerMinute, Math.max(20_000, Math.floor((upstream.tpm ?? 300_000) * ACCOUNT_MODEL_UPSTREAM_SHARE)));
    await this.checkBuckets([
      {
        key: `inference:account:${params.accountId}:provider:${params.providerName}:model:${params.externalModelId}:rpm`,
        capacity: requestsPerMinute,
        refillPerMinute: requestsPerMinute,
        ttlMs: 120_000
      },
      {
        key: `inference:account:${params.accountId}:provider:${params.providerName}:model:${params.externalModelId}:tpm`,
        capacity: tokensPerMinute,
        refillPerMinute: tokensPerMinute,
        cost: Math.max(1, params.estimatedTokens),
        ttlMs: 120_000
      }
    ]);
  }

  async limitProviderInference(params: {
    providerName: string;
    externalModelId: string;
    estimatedTokens: number;
  }) {
    const upstream = await this.providerModelLimits(params.providerName, params.externalModelId);
    await this.checkBuckets([
      {
        key: `provider:${params.providerName}:model:${params.externalModelId}:rpm`,
        capacity: upstream.rpm,
        refillPerMinute: upstream.rpm,
        ttlMs: 120_000
      },
      ...(upstream.tpm === undefined
        ? []
        : [{
            key: `provider:${params.providerName}:model:${params.externalModelId}:tpm`,
            capacity: upstream.tpm,
            refillPerMinute: upstream.tpm,
            cost: Math.max(1, params.estimatedTokens),
            ttlMs: 120_000
          }])
    ]);
  }

}

export function createRedis(config: AppConfig) {
  if (config.env === "test") {
    assertDisposableTestRedisUrl(config.redis.url);
  }
  return new Redis(config.redis.url, {
    maxRetriesPerRequest: 2,
    enableReadyCheck: true,
    lazyConnect: true
  });
}
