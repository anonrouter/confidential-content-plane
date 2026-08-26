import { randomUUID } from "node:crypto";
import type { Redis } from "ioredis";

/**
 * Shared guard for Lua scripts that allocate protection state. Valkey may have
 * enough room for one data-structure shape after rejecting another, so scripts
 * stop conservatively before the hard noeviction ceiling. Delete/release
 * scripts must not use this guard because they are part of recovery.
 */
export const VALKEY_LUA_WRITE_CAPACITY_FUNCTION = `
local function valkey_has_write_capacity()
  local info = redis.call('INFO', 'memory')
  local used = tonumber(string.match(info, 'used_memory:(%d+)'))
  local maximum = tonumber(string.match(info, 'maxmemory:(%d+)'))
  if maximum == nil then
    return false
  end
  if maximum == 0 then
    return true
  end
  if used == nil then
    return false
  end
  return used < math.floor(maximum * 0.98)
end
`;

const VALKEY_WRITE_PROBE = `${VALKEY_LUA_WRITE_CAPACITY_FUNCTION}
if not valkey_has_write_capacity() then
  return 0
end

local written = redis.call("SET", KEYS[1], ARGV[1], "PX", ARGV[2], "NX")
if not written then
  return 0
end

local observed = redis.call("GET", KEYS[1])
local deleted = redis.call("DEL", KEYS[1])
if observed == ARGV[1] and deleted == 1 then
  return 1
end
return 0
`;

/**
 * Prove that Valkey can still accept protection-state writes, not merely PING.
 * The random probe is payload-free and is deleted atomically; its short TTL is
 * only a cleanup backstop for a client timeout.
 */
export async function verifyValkeyWritable(
  redis: Redis,
  options: { timeoutMs?: number; ttlMs?: number } = {}
): Promise<void> {
  const timeoutMs = options.timeoutMs ?? 1_000;
  const ttlMs = options.ttlMs ?? 5_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("Valkey readiness timeout must be positive");
  }
  if (!Number.isFinite(ttlMs) || ttlMs <= timeoutMs) {
    throw new Error("Valkey readiness TTL must exceed its timeout");
  }

  const key = `anonrouter:readyz:valkey-write:${randomUUID()}`;
  const value = randomUUID();
  let timeout: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => reject(new Error("Valkey write readiness probe timed out")), timeoutMs);
    timeout.unref();
  });

  try {
    const result = await Promise.race([
      redis.eval(VALKEY_WRITE_PROBE, 1, key, value, String(ttlMs)),
      timeoutPromise
    ]);
    if (result !== 1) throw new Error("Valkey write readiness probe failed");
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

export interface ValkeyOperationalMetrics {
  used_memory_bytes: number | null;
  maxmemory_bytes: number | null;
  memory_utilization: number | null;
  maxmemory_policy: string | null;
  evicted_keys: number | null;
  oom_error_count: number | null;
}

function parseInfo(raw: string) {
  const fields = new Map<string, string>();
  for (const line of raw.split(/\r?\n/u)) {
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    fields.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return fields;
}

function nonNegativeInteger(value: string | undefined): number | null {
  if (value === undefined || !/^\d+$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function errorCount(value: string | undefined): number | null {
  if (value === undefined) return 0;
  const match = /(?:^|,)count=(\d+)(?:,|$)/u.exec(value);
  return match ? nonNegativeInteger(match[1]) : null;
}

/**
 * Collect only aggregate Valkey capacity and rejection counters.
 *
 * Key names, values, command arguments, client addresses, and payloads are
 * intentionally excluded. This makes the result safe for the private admin
 * health surface and for durable operational metrics.
 */
export async function collectValkeyOperationalMetrics(redis: Redis): Promise<ValkeyOperationalMetrics> {
  const [memoryRaw, statsRaw, errorsRaw] = await Promise.all([
    redis.info("memory"),
    redis.info("stats"),
    redis.info("errorstats")
  ]);
  const memory = parseInfo(memoryRaw);
  const stats = parseInfo(statsRaw);
  const errors = parseInfo(errorsRaw);
  const usedMemory = nonNegativeInteger(memory.get("used_memory"));
  const maxmemory = nonNegativeInteger(memory.get("maxmemory"));

  return {
    used_memory_bytes: usedMemory,
    maxmemory_bytes: maxmemory,
    memory_utilization: usedMemory !== null && maxmemory !== null && maxmemory > 0
      ? Math.round((usedMemory / maxmemory) * 10_000) / 10_000
      : null,
    maxmemory_policy: memory.get("maxmemory_policy") ?? null,
    evicted_keys: nonNegativeInteger(stats.get("evicted_keys")),
    oom_error_count: errorCount(errors.get("errorstat_OOM"))
  };
}
