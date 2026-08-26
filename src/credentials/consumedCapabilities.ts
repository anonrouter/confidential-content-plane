import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";

/**
 * Durable one-time-use enforcement for credential-administration capabilities.
 *
 * A capability's signature, target, scope and expiry can all be checked from the
 * capability itself. "Has this one already been used" cannot: it is the one
 * property that requires memory. In-process memory is not enough, because a
 * container restart would forget it and a replayed capability would succeed —
 * and restarting a container is not a difficult thing for an attacker who can
 * reach the orchestration layer.
 *
 * So the record lives on the worker's one writable mount, beside the keyset
 * overlay it protects, and is written the same way: temp file, atomic rename,
 * mode 0600. It stores capability IDs and timestamps only. A capability ID is
 * an opaque identifier chosen by the issuer; it is not derived from the secret
 * and does not name the operator.
 *
 * Entries are kept for a bounded window rather than forever. A capability that
 * has expired cannot be replayed regardless of whether we remember it, because
 * verifyCapability refuses it on expiry first, so retaining the ID past that
 * point protects nothing and grows without limit.
 */

interface ConsumedEntry {
  capabilityId: string;
  consumedAtMs: number;
  /** The capability's own expiry, so retention can be bounded by it. */
  expiresAtMs: number;
}

const CAPABILITY_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{2,63}$/;
/** Retain a consumed id well past its expiry, to absorb clock skew. */
const RETENTION_GRACE_MS = 24 * 60 * 60 * 1000;
const MAX_ENTRIES = 10_000;

function sanitize(parsed: unknown): ConsumedEntry[] {
  if (!Array.isArray(parsed)) return [];
  const entries: ConsumedEntry[] = [];
  const seen = new Set<string>();
  for (const raw of parsed) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const entry = raw as Record<string, unknown>;
    if (typeof entry.capabilityId !== "string" || !CAPABILITY_ID_PATTERN.test(entry.capabilityId)) continue;
    if (seen.has(entry.capabilityId)) continue;
    if (typeof entry.consumedAtMs !== "number" || typeof entry.expiresAtMs !== "number") continue;
    seen.add(entry.capabilityId);
    entries.push({
      capabilityId: entry.capabilityId,
      consumedAtMs: entry.consumedAtMs,
      expiresAtMs: entry.expiresAtMs
    });
  }
  return entries;
}

export class ConsumedCapabilityLog {
  private entries: ConsumedEntry[] | null = null;

  constructor(
    private readonly path: string,
    private readonly now: () => number = Date.now
  ) {}

  /**
   * Record a capability as used, or report that it already was.
   *
   * Read-then-write under a single call, and the file is the only source of
   * truth, so two workers sharing the mount cannot both see "unused". Within one
   * process the call is synchronous end to end, so there is no interleaving
   * point between the check and the write.
   */
  consume(capabilityId: string, expiresAtSeconds: number): { firstUse: boolean } {
    const entries = this.load();
    if (entries.some((entry) => entry.capabilityId === capabilityId)) {
      return { firstUse: false };
    }
    const now = this.now();
    const retained = entries
      .filter((entry) => entry.expiresAtMs + RETENTION_GRACE_MS > now)
      .slice(-(MAX_ENTRIES - 1));
    retained.push({ capabilityId, consumedAtMs: now, expiresAtMs: expiresAtSeconds * 1000 });
    this.persist(retained);
    return { firstUse: true };
  }

  /** Whether this id has been recorded. Used by tests and diagnostics. */
  wasConsumed(capabilityId: string): boolean {
    return this.load().some((entry) => entry.capabilityId === capabilityId);
  }

  private load(): ConsumedEntry[] {
    // Always re-read: a second worker process, or a replacement container on the
    // same volume, may have consumed a capability since we last looked. Caching
    // here would be caching exactly the thing that must not be stale.
    try {
      statSync(this.path);
    } catch {
      this.entries = [];
      return this.entries;
    }
    try {
      this.entries = sanitize(JSON.parse(readFileSync(this.path, "utf8")));
    } catch {
      // A corrupt log must FAIL CLOSED for replay purposes, but an empty list is
      // the opposite of that. There is no honest recovery: treat an unreadable
      // log as unusable and refuse the operation rather than silently allowing a
      // replay. The caller turns the throw into a 503.
      throw new Error("consumed capability log is unreadable");
    }
    return this.entries;
  }

  private persist(entries: ConsumedEntry[]): void {
    const directory = dirname(this.path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temp = join(directory, `.consumed-capabilities.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
    try {
      writeFileSync(temp, `${JSON.stringify(entries)}\n`, { mode: 0o600 });
      renameSync(temp, this.path);
    } catch (error) {
      rmSync(temp, { force: true });
      throw error;
    }
    chmodSync(this.path, 0o600);
    this.entries = entries;
  }
}
