// Durable Venice keyset overlay for the credential worker.
//
// The boot-time env/file keyset stays the base; operator add/remove actions
// land in a small JSON overlay file on the worker's one writable mount:
//   { "added": VeniceKey[], "removedIds": string[] }
// Effective keyset = (boot keys - removedIds) + added, with an added entry
// winning any id collision. The overlay holds real key material, so it is
// written atomically (temp file + rename) with mode 0600 and its contents are
// never logged. Reads re-check the file so a keyset change made by the RPC
// endpoints (or a replacement container on the same volume) applies without a
// process restart.

import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { KEY_ID_PATTERN, type VeniceKey } from "./veniceKeys.js";

interface KeysetOverlay {
  added: VeniceKey[];
  removedIds: string[];
}

function emptyOverlay(): KeysetOverlay {
  return { added: [], removedIds: [] };
}

/**
 * Parse a persisted overlay defensively: a corrupt or hand-edited file must
 * never crash the worker or smuggle malformed entries into the keyset. Invalid
 * entries are dropped rather than failing the whole overlay.
 */
function sanitizeOverlay(parsed: unknown): KeysetOverlay {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return emptyOverlay();
  const candidate = parsed as { added?: unknown; removedIds?: unknown };
  const added: VeniceKey[] = [];
  const seen = new Set<string>();
  if (Array.isArray(candidate.added)) {
    for (const entry of candidate.added) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
      const key = entry as { id?: unknown; label?: unknown; key?: unknown };
      if (typeof key.id !== "string" || !KEY_ID_PATTERN.test(key.id) || seen.has(key.id)) continue;
      if (typeof key.key !== "string" || key.key.trim().length === 0) continue;
      seen.add(key.id);
      added.push({
        id: key.id,
        label: typeof key.label === "string" && key.label.trim().length > 0 ? key.label.trim() : null,
        key: key.key.trim()
      });
    }
  }
  const removedIds = Array.isArray(candidate.removedIds)
    ? [...new Set(candidate.removedIds.filter((id): id is string => typeof id === "string" && KEY_ID_PATTERN.test(id)))]
    : [];
  return { added, removedIds };
}

export class VeniceKeysetStore {
  private overlay: KeysetOverlay = emptyOverlay();
  private loadedStat: { mtimeMs: number; size: number } | null = null;
  private loaded = false;

  constructor(
    private readonly bootKeys: VeniceKey[],
    private readonly overlayPath: string
  ) {}

  /** Re-read the overlay when the file appeared, changed, or vanished. */
  private refresh(): void {
    let stat: { mtimeMs: number; size: number };
    try {
      const fileStat = statSync(this.overlayPath);
      stat = { mtimeMs: fileStat.mtimeMs, size: fileStat.size };
    } catch {
      this.overlay = emptyOverlay();
      this.loadedStat = null;
      this.loaded = true;
      return;
    }
    if (this.loaded && this.loadedStat && this.loadedStat.mtimeMs === stat.mtimeMs && this.loadedStat.size === stat.size) {
      return;
    }
    try {
      this.overlay = sanitizeOverlay(JSON.parse(readFileSync(this.overlayPath, "utf8")));
    } catch {
      // A torn or corrupt overlay must not take inference down: fall back to
      // the boot keyset until the next successful write repairs the file.
      this.overlay = emptyOverlay();
    }
    this.loadedStat = stat;
    this.loaded = true;
  }

  private persist(): void {
    const directory = dirname(this.overlayPath);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temp = join(directory, `.venice-keyset-overlay.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
    try {
      writeFileSync(temp, `${JSON.stringify(this.overlay)}\n`, { mode: 0o600 });
      renameSync(temp, this.overlayPath);
    } catch (error) {
      rmSync(temp, { force: true });
      throw error;
    }
    chmodSync(this.overlayPath, 0o600);
    const fileStat = statSync(this.overlayPath);
    this.loadedStat = { mtimeMs: fileStat.mtimeMs, size: fileStat.size };
    this.loaded = true;
  }

  /** (boot keys - removedIds) + added; an added entry wins its id. */
  effectiveKeys(): VeniceKey[] {
    this.refresh();
    const shadowed = new Set([...this.overlay.removedIds, ...this.overlay.added.map((entry) => entry.id)]);
    return [
      ...this.bootKeys.filter((entry) => !shadowed.has(entry.id)),
      ...this.overlay.added
    ];
  }

  keyById(id: string): string | null {
    return this.effectiveKeys().find((entry) => entry.id === id)?.key ?? null;
  }

  /** The worker's default credential when control names no key id. */
  defaultKey(): string | null {
    return this.effectiveKeys()[0]?.key ?? null;
  }

  /** Add (or replace) an operator-supplied key and persist the overlay. */
  addKey(entry: VeniceKey): void {
    this.refresh();
    this.overlay = {
      added: [...this.overlay.added.filter((existing) => existing.id !== entry.id), entry],
      removedIds: this.overlay.removedIds.filter((id) => id !== entry.id)
    };
    this.persist();
  }

  /** True when removing this id would leave the effective keyset empty. */
  isLastRemaining(id: string): boolean {
    const keys = this.effectiveKeys();
    return keys.length === 1 && keys[0]!.id === id;
  }

  /** Remove a key (boot or added) from the effective keyset and persist. */
  removeKey(id: string): boolean {
    this.refresh();
    const known = this.effectiveKeys().some((entry) => entry.id === id);
    if (!known) return false;
    this.overlay = {
      added: this.overlay.added.filter((entry) => entry.id !== id),
      removedIds: this.bootKeys.some((entry) => entry.id === id)
        ? [...new Set([...this.overlay.removedIds, id])]
        : this.overlay.removedIds
    };
    this.persist();
    return true;
  }
}

declare module "fastify" {
  interface FastifyInstance {
    veniceKeyStore: VeniceKeysetStore;
  }
}
