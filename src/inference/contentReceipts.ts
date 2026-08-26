import { OPAQUE_RECEIPT_SQL_PATTERN, mintOpaqueReceiptId } from "./opaqueReceipt.js";

/**
 * Opaque settlement receipts: the content plane's replacement for the exact
 * request/response hashes that used to cross to the control plane.
 *
 * `CONTROL_RPC_CONTRACT.md` fixes the rule this module implements:
 *
 *   "Exact request and response hashes remain inside the attested content
 *    workload. Where a receipt must join a Phala record to a control
 *    settlement, Phala creates a fresh, uniformly random, opaque binding
 *    identifier of at least 128 bits. GCP may store that identifier but
 *    receives neither hash. It must be unguessable, single-purpose and
 *    unlinkable across requests; it is not a content commitment or a lookup
 *    oracle."
 *
 * So: uniformly random bits, minted here, never derived from anything. A
 * derived identifier — even an HMAC of the request hash — would be a content
 * commitment wearing a disguise, and would let anyone holding the plaintext
 * confirm a guess against a control-plane row. Random bytes cannot do that.
 *
 * The hashes themselves stay in this process, in memory. That is a deliberate
 * durability trade, not an oversight: writing them to a disk the control plane
 * can reach would reintroduce exactly the join the contract removes, and the
 * content plane has no database by construction. A receipt therefore survives
 * the CVM's uptime and no longer, which is stated in the public receipt
 * response rather than hidden.
 */

/**
 * `arcpt_` plus 52 characters of lowercase Crockford base32 over 32 random
 * bytes. Fixed length 58.
 *
 * The contract's floor is 128 bits; this is 256. The extra entropy costs
 * nothing and the format was converged with the GCP control-plane
 * implementation, which pins the same length in a PostgreSQL CHECK — so a
 * 64-character hex digest cannot be stored in the receipt column at the
 * database, not only at the wire schema. Two independent refusals of the same
 * mistake is the point.
 *
 * Crockford base32 rather than hex because it excludes i, l, o and u, so a
 * receipt read aloud or retyped from a support ticket cannot become a different
 * valid-looking receipt.
 */
// DERIVED, not restated. The encoding is defined once in ./opaqueReceipt.ts,
// which is also what migration 096's CHECK constraint is written from. Two
// hand-written copies of one wire format is how the two planes drifted apart on
// the credential capability; the same mistake in a receipt id would mean the
// content plane minting ids the control plane's column refuses.
export const OPAQUE_RECEIPT_ID_PATTERN = new RegExp(OPAQUE_RECEIPT_SQL_PATTERN);

/** 32 bytes = 256 bits from the CSPRNG, encoded big-endian into 52 symbols. */
export const newOpaqueReceiptId = mintOpaqueReceiptId;

export interface ContentReceipt {
  opaqueReceiptId: string;
  providerName: string;
  externalModelId: string;
  /** The public route id (catalog `publicModelId`), not an account or ticket. */
  routeId: string;
  canonicalModelId?: string;
  providerRequestId: string;
  /** Exact wire hashes. These never leave the content plane. */
  requestHash: string;
  responseHash: string;
  recordedAtMs: number;
  expiresAtMs: number;
}

export interface ContentReceiptStoreOptions {
  /** Bounded so a traffic spike cannot exhaust the CVM's memory. */
  maxEntries?: number;
  ttlMs?: number;
  now?: () => number;
}

const DEFAULT_MAX_ENTRIES = 20_000;
/** One hour. Long enough for a client to fetch its own receipt, short enough
 *  that the retained hash set stays small. */
const DEFAULT_TTL_MS = 60 * 60 * 1000;

/**
 * In-memory, bounded, TTL'd receipt store owned by the relay.
 *
 * Insertion-ordered eviction rather than LRU on purpose: a receipt is fetched
 * at most once or twice, immediately after the request it belongs to, so
 * recency tells us nothing that age does not, and FIFO cannot be steered by a
 * caller who repeatedly reads one receipt to keep it resident.
 */
export class ContentReceiptStore {
  private readonly entries = new Map<string, ContentReceipt>();
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(options: ContentReceiptStoreOptions = {}) {
    this.maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.now = options.now ?? Date.now;
  }

  /**
   * Mint an id and retain the binding. Returns the id the caller sends to the
   * control plane and hands to the customer.
   */
  record(binding: Omit<ContentReceipt, "opaqueReceiptId" | "recordedAtMs" | "expiresAtMs">): string {
    const opaqueReceiptId = newOpaqueReceiptId();
    this.put({
      ...binding,
      opaqueReceiptId,
      recordedAtMs: this.now(),
      expiresAtMs: this.now() + this.ttlMs
    });
    return opaqueReceiptId;
  }

  /**
   * Retain a binding under an id minted earlier in the request. Streaming needs
   * this: the id goes out in the SSE response headers before the first chunk,
   * but the response hash only exists once the stream has terminated.
   */
  recordUnder(
    opaqueReceiptId: string,
    binding: Omit<ContentReceipt, "opaqueReceiptId" | "recordedAtMs" | "expiresAtMs">
  ): void {
    if (!OPAQUE_RECEIPT_ID_PATTERN.test(opaqueReceiptId)) {
      throw new Error("opaque receipt id is not in the minted format");
    }
    this.put({
      ...binding,
      opaqueReceiptId,
      recordedAtMs: this.now(),
      expiresAtMs: this.now() + this.ttlMs
    });
  }

  get(opaqueReceiptId: string): ContentReceipt | undefined {
    const found = this.entries.get(opaqueReceiptId);
    if (!found) return undefined;
    if (found.expiresAtMs <= this.now()) {
      this.entries.delete(opaqueReceiptId);
      return undefined;
    }
    return found;
  }

  size(): number {
    return this.entries.size;
  }

  private put(receipt: ContentReceipt) {
    // A binding is only worth keeping if it actually binds something. The store
    // this one replaced refused a short or malformed hash, and dropping that
    // check would let a caller fill the receipt store with values that cannot
    // verify anything, which is worse than having no receipt: the customer is
    // told a receipt exists and it proves nothing.
    for (const [field, value] of [
      ["requestHash", receipt.requestHash],
      ["responseHash", receipt.responseHash]
    ] as const) {
      if (!/^[0-9a-f]{64}$/i.test(value)) {
        throw new Error(`content receipt ${field} is not an exact SHA-256 digest`);
      }
    }
    this.sweep();
    // Re-insert at the tail so the eviction order stays insertion order even
    // when a streaming request fills an id it minted earlier.
    this.entries.delete(receipt.opaqueReceiptId);
    this.entries.set(receipt.opaqueReceiptId, receipt);
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
  }

  /**
   * Amortized expiry. Map preserves insertion order and every entry gets the
   * same TTL, so the expired ones are always a prefix: stop at the first live
   * entry instead of walking the whole map on every write.
   */
  private sweep() {
    const now = this.now();
    for (const [id, receipt] of this.entries) {
      if (receipt.expiresAtMs > now) break;
      this.entries.delete(id);
    }
  }
}
