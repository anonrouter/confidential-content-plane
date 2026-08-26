// Independent replay of a dstack/TDX RTMR event log.
//
// The TDX quote carries RTMR0..RTMR3 as measured by hardware. The CVM also hands
// back a plaintext event log describing WHAT was measured. Neither alone is
// trustworthy: the quote's registers are authentic but opaque, and the event log
// is readable but forgeable. Replaying the log and checking that it reproduces
// the quote's registers is what turns the readable log into evidence.
//
// Replay rule (matches dstack's guest agent and @phala/dstack-sdk's
// replayRtmrs): each RTMR starts at 48 zero bytes and is extended per event as
//
//   rtmr = SHA384(rtmr_prev || right_zero_pad_48(event.digest))
//
// Implemented here with node:crypto so a verifier does not have to trust — or
// even install — the vendor SDK to check the vendor's own claim.

import { createHash } from "node:crypto";

/** One measured event as reported by the guest agent. */
export interface DstackEventLogEntry {
  /** Which register this event extended (0..3). */
  imr: number;
  event_type: number;
  /** 48-byte SHA-384 digest, lowercase hex. */
  digest: string;
  /** Event name, e.g. "compose-hash", "instance-id", "key-provider". */
  event: string;
  /** Event value, hex. For "compose-hash" this is the compose hash itself. */
  event_payload: string;
  /**
   * V2 events carry the exact bytes that were hashed, as hex. When present the
   * digest is SHA-384 of these bytes and the bytes themselves decode to a JSON
   * object naming the event and payload, so both can be checked without
   * reimplementing the canonical-JSON serializer.
   */
  preimage?: string;
  version?: number;
}

/** 48 zero bytes: the reset value of every RTMR. */
export const RTMR_INITIAL_VALUE = "0".repeat(96);

const RTMR_COUNT = 4;
const DIGEST_BYTES = 48;
/** A single event log is bounded so a hostile response cannot pin the CPU. */
const MAX_EVENTS = 4096;

export class EventLogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EventLogError";
  }
}

/**
 * Parse the guest agent's event log. `event_log` arrives as a JSON *string*
 * alongside the quote; `tcb_info.event_log` arrives already parsed. Both are
 * accepted. Throws on anything structurally wrong rather than skipping entries:
 * a skipped entry would change the replay and could hide a measurement.
 */
export function parseEventLog(input: unknown): DstackEventLogEntry[] {
  let raw: unknown = input;
  if (typeof raw === "string") {
    try {
      raw = JSON.parse(raw);
    } catch {
      throw new EventLogError("event log is not valid JSON");
    }
  }
  if (!Array.isArray(raw)) throw new EventLogError("event log must be an array");
  if (raw.length > MAX_EVENTS) throw new EventLogError(`event log exceeds ${MAX_EVENTS} entries`);

  return raw.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new EventLogError(`event ${index} is not an object`);
    }
    const record = entry as Record<string, unknown>;
    const imr = record.imr;
    const digest = record.digest;
    if (typeof imr !== "number" || !Number.isInteger(imr) || imr < 0 || imr >= RTMR_COUNT) {
      throw new EventLogError(`event ${index} has an out-of-range imr`);
    }
    if (typeof digest !== "string" || !/^[0-9a-fA-F]*$/.test(digest) || digest.length % 2 !== 0) {
      throw new EventLogError(`event ${index} has a malformed digest`);
    }
    if (digest.length > DIGEST_BYTES * 2) {
      throw new EventLogError(`event ${index} digest is longer than ${DIGEST_BYTES} bytes`);
    }
    if (record.preimage !== undefined && typeof record.preimage !== "string") {
      throw new EventLogError(`event ${index} has a malformed preimage`);
    }
    return {
      imr,
      event_type: typeof record.event_type === "number" ? record.event_type : -1,
      digest: digest.toLowerCase(),
      event: typeof record.event === "string" ? record.event : "",
      event_payload: typeof record.event_payload === "string" ? record.event_payload.toLowerCase() : "",
      ...(typeof record.preimage === "string" ? { preimage: record.preimage.toLowerCase() } : {}),
      ...(typeof record.version === "number" ? { version: record.version } : {})
    };
  });
}

/** Extend one register with an ordered list of event digests. */
export function replayRegister(digests: readonly string[]): string {
  let register = Buffer.from(RTMR_INITIAL_VALUE, "hex");
  for (const digest of digests) {
    let content = Buffer.from(digest, "hex");
    if (content.length < DIGEST_BYTES) {
      content = Buffer.concat([content, Buffer.alloc(DIGEST_BYTES - content.length, 0)]);
    }
    register = createHash("sha384").update(Buffer.concat([register, content])).digest();
  }
  return register.toString("hex");
}

/**
 * Replay RTMR0..RTMR3 from a parsed event log, in log order per register.
 *
 * RTMR0 through RTMR2 come from firmware and the TCG log, whose digests we
 * cannot recompute, so those are replayed from the supplied values. RTMR3 is
 * replayed from digests DERIVED from each event's own fields, because that is
 * what the guest agent expects (it ships those entries with an empty digest)
 * and because it is what makes reproducing the register prove the payloads.
 *
 * An RTMR3 entry that cannot be hashed contributes a value that cannot match,
 * so the replay fails rather than silently skipping it.
 */
export function replayRtmrs(events: readonly DstackEventLogEntry[]): [string, string, string, string] {
  const UNHASHABLE = "ff".repeat(48);
  const replayed = Array.from({ length: RTMR_COUNT }, (_unused, index) =>
    replayRegister(events
      .filter((event) => event.imr === index)
      .map((event) => (index === 3 ? rtmr3EventDigest(event) ?? UNHASHABLE : event.digest))));
  return replayed as [string, string, string, string];
}

/**
 * Recompute a dstack V1 RTMR3 event digest from its own fields.
 *
 * This is the check that makes the readable part of the log trustworthy. Replay
 * alone only proves the DIGESTS are the measured ones; it says nothing about the
 * `event` and `event_payload` strings printed next to them. Without recomputing,
 * a hostile server could take a genuine quote and its genuine log, leave every
 * digest untouched so the replay still matches RTMR3, and simply rewrite the
 * compose-hash payload to a value the client's policy accepts.
 *
 * V1 serialization (see the dstack-examples rtmr3-based verifier):
 *
 *   sha384( u32_le(event_type) || ":" || utf8(event) || ":" || bytes(event_payload) )
 *
 * where event_payload is hex-decoded to raw bytes first.
 */
export function computeRtmr3EventDigestV1(event: DstackEventLogEntry): string {
  const type = Buffer.alloc(4);
  type.writeUInt32LE(event.event_type >>> 0, 0);
  return createHash("sha384")
    .update(type)
    .update(":")
    .update(event.event, "utf8")
    .update(":")
    .update(Buffer.from(event.event_payload, "hex"))
    .digest("hex");
}

/**
 * Check a V2 event, which publishes the exact hashed bytes as `preimage`.
 *
 * Two things must hold, and checking only the first is a trap: the digest must
 * be SHA-384 of the preimage, AND the preimage must itself name the same event
 * and payload that are displayed. Otherwise a server could ship a genuine
 * preimage/digest pair beside arbitrary display fields.
 *
 * The preimage is canonical JSON of { name, payload, type }. Decoding it is
 * deliberately preferred over reimplementing the canonicalizer: we compare
 * decoded values, so serializer differences cannot cause a false rejection.
 */
function v2DigestIsSelfConsistent(event: DstackEventLogEntry): boolean {
  const preimage = event.preimage;
  if (preimage === undefined) return false;
  if (!/^[0-9a-f]*$/.test(preimage) || preimage.length % 2 !== 0 || preimage.length === 0) return false;
  const bytes = Buffer.from(preimage, "hex");
  if (createHash("sha384").update(bytes).digest("hex") !== event.digest) return false;

  let decoded: unknown;
  try {
    decoded = JSON.parse(bytes.toString("utf8"));
  } catch {
    return false;
  }
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) return false;
  const record = decoded as Record<string, unknown>;
  const payload = typeof record.payload === "string" ? record.payload.toLowerCase().replace(/^0x/, "") : null;
  return record.name === event.event
    && payload === event.event_payload.replace(/^0x/, "")
    && (record.type === undefined || record.type === event.event_type);
}

/**
 * The digest an RTMR3 event MUST have, derived from its own fields.
 *
 * A real dstack guest agent (observed on dstack 0.5.9 / guest agent 0.5.7)
 * returns RTMR3 entries with an EMPTY `digest` and expects the verifier to
 * derive it. That is the stronger arrangement, and it is why this returns the
 * computed value rather than comparing against a supplied one: when the replay
 * is performed over digests derived from (event_type, event, event_payload),
 * reproducing the hardware register proves the payloads are exactly what was
 * measured. There is nothing left for a hostile server to rewrite.
 *
 * Returns null when the entry cannot be hashed at all, which is a verification
 * failure rather than something to skip.
 */
export function rtmr3EventDigest(event: DstackEventLogEntry): string | null {
  // event_payload must be clean hex or the digest input is ambiguous.
  if (!/^[0-9a-f]*$/.test(event.event_payload) || event.event_payload.length % 2 !== 0) return null;
  if (event.preimage !== undefined) {
    return v2DigestIsSelfConsistent(event) ? event.digest : null;
  }
  if (event.event_type < 0) return null;
  return computeRtmr3EventDigestV1(event);
}

/**
 * True when an RTMR3 entry is internally consistent.
 *
 * An entry with no digest is consistent by construction, because the replay
 * will use the derived one. An entry that DOES carry a digest must agree with
 * the derived value, so a log cannot supply a digest that replays correctly
 * while displaying a different payload beside it.
 */
export function rtmr3EventDigestIsSelfConsistent(event: DstackEventLogEntry): boolean {
  const derived = rtmr3EventDigest(event);
  if (derived === null) return false;
  if (!event.digest) return true;
  return derived === event.digest;
}

/**
 * Every imr===3 entry whose digest does NOT commit to its own name and payload.
 * RTMR0..RTMR2 entries come from firmware and the TCG log and use a different
 * serialization, so they are deliberately out of scope here.
 */
export function inconsistentRtmr3Events(events: readonly DstackEventLogEntry[]): DstackEventLogEntry[] {
  return events.filter((event) => event.imr === 3 && !rtmr3EventDigestIsSelfConsistent(event));
}

/**
 * Read exactly one named RTMR3 event's payload from the log, ONLY if that
 * event's digest self-consistently commits to the payload. Returns null when the
 * event is absent. Throws when it appears more than once (a duplicated
 * "compose-hash" would let a server present whichever value the reader picks
 * first) or when the digest does not match its own fields.
 */
export function singleEventPayload(events: readonly DstackEventLogEntry[], name: string): string | null {
  const matches = events.filter((event) => event.event === name);
  if (matches.length === 0) return null;
  if (matches.length > 1) throw new EventLogError(`event log contains ${matches.length} "${name}" events`);
  const match = matches[0];
  if (match.imr !== 3) throw new EventLogError(`"${name}" event is not in RTMR3`);
  if (!rtmr3EventDigestIsSelfConsistent(match)) {
    throw new EventLogError(`"${name}" event digest does not commit to its payload`);
  }
  return match.event_payload;
}
