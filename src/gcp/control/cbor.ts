/**
 * Deterministic CBOR encoding (RFC 8949 section 4.2.1), the subset this
 * protocol needs.
 *
 * Why hand-rolled
 * ---------------
 * Both the bootstrap transcript and the release authorization are signed and
 * their digests are bound into attestation evidence. Two implementations that
 * disagree by one byte produce two different digests and a fail-closed
 * admission, so the encoding rules matter more than the convenience of a
 * library:
 *
 *   - integers, strings and byte strings use the shortest possible head;
 *   - maps are sorted by the bytewise lexicographic order of their ENCODED
 *     keys, not by the key values;
 *   - indefinite-length items, tags, floats and duplicate keys are refused;
 *   - decoding re-encodes and compares, so a non-canonical encoding is rejected
 *     rather than silently accepted.
 *
 * The guest-side implementation in
 * `infra/gcp-control/guest/bootstrap/anonrouter_cbor.py` follows the same rules
 * and is held to the same test vectors.
 */

export type CborValue =
  | number
  | bigint
  | boolean
  | null
  | string
  | Uint8Array
  | CborValue[]
  | Map<string, CborValue>;

const MAJOR_UINT = 0;
const MAJOR_NEGINT = 1;
const MAJOR_BSTR = 2;
const MAJOR_TSTR = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const MAJOR_SIMPLE = 7;

export class CborError extends Error {}

function head(major: number, value: bigint): Uint8Array {
  if (value < 0n) throw new CborError("negative argument");
  if (value < 24n) return Uint8Array.of((major << 5) | Number(value));
  if (value <= 0xffn) return Uint8Array.of((major << 5) | 24, Number(value));
  if (value <= 0xffffn) {
    return Uint8Array.of((major << 5) | 25, Number(value >> 8n) & 0xff, Number(value) & 0xff);
  }
  if (value <= 0xffff_ffffn) {
    const out = new Uint8Array(5);
    out[0] = (major << 5) | 26;
    new DataView(out.buffer).setUint32(1, Number(value), false);
    return out;
  }
  if (value <= 0xffff_ffff_ffff_ffffn) {
    const out = new Uint8Array(9);
    out[0] = (major << 5) | 27;
    new DataView(out.buffer).setBigUint64(1, value, false);
    return out;
  }
  throw new CborError("argument exceeds 64 bits");
}

function concat(parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i += 1) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/** Encode a value in deterministic CBOR. Throws on anything not canonical. */
export function encodeCbor(value: CborValue): Uint8Array {
  if (value === null) return Uint8Array.of((MAJOR_SIMPLE << 5) | 22);
  if (value === true) return Uint8Array.of((MAJOR_SIMPLE << 5) | 21);
  if (value === false) return Uint8Array.of((MAJOR_SIMPLE << 5) | 20);

  if (typeof value === "number" || typeof value === "bigint") {
    const asBigInt = typeof value === "bigint" ? value : BigInt(value);
    if (typeof value === "number" && !Number.isSafeInteger(value)) {
      throw new CborError("only safe integers are encodable; floats are not part of this profile");
    }
    return asBigInt >= 0n ? head(MAJOR_UINT, asBigInt) : head(MAJOR_NEGINT, -asBigInt - 1n);
  }

  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concat([head(MAJOR_TSTR, BigInt(bytes.length)), bytes]);
  }

  if (value instanceof Uint8Array) {
    return concat([head(MAJOR_BSTR, BigInt(value.length)), value]);
  }

  if (Array.isArray(value)) {
    return concat([head(MAJOR_ARRAY, BigInt(value.length)), ...value.map(encodeCbor)]);
  }

  if (value instanceof Map) {
    const entries = [...value.entries()].map(([key, item]) => ({
      key: encodeCbor(key),
      item: encodeCbor(item)
    }));
    entries.sort((a, b) => compareBytes(a.key, b.key));
    for (let i = 1; i < entries.length; i += 1) {
      if (compareBytes(entries[i - 1].key, entries[i].key) === 0) {
        throw new CborError("duplicate map key");
      }
    }
    return concat([head(MAJOR_MAP, BigInt(entries.length)), ...entries.flatMap((e) => [e.key, e.item])]);
  }

  throw new CborError("unsupported value");
}

/** Build a deterministic CBOR map from a plain object, in one call. */
export function encodeCborMap(entries: Record<string, CborValue>): Uint8Array {
  return encodeCbor(new Map(Object.entries(entries)));
}

interface Cursor {
  bytes: Uint8Array;
  offset: number;
}

function readHead(cursor: Cursor): { major: number; argument: bigint } {
  if (cursor.offset >= cursor.bytes.length) throw new CborError("truncated");
  const initial = cursor.bytes[cursor.offset];
  cursor.offset += 1;
  const major = initial >> 5;
  const additional = initial & 0x1f;
  if (additional < 24) return { major, argument: BigInt(additional) };
  if (additional === 31) throw new CborError("indefinite-length items are not canonical");
  if (additional > 27) throw new CborError("reserved additional information");
  const width = 1 << (additional - 24);
  if (cursor.offset + width > cursor.bytes.length) throw new CborError("truncated");
  let argument = 0n;
  for (let i = 0; i < width; i += 1) {
    argument = (argument << 8n) | BigInt(cursor.bytes[cursor.offset + i]);
  }
  cursor.offset += width;
  return { major, argument };
}

function decodeValue(cursor: Cursor): CborValue {
  const { major, argument } = readHead(cursor);
  switch (major) {
    case MAJOR_UINT:
      return argument <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(argument) : argument;
    case MAJOR_NEGINT: {
      const value = -argument - 1n;
      return value >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(value) : value;
    }
    case MAJOR_BSTR:
    case MAJOR_TSTR: {
      const length = Number(argument);
      if (cursor.offset + length > cursor.bytes.length) throw new CborError("truncated");
      const slice = cursor.bytes.subarray(cursor.offset, cursor.offset + length);
      cursor.offset += length;
      return major === MAJOR_BSTR ? new Uint8Array(slice) : new TextDecoder("utf-8", { fatal: true }).decode(slice);
    }
    case MAJOR_ARRAY: {
      const out: CborValue[] = [];
      for (let i = 0n; i < argument; i += 1n) out.push(decodeValue(cursor));
      return out;
    }
    case MAJOR_MAP: {
      const out = new Map<string, CborValue>();
      for (let i = 0n; i < argument; i += 1n) {
        const key = decodeValue(cursor);
        if (typeof key !== "string") throw new CborError("only text-string map keys are used in this profile");
        if (out.has(key)) throw new CborError("duplicate map key");
        out.set(key, decodeValue(cursor));
      }
      return out;
    }
    case MAJOR_SIMPLE:
      if (argument === 20n) return false;
      if (argument === 21n) return true;
      if (argument === 22n) return null;
      throw new CborError("unsupported simple value");
    default:
      throw new CborError("tags are not part of this profile");
  }
}

/**
 * Decode, then prove the input was canonical by re-encoding and comparing.
 *
 * A verifier that accepted a non-canonical encoding would accept two distinct
 * byte strings for one logical authorization, and only one of them would match
 * the digest that was signed.
 */
export function decodeCanonicalCbor(bytes: Uint8Array): CborValue {
  const cursor: Cursor = { bytes, offset: 0 };
  const value = decodeValue(cursor);
  if (cursor.offset !== bytes.length) throw new CborError("trailing bytes");
  if (compareBytes(encodeCbor(value), bytes) !== 0) throw new CborError("non-canonical encoding");
  return value;
}
