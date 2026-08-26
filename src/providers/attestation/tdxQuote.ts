// Structural parser for an Intel TDX v4 DCAP quote (the format Chutes and NEAR AI
// both return). We parse the fixed-offset TD report body to extract the
// measurement registers, report_data (nonce binding), mr_config_id (model/compose
// binding), and the TD debug flag. This is deterministic byte-offset parsing, not
// signature verification: the ECDSA chain to Intel roots is a separate, pluggable
// step (see providerAttested note in the verifiers). Parsing never throws on
// malformed input; it returns null so the verifier fails closed.
//
// Layout (Intel TDX Quote v4, TD Report / TD10):
//   Quote Header            48 bytes  (version, att_key_type, tee_type, ...)
//   TD Quote Body          584 bytes  starting at offset 48:
//     tee_tcb_svn   16 | mr_seam 48 | mr_signer_seam 48 | seam_attributes 8 |
//     td_attributes  8 | xfam    8 | mr_td 48 | mr_config_id 48 | mr_owner 48 |
//     mr_owner_config 48 | rtmr0 48 | rtmr1 48 | rtmr2 48 | rtmr3 48 |
//     report_data 64

export interface ParsedTdxQuote {
  version: number;
  teeType: number;
  /** TD build measurement (48-byte SHA-384), lowercase hex. */
  mrTd: string;
  mrConfigId: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  /** 64-byte report_data (nonce / key binding region), lowercase hex. */
  reportData: string;
  /** td_attributes (8 bytes), lowercase hex. */
  tdAttributes: string;
  /** True when the TUD.DEBUG bit (td_attributes bit 0) is set. */
  debugEnabled: boolean;
}

const HEADER_LEN = 48;
const BODY_LEN = 584;
const QUOTE_MIN_LEN = HEADER_LEN + BODY_LEN;

// Offsets from the start of the quote (header included).
const OFF_TD_ATTRIBUTES = 48 + 16 + 48 + 48 + 8; // 168
const OFF_MR_TD = 48 + 136; // 184
const OFF_MR_CONFIG_ID = OFF_MR_TD + 48; // 232
const OFF_RTMR0 = OFF_MR_CONFIG_ID + 48 * 3; // 376
const OFF_REPORT_DATA = OFF_RTMR0 + 48 * 4; // 568

function decodeQuote(input: string): Buffer | null {
  const clean = input.trim();
  // Accept hex (NEAR intel_quote) or base64 (Chutes quote).
  if (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0) {
    return Buffer.from(clean, "hex");
  }
  try {
    const buf = Buffer.from(clean, "base64");
    // Reject accidental round-trips of non-base64 that yield too-short buffers.
    return buf.length >= QUOTE_MIN_LEN ? buf : null;
  } catch {
    return null;
  }
}

export function parseTdxQuote(input: unknown): ParsedTdxQuote | null {
  if (typeof input !== "string" || input.length === 0) return null;
  const buf = decodeQuote(input);
  if (!buf || buf.length < QUOTE_MIN_LEN) return null;
  const hex = (off: number, len: number) => buf.subarray(off, off + len).toString("hex");
  const tdAttributes = hex(OFF_TD_ATTRIBUTES, 8);
  return {
    version: buf.readUInt16LE(0),
    teeType: buf.readUInt32LE(4),
    mrTd: hex(OFF_MR_TD, 48),
    mrConfigId: hex(OFF_MR_CONFIG_ID, 48),
    rtmr0: hex(OFF_RTMR0, 48),
    rtmr1: hex(OFF_RTMR0 + 48, 48),
    rtmr2: hex(OFF_RTMR0 + 96, 48),
    rtmr3: hex(OFF_RTMR0 + 144, 48),
    reportData: hex(OFF_REPORT_DATA, 64),
    tdAttributes,
    // TUD.DEBUG is bit 0 of the first td_attributes byte.
    debugEnabled: (buf[OFF_TD_ATTRIBUTES] & 0x01) === 0x01
  };
}

/**
 * Pluggable port for full cryptographic verification of a TDX quote's ECDSA
 * signature chain to Intel PCS/QVL roots plus TCB status, and (when present) the
 * NVIDIA GPU evidence chain to NRAS roots. Production wires a vetted DCAP verifier
 * (with collateral) here; absent one, the provider verifiers report the honest
 * `provider-attested` level rather than `hardware-verified`. Kept synchronous so
 * the verifier stays pure; a real implementation must pre-fetch collateral.
 */
export interface TdxChainVerifier {
  readonly implementation: string;
  /** True only when the quote's signature + cert chain verify to vendor roots and
   *  the TCB status is acceptable (UpToDate, or SWHardeningNeeded with reviewed
   *  advisories). Any doubt returns false (fail closed). */
  verifyChain(rawQuote: string, gpuEvidence: unknown): { verified: boolean; tcbStatus?: string };
}

/** A single accepted-measurement entry from a provider's published allowlist. */
export interface TdxMeasurementEntry {
  name: string;
  mrTd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  /** The reviewed runtime RTMR3 value. It is dynamic across releases, which is
   * why policies are versioned; it is never optional within a pinned entry. */
  rtmr3: string;
}

/** Whether a parsed quote's complete reviewed measurement identity (MRTD plus
 * RTMR0..3) matches an allowlist entry. Runtime changes require a new reviewed
 * policy version; silently ignoring RTMR3 would permit unreviewed runtime state. */
export function matchMeasurementAllowlist(
  quote: ParsedTdxQuote,
  allowlist: TdxMeasurementEntry[]
): string | null {
  const eq = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
  for (const entry of allowlist) {
    if (
      eq(quote.mrTd, entry.mrTd)
      && eq(quote.rtmr0, entry.rtmr0)
      && eq(quote.rtmr1, entry.rtmr1)
      && eq(quote.rtmr2, entry.rtmr2)
      && eq(quote.rtmr3, entry.rtmr3)
    ) {
      return entry.name;
    }
  }
  return null;
}
