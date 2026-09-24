/**
 * Integer micro-USD money.
 *
 * The rest of this codebase carries money as a JS `number` of dollars and
 * reconciles it with `Number(value.toFixed(6))` (see `moneyUsd` in
 * `./billing.ts`). That is float arithmetic with a rounding step bolted on: it
 * is adequate for a per-request charge that is immediately written back to a
 * `numeric(12,6)` column, and it is NOT adequate for a shared pool, where the
 * same global counter is incremented and decremented thousands of times a day
 * and every lost ulp is either budget the operator paid for and nobody could
 * spend, or budget that was spent twice.
 *
 * Trial Pool v2 therefore keeps ALL of its money as an integer count of
 * micro-USD (1 USD = 1_000_000 micros) end to end: `bigint` columns in
 * Postgres, `number` integers in TypeScript, integer strings on the wire. No
 * value in the pool accounting path is ever a decimal float.
 *
 * `number` is safe here rather than `bigint` because the representable range
 * is +/-9.007e15 micros, i.e. about +/-9.007 billion USD, and the pool's daily
 * budget is capped four orders of magnitude below that (see MAX_POOL_MICROS).
 * Every function below refuses a non-integer or out-of-range input rather than
 * silently truncating, so a float can never enter the accounting path at all.
 */

/** 1 USD expressed in micro-USD. */
export const MICROS_PER_USD = 1_000_000;

/**
 * Hard ceiling for any single pool-accounting quantity: $1,000,000.
 *
 * This is not a product limit, it is a representation guard. It sits far above
 * any plausible daily trial budget and far below `Number.MAX_SAFE_INTEGER`, so
 * sums of many such values stay exactly representable.
 */
export const MAX_POOL_MICROS = 1_000_000 * MICROS_PER_USD;

export class MoneyError extends Error {}

/** Assert a value is a usable micro-USD integer and return it unchanged. */
export function assertMicros(value: unknown, what = "amount"): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new MoneyError(`${what} must be an integer number of micro-USD`);
  }
  if (value < -MAX_POOL_MICROS || value > MAX_POOL_MICROS) {
    throw new MoneyError(`${what} is outside the representable micro-USD range`);
  }
  return value;
}

/** Assert a value is a non-negative micro-USD integer. */
export function assertNonNegativeMicros(value: unknown, what = "amount"): number {
  const micros = assertMicros(value, what);
  if (micros < 0) throw new MoneyError(`${what} must not be negative`);
  return micros;
}

/**
 * Read a micro-USD integer that arrived from Postgres.
 *
 * `bigint` columns come back from `pg` as strings (the driver refuses to risk a
 * lossy Number coercion, which is exactly the property we want). Accept the
 * string form, the already-numeric form, and null/undefined as `fallback`.
 * Reject anything that is not an exact integer, so a `numeric` column joined in
 * by mistake fails loudly instead of rounding.
 */
export function readMicros(value: string | number | null | undefined, fallback = 0): number {
  if (value === null || value === undefined) return assertMicros(fallback, "fallback");
  if (typeof value === "number") return assertMicros(value, "database value");
  if (!/^-?\d+$/.test(value.trim())) {
    throw new MoneyError(`database value "${value}" is not an integer micro-USD amount`);
  }
  const parsed = Number(value.trim());
  return assertMicros(parsed, "database value");
}

/**
 * Convert a dollar-denominated float (a provider price, a legacy config value)
 * into micro-USD, rounding UP.
 *
 * Ceiling is the safe direction everywhere this is used: it is applied to the
 * amount a request RESERVES, so rounding can only ever over-reserve. Rounding
 * down would let a sub-micro remainder escape the pool ceiling once per
 * request, which across a day is unbounded leakage.
 *
 * The `1e-9` epsilon absorbs the float representation error in values like
 * 0.07 * 3 before the ceiling is applied, so an exact multiple of one micro
 * does not get pushed up a whole micro by its own binary representation.
 */
export function usdToMicrosCeil(usd: number): number {
  if (!Number.isFinite(usd)) throw new MoneyError("USD amount must be finite");
  // `+ 0` normalizes the negative zero that Math.ceil(-1e-9) produces for an
  // input of exactly 0. It compares equal to 0 and stores as 0, so it is
  // harmless in arithmetic, but handing -0 back to a caller is the kind of
  // detail that later shows up in an Object.is comparison or a snapshot.
  const micros = Math.ceil(usd * MICROS_PER_USD - 1e-9) + 0;
  return assertMicros(micros === 0 ? 0 : micros, "converted amount");
}

/**
 * Convert a dollar-denominated float into micro-USD, rounding DOWN.
 *
 * Floor is the safe direction when CREDITING the pool or an allowance back,
 * for the mirror-image reason: it can only ever return less than was taken.
 */
export function usdToMicrosFloor(usd: number): number {
  if (!Number.isFinite(usd)) throw new MoneyError("USD amount must be finite");
  const micros = Math.floor(usd * MICROS_PER_USD + 1e-9);
  return assertMicros(micros === 0 ? 0 : micros, "converted amount");
}

/**
 * Convert micro-USD back to a dollar float.
 *
 * ONLY for handing an amount to the existing float-denominated billing
 * primitives (`reserveBalance` takes dollars) and for log lines. Never feed the
 * result back into pool accounting: use `microsToUsdString` for display and
 * keep the integer for arithmetic.
 */
export function microsToUsd(micros: number): number {
  return assertMicros(micros, "amount") / MICROS_PER_USD;
}

/**
 * Format micro-USD as an exact 6-decimal string, with no float in the path.
 *
 * This is the `*_usd` wire format in the Trial Pool v2 contract. It is produced
 * by integer division and string padding rather than `toFixed`, so it is exact
 * for every representable value.
 */
export function microsToUsdString(micros: number): string {
  const value = assertMicros(micros, "amount");
  const sign = value < 0 ? "-" : "";
  const abs = Math.abs(value);
  const whole = Math.floor(abs / MICROS_PER_USD);
  const fraction = abs - whole * MICROS_PER_USD;
  return `${sign}${whole}.${String(fraction).padStart(6, "0")}`;
}

/**
 * Apply an exact integer ratio (the operator's allocation / safety factor),
 * rounding DOWN.
 *
 * The factor is carried as a numerator and denominator rather than a decimal so
 * that "80%" is exactly 80/100 and never 0.8000000000000000444. Rounding down
 * keeps the effective budget at or below the configured budget, which is the
 * direction that cannot overspend.
 */
export function applyRatioFloor(micros: number, numerator: number, denominator: number): number {
  const amount = assertNonNegativeMicros(micros, "amount");
  if (!Number.isInteger(numerator) || numerator < 0) {
    throw new MoneyError("allocation numerator must be a non-negative integer");
  }
  if (!Number.isInteger(denominator) || denominator <= 0) {
    throw new MoneyError("allocation denominator must be a positive integer");
  }
  if (numerator > denominator) {
    throw new MoneyError("allocation factor must not exceed 1");
  }
  return Math.floor((amount * numerator) / denominator);
}

/** Clamp a micro-USD amount into an inclusive integer range. */
export function clampMicros(micros: number, minimum: number, maximum: number): number {
  const amount = assertMicros(micros, "amount");
  const low = assertNonNegativeMicros(minimum, "minimum");
  const high = assertNonNegativeMicros(maximum, "maximum");
  if (low > high) throw new MoneyError("minimum allowance exceeds maximum allowance");
  return Math.min(high, Math.max(low, amount));
}
