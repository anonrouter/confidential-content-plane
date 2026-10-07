import { describe, expect, it } from "vitest";
import { workerProbeLeaseBudget } from "../../src/providers/health/probeLeaseBudget.js";

const grant = { leaseId: "12".repeat(16), ttlMs: 30 * 60 * 1000 };
describe("paid-probe grant budget", () => {
  it.each([undefined, {}, { ...grant, leaseId: "bad" }, { ...grant, ttlMs: 0 }, { ...grant, ttlMs: 1_800_001 },
    { ...grant, prompt: "forbidden" }])("refuses a missing or invalid authority response", raw => {
    expect(workerProbeLeaseBudget(raw, 100)).toBeNull();
  });
  it("counts catalog round trip and queued work against the original budget", () => {
    let clock = 100;
    const budget = workerProbeLeaseBudget(grant, clock, () => clock)!;
    clock += 60_000;
    expect(budget.permitsProbe()).toBe(true);
    // Checked again when the global queue finally grants a slot. The remaining
    // time must accommodate the entire timeout, including its safety margin.
    clock = 100 + grant.ttlMs - 26_000;
    expect(budget.permitsProbe()).toBe(false);
    clock += 60_000;
    expect(budget.permitsProbe()).toBe(false);
  });
  it("refuses clock regression and non-finite values", () => {
    for (const start of [NaN, Infinity, -1]) expect(workerProbeLeaseBudget(grant, start)).toBeNull();
    for (const clock of [NaN, Infinity, 99]) {
      expect(workerProbeLeaseBudget(grant, 100, () => clock)!.permitsProbe()).toBe(false);
    }
  });
  it("cannot start a request with a grant shorter than the timeout", () => {
    expect(workerProbeLeaseBudget({ ...grant, ttlMs: 25_000 }, 100, () => 100)!.permitsProbe()).toBe(false);
  });
});
