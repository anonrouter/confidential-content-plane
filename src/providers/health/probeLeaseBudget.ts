import { performance } from "node:perf_hooks";
import { workerHealthLeaseSchema } from "./workerMetadata.js";

// Start the local budget before sending the request. That is earlier than the
// server's claim, so RTT/processing consumes the budget instead of extending it.
// Never use the machine's wall-clock offset to decide whether paid work may start.
export function workerProbeLeaseBudget(raw: unknown, requestStartedAt: number, now: () => number = () => performance.now()) {
  const parsed = workerHealthLeaseSchema.safeParse(raw);
  if (!parsed.success || !Number.isFinite(requestStartedAt) || requestStartedAt < 0) return null;
  const deadline = requestStartedAt + parsed.data.ttlMs;
  return { leaseId: parsed.data.leaseId, permitsProbe: () => {
    const current = now();
    return Number.isFinite(current) && current >= requestStartedAt && current + 26_000 < deadline;
  } };
}
