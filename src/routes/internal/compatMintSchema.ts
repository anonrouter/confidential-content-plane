import { z } from "zod";
import { ticketRequestSchema } from "../../inference/ticketRequestSchema.js";

/**
 * The compat mint body: the ONE acknowledged place where a customer credential
 * and a ticket request meet.
 *
 * SPLIT OUT OF `compat.ts` FOR D-22. The handler beside it authenticates the
 * key against the account database, which is control-plane work; the SCHEMA is
 * the boundary contract and D-22 requires it be publishable so a reviewer can
 * confirm this join is the only one and see exactly what crosses.
 *
 * The compat broker sends the caller's `ar_` key here, in the body, so the
 * SERVICE token can authenticate the channel via `Authorization`. `apiKey` is on
 * the logger redact allowlist, so it is censored if a body ever reaches a log
 * line. That exposure is deliberate, disclosed, and is why the broker runs
 * inside the same attested TD as the relay.
 */
export const compatMintSchema = ticketRequestSchema.extend({
  apiKey: z.string().min(8).max(200)
});
