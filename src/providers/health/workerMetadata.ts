import { z } from "zod";

/**
 * Health metadata that may cross from a credential-holding worker to control.
 *
 * The worker sends only the provider/model identifiers control handed to it and
 * a bounded result. No prompt, generation, provider response body, account
 * identity, credential, or raw error message is accepted by this schema.
 */
export const WORKER_HEALTH_TARGET_LIMIT = 32;

const providerNameSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/);
const externalModelIdSchema = z.string().min(1).max(256);

export const workerHealthTargetSchema = z
  .object({
    externalModelId: externalModelIdSchema
  })
  .strict();

export const workerHealthTargetsResponseSchema = z
  .object({
    // Default preserves rolling compatibility: a new worker talking to the
    // previous control release simply has no targets until control is upgraded.
    health_probe_targets: z.array(workerHealthTargetSchema).max(WORKER_HEALTH_TARGET_LIMIT).default([])
  })
  .passthrough();

export const workerHealthCheckSchema = z
  .object({
    externalModelId: externalModelIdSchema,
    ok: z.boolean(),
    latencyMs: z.number().int().min(0).max(120_000),
    statusCode: z.number().int().min(100).max(599).optional(),
    // Codes are machine labels only. In particular, raw provider error text is
    // unable to satisfy this field and therefore cannot cross the boundary.
    errorCode: z.string().regex(/^[a-z0-9][a-z0-9_]{0,63}$/).optional()
  })
  .strict()
  .superRefine((value, context) => {
    if (value.ok && (value.statusCode !== undefined || value.errorCode !== undefined)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Successful health checks cannot carry failure metadata"
      });
    }
  });

export const workerHealthReportSchema = z
  .object({
    deploymentId: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/).optional().default("primary"),
    provider: providerNameSchema,
    healthChecks: z.array(workerHealthCheckSchema).min(1).max(WORKER_HEALTH_TARGET_LIMIT)
  })
  .strict()
  .superRefine((value, context) => {
    const seen = new Set<string>();
    value.healthChecks.forEach((check, index) => {
      if (seen.has(check.externalModelId)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          message: "A health report may contain each model only once",
          path: ["healthChecks", index, "externalModelId"]
        });
      }
      seen.add(check.externalModelId);
    });
  });

export type WorkerHealthTarget = z.infer<typeof workerHealthTargetSchema>;
export type WorkerHealthCheck = z.infer<typeof workerHealthCheckSchema>;
export type WorkerHealthReport = z.infer<typeof workerHealthReportSchema>;
