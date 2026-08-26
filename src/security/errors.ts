export class AppError extends Error {
  readonly statusCode: number;
  readonly code: string;
  readonly expose: boolean;
  /** Optional sanitized, structured fields merged into the exposed error body. */
  readonly details?: Record<string, unknown>;

  constructor(statusCode: number, code: string, message: string, expose = true, details?: Record<string, unknown>) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.expose = expose;
    this.details = details;
  }
}

export class ProviderError extends AppError {
  readonly providerStatusCode?: number;
  /**
   * Sanitized, content-free provider-rejection metadata for the rejection ledger.
   * Deliberately NOT part of `details`, so they never enter the customer-facing
   * error body via publicErrorBody — they travel worker -> relay -> control plane
   * only. `providerRequestId` is an opaque per-request correlator from an
   * allowlisted response header; `providerCode` is an allowlisted machine code.
   */
  providerRequestId?: string;
  providerCode?: string;

  constructor(
    code: string,
    message = "Provider request failed",
    providerStatusCode?: number,
    meta?: { providerRequestId?: string; providerCode?: string }
  ) {
    super(providerStatusCode && providerStatusCode >= 400 && providerStatusCode < 500 ? 502 : 503, code, message, true);
    this.providerStatusCode = providerStatusCode;
    this.providerRequestId = meta?.providerRequestId;
    this.providerCode = meta?.providerCode;
  }
}

export function publicErrorBody(error: unknown, requestId: string) {
  if (error instanceof AppError && error.expose) {
    return {
      error: {
        message: error.message,
        type: error.code,
        request_id: requestId,
        ...(error.details ?? {})
      }
    };
  }

  return {
    error: {
      message: "Internal server error",
      type: "internal_error",
      request_id: requestId
    }
  };
}
