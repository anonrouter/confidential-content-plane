import { ProviderError } from "../security/errors.js";
import { extractProviderErrorMeta } from "./providerErrorMeta.js";

export async function parseJsonResponse(response: Response) {
  if (!response.ok) {
    // Capture the sanitized, allowlisted-header provider request id BEFORE the
    // body is discarded — it is a content-free correlator the rejection ledger
    // records. Then cancel the body immediately: provider-controlled error bodies
    // may be large and can contain reflected request content we never expose,
    // log, or inspect.
    const meta = extractProviderErrorMeta(response);
    await response.body?.cancel().catch(() => undefined);
    throw new ProviderError("provider_http_error", "Provider request failed", response.status, meta);
  }

  try {
    return await response.json();
  } catch {
    throw new ProviderError("provider_invalid_json", "Provider returned an invalid response", response.status);
  }
}

export async function requireStreamBody(response: Response) {
  if (!response.ok) {
    const meta = extractProviderErrorMeta(response);
    await response.body?.cancel().catch(() => undefined);
    throw new ProviderError("provider_http_error", "Provider request failed", response.status, meta);
  }
  if (!response.body) {
    throw new ProviderError("provider_no_stream", "Provider did not return a stream", response.status);
  }
  return response.body;
}
