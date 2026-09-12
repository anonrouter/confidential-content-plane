import { describe, expect, it, vi } from "vitest";
import type { ContentPlaneConfig } from "../../src/contentPlaneConfig.js";
import { fetchRawTinfoilModels } from "../../src/providers/catalog/tinfoilSync.js";

const config = {
  providers: {
    tinfoilBaseUrl: "https://inference.tinfoil.sh/v1",
    tinfoilApiKey: "tinfoil_test_secret",
    tinfoilConfigRepo: "tinfoilsh/confidential-model-router"
  }
} as ContentPlaneConfig;

describe("Tinfoil catalog transport", () => {
  it("uses the adapter's attested transport rather than global fetch", async () => {
    const globalFetch = vi.fn();
    vi.stubGlobal("fetch", globalFetch);
    const fetchModels = vi.fn(async () => new Response(JSON.stringify({
      data: [{ id: "model-a", owned_by: "tinfoil" }]
    }), { status: 200, headers: { "content-type": "application/json" } }));

    const models = await fetchRawTinfoilModels(config, {
      adapter: { fetchModels },
      maxRetries: 0,
      timeoutMs: 1_234
    });

    expect(models).toEqual([{ id: "model-a", owned_by: "tinfoil" }]);
    expect(fetchModels).toHaveBeenCalledWith(1_234);
    expect(globalFetch).not.toHaveBeenCalled();
  });
});
