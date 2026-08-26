import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    hookTimeout: 30_000,
    testTimeout: 45_000,
    pool: "forks",
    // Integration suites share the local Postgres/Valkey fixtures and must not
    // reset or migrate them concurrently. Vitest 4 removed poolOptions.singleFork;
    // the supported equivalent is a single worker with file parallelism off.
    fileParallelism: false,
    maxWorkers: 1
  }
});
