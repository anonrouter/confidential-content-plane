import pg from "pg";
import type { ControlPlaneConfig } from "../config.js";
import { assertDisposableTestPostgresUrl } from "./localSafety.js";

const { Pool } = pg;

export function createPool(config: ControlPlaneConfig) {
  if (config.env === "test") {
    assertDisposableTestPostgresUrl(config.db.url);
  }
  return new Pool({
    connectionString: config.db.url,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000
  });
}

export type DbPool = pg.Pool;
export type DbClient = pg.PoolClient | pg.Client;
