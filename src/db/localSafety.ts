import type pg from "pg";

const TEST_DATABASE_NAME = "anonrouter_test";
const TEST_DATABASE_SENTINEL = "anonrouter-disposable-test-v1";
const TEST_REDIS_DATABASE = "15";

function parseUrl(value: string, operation: string) {
  try {
    return new URL(value);
  } catch {
    throw new Error(`${operation} requires a valid URL`);
  }
}

function assertLiteralLoopback(parsed: URL, operation: string) {
  if (parsed.hostname !== "127.0.0.1") {
    throw new Error(`${operation} is restricted to literal 127.0.0.1`);
  }
  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error(`${operation} requires an explicit unprivileged loopback port`);
  }
  if (parsed.search || parsed.hash) {
    throw new Error(`${operation} does not accept URL query parameters or fragments`);
  }
}

function databaseName(parsed: URL) {
  return decodeURIComponent(parsed.pathname.replace(/^\//, ""));
}

function isConfirmedOperatorExercise(value: string, kind: "database" | "redis") {
  if (process.env.OPERATOR_EXERCISE_CONFIRM !== "disposable-loopback") return false;
  const allowed = kind === "redis"
    ? [process.env.OPERATOR_EXERCISE_REDIS_URL]
    : [process.env.OPERATOR_EXERCISE_DATABASE_URL, process.env.OPERATOR_EXERCISE_MIGRATION_DATABASE_URL];
  return allowed.includes(value);
}

export function assertDisposableTestPostgresUrl(value: string) {
  const operation = "integration-test PostgreSQL";
  const parsed = parseUrl(value, operation);
  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    throw new Error(`${operation} requires postgres:// or postgresql://`);
  }
  assertLiteralLoopback(parsed, operation);
  if (isConfirmedOperatorExercise(value, "database")) return;
  if (databaseName(parsed) !== TEST_DATABASE_NAME) {
    throw new Error(`${operation} requires the dedicated ${TEST_DATABASE_NAME} database`);
  }
}

export function assertDisposableTestRedisUrl(value: string) {
  const operation = "integration-test Valkey";
  const parsed = parseUrl(value, operation);
  if (parsed.protocol !== "redis:") {
    throw new Error(`${operation} requires redis://`);
  }
  assertLiteralLoopback(parsed, operation);
  if (isConfirmedOperatorExercise(value, "redis")) return;
  if (parsed.pathname !== `/${TEST_REDIS_DATABASE}`) {
    throw new Error(`${operation} requires dedicated logical database ${TEST_REDIS_DATABASE}`);
  }
}

export function assertLocalResetPostgresUrl(value: string) {
  const operation = "database reset";
  const parsed = parseUrl(value, operation);
  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    throw new Error(`${operation} requires postgres:// or postgresql://`);
  }
  if (parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") {
    throw new Error(`${operation} is restricted to a loopback PostgreSQL endpoint`);
  }
  const name = databaseName(parsed);
  if (name !== "anonrouter" && name !== TEST_DATABASE_NAME) {
    throw new Error(`${operation} requires the anonrouter or ${TEST_DATABASE_NAME} database`);
  }
  if (parsed.search || parsed.hash) {
    throw new Error(`${operation} does not accept URL query parameters or fragments`);
  }
}

export function assertLocalResetConfirmation(value: string | undefined) {
  if (value !== "local-reset") {
    throw new Error("set ANONROUTER_DB_RESET_CONFIRM=local-reset to confirm destructive local reset");
  }
}

export async function assertDisposableTestDatabaseSentinel(client: pg.Client, migrationUrl: string) {
  if (isConfirmedOperatorExercise(migrationUrl, "database")) return;
  const result = await client.query<{ database_name: string; marker: string | null }>(
    `SELECT current_database() AS database_name,
            (SELECT marker FROM public.anonrouter_test_environment WHERE singleton = true) AS marker`
  ).catch(() => ({ rows: [] }));
  const row = result.rows[0];
  if (row?.database_name !== TEST_DATABASE_NAME || row.marker !== TEST_DATABASE_SENTINEL) {
    throw new Error("integration-test PostgreSQL is missing the disposable test sentinel");
  }
}

export const LOCAL_TEST_INFRASTRUCTURE = {
  postgresDatabase: TEST_DATABASE_NAME,
  postgresSentinel: TEST_DATABASE_SENTINEL,
  redisDatabase: Number(TEST_REDIS_DATABASE)
} as const;
