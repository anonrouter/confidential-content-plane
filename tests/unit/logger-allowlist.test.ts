import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import pino from "pino";
import {
  createLoggerOptions,
  filterLoggedFields,
  LOGGED_FIELD_ALLOWLIST,
  safeErrorSerializer,
  UNALLOWLISTED_MESSAGE
} from "../../src/logger.js";
import { AppError, ProviderError } from "../../src/security/errors.js";

// The logger is a structural control, not a convention. These tests pin the two
// properties the confidential data plane depends on: unknown fields never reach
// stdout, and no Error ever contributes free text.
//
// Container stdout is platform-visible on a confidential host even with
// public_logs=false, so this file is what protects it.

describe("field allowlist", () => {
  it("keeps allowlisted fields and drops everything else", () => {
    const filtered = filterLoggedFields({
      request_id: "req_1",
      status_code: 200,
      latency_ms: 12,
      messages: [{ role: "user", content: "secret prompt" }],
      body: { messages: [{ content: "nested secret" }] },
      prompt: "secret",
      user_email: "a@b.c"
    });
    expect(filtered.request_id).toBe("req_1");
    expect(filtered.status_code).toBe(200);
    expect(filtered.latency_ms).toBe(12);
    expect(filtered).not.toHaveProperty("messages");
    expect(filtered).not.toHaveProperty("body");
    expect(filtered).not.toHaveProperty("prompt");
    expect(filtered).not.toHaveProperty("user_email");
  });

  it("reports what it dropped so a missing entry is visible, not silent", () => {
    const filtered = filterLoggedFields({ request_id: "req_1", surprise: 1, another: 2 });
    expect(filtered.dropped_fields).toBe(2);
    expect(filtered.dropped_field_names).toEqual(["surprise", "another"]);
  });

  it("adds no reporting fields when nothing was dropped", () => {
    const filtered = filterLoggedFields({ request_id: "req_1", status_code: 200 });
    expect(filtered).not.toHaveProperty("dropped_fields");
    expect(filtered).not.toHaveProperty("dropped_field_names");
  });

  it("does not echo a pathological key name", () => {
    const filtered = filterLoggedFields({ ["secret prompt \" injected"]: 1 });
    expect(filtered.dropped_field_names).toEqual(["invalid"]);
  });

  it("bounds the number of reported names", () => {
    const object: Record<string, unknown> = {};
    for (let i = 0; i < 50; i += 1) object[`field_${i}`] = i;
    const filtered = filterLoggedFields(object);
    expect(filtered.dropped_fields).toBe(50);
    expect((filtered.dropped_field_names as string[]).length).toBe(8);
  });

  it("allowlists nothing that names content", () => {
    // A guard against someone adding a content-shaped field by habit.
    for (const field of LOGGED_FIELD_ALLOWLIST) {
      expect(field, field).not.toMatch(/message|prompt|completion|content|input|output_text|body|token_value|email_address/);
    }
  });
});

describe("error serialization", () => {
  it("reduces an Error to a type, never a message or a stack", () => {
    const error = new Error("connection to postgres failed: DETAIL: Key (email)=(a@b.c) already exists");
    const serialized = safeErrorSerializer(error);
    expect(serialized).toEqual({ type: "Error" });
    expect(JSON.stringify(serialized)).not.toContain("a@b.c");
    expect(JSON.stringify(serialized)).not.toContain("DETAIL");
  });

  it("keeps AnonRouter's own reviewed error codes", () => {
    expect(safeErrorSerializer(new AppError(429, "rate_limited", "Too many requests")))
      .toEqual({ type: "AppError", code: "rate_limited" });
    expect(safeErrorSerializer(new ProviderError("provider_unavailable", "upstream down", 503)))
      .toEqual({ type: "ProviderError", code: "provider_unavailable" });
  });

  it("drops a non-identifier code rather than coercing it", () => {
    const error = new Error("boom") as Error & { code: unknown };
    error.code = "a code containing the secret prompt";
    expect(safeErrorSerializer(error)).toEqual({ type: "Error" });
  });

  it("handles a thrown non-Error", () => {
    expect(safeErrorSerializer("raw secret string")).toEqual({ type: "string" });
    expect(safeErrorSerializer({ messages: ["secret"] })).toEqual({ type: "object" });
    expect(safeErrorSerializer(undefined)).toEqual({ type: "undefined" });
  });
});

describe("channels that bypass formatters.log", () => {
  // Found by probing the logger rather than by reading it. Each of these
  // printed a planted secret verbatim before the fix.
  const SECRET = "TOP-SECRET-PROMPT";

  function capture(fn: (logger: pino.Logger) => void): string {
    const lines: string[] = [];
    const stream = { write: (chunk: string) => { lines.push(chunk); return true; } };
    const logger = pino(
      createLoggerOptions({ logging: { level: "trace" } } as never),
      stream as never
    );
    fn(logger);
    return lines.join("");
  }

  it("replaces a message that is not a reviewed event name", () => {
    // logger.info({}, prompt) printed the prompt: the message argument never
    // reaches formatters.log.
    const out = capture((logger) => logger.info({ request_id: "r" }, SECRET));
    expect(out).not.toContain(SECRET);
    expect(out).toContain(UNALLOWLISTED_MESSAGE);
    expect(out).toContain("dropped_message");
  });

  it("discards printf-style interpolation arguments", () => {
    const out = capture((logger) => logger.info({ request_id: "r" }, "request_complete %s", SECRET));
    expect(out).not.toContain(SECRET);
  });

  it("replaces a message-only call", () => {
    const out = capture((logger) => logger.info(SECRET));
    expect(out).not.toContain(SECRET);
  });

  it("coerces an allowlisted key whose value is not a scalar", () => {
    // An allowlisted KEY does not make its VALUE safe: a toJSON side channel
    // passed the key filter and then serialized whatever it liked.
    const out = capture((logger) => logger.info({ request_id: { toJSON: () => SECRET } }, "request_complete"));
    expect(out).not.toContain(SECRET);
    expect(out).toContain("[unserializable]");
  });

  it("bounds the length of an allowlisted string value", () => {
    const out = capture((logger) => logger.info({ request_id: "y".repeat(5_000) }, "request_complete"));
    expect(out.length).toBeLessThan(1_000);
    expect(out).toContain("...");
  });

  it("still emits reviewed event names and Fastify's boot line unchanged", () => {
    expect(capture((logger) => logger.info({ request_id: "r", status_code: 200 }, "request_complete")))
      .toContain('"message":"request_complete"');
    expect(capture((logger) => logger.info("Server listening at http://127.0.0.1:3000")))
      .toContain("Server listening at http://127.0.0.1:3000");
  });

  it("keeps the request correlator that Fastify adds as a child binding", () => {
    const out = capture((logger) => logger.child({ reqId: "req_abc" }).info({ request_id: "req_abc" }, "request_complete"));
    expect(out).toContain("req_abc");
  });

  it("no source file creates a child logger", () => {
    // pino does NOT run formatters.bindings over logger.child({...}), so a
    // child binding is not filtered at runtime. Only Fastify creates children
    // today, passing exactly reqId. This test is what keeps that true: it is
    // enforceable in a way the runtime filter is not.
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) { walk(full); continue; }
        if (!entry.name.endsWith(".ts")) continue;
        // Strip comments first: this module's own documentation explains the
        // hazard using the very expression being searched for.
        const source = readFileSync(full, "utf8")
          .replace(/\/\*[\s\S]*?\*\//g, "")
          .replace(/(^|[^:])\/\/.*$/gm, "$1");
        if (/\blog(ger)?\s*\.child\s*\(/.test(source)) offenders.push(full);
      }
    };
    walk(fileURLToPath(new URL("../../src", import.meta.url)));
    expect(offenders).toEqual([]);
  });
});

describe("end to end through pino", () => {
  function capture(fn: (logger: pino.Logger) => void): string[] {
    const lines: string[] = [];
    const stream = { write: (chunk: string) => { lines.push(chunk); return true; } };
    // The same options the app uses, minus the config dependency.
    const logger = pino(
      {
        level: "info",
        serializers: { err: safeErrorSerializer, error: safeErrorSerializer },
        formatters: { log: filterLoggedFields },
        base: { service: "anonrouter" },
        messageKey: "message"
      },
      stream as never
    );
    fn(logger);
    return lines;
  }

  it("strips content passed directly to a log call", () => {
    const lines = capture((logger) => {
      logger.info({ request_id: "req_1", messages: [{ content: "TOP-SECRET-PROMPT" }] }, "request_complete");
    });
    expect(lines.join("")).not.toContain("TOP-SECRET-PROMPT");
    expect(lines.join("")).toContain("req_1");
    expect(lines.join("")).toContain("dropped_field_names");
  });

  it("strips a nested error message that redaction would have missed", () => {
    // `{ err }` was the exact shape pino's exact-match redact paths could not
    // reach, which is why the serializer, not redaction, is the control.
    const lines = capture((logger) => {
      logger.warn({ err: new Error("provider said: TOP-SECRET-PROMPT") }, "request_error");
    });
    expect(lines.join("")).not.toContain("TOP-SECRET-PROMPT");
    expect(lines.join("")).toContain('"type":"Error"');
  });

  it("preserves child-logger bindings such as the request correlator", () => {
    const lines = capture((logger) => {
      logger.child({ reqId: "req_child" }).info({ request_id: "req_child" }, "request_complete");
    });
    // Bindings go through formatters.bindings, not formatters.log, so the
    // allowlist must not have swallowed Fastify's correlation id.
    expect(lines.join("")).toContain("req_child");
  });
});
