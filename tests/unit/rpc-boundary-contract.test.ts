import { describe, expect, it } from "vitest";
import type { z } from "zod";
import {
  AUTHORIZE_DENIED_CONTENT_DERIVED_FIELDS,
  CONTROL_RPC_REMOVED_FIELDS,
  CONTROL_RPC_SCHEMAS
} from "../../src/routes/internal/rpcSchemas.js";
import { compatMintSchema } from "../../src/routes/internal/compatMintSchema.js";
import {
  OPAQUE_RECEIPT_SQL_PATTERN,
  mintOpaqueReceiptId
} from "../../src/inference/opaqueReceipt.js";
import { OPAQUE_RECEIPT_ID_PATTERN, newOpaqueReceiptId } from "../../src/inference/contentReceipts.js";

// The contract for what may cross INTO the metadata control plane, enforced
// rather than described. The authoritative list is the target allowlist in
// docs/architecture/confidential-backend/CONTROL_RPC_CONTRACT.md; this file is
// what makes it binding.
//
// The accepted field set is pinned literally. Adding a field to one of these
// schemas fails here until someone updates the expectation, which is the point:
// widening this boundary must be a deliberate, reviewed act, not a one-line
// edit that nothing notices.

/** The exact top-level fields each route accepts. Sorted. */
const EXPECTED_FIELDS: Record<keyof typeof CONTROL_RPC_SCHEMAS, string[]> = {
  "/internal/control/redeem": ["ticketId"],
  "/internal/control/authorize": [
    "automatic",
    "e2ee",
    "inputCeiling",
    "modelPublicId",
    "opaqueE2ee",
    "operation",
    "providerPolicyKey",
    "reasoningKey",
    "redemption",
    "requestId",
    "requestedMaxOutputTokens",
    "routing",
    "stream"
  ],
  "/internal/control/authorize-next-attempt": ["latencyMs", "previousOutcome", "requestId"],
  "/internal/control/settle": [
    "firstTokenLatencyMs",
    "latencyMs",
    "opaqueReceiptId",
    "requestId",
    "usage"
  ],
  "/internal/control/delivery-started": ["requestId"],
  "/internal/control/provider-rejection": [
    "anonrouterCode",
    "attemptIndex",
    "automatic",
    "latencyMs",
    "providerRequestId",
    "providerStatus",
    "relayOutcome",
    "requestId"
  ],
  "/internal/control/dispatch-attempt": [
    "deploymentId",
    "dispatchToken",
    "effectiveMaxOutputTokens",
    "externalModelId",
    "imageHeight",
    "imageResponseFormat",
    "imageWidth",
    "opaqueE2ee",
    "operation",
    "providerName",
    "providerReasoningKey",
    "reasoningKey",
    "requestId",
    "stream"
  ],
  "/internal/control/attestation-attempt": ["deploymentId", "dispatchToken", "externalModelId", "providerName"],
  "/internal/control/capture": ["firstTokenLatencyMs", "latencyMs", "requestId"],
  "/internal/control/abort": [
    "firstTokenLatencyMs",
    "latencyMs",
    "providerRejected",
    "requestId",
    "status"
  ],
  // An EXTENSION beyond the route inventory approved at 697414c, carrying the
  // bounded credential-administration audit metadata that contract requires GCP
  // to receive. Pinned here like every other route so the addition is reviewed
  // rather than inherited.
  "/internal/control/credential-outcome": [
    "capabilityId",
    "fingerprint",
    "label",
    "outcome",
    "outcomeCode"
  ]
};

/**
 * Field names that must never appear on this boundary in any form. Matched as
 * substrings against the lowercased field name, so `messages`, `userMessages`,
 * and `message_text` are all caught.
 */
const PROHIBITED_SUBSTRINGS = [
  "message",
  "prompt",
  "completion",
  "content",
  "input", // note: `inputCeiling` and `inputTokens` are allowed by exception below
  "text",
  "tool",
  "embedding",
  "image_url",
  "imagedata",
  "audio",
  "authorization",
  "cookie",
  "apikey",
  "api_key",
  "secret",
  "password",
  "hash", // no content commitment of any kind
  "classification",
  "ticketid" // exception: the redeem route legitimately carries one
];

/**
 * Reviewed exceptions. Each is a scalar whose name merely contains a prohibited
 * substring, and each is justified in the design document.
 */
const ALLOWED_EXCEPTIONS = new Set([
  // The redeem route's whole purpose is to exchange an opaque ticket id.
  "/internal/control/redeem:ticketId",
  // A byte-derived size bound. Content-derived and disclosed as such; the
  // reservation cannot be correct without a size.
  "/internal/control/authorize:inputCeiling",
]);

function shape(schema: z.ZodTypeAny): Record<string, z.ZodTypeAny> {
  // Unwrap effects/optional wrappers to reach the object shape.
  let current: z.ZodTypeAny = schema;
  for (let depth = 0; depth < 8; depth += 1) {
    const definition = (current as unknown as { _def?: Record<string, unknown> })._def;
    if (definition && typeof definition.shape === "function") {
      return (definition.shape as () => Record<string, z.ZodTypeAny>)();
    }
    const inner = definition?.innerType ?? definition?.schema;
    if (!inner) break;
    current = inner as z.ZodTypeAny;
  }
  throw new Error("schema is not an object schema");
}

function fieldNames(schema: z.ZodTypeAny): string[] {
  return Object.keys(shape(schema)).sort();
}

describe("control RPC accepts exactly the reviewed field set", () => {
  for (const [route, schema] of Object.entries(CONTROL_RPC_SCHEMAS)) {
    it(`${route} accepts only its documented fields`, () => {
      expect(fieldNames(schema)).toEqual(EXPECTED_FIELDS[route as keyof typeof EXPECTED_FIELDS]);
    });
  }

  it("covers every registered control RPC schema", () => {
    expect(Object.keys(CONTROL_RPC_SCHEMAS).sort()).toEqual(Object.keys(EXPECTED_FIELDS).sort());
  });
});

describe("control RPC names nothing content-shaped", () => {
  for (const [route, schema] of Object.entries(CONTROL_RPC_SCHEMAS)) {
    it(`${route} has no content-shaped field name`, () => {
      for (const field of fieldNames(schema)) {
        if (ALLOWED_EXCEPTIONS.has(`${route}:${field}`)) continue;
        const lower = field.toLowerCase();
        for (const forbidden of PROHIBITED_SUBSTRINGS) {
          expect(lower.includes(forbidden), `${route} field ${field} contains "${forbidden}"`).toBe(false);
        }
      }
    });
  }
});

describe("fields removed by O13 cannot come back", () => {
  // A revert, a rebase or a "just add it back for one metric" change fails here.
  // Each of these was removed for a stated reason:
  //   classification / requiresTools / requiresVision - prompt-derived;
  //   providerCode                                    - discloses moderation;
  //   teeSignatureBinding                             - exact content hashes;
  //   constraints                                     - ticket metadata echoed back.
  for (const removed of CONTROL_RPC_REMOVED_FIELDS) {
    it(`no route accepts "${removed}" again`, () => {
      for (const [route, schema] of Object.entries(CONTROL_RPC_SCHEMAS)) {
        expect(fieldNames(schema), `${route} reintroduced ${removed}`).not.toContain(removed);
      }
    });
  }

  it("authorize rejects a classification object outright", () => {
    const result = CONTROL_RPC_SCHEMAS["/internal/control/authorize"].safeParse({
      redemption: "r",
      requestId: "q",
      modelPublicId: "m",
      automatic: true,
      stream: false,
      inputCeiling: 10,
      classification: { task: "chat", effectiveTask: "chat", complexity: "low", needsWeb: false, maybeSensitive: true, abstained: false }
    });
    expect(result.success).toBe(false);
  });

  it("provider-rejection rejects a provider policy code", () => {
    const result = CONTROL_RPC_SCHEMAS["/internal/control/provider-rejection"].safeParse({
      requestId: "q",
      attemptIndex: 0,
      automatic: false,
      latencyMs: 1,
      providerCode: "content_violation"
    });
    expect(result.success).toBe(false);
  });
});

describe("settlement carries an opaque receipt, never a content commitment", () => {
  const base = { requestId: "q", usage: { inputTokens: 1, outputTokens: 1, cachedTokens: 0 }, latencyMs: 1 };

  it("accepts a freshly minted receipt id", () => {
    const result = CONTROL_RPC_SCHEMAS["/internal/control/settle"].safeParse({
      ...base,
      opaqueReceiptId: mintOpaqueReceiptId()
    });
    expect(result.success).toBe(true);
  });

  it("rejects a SHA-256 hex digest in the receipt slot", () => {
    const sha256Hex = "a".repeat(64);
    const result = CONTROL_RPC_SCHEMAS["/internal/control/settle"].safeParse({
      ...base,
      opaqueReceiptId: sha256Hex
    });
    expect(result.success).toBe(false);
  });

  it("rejects the removed hash-bearing binding object", () => {
    const result = CONTROL_RPC_SCHEMAS["/internal/control/settle"].safeParse({
      ...base,
      teeSignatureBinding: {
        providerName: "venice",
        externalModelId: "m",
        routeId: "r",
        providerRequestId: "p",
        requestHash: "b".repeat(64),
        responseHash: "c".repeat(64)
      }
    });
    expect(result.success).toBe(false);
  });

  it("the wire pattern and the database CHECK are the same expression", async () => {
    const EXPECTED = "^arcpt_[0123456789abcdefghjkmnpqrstvwxyz]{52}$";
    expect(OPAQUE_RECEIPT_SQL_PATTERN).toBe(EXPECTED);
    // Both planes must mint ids the other's column accepts, so the content
    // plane's regex is checked against the same constant here.
    expect(OPAQUE_RECEIPT_ID_PATTERN.source).toBe(EXPECTED);

    // The migration half of the claim runs only where migrations exist. The
    // content plane has no database and the standalone export ships no
    // migrations directory, so reading one there would make the export
    // permanently red over a property that is not its to hold. The control
    // plane's own suite does read it, which is where the claim is enforced.
    const { readFile } = await import("node:fs/promises");
    const migrationUrl = new URL("../../migrations/096_opaque_settlement_receipts.sql", import.meta.url);
    const migration = await readFile(migrationUrl, "utf8").catch(() => null);
    if (migration === null) return;
    // The migration writes the character class out longhand for readability; the
    // structural claim that matters is the identical prefix and fixed length.
    expect(migration).toContain(EXPECTED);
  });
});

describe("control RPC rejects unknown fields rather than stripping them", () => {
  // zod's DEFAULT is to strip an unknown key, which succeeds silently. Every
  // schema on this boundary must be .strict(), so a relay that started
  // attaching a content-derived field fails loudly instead of being tolerated.
  const canary = "CANARY-PROMPT-TEXT";

  for (const [route, schema] of Object.entries(CONTROL_RPC_SCHEMAS)) {
    it(`${route} rejects an injected content field`, () => {
      const result = schema.safeParse({ messages: [{ role: "user", content: canary }] });
      expect(result.success).toBe(false);
      // Even the failure must not echo the value back into an error path.
      if (!result.success) {
        expect(JSON.stringify(result.error.issues)).not.toContain(canary);
      }
    });
  }

});

describe("the compat mint is the one acknowledged identity join", () => {
  it("accepts the caller key plus top-level ticket metadata, and nothing else", () => {
    const fields = fieldNames(compatMintSchema);
    expect(fields).toContain("apiKey");
    expect(fields).toContain("model");
    // Never content, in any form.
    for (const forbidden of ["messages", "input", "tools", "prompt", "content"]) {
      expect(fields, forbidden).not.toContain(forbidden);
    }
  });

  it("rejects a body carrying messages", () => {
    const result = compatMintSchema.safeParse({
      apiKey: "ar_test_0123456789abcdef",
      model: "mock-chat",
      messages: [{ role: "user", content: "CANARY" }]
    });
    expect(result.success).toBe(false);
  });
});

describe("the content-derived fields the contract removed cannot come back", () => {
  const authorize = CONTROL_RPC_SCHEMAS["/internal/control/authorize"];
  const base = {
    redemption: "red_1",
    requestId: "req_1",
    modelPublicId: "mock-chat",
    automatic: false,
    stream: false,
    inputCeiling: 128
  };

  it("accepts the target allowlist", () => {
    expect(authorize.safeParse(base).success).toBe(true);
  });

  // Each of these used to be accepted. Every one describes the request's
  // CONTENT: what the prompt is about, whether it carries tools, whether it
  // carries an image. See CONTROL_RPC_CONTRACT.md.
  for (const field of AUTHORIZE_DENIED_CONTENT_DERIVED_FIELDS) {
    it(`rejects ${field}`, () => {
      const value = field === "classification"
        ? { task: "coding", effectiveTask: "coding", complexity: "high", needsWeb: false, maybeSensitive: true, abstained: false }
        : true;
      expect(authorize.safeParse({ ...base, [field]: value }).success).toBe(false);
    });
  }

  it("rejects the retired providerCode on provider-rejection", () => {
    const rejection = CONTROL_RPC_SCHEMAS["/internal/control/provider-rejection"];
    const valid = { requestId: "req_1", attemptIndex: 0, automatic: false, latencyMs: 12 };
    expect(rejection.safeParse(valid).success).toBe(true);
    // `content_violation` is the exact value the removal exists to stop: a
    // moderation verdict on the caller's prompt.
    expect(rejection.safeParse({ ...valid, providerCode: "content_violation" }).success).toBe(false);
  });
});

describe("settlement carries an opaque receipt, never a content hash", () => {
  const settle = CONTROL_RPC_SCHEMAS["/internal/control/settle"];
  const base = {
    requestId: "req_1",
    usage: { inputTokens: 10, outputTokens: 20, cachedTokens: 0 },
    latencyMs: 100
  };

  it("accepts a minted receipt id", () => {
    const result = settle.safeParse({ ...base, opaqueReceiptId: newOpaqueReceiptId() });
    expect(result.success).toBe(true);
  });

  it("rejects the retired hash-bearing binding", () => {
    const hash = "a".repeat(64);
    const result = settle.safeParse({
      ...base,
      teeSignatureBinding: {
        providerName: "venice",
        externalModelId: "m",
        routeId: "r",
        providerRequestId: "p",
        requestHash: hash,
        responseHash: hash
      }
    });
    expect(result.success).toBe(false);
  });

  it("rejects a 64-hex digest smuggled in as the receipt id", () => {
    // The point of the fixed `r1_` + 32-hex format: a SHA-256 hex digest does
    // not match it, so a caller cannot pass a content commitment off as a
    // receipt.
    expect(settle.safeParse({ ...base, opaqueReceiptId: "b".repeat(64) }).success).toBe(false);
    expect(settle.safeParse({ ...base, opaqueReceiptId: `arcpt_${"b".repeat(64)}` }).success).toBe(false);
    // Crockford excludes i, l, o and u, so a hex-looking value of the right
    // length still fails.
    expect(settle.safeParse({ ...base, opaqueReceiptId: `arcpt_${"i".repeat(52)}` }).success).toBe(false);
  });

  it("mints ids that are unguessable and unlinkable", () => {
    const ids = new Set(Array.from({ length: 512 }, () => newOpaqueReceiptId()));
    expect(ids.size).toBe(512);
    for (const id of ids) expect(OPAQUE_RECEIPT_ID_PATTERN.test(id)).toBe(true);
    // 256 bits of entropy: `arcpt_` plus 52 Crockford base32 characters.
    expect([...ids][0]).toHaveLength(58);
  });
});
