// The content-plane entry point. This is what the CVM image runs (D-22).
//
// It differs from `index.ts` in exactly one way, and the difference is the
// entire point: **it has no branch that imports `server.js`.**
//
// `index.ts` serves the `api` monolith and the `control` role as well as the
// content roles, so it necessarily reaches `server.ts`, and through it the
// control plane, payments, admin, account identity and the database. A single
// image built from that entry point therefore contains the whole backend, which
// is what D-22 exists to end: "publish the plaintext-capable workload" and
// "publish the whole backend" must stop being the same statement.
//
// The roles here are exactly the components that `PHALA_CONFIDENTIAL_DATA_PLANE`
// section 5 permits to hold content, plus the attestation producer that holds
// none:
//
//   relay              full request and response bodies, transiently
//   compat             full bodies and the caller's static `ar_` key
//   <provider>-worker  full bodies plus exactly one provider credential
//   gateway-attestation  no content at all; sole holder of /var/run/dstack.sock
//
// A role this entry point does not recognize is refused rather than defaulted.
// `index.ts` falls through to the monolith, which is right for a dev process and
// wrong here: silently starting a control plane inside the TD because an
// environment variable was misspelled is precisely the failure the split is
// meant to make impossible.
//
// `tests/unit/content-plane-closure.test.ts` asserts that the module graph
// reachable from this file contains no control-plane source at all.

import { loadConfig } from "./config.js";

const config = loadConfig();
const role = config.internal.role;

const CONTENT_ROLES = new Set([
  "relay",
  "compat",
  "gateway-attestation",
  "venice-worker",
  "fireworks-worker",
  "bedrock-worker",
  "deepinfra-worker",
  "chutes-worker",
  "tinfoil-worker",
  "near-worker",
  "phala-ai-worker"
]);

async function buildForRole() {
  if (!CONTENT_ROLES.has(role)) {
    // Fail closed and say why. There is no monolith in this image to fall back
    // to, and pretending otherwise would produce a confusing crash deep inside
    // config validation instead of one line naming the mistake.
    throw new Error(
      `RUNTIME_ROLE=${role} is not a content-plane role. This image serves only ` +
        `${[...CONTENT_ROLES].sort().join(", ")}. The control plane runs from a different image.`
    );
  }

  const roles = await import("./roles.js");
  if (role === "relay") return roles.buildRelayServer(config);
  if (role === "compat") return roles.buildCompatServer(config);
  if (role === "gateway-attestation") return roles.buildGatewayAttestationServer(config);
  return roles.buildWorkerServer(config);
}

const server = await buildForRole();

try {
  await server.listen({
    host: config.server.host,
    port: config.server.port
  });
} catch (error) {
  server.log.error(
    {
      error_type: error instanceof Error ? error.name : "unknown"
    },
    "server_start_failed"
  );
  process.exitCode = 1;
}
