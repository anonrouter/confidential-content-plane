import { existsSync, readFileSync } from "node:fs";
import { isIP } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseDotenv } from "dotenv";
import { z } from "zod";
import { parseVeniceKeyset } from "./providers/veniceKeys.js";

function unique(values: string[]) {
  return [...new Set(values)];
}

function looksLikeRepoRoot(directory: string) {
  return existsSync(resolve(directory, "package.json")) || existsSync(resolve(directory, ".git"));
}

const parentEnvAllowlist = new Set([
  "FIREWORKS_API_KEY",
  "FIREWORKS_BASE_URL",
  "DEEPINFRA_API_KEY",
  "DEEPINFRA_BASE_URL",
  "VENICE_INFERENCE_KEY",
  "VENICE_INFERENCE_API_KEY",
  "VENICE_API_KEY",
  "VENICE_INFERENCE_KEYS",
  "VENICE_BASE_URL",
  "VENICE_DEFAULT_MODEL"
]);

function loadEnvFile(filePath: string, allowlist?: Set<string>) {
  if (!existsSync(filePath)) {
    return;
  }

  const parsed = parseDotenv(readFileSync(filePath));
  for (const [key, value] of Object.entries(parsed)) {
    if (allowlist && !allowlist.has(key)) {
      continue;
    }
    if (value.trim() === "") {
      continue;
    }
    if (process.env[key] === undefined || process.env[key] === "") {
      process.env[key] = value;
    }
  }
}

function loadLocalEnv() {
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  const moduleProjectRoot = resolve(moduleDirectory, "..");
  const cwdParent = resolve(process.cwd(), "..");
  const projectDirectories = [
    process.cwd(),
    moduleProjectRoot
  ];
  const parentDirectories = [
    "/workspace-parent",
    looksLikeRepoRoot(cwdParent) ? cwdParent : ""
  ].filter(Boolean);

  const explicitEnvFile = process.env.ANONROUTER_ENV_FILE;
  if (explicitEnvFile) {
    loadEnvFile(explicitEnvFile);
  }

  // Production roles receive an explicit environment + mounted secret files.
  // Never let a developer checkout's `.env` silently inject provider
  // credentials across a split-role trust boundary. An explicitly selected
  // ANONROUTER_ENV_FILE above remains supported for operator-managed launches.
  if (process.env.NODE_ENV === "production") return;

  const projectFiles = unique(projectDirectories).flatMap((directory) => [
    resolve(directory, ".env.local"),
    resolve(directory, ".env")
  ]);
  for (const filePath of unique(projectFiles)) {
    loadEnvFile(filePath);
  }

  const parentFiles = unique(parentDirectories).flatMap((directory) => [
    resolve(directory, ".env.local"),
    resolve(directory, ".env")
  ]);
  for (const filePath of unique(parentFiles)) {
    loadEnvFile(filePath, parentEnvAllowlist);
  }
}

loadLocalEnv();

const optionalBooleanSwitch = z.preprocess(
  (value) => value === "" ? undefined : value,
  z.enum(["true", "false"]).optional()
).transform((value) => value === undefined ? undefined : value === "true");

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  // Roles: `api` is the local dev monolith (all in-process). Production splits
  // into independently runnable control, relay, and credential-isolated
  // provider-worker roles.
  // `compat` is the optional static-key OpenAI-compatibility broker: it mints a
  // single-use ticket at control over an authenticated RPC and forwards content
  // to the relay. It holds no DB, provider credential, or payment access.
  // `gateway-attestation` is the ONLY role that mounts /var/run/dstack.sock.
  // The guest agent is an app-wide key oracle: any container that can reach the
  // socket can derive every key the app uses and mint a quote over arbitrary
  // report data. Isolating it into a single-route process means the relay,
  // which is the component most exposed to hostile input, cannot do either.
  RUNTIME_ROLE: z.enum(["api", "migrate", "control", "control-rpc", "metadata-api", "email-worker", "relay", "venice-worker", "fireworks-worker", "bedrock-worker", "deepinfra-worker", "chutes-worker", "tinfoil-worker", "near-worker", "phala-ai-worker", "compat", "gateway-attestation"]).default("api"),
  PORT: z.coerce.number().int().positive().default(3000),
  HOST: z.string().default("0.0.0.0"),
  // A closed enum, not a free string. `trace`/`debug` were settable in
  // production; no debug content logging exists today, but nothing prevented
  // one being added and switched on. Content roles additionally refuse anything
  // more verbose than `info` in production (see the split-role validation).
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  // Production HTTP services sit behind exactly one Caddy hop. Keep this at
  // zero for direct local development; values above one would let an attacker
  // influence request.ip by prepending addresses to X-Forwarded-For.
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(1).default(0),
  // Internal RPC boundary between roles.
  CONTROL_RPC_URL: z.string().url().default("http://control:3000"),
  WORKER_RPC_URL: z.string().url().default("http://venice-worker:3000"),
  FIREWORKS_WORKER_RPC_URL: z.string().url().default("http://fireworks-worker:3000"),
  BEDROCK_WORKER_RPC_URL: z.string().url().default("http://bedrock-worker:3000"),
  DEEPINFRA_WORKER_RPC_URL: z.string().url().default("http://deepinfra-worker:3000"),
  CHUTES_WORKER_RPC_URL: z.string().url().default("http://chutes-worker:3000"),
  TINFOIL_WORKER_RPC_URL: z.string().url().default("http://tinfoil-worker:3000"),
  NEAR_WORKER_RPC_URL: z.string().url().default("http://near-worker:3000"),
  // `phala-ai` is the Phala INFERENCE PROVIDER, and the hyphen is load-bearing.
  // `phala` throughout this repository means the confidential HOSTING platform
  // (deploy/phala/, the prod5 CVM, docs/PHALA_*.md). One name for both would make
  // "the Phala worker" and "the Phala CVM" the same phrase for different things.
  PHALA_AI_WORKER_RPC_URL: z.string().url().default("http://phala-ai-worker:3000"),
  // The compat broker forwards content to the relay's inference ingress over a
  // dedicated internal network (never the public edge). Distinct from the
  // relay→control/worker RPC URLs above.
  RELAY_INGRESS_URL: z.string().url().default("http://relay:3000"),
  // High-entropy service credentials for the internal RPC (file-backed in prod).
  RELAY_RPC_TOKEN: z.string().optional(),
  RELAY_RPC_TOKEN_FILE: z.string().optional(),
  WORKER_RPC_TOKEN: z.string().optional(),
  WORKER_RPC_TOKEN_FILE: z.string().optional(),
  // Authenticates the compat broker → control ticket-mint RPC. The broker
  // proves it is the audited joiner; the ar_ key it carries proves the user.
  COMPAT_RPC_TOKEN: z.string().optional(),
  COMPAT_RPC_TOKEN_FILE: z.string().optional(),
  // Scoped worker → control channel for catalog/rate-limit metadata and the
  // opaque provider-dispatch fence. It is distinct from relay control RPC.
  METADATA_RPC_TOKEN: z.string().optional(),
  METADATA_RPC_TOKEN_FILE: z.string().optional(),
  // Per-provider metadata tokens. When configured, control binds a catalog push
  // to exactly one provider: a worker may only overwrite its OWN provider's
  // catalog rows, so a single compromised worker cannot re-price or relabel a
  // peer provider's models (AR-02). Each worker presents its own token; control
  // is mounted all configured provider tokens. Optional: when a provider's
  // token is unset the shared METADATA_RPC_TOKEN is used and the strict binding is not
  // enforced, keeping dev/test/monolith single-token deployments working.
  METADATA_RPC_TOKEN_VENICE: z.string().optional(),
  METADATA_RPC_TOKEN_VENICE_FILE: z.string().optional(),
  METADATA_RPC_TOKEN_FIREWORKS: z.string().optional(),
  METADATA_RPC_TOKEN_FIREWORKS_FILE: z.string().optional(),
  METADATA_RPC_TOKEN_BEDROCK: z.string().optional(),
  METADATA_RPC_TOKEN_BEDROCK_FILE: z.string().optional(),
  METADATA_RPC_TOKEN_DEEPINFRA: z.string().optional(),
  METADATA_RPC_TOKEN_DEEPINFRA_FILE: z.string().optional(),
  METADATA_RPC_TOKEN_CHUTES: z.string().optional(),
  METADATA_RPC_TOKEN_CHUTES_FILE: z.string().optional(),
  METADATA_RPC_TOKEN_TINFOIL: z.string().optional(),
  METADATA_RPC_TOKEN_TINFOIL_FILE: z.string().optional(),
  METADATA_RPC_TOKEN_NEAR: z.string().optional(),
  METADATA_RPC_TOKEN_NEAR_FILE: z.string().optional(),
  METADATA_RPC_TOKEN_PHALA_AI: z.string().optional(),
  METADATA_RPC_TOKEN_PHALA_AI_FILE: z.string().optional(),
  // A regional/confidential deployment gets its own metadata capability. The
  // worker presents the token; control loads the complete provider+deployment
  // scope map. This keeps a key id local to the deployment that actually owns
  // it instead of relying on a proxy response rewrite.
  CONFIDENTIAL_DEPLOYMENT_ID: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/).default("primary"),
  METADATA_RPC_DEPLOYMENT_TOKEN: z.string().optional(),
  METADATA_RPC_DEPLOYMENT_TOKEN_FILE: z.string().optional(),
  METADATA_RPC_DEPLOYMENT_SCOPES: z.string().optional(),
  METADATA_RPC_DEPLOYMENT_SCOPES_FILE: z.string().optional(),
  CONTROL_METADATA_URL: z.string().url().default("http://control:3000"),
  CATALOG_SYNC_INTERVAL_SECONDS: z.coerce.number().int().positive().max(86_400).default(300),
  // Gate so exactly one designated worker polls Venice when the service is scaled.
  CATALOG_SYNC_ENABLED: z.enum(["true", "false"]).default("true").transform((value) => value === "true"),
  // Synthetic model health probes: a one-token request per enabled model on a
  // schedule so untouched models still have uptime and stale/down models surface.
  // OFF by default because each probe is a (tiny) billed inference call.
  MODEL_HEALTH_PROBE_INTERVAL_SECONDS: z.coerce.number().int().positive().max(86_400).default(900),
  MODEL_HEALTH_PROBE_ENABLED: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  // The weaker OpenAI-compatible convenience path: the relay authenticates the
  // caller and mints a ticket inline, exposing stable identity to the inference
  // process. Forbidden in production (must fail closed without a ticket).
  ALLOW_INLINE_TICKET: z.enum(["true", "false"]).default("true").transform((value) => value === "true"),
  // Static-key OpenAI-compatibility broker. When false (the default in every
  // environment) the compat broker and the control-side mint RPC both fail
  // closed, so no static ar_ key can drive inference. Unlike ALLOW_INLINE_TICKET
  // this is production-enableable: the relay still sees only an opaque ticket
  // (the broker mints a real single-use ticket at control), so it does not
  // expose stable identity to the content tier. It does concentrate identity and
  // plaintext at the audited broker for compat traffic (see docs/COMPAT_MODE.md).
  ALLOW_COMPAT_MODE: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  // Split-architecture media (image + TTS). Both default OFF everywhere and are
  // enforced server-side and independently at the relay ingress/route and the
  // control authorization. Neither makes a monolith assumption: the prompt,
  // input text, and generated bytes never touch control, the worker holds the
  // provider credential, and control only authorizes and settles the reviewed
  // price. Enable per role in a staged rollout (see docs/SPLIT_MEDIA_IMAGE.md).
  // Missing/false fails closed with a clear 503 media_disabled. The two are
  // separate flags so either surface can be rolled back without the other.
  // (The former MEDIA_ENABLED monolith flag was removed with the monolith
  // speech route: it colocated the credential with identity, which the split
  // topology forbids. An env var of that name is now ignored.)
  IMAGE_GENERATION_ENABLED: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  SPEECH_GENERATION_ENABLED: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),

  // --- Confidential data plane (Phala TDX). See docs/PHALA_CONFIDENTIAL_DATA_PLANE.md.
  //
  // GET /v1/gateway/attestation is registered on the content tier whenever
  // GATEWAY_ATTESTATION_ENABLED is true. It reports 503 rather than 404 when no
  // dstack guest agent is reachable, so "not in an enclave" is visible instead
  // of looking like a routing mistake.
  GATEWAY_ATTESTATION_ENABLED: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  // The public origin clients connect to. Bound into the quote's report_data, so
  // a quote minted for one origin cannot be replayed at another.
  GATEWAY_PUBLIC_ORIGIN: z.string().optional(),
  // The reviewed release this build corresponds to. Verifiers pin it, so it must
  // change with the build and must map to a source commit in the release manifest.
  GATEWAY_RELEASE_ID: z.string().max(128).optional(),
  // Where the caller's TLS session terminates. `gateway-tls` is the honest
  // default: Phala's *.phala.network hostname terminates TLS in Phala's own
  // gateway CVM. Claim `in-tee-tls` only when this CVM terminates TLS itself,
  // which on Phala means reaching it through the `-<port>s` passthrough suffix
  // or a custom domain.
  //
  // This value belongs in the MEASURED compose, not in an environment file. An
  // unmeasured switch that turns on a privacy claim is worth nothing: a
  // verifier reading the attested manifest should be able to see that this
  // deployment terminates its own TLS.
  GATEWAY_TRANSPORT: z.enum(["in-tee-tls", "gateway-tls"]).default("gateway-tls"),
  // Where OUR in-CVM TLS terminator listens, as host:port. The attestation
  // service completes a real handshake against it and reads the SPKI out of the
  // certificate it served.
  //
  // GATEWAY_TLS_SPKI_SHA256 USED TO LIVE HERE AND HAS BEEN DELIBERATELY
  // REMOVED. Environment values are not measured, so accepting the fingerprint
  // as input let a deployer claim in-tee-tls while naming a certificate whose
  // private key sat on another machine: the client observes that SPKI, the
  // quote repeats it, the comparison passes, and the TD has attested to owning
  // a key it never saw. There is now no input that can express that lie.
  GATEWAY_TLS_TERMINATOR: z.string().optional()
    .transform((value) => (value?.trim() ? value.trim() : undefined))
    .refine((value) => value === undefined || /^[a-zA-Z0-9._-]+:\d{1,5}$/.test(value), {
      message: "GATEWAY_TLS_TERMINATOR must be host:port"
    }),
  // Explicit guest-agent endpoint. Empty means probe the standard socket paths
  // (and honor DSTACK_SIMULATOR_ENDPOINT for local development).
  DSTACK_ENDPOINT: z.string().optional(),

  // --- Cross-host RPC deadlines -------------------------------------------
  //
  // Every internal deadline was tuned for a same-host Docker bridge, where a
  // hung peer was effectively impossible. Across a WAN it is not, and two of
  // these hops previously had NO deadline at all. Each of the values below
  // bounds the wait for RESPONSE HEADERS, never the body, so a long streamed
  // generation is not truncated by a transport timeout.
  //
  // Raising these is the correct response to a high-RTT deployment. Lowering
  // them below the provider's own worst case would convert slow generations
  // into spurious failures with an open reservation.
  CONTROL_RPC_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(60_000).default(5_000),
  // Generous on purpose: this bounds the worker's own upstream provider call,
  // which happens before the worker answers the relay.
  // Must exceed the provider deadline the adapters enforce (CHAT_TIMEOUT_MS,
  // 10 minutes): for a non-streaming chat the worker writes headers only
  // AFTER the upstream call completes, so a shorter value here would
  // truncate generations the provider layer explicitly permits.
  WORKER_RPC_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(900_000).default(620_000),
  // The compat broker's forward to the relay wraps the whole inference path.
  RELAY_FORWARD_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(900_000).default(650_000),

  // The database settings are deliberately absent from this schema. They are
  // parsed by src/db/config.ts, which only control-plane roles import, so the
  // confidential content plane never validates or carries them. See the note at
  // the top of that module.
  REDIS_URL: z.string().default("redis://localhost:6379"),
  APP_SECRET: z.string().optional(),
  APP_SECRET_FILE: z.string().optional(),
  EMAIL_HASH_SECRET: z.string().optional(),
  EMAIL_HASH_SECRET_FILE: z.string().optional(),
  EMAIL_ENCRYPTION_KEY: z.string().optional(),
  EMAIL_ENCRYPTION_KEY_FILE: z.string().optional(),
  COOKIE_SECRET: z.string().optional(),
  COOKIE_SECRET_FILE: z.string().optional(),
  BETTER_AUTH_SECRET: z.string().optional(),
  BETTER_AUTH_SECRET_FILE: z.string().optional(),
  AUTH_PUBLIC_URL: z.string().url().default("http://127.0.0.1:3001/api/anonrouter/api/auth"),
  AUTH_COOKIE_PREFIX: z.string().regex(/^[a-zA-Z0-9_-]+$/).default("anonrouter_local"),
  AUTH_REQUIRE_EMAIL_VERIFICATION: z.enum(["true", "false"]).default("true").transform((value) => value === "true"),
  // Social login is opt-in. Credentials alone never enable a provider: this
  // avoids an accidentally mounted secret silently changing the public auth
  // surface, and lets production run securely with verified email only.
  GOOGLE_AUTH_ENABLED: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_ID_FILE: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GOOGLE_CLIENT_SECRET_FILE: z.string().optional(),
  SMTP_HOST: z.string().default("localhost"),
  SMTP_PORT: z.coerce.number().int().positive().max(65_535).default(1025),
  SMTP_SECURE: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  SMTP_USER: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_PASSWORD_FILE: z.string().optional(),
  // Optional additional trust anchor for private/rehearsal SMTP servers. Public
  // production providers should normally rely on the container's system CAs.
  SMTP_TLS_CA_FILE: z.string().optional(),
  AUTH_EMAIL_FROM: z.string().default("AnonRouter <no-reply@localhost>"),
  AUTH_EMAIL_REPLY_TO: z.string().default("AnonRouter Contact <contact@anonrouter.local>"),
  AUTH_EMAIL_OUTBOX_POLL_MS: z.coerce.number().int().min(1_000).max(60_000).default(5_000),
  AUTH_EMAIL_OUTBOX_BATCH_SIZE: z.coerce.number().int().min(1).max(100).default(20),
  // AnonRouter Connect is a separately gated OAuth 2.1/OIDC provider. Merely
  // mounting its secrets never enables the public endpoints.
  CONNECT_ENABLED: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  CONNECT_ISSUER: z.string().url().optional(),
  CONNECT_SUBJECT_KEYS: z.string().optional(),
  CONNECT_SUBJECT_KEYS_FILE: z.string().optional(),
  CONNECT_ACTIVE_SUBJECT_KEY_VERSION: z.string().regex(/^v[1-9][0-9]*$/).default("v1"),
  CONNECT_COOKIE_KEYS: z.string().optional(),
  CONNECT_COOKIE_KEYS_FILE: z.string().optional(),
  CONNECT_JWKS: z.string().optional(),
  CONNECT_JWKS_FILE: z.string().optional(),
  CONNECT_ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3_600).default(900),
  CONNECT_REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(30),
  CONNECT_CODE_TTL_SECONDS: z.coerce.number().int().min(30).max(300).default(120),
  CONNECT_MAX_GRANT_USD: z.coerce.number().positive().max(100_000).default(1_000),
  CONNECT_MAX_GRANT_DAYS: z.coerce.number().int().min(1).max(365).default(365),
  // Scaleway Transactional Email bounce/complaint webhook (Topics & Events / SNS).
  // Disabled until the Scaleway topic + HTTP subscription are provisioned; the
  // receiver route is not even registered while this is false.
  SCALEWAY_WEBHOOK_ENABLED: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  // REQUIRED whenever the receiver is enabled; see validateScalewayWebhookConfig.
  // It stays `optional()` here because the schema is shared with every deployment
  // that leaves the receiver off, and a schema-level `required` would refuse to
  // boot control, relay and every worker over a variable none of them use.
  SCALEWAY_SNS_TOPIC_ARN: z.string().max(512).optional(),
  SCALEWAY_SNS_CERT_HOST: z.string().max(255).default("messaging.s3.fr-par.scw.cloud"),
  // `.scaleway.com`, NOT `.scw.cloud`, and this was a live defect.
  //
  // The certificate host and the confirmation host are DIFFERENT Scaleway domains.
  // Certificates come from the object-storage host
  // `messaging.s3.fr-par.scw.cloud`; the SubscribeURL Scaleway documents is
  // `https://sns.mnq.{region}.scaleway.com/?Action=ConfirmSubscription&...`.
  // Defaulting this suffix to `.scw.cloud` -- reasonable-looking, since it matches
  // the other host -- meant isScalewayCloudUrl() rejected every real SubscribeURL,
  // so the receiver would have refused to confirm its own subscription with
  // `invalid_subscribe_url` and never received a single event. The failure would
  // only have appeared at activation, which is the moment nothing else is known to
  // work either.
  SCALEWAY_SNS_SUBSCRIBE_HOST_SUFFIX: z.string().max(64).default(".scaleway.com"),
  SCALEWAY_WEBHOOK_MAX_SKEW_SECONDS: z.coerce.number().int().min(60).max(86_400).default(3_600),
  // How long one delivery may hold the claim on a MessageId before another
  // delivery may take it over.
  //
  // THIS MUST BE STRICTLY SHORTER THAN THE FRESHNESS WINDOW, and it is a separate
  // setting because it previously was not: the lease was
  // max(60, MAX_SKEW_SECONDS), i.e. the freshness window itself. That made the
  // recovery path unreachable. A redelivery carries the ORIGINAL Timestamp, so by
  // the time a lease of MAX_SKEW had expired, any message able to reclaim it was
  // already older than MAX_SKEW and was rejected as `stale_timestamp` several
  // steps earlier. The takeover branch could never run, and a crashed attempt
  // owned its message forever -- the exact defect the pending/completed split was
  // introduced to fix.
  //
  // 120s by default: comfortably longer than any effect here (one suppression
  // INSERT, or one confirmation GET with a 5s timeout) and far shorter than the
  // 3600s freshness window, leaving a wide band in which a redelivery is both
  // fresh enough to accept and late enough to reclaim.
  SCALEWAY_WEBHOOK_CLAIM_LEASE_SECONDS: z.coerce.number().int().min(5).max(3_600).default(120),
  // Optional privacy-safe operational notification receiver. The application
  // persists transition events regardless; configuring this endpoint enables
  // bounded, retrying off-host delivery without attaching logs or payloads.
  ALERT_RECEIVER_AUTH_MODE: z.enum(["bearer", "url-token"]).optional(),
  ALERT_RECEIVER_URL: z.string().optional(),
  ALERT_RECEIVER_URL_FILE: z.string().optional(),
  ALERT_RECEIVER_TOKEN: z.string().optional(),
  ALERT_RECEIVER_TOKEN_FILE: z.string().optional(),
  ALERT_RECEIVER_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(30_000).default(8_000),
  ADMIN_ACCESS_TOKEN: z.string().min(12).optional(),
  ADMIN_ACCESS_TOKEN_FILE: z.string().optional(),
  ADMIN_ENVIRONMENT: z.enum(["local", "production"]).optional(),
  ADMIN_INSTANCE_ID: z.string().trim().min(1).max(128).default("anonrouter-local"),
  ADMIN_DEPLOYMENT_VERSION: z.string().trim().min(1).max(128).default("development"),
  ADMIN_MUTATIONS_ENABLED: z.enum(["true", "false"]).optional().transform((value) => value === undefined ? undefined : value === "true"),
  // A control process that is NOT the deployment's primary. It serves requests
  // but must never write deployment-wide state.
  //
  // This exists because a second control instance pointed at the same database
  // disabled production's Stripe and crypto reconciliation heartbeat rows: its
  // startup writes enablement for the whole deployment, and because that
  // instance had payments disabled to ease boot validation, it wrote
  // "disabled". Disabling a feature is itself a write, and the row it writes is
  // shared. See docs/POC_PRODUCTION_IMPACT.md.
  //
  // The test environment already suppresses background workers for the same
  // reason ("so they cannot fire mid-test and mutate shared database state").
  // This makes that protection available outside tests.
  SECONDARY_CONTROL_INSTANCE: z.enum(["true", "false"]).optional().transform((value) => value === "true"),
  ADMIN_SESSION_COOKIE_NAME: z.string().regex(/^[a-zA-Z0-9_-]+$/).default("anonrouter_admin_session"),
  ADMIN_SESSION_COOKIE_PATH: z.string().min(1).max(256).default("/v1/admin").superRefine((value, context) => {
    if (!value.startsWith("/") || value.includes("..") || /[;\s\\]/.test(value)) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: "must be an absolute, normalized cookie path" });
    }
  }),
  // Upper bound raised to 7 days (10080) so a WireGuard-only operator can keep a
  // single login valid for a full week. Defaults stay short (12h / 1h) so any
  // environment that does not explicitly opt in keeps the stricter posture; the
  // extended window is applied only via the deployment's ADMIN_* env values.
  ADMIN_SESSION_TTL_MINUTES: z.coerce.number().int().min(5).max(10_080).default(720),
  ADMIN_RECENT_AUTH_MINUTES: z.coerce.number().int().min(1).max(10_080).default(60),
  ADMIN_ADJUSTMENT_APPROVAL_THRESHOLD_CENTS: z.coerce.number().int().positive().default(50_000),
  // Rolling 24h cap on the total CREDIT a single operator may auto-apply via
  // below-threshold balance adjustments before a second approver is forced. The
  // per-request approval threshold alone is bypassable by structuring many
  // sub-threshold credits; once an operator's trailing-24h auto-applied credit
  // plus the current request would cross this cap, the request is routed through
  // the same two-person approval path as an over-threshold adjustment.
  ADMIN_ADJUSTMENT_AUTO_APPLY_DAILY_CAP_CENTS: z.coerce.number().int().positive().default(250_000),
  // Retention for the content-free inference rejection ledger. Detailed
  // provider-rejection events default to 30 days; hourly aggregate rollups to 90.
  // Both are actually enforced by the bounded purge job (see rejectionLedger.ts).
  REJECTION_EVENT_RETENTION_DAYS: z.coerce.number().int().min(1).max(365).default(30),
  REJECTION_ROLLUP_RETENTION_DAYS: z.coerce.number().int().min(1).max(730).default(90),
  SESSION_COOKIE_NAME: z.string().default("anonrouter_session"),
  SESSION_TTL_DAYS: z.coerce.number().int().positive().default(30),
  MOCK_PROVIDER_BASE_URL: z.string().url().default("http://localhost:4010/v1"),
  DEFAULT_PROVIDER: z.string().default("mock"),
  VENICE_INFERENCE_KEY: z.string().optional(),
  VENICE_INFERENCE_API_KEY: z.string().optional(),
  VENICE_API_KEY: z.string().optional(),
  VENICE_INFERENCE_KEY_FILE: z.string().optional(),
  // JSON keyset for multi-credential routing: [{"id":"primary","label":"...","key":"..."}].
  // Takes precedence over the single-key variables above when configured.
  VENICE_INFERENCE_KEYS: z.string().optional(),
  VENICE_INFERENCE_KEYS_FILE: z.string().optional(),
  // Durable operator keyset overlay on the credential worker's one writable
  // mount. Added/removed keys land here so lifecycle changes survive restarts
  // without editing the boot secret.
  VENICE_KEYSET_OVERLAY_FILE: z.string().default("/var/lib/anonrouter-worker/venice-keyset-overlay.json"),
  // Provider-credential administration. In `capability` mode the only way to
  // install, rotate or revoke a provider secret is a signed, single-use, short-
  // lived authorization from the control plane, presented directly to this
  // workload alongside the secret. `legacy` keeps the bearer-token key-push the
  // pre-confidential topology used, where the control plane HELD the credential
  // and sent it to the worker -- which CONTROL_RPC_CONTRACT.md rules out for
  // launch. It stays the default only so existing deployments are unaffected
  // until they opt in; the Phala production compose sets `capability`.
  CREDENTIAL_ADMIN_MODE: z.enum(["legacy", "capability"]).default("legacy"),
  // Pinned Ed25519 capability signers: `<keyId>:<base64 raw public key>`, comma
  // separated. Measured with the rest of the workload configuration, so changing
  // who may authorize a credential installation changes the deployment identity.
  CREDENTIAL_CAPABILITY_SIGNERS: z.string().default(""),
  // SHA-256 of the SubjectPublicKeyInfo this deployment serves on its customer
  // TLS endpoint, lowercase hex. The workload compares a capability's endpoint
  // binding against this, which is what ties "the client verified an attested
  // endpoint" to "the client verified THIS endpoint".
  CONTENT_TLS_SPKI_SHA256: z.string().regex(/^([0-9a-f]{64})?$/).default(""),
  CONSUMED_CAPABILITY_FILE: z.string().default("/var/lib/anonrouter-worker/consumed-capabilities.json"),
  // Control -> worker admin RPC base URL for operator key lifecycle actions.
  // Empty (the default) disables the feature: control then has no path to the
  // credential worker and the admin routes fail closed with a clear 503.
  VENICE_WORKER_URL: z.string().optional(),
  /**
   * Where provider-credential administration terminates.
   *
   * "direct-to-tee" is the launch boundary (O15/D31): the operator's client
   * verifies fresh Phala evidence and in-TEE TLS, gets a short-lived one-use
   * content-free capability from control, and sends the raw secret straight to
   * the attested workload. Control never sees it.
   *
   * "legacy-control-terminating" is the pre-launch path, where the secret
   * transits control on its way to the credential worker. It cannot launch on
   * GCP, so enabling it is a deliberate, visible act rather than a default.
   */
  PROVIDER_CREDENTIAL_ADMIN_MODE: z.enum(["direct-to-tee", "legacy-control-terminating"]).default("direct-to-tee"),
  /**
   * Ed25519 signing key for credential capabilities, raw 32 bytes as hex.
   *
   * Generated INSIDE the admitted guest and persisted under the application
   * envelope hierarchy; it is not part of the bootstrap bundle. Absent means
   * capability issuance fails closed rather than falling back to the legacy
   * secret-bearing path.
   */
  PROVIDER_CAPABILITY_SIGNING_KEY: z.string().optional(),
  PROVIDER_CAPABILITY_SIGNING_KEY_ID: z.string().default("capability-v1"),
  VENICE_BASE_URL: z.string().url().default("https://api.venice.ai/api/v1"),
  VENICE_DEFAULT_MODEL: z.string().default("llama-3.3-70b"),
  // Fireworks open-model Chat Completions. The adapter deliberately never uses
  // the Responses API because its default persistence policy differs.
  FIREWORKS_API_KEY: z.string().optional(),
  FIREWORKS_API_KEY_FILE: z.string().optional(),
  FIREWORKS_BASE_URL: z.string().url().default("https://api.fireworks.ai/inference/v1"),
  // DeepInfra open-model inference via its OpenAI-compatible Chat Completions API.
  // The adapter uses only the standard chat path and never DeepInfra's bulk/batch
  // endpoints, keeping requests under DeepInfra's memory-only, delete-after-request
  // handling (classified `private`).
  DEEPINFRA_API_KEY: z.string().optional(),
  DEEPINFRA_API_KEY_FILE: z.string().optional(),
  DEEPINFRA_BASE_URL: z.string().url().default("https://api.deepinfra.com/v1/openai"),
  // Chutes decentralized inference (OpenAI-compatible Chat Completions +
  // embeddings). Confidential-compute routes run in an attested Intel TDX +
  // NVIDIA CC enclave; attestation evidence is fetched from a separate public host.
  CHUTES_API_KEY: z.string().optional(),
  CHUTES_API_KEY_FILE: z.string().optional(),
  CHUTES_BASE_URL: z.string().url().default("https://llm.chutes.ai/v1"),
  CHUTES_ATTESTATION_BASE_URL: z.string().url().default("https://api.chutes.ai"),
  // Tinfoil confidential inference. The standard route runs in a verified
  // SEV-SNP + NVIDIA CC enclave (classified `tee`); the official `tinfoil` SDK is
  // the attestation root of trust (loaded via a guarded dynamic import).
  TINFOIL_API_KEY: z.string().optional(),
  TINFOIL_API_KEY_FILE: z.string().optional(),
  TINFOIL_BASE_URL: z.string().url().default("https://inference.tinfoil.sh/v1"),
  TINFOIL_CONFIG_REPO: z.string().default("tinfoilsh/confidential-model-router"),
  // NEAR AI Cloud. Direct confidential routes ({slug}.completions.near.ai)
  // terminate TLS inside the model TEE and expose per-request signatures; the
  // gateway serves attested-3p routes. The endpoints map resolves direct hosts.
  NEAR_API_KEY: z.string().optional(),
  NEAR_API_KEY_FILE: z.string().optional(),
  NEAR_BASE_URL: z.string().url().default("https://cloud-api.near.ai/v1"),
  NEAR_ENDPOINTS_URL: z.string().url().default("https://completions.near.ai/endpoints"),
  // Phala AI: an OpenAI-compatible AGGREGATOR gateway, classified `private`.
  // It decrypts downstream traffic at its frontend before forwarding upstream and
  // its published TDX evidence attests that gateway (zero GPUs, no model bound),
  // so no `tee`/`e2ee` claim is made and no verifier is registered for it. Not to
  // be confused with the Phala platform that HOSTS this deployment.
  PHALA_AI_API_KEY: z.string().optional(),
  PHALA_AI_API_KEY_FILE: z.string().optional(),
  PHALA_AI_BASE_URL: z.string().url().default("https://inference.phala.com/v1"),
  // Bedrock Mantle is SigV4-authenticated through the AWS default credential
  // chain. Local development may select an SSO profile; production must use the
  // bedrock-worker's workload role and never a long-lived static key.
  BEDROCK_ENABLED: optionalBooleanSwitch,
  BEDROCK_REGION: z.string().regex(/^[a-z]{2}-[a-z]+-\d$/).default("us-east-1"),
  BEDROCK_BASE_URL: z.string().url().optional(),
  // docker-compose supplies an empty string when no local profile is selected;
  // normalize that to absence so workload/env credentials remain usable.
  BEDROCK_AWS_PROFILE: z.preprocess(
    (value) => value === "" ? undefined : value,
    z.string().trim().min(1).max(128).optional()
  ),
  BEDROCK_RETENTION_CHECK_TTL_SECONDS: z.coerce.number().int().min(5).max(300).default(30),
  PAYMENTS_MODE: z.enum(["disabled", "sandbox", "live"]).default("disabled"),
  // Runtime acceptance switches are separate from PAYMENTS_MODE so an
  // operator can freeze new charges without taking signed webhooks, refunds,
  // or reconciliation offline. Sandbox defaults these on for local ergonomics;
  // live mode defaults them off until each rail is deliberately opened.
  STRIPE_PURCHASES_ENABLED: optionalBooleanSwitch,
  STRIPE_AUTO_TOP_UP_ENABLED: optionalBooleanSwitch,
  APP_BASE_URL: z.string().url().default("http://localhost:3001"),
  MINIMUM_CREDIT_PURCHASE_USD: z.coerce.number().int().positive().max(10_000).default(1),
  MAXIMUM_CREDIT_PURCHASE_USD: z.coerce.number().int().positive().max(100_000).default(1_000),
  PROMOTION_MAX_CREDIT_CENTS: z.coerce.number().int().positive().max(1_000_000).default(50_000),
  PROMOTION_MAX_CAMPAIGN_CENTS: z.coerce.number().int().positive().max(1_000_000_000).default(5_000_000),
  STRIPE_API_KEY: z.string().optional(),
  STRIPE_API_KEY_FILE: z.string().optional(),
  STRIPE_PUBLISHABLE_KEY: z.string().optional(),
  STRIPE_PUBLISHABLE_KEY_FILE: z.string().optional(),
  STRIPE_WEBHOOK_SECRET: z.string().optional(),
  STRIPE_WEBHOOK_SECRET_FILE: z.string().optional(),
  CRYPTO_PAYMENTS_MODE: z.enum(["disabled", "sandbox", "live"]).default("disabled"),
  // This switch controls both customer-facing rail visibility and creation of
  // new BTCPay invoices. It never disables webhook/manual-resolution or
  // reconciliation paths for invoices that may already hold funds.
  CRYPTO_INVOICES_ENABLED: optionalBooleanSwitch,
  CRYPTO_ENABLED_RAILS: z.string().optional(),
  // Fail-closed global cap on crypto credits granted per rolling 24h for the
  // private beta. Settlement that would exceed it quarantines instead.
  CRYPTO_MAX_DAILY_CREDIT_USD: z.coerce.number().positive().max(1_000_000).default(250),
  BTCPAY_INTERNAL_URL: z.string().optional(),
  BTCPAY_PUBLIC_URL: z.string().optional(),
  BTCPAY_STORE_ID: z.string().optional(),
  BTCPAY_API_KEY: z.string().optional(),
  BTCPAY_API_KEY_FILE: z.string().optional(),
  BTCPAY_WEBHOOK_SECRET: z.string().optional(),
  BTCPAY_WEBHOOK_SECRET_FILE: z.string().optional(),
  // Secure default: public signup must not mint spendable provider credit.
  // Local development may opt in explicitly for fixture convenience.
  REGISTERED_FREE_CREDITS_USD: z.coerce.number().nonnegative().default(0),
  FREE_TIER_DAILY_TOKENS: z.coerce.number().int().nonnegative().default(20_000),
  // Model-locked trial chat for new registered accounts: a one-time
  // entitlement (NOT wallet credit) pinned to one model + provider with hard
  // reply/token/spend caps. Off by default; enabling only ever exposes the
  // per-account spend ceiling, not general provider credit.
  TRIAL_CHAT_ENABLED: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  TRIAL_CHAT_MODEL: z.string().default("openai/gpt-oss-120b"),
  TRIAL_CHAT_PROVIDER: z.string().default("tinfoil"),
  TRIAL_CHAT_REPLIES: z.coerce.number().int().positive().max(64).default(8),
  TRIAL_CHAT_MAX_OUTPUT_TOKENS: z.coerce.number().int().positive().max(32_768).default(1024),
  // Cumulative prompt-token budget for the whole trial. Prompt tokens include
  // the transcript resent every turn, so this sits well above the user-typed
  // allowance the client enforces (~2k tokens).
  TRIAL_CHAT_INPUT_TOKEN_BUDGET: z.coerce.number().int().positive().default(48_000),
  TRIAL_CHAT_SPEND_CEILING_USD: z.coerce.number().positive().max(1).default(0.02),
  TRIAL_CHAT_DAYS: z.coerce.number().int().positive().max(90).default(7),
  ROUTER_ENABLED: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  ROUTER_MODEL_CACHE_DIR: z.string().default(".cache/router-models"),
  ROUTER_ARTIFACT_PATH: z.string().default("src/routing/artifacts/embeddinggemma-q4-v1.json"),
  ROUTER_ALLOW_REMOTE_MODELS: z.enum(["true", "false"]).default("false").transform((value) => value === "true"),
  ROUTER_CONFIDENCE_THRESHOLD: z.coerce.number().min(0).max(1).default(0.55),
  ROUTER_MAX_INPUT_CHARS: z.coerce.number().int().positive().max(100_000).default(12_000),
  ROUTER_TIMEOUT_MS: z.coerce.number().int().positive().max(10_000).default(100),
  ROUTER_MAX_QUEUE: z.coerce.number().int().positive().max(10_000).default(8),
  REQUEST_BODY_LIMIT_BYTES: z.coerce.number().int().positive().default(1_000_000),
  CORS_ORIGIN: z.string().default("http://localhost:3000"),
  // Edge / abuse hardening (see docs/SECURITY_HARDENING.md). All default to
  // dev-safe behavior: CSRF is on only in production, the proof-of-work bot
  // check is off unless explicitly enabled, and the challenge cost is bounded.
  CSRF_ENABLED: z.enum(["true", "false"]).optional(),
  APP_ORIGIN: z.string().optional(),
  CAPTCHA_ENABLED: z.enum(["true", "false"]).optional(),
  CAPTCHA_SECRET: z.string().optional(),
  CAPTCHA_SECRET_FILE: z.string().optional(),
  CAPTCHA_MAX_NUMBER: z.coerce.number().int().positive().max(10_000_000).default(50_000),
  CAPTCHA_CHALLENGE_TTL_SECONDS: z.coerce.number().int().positive().max(3600).default(300),
  MOCK_PROVIDER_PORT: z.coerce.number().int().positive().default(4010),
  MOCK_PROVIDER_HOST: z.string().default("0.0.0.0")
});

/**
 * Everything `loadConfig()` parses: the settings any role may hold.
 *
 * This excludes the database, which control-plane roles add via
 * `loadAppConfig()` in src/appConfig.ts. The content plane loads exactly this
 * and no more.
 */
export type SharedConfig = ReturnType<typeof loadConfig>;

/**
 * How to reach PostgreSQL.
 *
 * The SHAPE is written out here rather than imported from src/db/config.ts on
 * purpose: importing the type would put that module into the content plane's
 * compile closure, which is exactly what published the connection-string
 * literal into the public export. Field names are not environment variables and
 * carry no value. The parsing, the variable names and the development fallbacks
 * all live in src/db/config.ts, which builds this shape, so each still has one
 * definition.
 */
export type DatabaseSettings = {
  readonly url: string;
  readonly migrationUrl: string;
  readonly appUser: string;
  readonly appPassword: string;
};

/**
 * The configuration type shared code is written against.
 *
 * `db` is OPTIONAL because it genuinely is: a relay, compat broker or provider
 * worker has no database, and since the settings left `loadConfig()` there is
 * nothing to populate it with on those roles. Optionality here is not laxity,
 * it is the type telling the truth. Code that actually opens a connection asks
 * for `ControlPlaneConfig` instead and gets a compile error if handed a content
 * role's configuration.
 */
export type AppConfig = SharedConfig & {
  readonly db?: DatabaseSettings;
};

/**
 * The configuration of a role that owns a database, produced only by
 * `loadAppConfig()` in src/appConfig.ts.
 */
export type ControlPlaneConfig = SharedConfig & {
  readonly db: DatabaseSettings;
};

export function sensitiveValue(params: { key: string; direct?: string; file?: string; fallback?: string }) {
  if (params.direct !== undefined && params.file !== undefined) {
    throw new Error(`${params.key} and ${params.key}_FILE cannot both be configured`);
  }
  if (params.file !== undefined) {
    const value = readFileSync(params.file, "utf8").trim();
    if (!value) throw new Error(`${params.key}_FILE is empty`);
    return value;
  }
  return params.direct ?? params.fallback ?? "";
}

function validateProductionSecrets(entries: Array<{ key: string; value: string; explicitlyConfigured: boolean }>) {
  const problems: string[] = [];
  const missing = entries.filter((entry) => !entry.explicitlyConfigured).map((entry) => entry.key);
  const short = entries.filter((entry) => Buffer.byteLength(entry.value, "utf8") < 32).map((entry) => entry.key);
  const placeholders = entries
    .filter((entry) => /dev-only|change-me|replace-with|local-admin/i.test(entry.value))
    .map((entry) => entry.key);
  const keysByValue = new Map<string, string[]>();

  for (const entry of entries) {
    keysByValue.set(entry.value, [...(keysByValue.get(entry.value) ?? []), entry.key]);
  }
  const reused = [...keysByValue.values()].filter((keys) => keys.length > 1).flat();

  if (missing.length > 0) problems.push(`missing: ${missing.join(", ")}`);
  if (short.length > 0) problems.push(`shorter than 32 bytes: ${short.join(", ")}`);
  if (placeholders.length > 0) problems.push(`placeholder values: ${placeholders.join(", ")}`);
  if (reused.length > 0) problems.push(`reused values: ${reused.join(", ")}`);

  if (problems.length > 0) {
    throw new Error(`Production secrets are not configured safely (${problems.join("; ")})`);
  }
}

function parseConnectSubjectKeys(raw: string, activeVersion: string) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("CONNECT_SUBJECT_KEYS must be a JSON object of versioned secrets");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("CONNECT_SUBJECT_KEYS must be a JSON object of versioned secrets");
  }
  const keys: Record<string, string> = {};
  for (const [version, value] of Object.entries(parsed)) {
    if (!/^v[1-9][0-9]*$/.test(version) || typeof value !== "string" || Buffer.byteLength(value, "utf8") < 32) {
      throw new Error("CONNECT_SUBJECT_KEYS entries require vN names and secrets of at least 32 bytes");
    }
    keys[version] = value;
  }
  if (!keys[activeVersion]) {
    throw new Error("CONNECT_ACTIVE_SUBJECT_KEY_VERSION is not present in CONNECT_SUBJECT_KEYS");
  }
  return keys;
}

function parseConnectCookieKeys(raw: string) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("CONNECT_COOKIE_KEYS must be a JSON array of secrets");
  }
  if (
    !Array.isArray(parsed)
    || parsed.length < 2
    || parsed.some((value) => typeof value !== "string" || Buffer.byteLength(value, "utf8") < 32)
    || new Set(parsed).size !== parsed.length
  ) {
    throw new Error("CONNECT_COOKIE_KEYS requires at least two distinct secrets of at least 32 bytes");
  }
  return parsed as string[];
}

function parseConnectJwks(raw: string) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("CONNECT_JWKS must be a private JSON Web Key Set");
  }
  const keys = (parsed as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error("CONNECT_JWKS must contain at least one private signing key");
  }
  const kids = new Set<string>();
  for (const entry of keys) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("CONNECT_JWKS contains an invalid key");
    }
    const key = entry as Record<string, unknown>;
    if (typeof key.kid !== "string" || !key.kid || typeof key.kty !== "string" || !key.kty || typeof key.d !== "string" || !key.d) {
      throw new Error("CONNECT_JWKS keys require unique kid, kty, and private key material");
    }
    if (kids.has(key.kid)) throw new Error("CONNECT_JWKS key ids must be unique");
    kids.add(key.kid);
  }
  return { keys: keys as Array<Record<string, unknown>> };
}

export interface MetadataDeploymentScope {
  deploymentId: string;
  provider: string;
  token: string;
}

const DEPLOYMENT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const METADATA_SCOPE_PROVIDERS = new Set([
  "venice", "fireworks", "aws-bedrock", "deepinfra", "chutes", "tinfoil", "near-ai", "phala-ai"
]);

/** Parse the control-only map of regional worker capabilities. */
export function parseMetadataDeploymentScopes(raw: string, source: string): MetadataDeploymentScope[] {
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${source} is not valid JSON`);
  }
  if (!Array.isArray(parsed)) throw new Error(`${source} must be a JSON array`);
  const pairs = new Set<string>();
  const tokens = new Set<string>();
  return parsed.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${source}[${index}] must be an object`);
    }
    const candidate = entry as Record<string, unknown>;
    const deploymentId = candidate.deploymentId;
    const provider = candidate.provider;
    const token = candidate.token;
    if (typeof deploymentId !== "string" || !DEPLOYMENT_ID_PATTERN.test(deploymentId)) {
      throw new Error(`${source}[${index}].deploymentId is invalid`);
    }
    if (typeof provider !== "string" || !METADATA_SCOPE_PROVIDERS.has(provider)) {
      throw new Error(`${source}[${index}].provider is invalid`);
    }
    if (typeof token !== "string" || Buffer.byteLength(token, "utf8") < 32
      || /dev-only|change-me|replace-with/i.test(token)) {
      throw new Error(`${source}[${index}].token must be a non-placeholder value of at least 32 bytes`);
    }
    const pair = `${deploymentId}\0${provider}`;
    if (pairs.has(pair)) throw new Error(`${source} contains duplicate deployment/provider scope`);
    if (tokens.has(token)) throw new Error(`${source} contains a reused token`);
    pairs.add(pair);
    tokens.add(token);
    return { deploymentId, provider, token };
  });
}

function validateStripeConfig(params: {
  mode: "sandbox" | "live";
  nodeEnv: "development" | "test" | "production";
  appBaseUrl: string;
  apiKey: string;
  publishableKey: string;
  webhookSecret: string;
  apiKeyFromFile: boolean;
  publishableKeyFromFile: boolean;
  webhookSecretFromFile: boolean;
}) {
  const problems: string[] = [];
  const sandboxKey = /^(sk|rk)_test_/.test(params.apiKey);
  const liveKey = /^rk_live_/.test(params.apiKey);
  const sandboxPublishableKey = /^pk_test_/.test(params.publishableKey);
  const livePublishableKey = /^pk_live_/.test(params.publishableKey);

  if (params.mode === "sandbox" && !sandboxKey) {
    problems.push("sandbox mode requires an sk_test_ or rk_test_ API key");
  }
  if (params.mode === "live" && !liveKey) {
    problems.push("live mode requires an rk_live_ restricted API key");
  }
  if (params.mode === "sandbox" && !sandboxPublishableKey) {
    problems.push("sandbox mode requires a pk_test_ publishable key");
  }
  if (params.mode === "live" && !livePublishableKey) {
    problems.push("live mode requires a pk_live_ publishable key");
  }
  if (!params.webhookSecret.startsWith("whsec_")) {
    problems.push("webhook secret must start with whsec_");
  }
  if (params.apiKey.length < 24 || /\s/.test(params.apiKey)) {
    problems.push("API key is malformed");
  }
  if (params.publishableKey.length < 24 || /\s/.test(params.publishableKey)) {
    problems.push("publishable key is malformed");
  }
  if (params.webhookSecret.length < 24 || /\s/.test(params.webhookSecret)) {
    problems.push("webhook secret is malformed");
  }
  if (params.mode === "live" && params.nodeEnv !== "production") {
    problems.push("live payments require NODE_ENV=production");
  }
  if (params.mode === "live" && new URL(params.appBaseUrl).protocol !== "https:") {
    problems.push("live payments require an HTTPS APP_BASE_URL");
  }
  if (
    params.mode === "live"
    && (!params.apiKeyFromFile || !params.publishableKeyFromFile || !params.webhookSecretFromFile)
  ) {
    problems.push("live payments require file-backed Stripe API, publishable, and webhook credentials");
  }

  if (problems.length > 0) {
    throw new Error(`Stripe payment configuration is invalid (${problems.join("; ")})`);
  }
}

const knownCryptoRails = ["btc_onchain", "btc_lightning", "xmr"] as const;
export type ConfiguredCryptoRail = (typeof knownCryptoRails)[number];

/**
 * Server-authoritative rail enablement. Monero runs as a community plugin
 * inside the BTCPay process, so it is excluded from the production trust
 * boundary: live mode defaults to (and only permits) the Bitcoin rails until
 * an independently verified Monero architecture passes its own review.
 * Historical sandbox XMR records remain schema-readable, but no runtime mode
 * offers or credits XMR for the production launch.
 */
function resolveCryptoRails(_mode: "sandbox" | "live", raw: string | undefined): ConfiguredCryptoRail[] {
  const fallback: ConfiguredCryptoRail[] = ["btc_onchain", "btc_lightning"];
  if (raw === undefined || raw.trim() === "") return fallback;
  const requested = raw.split(",").map((value) => value.trim()).filter(Boolean);
  const problems: string[] = [];
  const rails: ConfiguredCryptoRail[] = [];
  for (const entry of requested) {
    if (!knownCryptoRails.includes(entry as ConfiguredCryptoRail)) {
      problems.push(`unknown rail: ${entry}`);
    } else if (!rails.includes(entry as ConfiguredCryptoRail)) {
      rails.push(entry as ConfiguredCryptoRail);
    }
  }
  if (rails.length === 0) problems.push("at least one rail is required");
  if (rails.includes("xmr")) {
    problems.push("xmr cannot be enabled: the Monero plugin is outside the production launch trust boundary");
  }
  if (problems.length > 0) {
    throw new Error(`Crypto payment configuration is invalid (CRYPTO_ENABLED_RAILS: ${problems.join("; ")})`);
  }
  return rails;
}

/**
 * The Scaleway receiver may not start without an exact topic to trust.
 *
 * THE FAIL-OPEN THIS CLOSES. `SCALEWAY_SNS_TOPIC_ARN` was optional and the route
 * only rejected a topic MISMATCH -- `cfg.topicArn && message.TopicArn && ...`. So
 * a deployment that enabled the receiver and forgot the ARN got a receiver that
 * accepted a signed message from ANY Scaleway topic, including a topic created by
 * a different Scaleway customer, and the misconfiguration was invisible: nothing
 * logged, nothing refused, and the happy path looked identical.
 *
 * The certificate chain proves the message came from Scaleway's messaging
 * infrastructure. It says nothing about WHOSE topic it came from. The topic ARN is
 * the only field that distinguishes our events from any other tenant's, so without
 * it a valid signature from a stranger's topic is indistinguishable from ours.
 *
 * Enabled-without-ARN is therefore a startup failure rather than a warning: the
 * only safe states are "off" and "on with an exact topic", and a receiver that is
 * on but trusts everything is the state this refuses to be in.
 */
function validateScalewayWebhookConfig(params: {
  enabled: boolean;
  topicArn: string | undefined;
  certHost: string;
  subscribeHostSuffix: string;
  maxSkewSeconds: number;
  claimLeaseSeconds: number;
}) {
  if (!params.enabled) return;
  const problems: string[] = [];

  const topicArn = params.topicArn ?? "";
  if (topicArn.length === 0) {
    problems.push("SCALEWAY_SNS_TOPIC_ARN is required when SCALEWAY_WEBHOOK_ENABLED=true");
  } else {
    // Surrounding or embedded whitespace is refused rather than trimmed. The route
    // compares this value byte-for-byte against the message field, so a value that
    // is silently normalised here and not there would never match, and the failure
    // would present as "every legitimate event is rejected" long after deploy.
    if (topicArn !== topicArn.trim() || /\s/.test(topicArn)) {
      problems.push("SCALEWAY_SNS_TOPIC_ARN must not contain whitespace");
    }
    // Placeholders are the realistic way this goes wrong: a template copied into an
    // env file with the sample value left in, which would then be the exact string
    // the receiver trusts.
    if (/^(changeme|placeholder|todo|xxx+|<.*>|arn:scw:sns:REGION)/i.test(topicArn)) {
      problems.push("SCALEWAY_SNS_TOPIC_ARN still holds a placeholder value");
    }
  }

  if (params.certHost.length === 0 || /\s/.test(params.certHost)) {
    problems.push("SCALEWAY_SNS_CERT_HOST must be a non-empty hostname");
  }
  // THE LEASE MUST EXPIRE WHILE A REDELIVERY IS STILL FRESH ENOUGH TO ACCEPT.
  //
  // A redelivery carries the original Timestamp, so it is rejected once it is
  // older than the freshness window. If the lease were as long as -- or longer
  // than -- that window, every message able to reclaim an expired lease would
  // already have been refused as stale, and the takeover path would be dead code
  // that reads as if it worked. Requiring a strict inequality here is what keeps
  // a band of time in which reclaim is actually reachable.
  if (params.claimLeaseSeconds >= params.maxSkewSeconds) {
    problems.push(
      `SCALEWAY_WEBHOOK_CLAIM_LEASE_SECONDS (${params.claimLeaseSeconds}) must be strictly less `
      + `than SCALEWAY_WEBHOOK_MAX_SKEW_SECONDS (${params.maxSkewSeconds}), or a stale claim `
      + "can never be reclaimed by a message that is still fresh enough to accept");
  }

  if (!params.subscribeHostSuffix.startsWith(".")) {
    // A suffix without the leading dot turns a suffix test into a substring test:
    // "scw.cloud" would accept "evil-scw.cloud".
    problems.push("SCALEWAY_SNS_SUBSCRIBE_HOST_SUFFIX must begin with a dot");
  }

  if (problems.length > 0) {
    throw new Error(`Scaleway webhook configuration is invalid (${problems.join("; ")})`);
  }
}

function validateCryptoPaymentConfig(params: {
  mode: "sandbox" | "live";
  nodeEnv: "development" | "test" | "production";
  appBaseUrl: string;
  internalUrl: string;
  publicUrl: string;
  storeId: string;
  apiKey: string;
  webhookSecret: string;
  apiKeyFromFile: boolean;
  webhookSecretFromFile: boolean;
}) {
  const problems: string[] = [];

  const parsedUrl = (value: string, key: string) => {
    try {
      return new URL(value);
    } catch {
      problems.push(`${key} must be a valid URL`);
      return null;
    }
  };

  if (!params.internalUrl) problems.push("BTCPAY_INTERNAL_URL is required");
  if (!params.publicUrl) problems.push("BTCPAY_PUBLIC_URL is required");
  if (!params.storeId) problems.push("BTCPAY_STORE_ID is required");
  if (!params.apiKey) problems.push("BTCPay API key is required");
  if (params.webhookSecret.length < 24) {
    problems.push("BTCPay webhook secret must be at least 24 characters");
  }

  const internal = params.internalUrl ? parsedUrl(params.internalUrl, "BTCPAY_INTERNAL_URL") : null;
  const publicCheckout = params.publicUrl ? parsedUrl(params.publicUrl, "BTCPAY_PUBLIC_URL") : null;

  const requireOriginOnly = (url: URL | null, key: string) => {
    if (!url) return;
    if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
      problems.push(`${key} must be an origin only (no credentials, path, query, or fragment)`);
    }
  };
  requireOriginOnly(internal, "BTCPAY_INTERNAL_URL");
  requireOriginOnly(publicCheckout, "BTCPAY_PUBLIC_URL");
  if (internal && internal.protocol !== "https:" && internal.protocol !== "http:") {
    problems.push("BTCPAY_INTERNAL_URL must be an http(s) URL");
  }

  if (params.mode === "live") {
    if (params.nodeEnv !== "production") problems.push("live crypto payments require NODE_ENV=production");
    if (publicCheckout && publicCheckout.protocol !== "https:") {
      problems.push("live crypto payments require an HTTPS BTCPAY_PUBLIC_URL");
    }
    if (publicCheckout && ["localhost", "127.0.0.1", "[::1]"].includes(publicCheckout.hostname.toLowerCase())) {
      problems.push("live crypto payments require a non-local BTCPAY_PUBLIC_URL");
    }
    if (internal && internal.origin !== "http://gateway:23001") {
      problems.push("live BTCPAY_INTERNAL_URL must be exactly http://gateway:23001");
    }
    try {
      if (new URL(params.appBaseUrl).protocol !== "https:") {
        problems.push("live crypto payments require an HTTPS APP_BASE_URL");
      }
    } catch {
      problems.push("APP_BASE_URL must be a valid URL");
    }
    if (!params.apiKeyFromFile) problems.push("live mode requires BTCPAY_API_KEY_FILE (file-backed credentials only)");
    if (!params.webhookSecretFromFile) {
      problems.push("live mode requires BTCPAY_WEBHOOK_SECRET_FILE (file-backed credentials only)");
    }
  }

  if (problems.length > 0) {
    throw new Error(`Crypto payment configuration is invalid (${problems.join("; ")})`);
  }
}

/** `host:port` for the in-CVM TLS terminator the attestation service observes. */
function parseTlsTerminator(value: string | undefined): { host: string; port: number } | null {
  if (!value) return null;
  const index = value.lastIndexOf(":");
  return {
    host: value.slice(0, index),
    port: Number(value.slice(index + 1))
  };
}

/**
 * The ordered, de-spaced list of public origins this workload may attest to.
 *
 * ONE PARSER, because three call sites read this value: the production
 * validation above, the config object below, and the attestation service's own
 * assertion that a requested origin is one it serves. Three copies of a split
 * is how `CORS_ORIGIN` ended up with two of its readers not trimming, which
 * produced an entry that could never equal an Origin header while every file
 * involved still read as correct.
 *
 * ORDER IS MEANING: the first entry is CANONICAL and is what a document binds
 * when the caller's Host header names nothing this workload recognises.
 */
export function gatewayPublicOrigins(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim().replace(/\/$/, ""))
    .filter(Boolean);
}

/**
 * The one way to read `CORS_ORIGIN` as a list.
 *
 * `CORS_ORIGIN` became a MULTI-ENTRY list when the GCP control plane split the
 * API origin (`https://api.anonrouter.ai`, where the session cookie lives) from
 * the browser site origin (`https://anonrouter.ai`, which must be allowed to
 * call it). Before that it was effectively always one value, so the difference
 * between `split(",")` and a trimmed split never showed.
 *
 * It shows now, and it shows SILENTLY: an entry rendered as `a, b` yields
 * `" b"`, which can never equal an Origin header, so the browser is refused
 * while every file involved still reads as correct. Three call sites split this
 * string; two of them did not trim. Exported so there is one answer rather than
 * three copies that can drift apart again.
 */
export function corsAllowlist(value: string): string[] {
  return value.split(",").map((origin) => origin.trim()).filter(Boolean);
}

/**
 * Roles that serve the public metadata surface: the website's API, signup and
 * login, API-key administration, billing and the admin console. These owe the
 * full production auth contract because they actually expose it.
 */
export const SERVES_PUBLIC_AUTH = new Set(["api", "control", "metadata-api"]);

/**
 * Roles that actually open an SMTP connection. `email-worker` is the separated
 * outbox; the public metadata service hands mail to the outbox table and never
 * dials a mail server itself, which is what lets its egress stay closed.
 */
export const SENDS_EMAIL = new Set(["api", "control", "email-worker"]);

/**
 * Roles that terminate HTTP behind exactly one trusted edge. `control-rpc` is
 * included: its edge is the in-guest mTLS terminator on the bridge.
 */
export const HTTP_EDGE_ROLES = new Set([
  "api", "control", "control-rpc", "metadata-api", "relay", "compat"
]);

export function loadConfig() {
  const env = envSchema.parse(process.env);
  if (
    env.NODE_ENV === "production"
    && HTTP_EDGE_ROLES.has(env.RUNTIME_ROLE)
    && env.TRUST_PROXY_HOPS !== 1
  ) {
    throw new Error("Production HTTP services require TRUST_PROXY_HOPS=1 (the single trusted Caddy edge)");
  }
  if (env.MAXIMUM_CREDIT_PURCHASE_USD < env.MINIMUM_CREDIT_PURCHASE_USD) {
    throw new Error("MAXIMUM_CREDIT_PURCHASE_USD must be at least MINIMUM_CREDIT_PURCHASE_USD");
  }
  const appSecret = sensitiveValue({
    key: "APP_SECRET",
    direct: env.APP_SECRET,
    file: env.APP_SECRET_FILE,
    fallback: "dev-only-app-secret-change-me-32-bytes"
  });
  const emailHashSecret = sensitiveValue({
    key: "EMAIL_HASH_SECRET",
    direct: env.EMAIL_HASH_SECRET,
    file: env.EMAIL_HASH_SECRET_FILE,
    fallback: appSecret
  });
  const emailEncryptionKey = sensitiveValue({
    key: "EMAIL_ENCRYPTION_KEY",
    direct: env.EMAIL_ENCRYPTION_KEY,
    file: env.EMAIL_ENCRYPTION_KEY_FILE,
    fallback: appSecret
  });
  const cookieSecret = sensitiveValue({
    key: "COOKIE_SECRET",
    direct: env.COOKIE_SECRET,
    file: env.COOKIE_SECRET_FILE,
    fallback: appSecret
  });
  // HMAC key that signs proof-of-work captcha challenges. Falls back to
  // APP_SECRET so local dev works with no extra configuration; production
  // deployments should set a distinct value.
  const captchaSecret = sensitiveValue({
    key: "CAPTCHA_SECRET",
    direct: env.CAPTCHA_SECRET,
    file: env.CAPTCHA_SECRET_FILE,
    fallback: appSecret
  });
  // Trusted browser origins for the CSRF Origin check. Falls back to the CORS
  // allowlist. Defense-in-depth defaults: CSRF on in production (cookie
  // requests must carry a same-origin Origin/Referer), off in dev/test so local
  // tooling and the suite need no Origin header. The proof-of-work bot check is
  // off unless explicitly enabled, so local signup stays frictionless.
  const appOrigins = (env.APP_ORIGIN ?? env.CORS_ORIGIN)
    .split(",")
    .map((origin) => origin.trim().replace(/\/$/, ""))
    .filter(Boolean);
  const csrfEnabled = env.CSRF_ENABLED ? env.CSRF_ENABLED === "true" : env.NODE_ENV === "production";
  const captchaEnabled = env.CAPTCHA_ENABLED === "true";
  const betterAuthSecret = sensitiveValue({
    key: "BETTER_AUTH_SECRET",
    direct: env.BETTER_AUTH_SECRET,
    file: env.BETTER_AUTH_SECRET_FILE,
    fallback: "dev-only-better-auth-secret-change-me"
  });
  const connectIssuer = (env.CONNECT_ISSUER ?? `${env.APP_BASE_URL.replace(/\/$/, "")}/api/anonrouter/connect`).replace(/\/$/, "");
  let connectSubjectKeys: Record<string, string> = {};
  let connectCookieKeys: string[] = [];
  let connectJwks: { keys: Array<Record<string, unknown>> } = { keys: [] };
  if (env.CONNECT_ENABLED) {
    // WHICH ROLES MAY RUN CONNECT, derived from which role SERVES it.
    //
    // This used to name `api` and `control` literally, and that list was
    // complete when it was written: those were the only two roles that
    // registered the Connect routes. The GCP split then moved the public
    // metadata surface into `metadata-api`, src/server.ts registers Connect
    // under `servesPublicMetadata` (which that role satisfies), and this
    // allowlist was not moved with it. The result is a role that serves the
    // routes and refuses to boot when told to.
    //
    // SERVES_PUBLIC_AUTH is the same predicate src/server.ts uses to decide
    // whether to register them, so the two cannot drift again. `api` is added
    // separately because the development monolith serves everything and is not
    // in that set.
    if (env.RUNTIME_ROLE !== "api" && !SERVES_PUBLIC_AUTH.has(env.RUNTIME_ROLE)) {
      throw new Error("AnonRouter Connect can only run on a role that serves the public auth surface");
    }
    const issuer = new URL(connectIssuer);
    const localIssuer = ["localhost", "127.0.0.1", "[::1]"].includes(issuer.hostname.toLowerCase());
    if (issuer.pathname === "/" || !issuer.pathname.endsWith("/connect") || issuer.search || issuer.hash) {
      throw new Error("CONNECT_ISSUER must be a stable issuer URL whose path ends in /connect");
    }
    if (env.NODE_ENV === "production") {
      if (issuer.protocol !== "https:" || localIssuer) {
        throw new Error("Production CONNECT_ISSUER must be a public HTTPS URL");
      }
      if (env.CONNECT_ISSUER === undefined) {
        throw new Error("Production AnonRouter Connect requires an explicit CONNECT_ISSUER");
      }
      if (
        env.CONNECT_SUBJECT_KEYS_FILE === undefined
        || env.CONNECT_SUBJECT_KEYS !== undefined
        || env.CONNECT_COOKIE_KEYS_FILE === undefined
        || env.CONNECT_COOKIE_KEYS !== undefined
        || env.CONNECT_JWKS_FILE === undefined
        || env.CONNECT_JWKS !== undefined
      ) {
        throw new Error("Production AnonRouter Connect requires file-backed subject, cookie, and JWKS secrets only");
      }
    } else if (issuer.protocol !== "https:" && !(issuer.protocol === "http:" && localIssuer)) {
      throw new Error("Non-HTTPS CONNECT_ISSUER is allowed only on localhost in development or test");
    }
    connectSubjectKeys = parseConnectSubjectKeys(sensitiveValue({
      key: "CONNECT_SUBJECT_KEYS",
      direct: env.CONNECT_SUBJECT_KEYS,
      file: env.CONNECT_SUBJECT_KEYS_FILE
    }), env.CONNECT_ACTIVE_SUBJECT_KEY_VERSION);
    connectCookieKeys = parseConnectCookieKeys(sensitiveValue({
      key: "CONNECT_COOKIE_KEYS",
      direct: env.CONNECT_COOKIE_KEYS,
      file: env.CONNECT_COOKIE_KEYS_FILE
    }));
    connectJwks = parseConnectJwks(sensitiveValue({
      key: "CONNECT_JWKS",
      direct: env.CONNECT_JWKS,
      file: env.CONNECT_JWKS_FILE
    }));
  }
  const googleCredentialsConfigured = [
    env.GOOGLE_CLIENT_ID,
    env.GOOGLE_CLIENT_ID_FILE,
    env.GOOGLE_CLIENT_SECRET,
    env.GOOGLE_CLIENT_SECRET_FILE
  ].some((value) => value !== undefined && value.trim().length > 0);
  if (!env.GOOGLE_AUTH_ENABLED && googleCredentialsConfigured) {
    throw new Error("Google OAuth credentials must not be configured when GOOGLE_AUTH_ENABLED is false");
  }
  let googleClientId = "";
  let googleClientSecret = "";
  if (env.GOOGLE_AUTH_ENABLED) {
    googleClientId = sensitiveValue({
      key: "GOOGLE_CLIENT_ID",
      direct: env.GOOGLE_CLIENT_ID,
      file: env.GOOGLE_CLIENT_ID_FILE
    });
    googleClientSecret = sensitiveValue({
      key: "GOOGLE_CLIENT_SECRET",
      direct: env.GOOGLE_CLIENT_SECRET,
      file: env.GOOGLE_CLIENT_SECRET_FILE
    });
    if (!googleClientId || !googleClientSecret) {
      throw new Error("GOOGLE_AUTH_ENABLED requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET");
    }
  }
  const smtpPassword = sensitiveValue({
    key: "SMTP_PASSWORD",
    direct: env.SMTP_PASSWORD,
    file: env.SMTP_PASSWORD_FILE
  });
  const smtpTlsCa = env.SMTP_TLS_CA_FILE === undefined
    ? ""
    : readFileSync(env.SMTP_TLS_CA_FILE, "utf8").trim();
  if (env.SMTP_TLS_CA_FILE !== undefined && !smtpTlsCa) {
    throw new Error("SMTP_TLS_CA_FILE is empty");
  }
  const alertReceiverConfigured = [
    env.ALERT_RECEIVER_URL,
    env.ALERT_RECEIVER_URL_FILE,
    env.ALERT_RECEIVER_TOKEN,
    env.ALERT_RECEIVER_TOKEN_FILE
  ].some((value) => value !== undefined);
  if (!alertReceiverConfigured && env.ALERT_RECEIVER_AUTH_MODE !== undefined) {
    throw new Error("ALERT_RECEIVER_AUTH_MODE must not be configured without a receiver");
  }
  if (alertReceiverConfigured && env.NODE_ENV === "production" && env.ALERT_RECEIVER_AUTH_MODE === undefined) {
    throw new Error("production alert delivery requires explicit ALERT_RECEIVER_AUTH_MODE");
  }
  const alertReceiverAuthMode = alertReceiverConfigured
    ? (env.ALERT_RECEIVER_AUTH_MODE ?? "bearer")
    : null;
  let alertReceiverUrl = "";
  let alertReceiverToken = "";
  if (alertReceiverAuthMode === "bearer") {
    if (env.ALERT_RECEIVER_URL_FILE !== undefined) {
      throw new Error("bearer alert delivery forbids ALERT_RECEIVER_URL_FILE");
    }
    alertReceiverUrl = env.ALERT_RECEIVER_URL?.trim() ?? "";
    if (!alertReceiverUrl) {
      throw new Error("bearer alert delivery requires ALERT_RECEIVER_URL");
    }
    alertReceiverToken = sensitiveValue({
      key: "ALERT_RECEIVER_TOKEN",
      direct: env.ALERT_RECEIVER_TOKEN,
      file: env.ALERT_RECEIVER_TOKEN_FILE
    });
  } else if (alertReceiverAuthMode === "url-token") {
    if (env.ALERT_RECEIVER_URL !== undefined) {
      throw new Error("url-token alert delivery forbids ALERT_RECEIVER_URL");
    }
    if (env.ALERT_RECEIVER_TOKEN !== undefined || env.ALERT_RECEIVER_TOKEN_FILE !== undefined) {
      throw new Error("url-token alert delivery forbids ALERT_RECEIVER_TOKEN credentials");
    }
    alertReceiverUrl = sensitiveValue({
      key: "ALERT_RECEIVER_URL",
      file: env.ALERT_RECEIVER_URL_FILE
    });
    if (!alertReceiverUrl) {
      throw new Error("url-token alert delivery requires ALERT_RECEIVER_URL_FILE");
    }
  }
  if (alertReceiverAuthMode) {
    const problems: string[] = [];
    let parsed: URL | null = null;
    try {
      parsed = new URL(alertReceiverUrl);
    } catch {
      problems.push("ALERT_RECEIVER_URL must be a valid URL");
    }
    if (alertReceiverAuthMode === "bearer" && Buffer.byteLength(alertReceiverToken, "utf8") < 32) {
      problems.push("ALERT_RECEIVER_TOKEN must be at least 32 bytes");
    }
    if (env.NODE_ENV === "production") {
      if (parsed?.protocol !== "https:") problems.push("production ALERT_RECEIVER_URL must use HTTPS");
      if (alertReceiverAuthMode === "bearer" && env.ALERT_RECEIVER_TOKEN_FILE === undefined) {
        problems.push("production alert delivery requires ALERT_RECEIVER_TOKEN_FILE");
      }
      if (alertReceiverAuthMode === "url-token" && env.ALERT_RECEIVER_URL_FILE === undefined) {
        problems.push("production url-token alert delivery requires ALERT_RECEIVER_URL_FILE");
      }
    }
    if (problems.length > 0) {
      throw new Error(`Operational alert receiver configuration is invalid (${problems.join("; ")})`);
    }
  }
  const adminAccessToken = sensitiveValue({
    key: "ADMIN_ACCESS_TOKEN",
    direct: env.ADMIN_ACCESS_TOKEN,
    file: env.ADMIN_ACCESS_TOKEN_FILE,
    fallback: "local-admin-change-me"
  });
  const adminEnvironment = env.ADMIN_ENVIRONMENT ?? (env.NODE_ENV === "production" ? "production" : "local");
  if ((env.NODE_ENV === "production") !== (adminEnvironment === "production")) {
    throw new Error("ADMIN_ENVIRONMENT must match NODE_ENV production isolation");
  }
  const servesAdminRoutes = SERVES_PUBLIC_AUTH.has(env.RUNTIME_ROLE);
  if (
    adminEnvironment === "production"
    && servesAdminRoutes
    && env.ADMIN_SESSION_COOKIE_PATH !== "/api/production/v1/admin"
  ) {
    throw new Error("Production ADMIN_SESSION_COOKIE_PATH must match /api/production/v1/admin");
  }
  const directVeniceKey = env.VENICE_INFERENCE_KEY || env.VENICE_INFERENCE_API_KEY || env.VENICE_API_KEY;
  const rawVeniceKeyset = sensitiveValue({
    key: "VENICE_INFERENCE_KEYS",
    direct: env.VENICE_INFERENCE_KEYS,
    file: env.VENICE_INFERENCE_KEYS_FILE
  });
  const veniceKeys = rawVeniceKeyset
    ? parseVeniceKeyset(rawVeniceKeyset, env.VENICE_INFERENCE_KEYS_FILE ? "VENICE_INFERENCE_KEYS_FILE" : "VENICE_INFERENCE_KEYS")
    : (() => {
        const single = sensitiveValue({
          key: "VENICE_INFERENCE_KEY",
          direct: directVeniceKey,
          file: env.VENICE_INFERENCE_KEY_FILE
        });
        return single ? [{ id: "primary", label: null, key: single }] : [];
      })();
  // Legacy single-key surfaces (catalog sync, rate-limit refresh, media,
  // admin health probes) keep using the first configured key.
  const veniceInferenceKey = veniceKeys[0]?.key ?? "";
  const fireworksApiKey = sensitiveValue({
    key: "FIREWORKS_API_KEY",
    direct: env.FIREWORKS_API_KEY,
    file: env.FIREWORKS_API_KEY_FILE
  });
  const deepinfraApiKey = sensitiveValue({
    key: "DEEPINFRA_API_KEY",
    direct: env.DEEPINFRA_API_KEY,
    file: env.DEEPINFRA_API_KEY_FILE
  });
  const chutesApiKey = sensitiveValue({
    key: "CHUTES_API_KEY",
    direct: env.CHUTES_API_KEY,
    file: env.CHUTES_API_KEY_FILE
  });
  const tinfoilApiKey = sensitiveValue({
    key: "TINFOIL_API_KEY",
    direct: env.TINFOIL_API_KEY,
    file: env.TINFOIL_API_KEY_FILE
  });
  const phalaAiApiKey = sensitiveValue({
    key: "PHALA_AI_API_KEY",
    direct: env.PHALA_AI_API_KEY,
    file: env.PHALA_AI_API_KEY_FILE
  });
  const nearApiKey = sensitiveValue({
    key: "NEAR_API_KEY",
    direct: env.NEAR_API_KEY,
    file: env.NEAR_API_KEY_FILE
  });
  const relayRpcToken = sensitiveValue({
    key: "RELAY_RPC_TOKEN",
    direct: env.RELAY_RPC_TOKEN,
    file: env.RELAY_RPC_TOKEN_FILE,
    fallback: env.NODE_ENV === "production" ? undefined : "dev-only-relay-rpc-token-change-me-32-bytes"
  });
  const workerRpcToken = sensitiveValue({
    key: "WORKER_RPC_TOKEN",
    direct: env.WORKER_RPC_TOKEN,
    file: env.WORKER_RPC_TOKEN_FILE,
    fallback: env.NODE_ENV === "production" ? undefined : "dev-only-worker-rpc-token-change-me-32-bytes"
  });
  const metadataRpcToken = sensitiveValue({
    key: "METADATA_RPC_TOKEN",
    direct: env.METADATA_RPC_TOKEN,
    file: env.METADATA_RPC_TOKEN_FILE,
    fallback: env.NODE_ENV === "production" ? undefined : "dev-only-metadata-rpc-token-change-me-32-bytes"
  });
  // Per-provider metadata tokens (AR-02). Each maps to exactly one provider name
  // so control can reject a catalog push whose payload.provider does not match the
  // presented token. Unconfigured providers are simply absent from the map; there
  // is no dev fallback because the shared token above already covers single-token
  // deployments (the map being empty is the signal that binding is not enforced).
  const metadataTokenVenice = sensitiveValue({
    key: "METADATA_RPC_TOKEN_VENICE", direct: env.METADATA_RPC_TOKEN_VENICE, file: env.METADATA_RPC_TOKEN_VENICE_FILE
  });
  const metadataTokenFireworks = sensitiveValue({
    key: "METADATA_RPC_TOKEN_FIREWORKS", direct: env.METADATA_RPC_TOKEN_FIREWORKS, file: env.METADATA_RPC_TOKEN_FIREWORKS_FILE
  });
  const metadataTokenBedrock = sensitiveValue({
    key: "METADATA_RPC_TOKEN_BEDROCK", direct: env.METADATA_RPC_TOKEN_BEDROCK, file: env.METADATA_RPC_TOKEN_BEDROCK_FILE
  });
  const metadataTokenDeepInfra = sensitiveValue({
    key: "METADATA_RPC_TOKEN_DEEPINFRA", direct: env.METADATA_RPC_TOKEN_DEEPINFRA, file: env.METADATA_RPC_TOKEN_DEEPINFRA_FILE
  });
  const metadataTokenChutes = sensitiveValue({
    key: "METADATA_RPC_TOKEN_CHUTES", direct: env.METADATA_RPC_TOKEN_CHUTES, file: env.METADATA_RPC_TOKEN_CHUTES_FILE
  });
  const metadataTokenTinfoil = sensitiveValue({
    key: "METADATA_RPC_TOKEN_TINFOIL", direct: env.METADATA_RPC_TOKEN_TINFOIL, file: env.METADATA_RPC_TOKEN_TINFOIL_FILE
  });
  const metadataTokenNear = sensitiveValue({
    key: "METADATA_RPC_TOKEN_NEAR", direct: env.METADATA_RPC_TOKEN_NEAR, file: env.METADATA_RPC_TOKEN_NEAR_FILE
  });
  const metadataTokenPhalaAi = sensitiveValue({
    key: "METADATA_RPC_TOKEN_PHALA_AI", direct: env.METADATA_RPC_TOKEN_PHALA_AI, file: env.METADATA_RPC_TOKEN_PHALA_AI_FILE
  });
  const providerMetadataTokens: Record<string, string> = {};
  if (metadataTokenVenice) providerMetadataTokens.venice = metadataTokenVenice;
  if (metadataTokenFireworks) providerMetadataTokens.fireworks = metadataTokenFireworks;
  if (metadataTokenBedrock) providerMetadataTokens["aws-bedrock"] = metadataTokenBedrock;
  if (metadataTokenDeepInfra) providerMetadataTokens.deepinfra = metadataTokenDeepInfra;
  if (metadataTokenChutes) providerMetadataTokens.chutes = metadataTokenChutes;
  if (metadataTokenTinfoil) providerMetadataTokens.tinfoil = metadataTokenTinfoil;
  if (metadataTokenNear) providerMetadataTokens["near-ai"] = metadataTokenNear;
  if (metadataTokenPhalaAi) providerMetadataTokens["phala-ai"] = metadataTokenPhalaAi;
  const deploymentMetadataToken = sensitiveValue({
    key: "METADATA_RPC_DEPLOYMENT_TOKEN",
    direct: env.METADATA_RPC_DEPLOYMENT_TOKEN,
    file: env.METADATA_RPC_DEPLOYMENT_TOKEN_FILE
  });
  const rawDeploymentScopes = sensitiveValue({
    key: "METADATA_RPC_DEPLOYMENT_SCOPES",
    direct: env.METADATA_RPC_DEPLOYMENT_SCOPES,
    file: env.METADATA_RPC_DEPLOYMENT_SCOPES_FILE
  });
  const metadataDeploymentScopes = parseMetadataDeploymentScopes(
    rawDeploymentScopes,
    env.METADATA_RPC_DEPLOYMENT_SCOPES_FILE ? "METADATA_RPC_DEPLOYMENT_SCOPES_FILE" : "METADATA_RPC_DEPLOYMENT_SCOPES"
  );
  // The metadata token THIS worker presents for its catalog push and dispatch
  // fence: its own per-provider token when configured, else the shared token.
  const workerProviderName = env.RUNTIME_ROLE === "venice-worker" ? "venice"
    : env.RUNTIME_ROLE === "fireworks-worker" ? "fireworks"
      : env.RUNTIME_ROLE === "bedrock-worker" ? "aws-bedrock"
        : env.RUNTIME_ROLE === "deepinfra-worker" ? "deepinfra"
          : env.RUNTIME_ROLE === "chutes-worker" ? "chutes"
            : env.RUNTIME_ROLE === "tinfoil-worker" ? "tinfoil"
              : env.RUNTIME_ROLE === "near-worker" ? "near-ai"
                : env.RUNTIME_ROLE === "phala-ai-worker" ? "phala-ai"
                  : null;
  const workerMetadataToken = deploymentMetadataToken
    || (workerProviderName ? providerMetadataTokens[workerProviderName] : undefined)
    || metadataRpcToken;
  const compatRpcToken = sensitiveValue({
    key: "COMPAT_RPC_TOKEN",
    direct: env.COMPAT_RPC_TOKEN,
    file: env.COMPAT_RPC_TOKEN_FILE,
    fallback: env.NODE_ENV === "production" ? undefined : "dev-only-compat-rpc-token-change-me-32-bytes"
  });
  const isSplitRole = env.RUNTIME_ROLE === "control" || env.RUNTIME_ROLE === "relay"
    || env.RUNTIME_ROLE === "venice-worker" || env.RUNTIME_ROLE === "fireworks-worker"
    || env.RUNTIME_ROLE === "bedrock-worker" || env.RUNTIME_ROLE === "deepinfra-worker"
    || env.RUNTIME_ROLE === "chutes-worker" || env.RUNTIME_ROLE === "tinfoil-worker"
    || env.RUNTIME_ROLE === "near-worker" || env.RUNTIME_ROLE === "phala-ai-worker"
    || env.RUNTIME_ROLE === "compat"
    || env.RUNTIME_ROLE === "gateway-attestation";
  // The migrate role holds the schema-owner credential and is deliberately NOT
  // part of isSplitRole, so this check sits outside that block. Nothing else
  // stops it being scheduled into a CVM, and a confidential host is the last
  // place a migration superuser password belongs.
  if (env.RUNTIME_ROLE === "migrate" && env.GATEWAY_ATTESTATION_ENABLED) {
    throw new Error("the migrate role must never run inside the confidential data plane");
  }

  if (env.NODE_ENV === "production" && isSplitRole) {
    const problems: string[] = [];
    const strong = (value: string) => Buffer.byteLength(value, "utf8") >= 32 && !/dev-only|change-me/i.test(value);

    // Gateway attestation config is validated for every split role that can
    // enable it. A misconfigured binding is worse than no attestation: it would
    // publish a quote committing to an origin or a transport claim that is not
    // true, and clients would pin against it.
    if (env.GATEWAY_ATTESTATION_ENABLED) {
      // A LIST, canonical first. The content plane serves the restored
      // api.anonrouter.ai base URL and keeps api.private.anonrouter.ai as the
      // verification alias, and dstack-ingress issues a separate certificate per
      // name -- so the attestation producer must be able to bind whichever name
      // the caller actually connected to, with that name's SPKI.
      //
      // Every entry is validated. A single malformed member is a boot failure,
      // not a silently dropped origin: an origin that quietly vanishes from the
      // accepted set turns into a client-side verification failure on a name
      // that looks configured.
      const origins = gatewayPublicOrigins(env.GATEWAY_PUBLIC_ORIGIN);
      if (origins.length === 0) {
        problems.push("GATEWAY_PUBLIC_ORIGIN is required when GATEWAY_ATTESTATION_ENABLED=true");
      }
      for (const origin of origins) {
        let parsed: URL | null = null;
        try {
          parsed = new URL(origin);
        } catch {
          parsed = null;
        }
        if (!parsed || parsed.protocol !== "https:") {
          problems.push(`GATEWAY_PUBLIC_ORIGIN entry '${origin}' must be an absolute https origin`);
        } else if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/") {
          problems.push(`GATEWAY_PUBLIC_ORIGIN entry '${origin}' must contain only scheme, host, and optional port`);
        }
      }
      if (new Set(origins).size !== origins.length) {
        problems.push("GATEWAY_PUBLIC_ORIGIN must not repeat an origin");
      }
      if (!env.GATEWAY_RELEASE_ID?.trim()) {
        problems.push("GATEWAY_RELEASE_ID is required when GATEWAY_ATTESTATION_ENABLED=true");
      } else if (!/^[A-Za-z0-9._:@+-]{1,128}$/.test(env.GATEWAY_RELEASE_ID.trim())) {
        problems.push("GATEWAY_RELEASE_ID must be 1..128 chars of [A-Za-z0-9._:@+-]");
      }
      // Claiming to terminate TLS inside the TD without naming the certificate
      // is precisely the ambiguity the binding is designed to remove.
      if (env.GATEWAY_TRANSPORT === "in-tee-tls" && !env.GATEWAY_TLS_TERMINATOR) {
        problems.push("GATEWAY_TLS_TERMINATOR is required when GATEWAY_TRANSPORT=in-tee-tls");
      }
      if (env.GATEWAY_TRANSPORT === "gateway-tls" && env.GATEWAY_TLS_TERMINATOR) {
        problems.push("GATEWAY_TLS_TERMINATOR must be unset when GATEWAY_TRANSPORT=gateway-tls");
      }
    }

    // When the browser posts content directly to the content tier, that tier's
    // CORS allowlist is the only thing standing between a hostile page and a
    // ticketed request from a victim's browser. CORS_ORIGIN was previously
    // validated for api|control only, so relay and compat could boot in
    // production with the zod default of http://localhost:3000.
    // The attestation service holds the guest-agent socket and must hold
    // nothing else. Assert the absence rather than relying on compose.
    if (env.RUNTIME_ROLE === "gateway-attestation") {
      if (!env.GATEWAY_ATTESTATION_ENABLED) {
        problems.push("GATEWAY_ATTESTATION_ENABLED must be true for the gateway-attestation role");
      }
      if (veniceKeys.length > 0 || fireworksApiKey || deepinfraApiKey) {
        problems.push("the gateway-attestation service must not hold provider credentials");
      }
      if (env.BEDROCK_AWS_PROFILE) {
        problems.push("the gateway-attestation service must not select an AWS Bedrock credential profile");
      }
      // Read process.env directly: the database settings are no longer part of
      // this schema at all (they moved to src/db/config.ts), and the question
      // here is whether an operator EXPLICITLY handed this role one.
      if (["DATABASE_URL", "DATABASE_URL_FILE", "MIGRATION_DATABASE_URL", "MIGRATION_DATABASE_URL_FILE"].some((key) => process.env[key])) {
        problems.push("the gateway-attestation service must not be given a database URL");
      }
    }

    if (env.RUNTIME_ROLE === "relay" || env.RUNTIME_ROLE === "compat") {
      const origins = env.CORS_ORIGIN.split(",").map((origin) => origin.trim()).filter(Boolean);
      const invalid = origins.length === 0 || origins.some((origin) => {
        try {
          const parsed = new URL(origin);
          return parsed.protocol !== "https:"
            || parsed.hostname === "localhost"
            || parsed.hostname === "127.0.0.1";
        } catch {
          return true;
        }
      });
      if (invalid) {
        problems.push("CORS_ORIGIN must contain only explicit public HTTPS origins on the content tier");
      }
    }

    // The content tier and the credential workers hold plaintext and provider
    // secrets. Container stdout is platform-visible on a confidential host, so
    // a verbose level there is a standing invitation to leak. The allowlist
    // logger already drops unknown fields; this closes the other half.
    if (env.RUNTIME_ROLE !== "control" && (env.LOG_LEVEL === "debug" || env.LOG_LEVEL === "trace")) {
      problems.push("LOG_LEVEL must not be debug or trace on a content or credential role in production");
    }

    // Negative assertions for the roles that move into the confidential VM.
    //
    // Until now, isolation was purely network and compose: the split-role checks
    // asserted only the ABSENCE OF PROVIDER CREDENTIALS, while DATABASE_URL and
    // REDIS_URL both have defaults, so every relay, compat, and worker config
    // silently carried a populated connection string. That was survivable when
    // the only thing standing between them and Postgres was an `internal: true`
    // Docker network we controlled. On a host we do not control it is not, and
    // the failure would be silent: a misconfigured CVM would simply connect.
    //
    // Asserted here rather than in compose so it holds wherever the image runs.
    const contentTierRole = env.RUNTIME_ROLE === "relay"
      || env.RUNTIME_ROLE === "compat"
      || env.RUNTIME_ROLE === "gateway-attestation"
      || env.RUNTIME_ROLE.endsWith("-worker");
    if (contentTierRole) {
      // Read process.env, NOT the parsed env: several of these have zod
      // defaults (REDIS_URL defaults to redis://localhost:6379, APP_DB_USER to
      // anonrouter_app), so the parsed value is always populated and a check
      // against it would fire for every deployment. The question here is
      // whether an operator EXPLICITLY handed this role the value.
      const forbidden = [
        "DATABASE_URL",
        "DATABASE_URL_FILE",
        "MIGRATION_DATABASE_URL",
        "MIGRATION_DATABASE_URL_FILE",
        "REDIS_URL",
        "APP_DB_PASSWORD",
        "BETTER_AUTH_SECRET",
        "BETTER_AUTH_SECRET_FILE",
        "COOKIE_SECRET",
        "COOKIE_SECRET_FILE",
        "EMAIL_ENCRYPTION_KEY",
        "EMAIL_ENCRYPTION_KEY_FILE",
        "ADMIN_ACCESS_TOKEN",
        "ADMIN_ACCESS_TOKEN_FILE",
        "STRIPE_API_KEY",
        "STRIPE_API_KEY_FILE",
        "SMTP_PASSWORD",
        "SMTP_PASSWORD_FILE"
      ];
      for (const name of forbidden) {
        const value = process.env[name];
        if (typeof value === "string" && value.trim().length > 0) {
          problems.push(`${env.RUNTIME_ROLE} must not be given ${name}`);
        }
      }
    }

    if (env.RUNTIME_ROLE === "control") {
      // control authenticates the relay's RPC; it must NOT hold a Venice key.
      if (!strong(relayRpcToken)) problems.push("RELAY_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!strong(metadataRpcToken)) problems.push("METADATA_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      // Authenticated public/admin TEE evidence calls are dispatched from
      // control to provider-bound credential workers. This token authorizes the
      // narrow worker RPC only; no provider credential or request content is
      // introduced on control.
      if (!strong(workerRpcToken)) problems.push("WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value for TEE worker evidence fetches");
      // Per-provider metadata tokens (AR-02) are optional, but any that ARE
      // configured must be strong so a mounted-but-weak token can never
      // authenticate a catalog push. The hardened split prod compose mounts all
      // four into control so it accepts each worker's provider-bound push.
      for (const [provider, token] of Object.entries(providerMetadataTokens)) {
        if (!strong(token)) problems.push(`METADATA_RPC_TOKEN for ${provider} must be a >= 32-byte non-placeholder value`);
      }
      const allMetadataTokens = [metadataRpcToken, ...Object.values(providerMetadataTokens), ...metadataDeploymentScopes.map((scope) => scope.token)]
        .filter(Boolean);
      if (new Set(allMetadataTokens).size !== allMetadataTokens.length) {
        problems.push("metadata RPC tokens must be distinct across shared, provider, and deployment scopes");
      }
      // Control authenticates the compat broker's mint RPC only when compat is
      // enabled. Fail closed so an enabled flag can never run on a weak token.
      if (env.ALLOW_COMPAT_MODE && !strong(compatRpcToken)) {
        problems.push("COMPAT_RPC_TOKEN must be a >= 32-byte non-placeholder value when ALLOW_COMPAT_MODE=true");
      }
      if (veniceKeys.length > 0) problems.push("the control plane must not hold a Venice credential");
      if (fireworksApiKey) problems.push("the control plane must not hold a Fireworks credential");
      if (deepinfraApiKey) problems.push("the control plane must not hold a DeepInfra credential");
      if (env.BEDROCK_AWS_PROFILE) problems.push("the control plane must not select an AWS Bedrock credential profile");
    }
    if (env.RUNTIME_ROLE === "relay") {
      // The relay must fail closed without a ticket and needs both RPC tokens+URLs.
      if (env.ALLOW_INLINE_TICKET) problems.push("ALLOW_INLINE_TICKET must be false on the relay");
      if (!strong(relayRpcToken)) problems.push("RELAY_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!strong(workerRpcToken)) problems.push("WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!env.CONTROL_RPC_URL) problems.push("CONTROL_RPC_URL is required");
      if (!env.WORKER_RPC_URL) problems.push("WORKER_RPC_URL is required");
      if (!env.FIREWORKS_WORKER_RPC_URL) problems.push("FIREWORKS_WORKER_RPC_URL is required");
      if (!env.BEDROCK_WORKER_RPC_URL) problems.push("BEDROCK_WORKER_RPC_URL is required");
      if (!env.DEEPINFRA_WORKER_RPC_URL) problems.push("DEEPINFRA_WORKER_RPC_URL is required");
      if (!env.CHUTES_WORKER_RPC_URL) problems.push("CHUTES_WORKER_RPC_URL is required");
      if (!env.TINFOIL_WORKER_RPC_URL) problems.push("TINFOIL_WORKER_RPC_URL is required");
      if (!env.NEAR_WORKER_RPC_URL) problems.push("NEAR_WORKER_RPC_URL is required");
      if (!env.PHALA_AI_WORKER_RPC_URL) problems.push("PHALA_AI_WORKER_RPC_URL is required");
      if (veniceKeys.length > 0 || fireworksApiKey || deepinfraApiKey) problems.push("the relay must not hold provider credentials");
      if (env.BEDROCK_AWS_PROFILE) problems.push("the relay must not select an AWS Bedrock credential profile");
    }
    if (env.RUNTIME_ROLE === "venice-worker") {
      // The worker holds a file-backed Venice credential plus narrowly scoped
      // worker/metadata tokens. The explicit control URL is required for the
      // fail-closed provider-attempt acknowledgment before upstream fetch.
      if (!strong(workerRpcToken)) problems.push("WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!strong(workerMetadataToken)) problems.push("METADATA_RPC_TOKEN (or its per-provider override) must be a >= 32-byte non-placeholder value");
      if (!process.env.CONTROL_METADATA_URL?.trim()) problems.push("CONTROL_METADATA_URL is required");
      if (env.VENICE_INFERENCE_KEY_FILE === undefined && env.VENICE_INFERENCE_KEYS_FILE === undefined) {
        problems.push("VENICE_INFERENCE_KEY_FILE or VENICE_INFERENCE_KEYS_FILE (file-backed) is required");
      }
      if (veniceKeys.length === 0) problems.push("A Venice inference credential is required");
      if (fireworksApiKey) problems.push("the Venice worker must not hold a Fireworks credential");
      if (deepinfraApiKey) problems.push("the Venice worker must not hold a DeepInfra credential");
      if (env.BEDROCK_AWS_PROFILE) problems.push("the Venice worker must not select an AWS Bedrock credential profile");
    }
    if (env.RUNTIME_ROLE === "fireworks-worker") {
      if (!strong(workerRpcToken)) problems.push("WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!strong(workerMetadataToken)) problems.push("METADATA_RPC_TOKEN (or its per-provider override) must be a >= 32-byte non-placeholder value");
      if (!process.env.CONTROL_METADATA_URL?.trim()) problems.push("CONTROL_METADATA_URL is required");
      if (env.FIREWORKS_API_KEY_FILE === undefined) problems.push("FIREWORKS_API_KEY_FILE (file-backed) is required");
      if (!fireworksApiKey) problems.push("A Fireworks API credential is required");
      if (veniceKeys.length > 0) problems.push("the Fireworks worker must not hold a Venice credential");
      if (deepinfraApiKey) problems.push("the Fireworks worker must not hold a DeepInfra credential");
      if (env.BEDROCK_AWS_PROFILE) problems.push("the Fireworks worker must not select an AWS Bedrock credential profile");
    }
    if (env.RUNTIME_ROLE === "deepinfra-worker") {
      if (!strong(workerRpcToken)) problems.push("WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!strong(workerMetadataToken)) problems.push("METADATA_RPC_TOKEN (or its per-provider override) must be a >= 32-byte non-placeholder value");
      if (!process.env.CONTROL_METADATA_URL?.trim()) problems.push("CONTROL_METADATA_URL is required");
      if (env.DEEPINFRA_API_KEY_FILE === undefined) problems.push("DEEPINFRA_API_KEY_FILE (file-backed) is required");
      if (!deepinfraApiKey) problems.push("A DeepInfra API credential is required");
      if (veniceKeys.length > 0 || fireworksApiKey) problems.push("the DeepInfra worker must not hold another provider credential");
      if (env.BEDROCK_AWS_PROFILE) problems.push("the DeepInfra worker must not select an AWS Bedrock credential profile");
    }
    if (env.RUNTIME_ROLE === "bedrock-worker") {
      if (!strong(workerRpcToken)) problems.push("WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!strong(workerMetadataToken)) problems.push("METADATA_RPC_TOKEN (or its per-provider override) must be a >= 32-byte non-placeholder value");
      if (!process.env.CONTROL_METADATA_URL?.trim()) problems.push("CONTROL_METADATA_URL is required");
      if (env.BEDROCK_ENABLED !== true) problems.push("BEDROCK_ENABLED must be true");
      if (env.BEDROCK_AWS_PROFILE) problems.push("production Bedrock must use its workload role, not BEDROCK_AWS_PROFILE");
      if (process.env.AWS_ACCESS_KEY_ID || process.env.AWS_SECRET_ACCESS_KEY) {
        problems.push("production Bedrock must use temporary workload credentials, not static AWS access-key environment variables");
      }
      if (veniceKeys.length > 0 || fireworksApiKey || deepinfraApiKey) problems.push("the Bedrock worker must not hold another provider credential");
    }
    if (env.RUNTIME_ROLE === "compat") {
      // The compat broker mints at control and forwards to the relay. It holds
      // NO Venice credential, DB, Redis, or payment access (enforced by the
      // compose networks/secrets); assert the credential isolation here as
      // defense in depth, and require its RPC token whenever compat is enabled.
      if (!env.CONTROL_RPC_URL) problems.push("CONTROL_RPC_URL is required");
      if (env.ALLOW_COMPAT_MODE && !strong(compatRpcToken)) {
        problems.push("COMPAT_RPC_TOKEN must be a >= 32-byte non-placeholder value when ALLOW_COMPAT_MODE=true");
      }
      if (veniceKeys.length > 0) problems.push("the compat broker must not hold a Venice credential");
      if (fireworksApiKey) problems.push("the compat broker must not hold a Fireworks credential");
      if (deepinfraApiKey) problems.push("the compat broker must not hold a DeepInfra credential");
      if (env.BEDROCK_AWS_PROFILE) problems.push("the compat broker must not select an AWS Bedrock credential profile");
    }
    // Confidential-compute providers (Chutes / Tinfoil / NEAR AI): each holds its
    // own file-backed credential and the shared worker-role invariants. Foreign
    // credentials are rejected globally by the consolidated cross-check below.
    if (env.RUNTIME_ROLE === "chutes-worker") {
      if (!strong(workerRpcToken)) problems.push("WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!strong(workerMetadataToken)) problems.push("METADATA_RPC_TOKEN (or its per-provider override) must be a >= 32-byte non-placeholder value");
      if (!process.env.CONTROL_METADATA_URL?.trim()) problems.push("CONTROL_METADATA_URL is required");
      if (env.CHUTES_API_KEY_FILE === undefined) problems.push("CHUTES_API_KEY_FILE (file-backed) is required");
      if (!chutesApiKey) problems.push("A Chutes API credential is required");
    }
    if (env.RUNTIME_ROLE === "tinfoil-worker") {
      if (!strong(workerRpcToken)) problems.push("WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!strong(workerMetadataToken)) problems.push("METADATA_RPC_TOKEN (or its per-provider override) must be a >= 32-byte non-placeholder value");
      if (!process.env.CONTROL_METADATA_URL?.trim()) problems.push("CONTROL_METADATA_URL is required");
      if (env.TINFOIL_API_KEY_FILE === undefined) problems.push("TINFOIL_API_KEY_FILE (file-backed) is required");
      if (!tinfoilApiKey) problems.push("A Tinfoil API credential is required");
    }
    if (env.RUNTIME_ROLE === "near-worker") {
      if (!strong(workerRpcToken)) problems.push("WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!strong(workerMetadataToken)) problems.push("METADATA_RPC_TOKEN (or its per-provider override) must be a >= 32-byte non-placeholder value");
      if (!process.env.CONTROL_METADATA_URL?.trim()) problems.push("CONTROL_METADATA_URL is required");
      if (env.NEAR_API_KEY_FILE === undefined) problems.push("NEAR_API_KEY_FILE (file-backed) is required");
      if (!nearApiKey) problems.push("A NEAR AI API credential is required");
    }
    if (env.RUNTIME_ROLE === "phala-ai-worker") {
      if (!strong(workerRpcToken)) problems.push("WORKER_RPC_TOKEN must be a >= 32-byte non-placeholder value");
      if (!strong(workerMetadataToken)) problems.push("METADATA_RPC_TOKEN (or its per-provider override) must be a >= 32-byte non-placeholder value");
      if (!process.env.CONTROL_METADATA_URL?.trim()) problems.push("CONTROL_METADATA_URL is required");
      // File-backed only. The measured compose carries the ordered allowlist of
      // env NAMES; the value reaches this worker as an encrypted value decoded to
      // tmpfs by the entrypoint, which then unsets the base64 form before exec.
      if (env.PHALA_AI_API_KEY_FILE === undefined) problems.push("PHALA_AI_API_KEY_FILE (file-backed) is required");
      if (!phalaAiApiKey) problems.push("A Phala AI API credential is required");
    }
    // Consolidated credential isolation for the confidential-compute providers:
    // each credential belongs to exactly one worker role; every OTHER split role
    // (control, relay, compat, and each peer worker) must hold none. This mirrors
    // the AWS static-key rejection below and keeps a single compromised worker
    // from ever reaching a peer provider's inference credential.
    if (env.RUNTIME_ROLE !== "chutes-worker" && chutesApiKey) problems.push("only the Chutes worker may hold a Chutes credential");
    if (env.RUNTIME_ROLE !== "tinfoil-worker" && tinfoilApiKey) problems.push("only the Tinfoil worker may hold a Tinfoil credential");
    if (env.RUNTIME_ROLE !== "near-worker" && nearApiKey) problems.push("only the NEAR AI worker may hold a NEAR AI credential");
    if (env.RUNTIME_ROLE !== "phala-ai-worker" && phalaAiApiKey) problems.push("only the Phala AI worker may hold a Phala AI credential");
    // The Bedrock credential also has a static-access-key form (the AWS default
    // chain signs SigV4 with AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY). The bedrock
    // worker rejects it above (it uses IAM Roles Anywhere); every other split role
    // must reach no provider inference credential at all, so reject the static-key
    // form wherever the BEDROCK_AWS_PROFILE form is already rejected.
    if (env.RUNTIME_ROLE !== "bedrock-worker"
        && (process.env.AWS_ACCESS_KEY_ID || process.env.AWS_SECRET_ACCESS_KEY)) {
      problems.push("this role must not hold static AWS credentials");
    }
    if (problems.length > 0) throw new Error(`Split-role configuration is invalid (${problems.join("; ")})`);
  }
  let stripeApiKey = "";
  let stripePublishableKey = "";
  let stripeWebhookSecret = "";
  const stripePurchasesEnabled = env.STRIPE_PURCHASES_ENABLED ?? env.PAYMENTS_MODE === "sandbox";
  const stripeAutoTopUpEnabled = env.STRIPE_AUTO_TOP_UP_ENABLED ?? env.PAYMENTS_MODE === "sandbox";
  if (
    env.PAYMENTS_MODE === "disabled"
    && (stripePurchasesEnabled || stripeAutoTopUpEnabled)
  ) {
    throw new Error("Stripe runtime controls are invalid (PAYMENTS_MODE must configure sandbox or live before Stripe purchases or auto top-up can be enabled)");
  }
  if (env.PAYMENTS_MODE !== "disabled") {
    stripeApiKey = sensitiveValue({
      key: "STRIPE_API_KEY",
      direct: env.STRIPE_API_KEY,
      file: env.STRIPE_API_KEY_FILE
    });
    stripePublishableKey = sensitiveValue({
      key: "STRIPE_PUBLISHABLE_KEY",
      direct: env.STRIPE_PUBLISHABLE_KEY,
      file: env.STRIPE_PUBLISHABLE_KEY_FILE
    });
    stripeWebhookSecret = sensitiveValue({
      key: "STRIPE_WEBHOOK_SECRET",
      direct: env.STRIPE_WEBHOOK_SECRET,
      file: env.STRIPE_WEBHOOK_SECRET_FILE
    });
    validateStripeConfig({
      mode: env.PAYMENTS_MODE,
      nodeEnv: env.NODE_ENV,
      appBaseUrl: env.APP_BASE_URL,
      apiKey: stripeApiKey,
      publishableKey: stripePublishableKey,
      webhookSecret: stripeWebhookSecret,
      apiKeyFromFile: env.STRIPE_API_KEY_FILE !== undefined,
      publishableKeyFromFile: env.STRIPE_PUBLISHABLE_KEY_FILE !== undefined,
      webhookSecretFromFile: env.STRIPE_WEBHOOK_SECRET_FILE !== undefined
    });
  }

  let btcpayApiKey = "";
  let btcpayWebhookSecret = "";
  let cryptoEnabledRails: ConfiguredCryptoRail[] = [];
  const cryptoInvoicesEnabled = env.CRYPTO_INVOICES_ENABLED ?? env.CRYPTO_PAYMENTS_MODE === "sandbox";
  if (env.CRYPTO_PAYMENTS_MODE === "disabled" && cryptoInvoicesEnabled) {
    throw new Error("Crypto runtime controls are invalid (CRYPTO_PAYMENTS_MODE must configure sandbox or live before new invoices can be enabled)");
  }
  const btcpayInternalUrl = (env.BTCPAY_INTERNAL_URL ?? "").replace(/\/$/, "");
  const btcpayPublicUrl = (env.BTCPAY_PUBLIC_URL ?? "").replace(/\/$/, "");
  const btcpayStoreId = env.BTCPAY_STORE_ID ?? "";
  if (env.CRYPTO_PAYMENTS_MODE !== "disabled") {
    cryptoEnabledRails = resolveCryptoRails(env.CRYPTO_PAYMENTS_MODE, env.CRYPTO_ENABLED_RAILS);
    btcpayApiKey = sensitiveValue({
      key: "BTCPAY_API_KEY",
      direct: env.BTCPAY_API_KEY,
      file: env.BTCPAY_API_KEY_FILE
    });
    btcpayWebhookSecret = sensitiveValue({
      key: "BTCPAY_WEBHOOK_SECRET",
      direct: env.BTCPAY_WEBHOOK_SECRET,
      file: env.BTCPAY_WEBHOOK_SECRET_FILE
    });
    validateCryptoPaymentConfig({
      mode: env.CRYPTO_PAYMENTS_MODE,
      nodeEnv: env.NODE_ENV,
      appBaseUrl: env.APP_BASE_URL,
      internalUrl: btcpayInternalUrl,
      publicUrl: btcpayPublicUrl,
      storeId: btcpayStoreId,
      apiKey: btcpayApiKey,
      webhookSecret: btcpayWebhookSecret,
      apiKeyFromFile: env.BTCPAY_API_KEY_FILE !== undefined,
      webhookSecretFromFile: env.BTCPAY_WEBHOOK_SECRET_FILE !== undefined
    });
  }

  // Unconditional: the receiver either is off, or is on with an exact topic. This
  // runs for every role, because whichever role registers the route is the one
  // that must not come up half-configured.
  validateScalewayWebhookConfig({
    enabled: env.SCALEWAY_WEBHOOK_ENABLED,
    topicArn: env.SCALEWAY_SNS_TOPIC_ARN,
    certHost: env.SCALEWAY_SNS_CERT_HOST,
    subscribeHostSuffix: env.SCALEWAY_SNS_SUBSCRIBE_HOST_SUFFIX,
    maxSkewSeconds: env.SCALEWAY_WEBHOOK_MAX_SKEW_SECONDS,
    claimLeaseSeconds: env.SCALEWAY_WEBHOOK_CLAIM_LEASE_SECONDS
  });

  // The control plane carries auth, accounts, billing, and email — apply the full
  // production secret/auth validation to it as well as the dev monolith.
  // WHICH ROLES OWE THE PUBLIC AUTH CONTRACT.
  //
  // `metadata-api` is added because it genuinely serves signup, login and the
  // admin console, so a public HTTPS identity and a working mail path are real
  // obligations for it. `control-rpc` is deliberately absent: it registers only
  // the content-free internal contract behind the mTLS bridge, has no auth or
  // admin route at all, and demanding a public HTTPS origin and an SMTP
  // credential of it would force an operator to fabricate both. That is not a
  // relaxation of the contract, it is the contract applied to the role that
  // actually has the surface.
  if (env.NODE_ENV === "production" && SERVES_PUBLIC_AUTH.has(env.RUNTIME_ROLE)) {
    const productionSecrets = [
      { key: "APP_SECRET", value: appSecret, explicitlyConfigured: env.APP_SECRET !== undefined || env.APP_SECRET_FILE !== undefined },
      { key: "EMAIL_HASH_SECRET", value: emailHashSecret, explicitlyConfigured: env.EMAIL_HASH_SECRET !== undefined || env.EMAIL_HASH_SECRET_FILE !== undefined },
      { key: "EMAIL_ENCRYPTION_KEY", value: emailEncryptionKey, explicitlyConfigured: env.EMAIL_ENCRYPTION_KEY !== undefined || env.EMAIL_ENCRYPTION_KEY_FILE !== undefined },
      { key: "COOKIE_SECRET", value: cookieSecret, explicitlyConfigured: env.COOKIE_SECRET !== undefined || env.COOKIE_SECRET_FILE !== undefined },
      { key: "BETTER_AUTH_SECRET", value: betterAuthSecret, explicitlyConfigured: env.BETTER_AUTH_SECRET !== undefined || env.BETTER_AUTH_SECRET_FILE !== undefined }
    ];
    if (env.CONNECT_ENABLED) {
      for (const [version, value] of Object.entries(connectSubjectKeys)) {
        productionSecrets.push({ key: `CONNECT_SUBJECT_KEYS.${version}`, value, explicitlyConfigured: true });
      }
      connectCookieKeys.forEach((value, index) => {
        productionSecrets.push({ key: `CONNECT_COOKIE_KEYS[${index}]`, value, explicitlyConfigured: true });
      });
    }
    validateProductionSecrets(productionSecrets);
    const authProblems: string[] = [];
    if (new URL(env.AUTH_PUBLIC_URL).protocol !== "https:") authProblems.push("AUTH_PUBLIC_URL must use HTTPS");
    const corsOrigins = env.CORS_ORIGIN.split(",").map((origin) => origin.trim()).filter(Boolean);
    if (corsOrigins.length === 0 || corsOrigins.some((origin) => {
      try {
        const parsed = new URL(origin);
        return parsed.protocol !== "https:" || parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
      } catch {
        return true;
      }
    })) {
      authProblems.push("CORS_ORIGIN must contain only explicit public HTTPS origins");
    }
    if (env.AUTH_COOKIE_PREFIX.toLowerCase().includes("local") || env.AUTH_COOKIE_PREFIX.toLowerCase().includes("test")) {
      authProblems.push("AUTH_COOKIE_PREFIX must not identify a local/test environment");
    }
    if (!env.AUTH_REQUIRE_EMAIL_VERIFICATION) authProblems.push("AUTH_REQUIRE_EMAIL_VERIFICATION must be true");
    const mailboxAddress = (value: string) => value.match(/<([^<>]+)>\s*$/)?.[1] ?? value.trim();
    const validMailbox = (value: string) => !/[\r\n]/.test(value)
      && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mailboxAddress(value));
    const publicMailbox = (value: string) => {
      if (!validMailbox(value)) return false;
      const domain = mailboxAddress(value).split("@").at(-1)?.toLowerCase() ?? "";
      return isIP(domain) === 0
        && domain !== "localhost"
        && !domain.endsWith(".localhost")
        && !domain.endsWith(".local")
        && !domain.endsWith(".lan")
        && !domain.endsWith(".internal")
        && !domain.endsWith(".test")
        && !domain.endsWith(".example")
        && !domain.endsWith(".invalid");
    };
    if (!env.SMTP_HOST || !env.SMTP_USER || !smtpPassword) {
      authProblems.push("SMTP_HOST, SMTP_USER, and SMTP_PASSWORD are required");
    }
    if (env.SMTP_PASSWORD_FILE === undefined || env.SMTP_PASSWORD !== undefined) {
      authProblems.push("production SMTP credentials must use SMTP_PASSWORD_FILE only");
    }
    if (process.env.AUTH_EMAIL_FROM === undefined || !publicMailbox(env.AUTH_EMAIL_FROM)) {
      authProblems.push("AUTH_EMAIL_FROM must be explicitly configured with a valid public email address");
    }
    if (process.env.AUTH_EMAIL_REPLY_TO === undefined || !publicMailbox(env.AUTH_EMAIL_REPLY_TO)) {
      authProblems.push("AUTH_EMAIL_REPLY_TO must be explicitly configured with a valid public email address");
    }
    if (env.SMTP_PORT === 465 && !env.SMTP_SECURE) {
      authProblems.push("SMTP port 465 requires SMTP_SECURE=true for implicit TLS");
    }
    if (env.SMTP_PORT === 587 && env.SMTP_SECURE) {
      authProblems.push("SMTP port 587 requires SMTP_SECURE=false so STARTTLS can be negotiated and required");
    }
    if (authProblems.length > 0) {
      throw new Error(`Production auth configuration is invalid (${authProblems.join("; ")})`);
    }
  }

  return {
    env: env.NODE_ENV,
    runtimeRole: env.RUNTIME_ROLE,
    secondaryControlInstance: env.SECONDARY_CONTROL_INSTANCE,
    server: {
      port: env.PORT,
      host: env.HOST,
      bodyLimitBytes: env.REQUEST_BODY_LIMIT_BYTES,
      corsOrigin: env.CORS_ORIGIN,
      trustProxyHops: env.TRUST_PROXY_HOPS
    },
    security: {
      csrfEnabled,
      appOrigins,
      captchaEnabled,
      captchaSecret,
      captchaMaxNumber: env.CAPTCHA_MAX_NUMBER,
      captchaChallengeTtlSeconds: env.CAPTCHA_CHALLENGE_TTL_SECONDS
    },
    logging: {
      level: env.LOG_LEVEL
    },
    redis: {
      url: env.REDIS_URL
    },
    secrets: {
      appSecret,
      emailHashSecret,
      emailEncryptionKey,
      cookieSecret,
      adminAccessToken
    },
    admin: {
      environment: adminEnvironment,
      instanceId: env.ADMIN_INSTANCE_ID,
      deploymentVersion: env.ADMIN_DEPLOYMENT_VERSION,
      mutationsEnabled: env.ADMIN_MUTATIONS_ENABLED ?? (adminEnvironment === "local"),
      sessionCookieName: env.ADMIN_SESSION_COOKIE_NAME,
      sessionCookiePath: env.ADMIN_SESSION_COOKIE_PATH,
      sessionTtlMinutes: env.ADMIN_SESSION_TTL_MINUTES,
      recentAuthMinutes: env.ADMIN_RECENT_AUTH_MINUTES,
      adjustmentApprovalThresholdCents: env.ADMIN_ADJUSTMENT_APPROVAL_THRESHOLD_CENTS,
      adjustmentAutoApplyDailyCapCents: env.ADMIN_ADJUSTMENT_AUTO_APPLY_DAILY_CAP_CENTS
    },
    rejections: {
      eventRetentionDays: env.REJECTION_EVENT_RETENTION_DAYS,
      rollupRetentionDays: env.REJECTION_ROLLUP_RETENTION_DAYS
    },
    auth: {
      sessionCookieName: env.SESSION_COOKIE_NAME,
      sessionTtlDays: env.SESSION_TTL_DAYS,
      publicUrl: env.AUTH_PUBLIC_URL.replace(/\/$/, ""),
      cookiePrefix: env.AUTH_COOKIE_PREFIX,
      secret: betterAuthSecret,
      requireEmailVerification: env.AUTH_REQUIRE_EMAIL_VERIFICATION,
      google: googleClientId && googleClientSecret ? {
        clientId: googleClientId,
        clientSecret: googleClientSecret
      } : null,
      email: {
        from: env.AUTH_EMAIL_FROM,
        replyTo: env.AUTH_EMAIL_REPLY_TO,
        outboxPollMs: env.AUTH_EMAIL_OUTBOX_POLL_MS,
        outboxBatchSize: env.AUTH_EMAIL_OUTBOX_BATCH_SIZE,
        smtp: {
          host: env.SMTP_HOST,
          port: env.SMTP_PORT,
          secure: env.SMTP_SECURE,
          requireTls: env.NODE_ENV === "production" && !env.SMTP_SECURE,
          tlsCa: smtpTlsCa,
          user: env.SMTP_USER ?? "",
          password: smtpPassword
        },
        scalewayWebhook: {
          enabled: env.SCALEWAY_WEBHOOK_ENABLED,
          // Still nullable in the type, because the receiver may legitimately be
          // OFF with no ARN configured. It cannot be null while `enabled` is true:
          // validateScalewayWebhookConfig refuses to build a config in that state,
          // and the route asserts it again rather than trusting that.
          topicArn: env.SCALEWAY_SNS_TOPIC_ARN ?? null,
          certHost: env.SCALEWAY_SNS_CERT_HOST,
          subscribeHostSuffix: env.SCALEWAY_SNS_SUBSCRIBE_HOST_SUFFIX,
          maxSkewSeconds: env.SCALEWAY_WEBHOOK_MAX_SKEW_SECONDS,
          claimLeaseSeconds: env.SCALEWAY_WEBHOOK_CLAIM_LEASE_SECONDS
        }
      }
    },
    connect: {
      enabled: env.CONNECT_ENABLED,
      issuer: connectIssuer,
      publicAppUrl: env.APP_BASE_URL.replace(/\/$/, ""),
      subjectKeys: connectSubjectKeys,
      activeSubjectKeyVersion: env.CONNECT_ACTIVE_SUBJECT_KEY_VERSION,
      cookieKeys: connectCookieKeys,
      jwks: connectJwks,
      accessTokenTtlSeconds: env.CONNECT_ACCESS_TOKEN_TTL_SECONDS,
      refreshTokenTtlSeconds: env.CONNECT_REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60,
      codeTtlSeconds: env.CONNECT_CODE_TTL_SECONDS,
      maxGrantUsd: env.CONNECT_MAX_GRANT_USD,
      maxGrantDays: env.CONNECT_MAX_GRANT_DAYS
    },
    monitoring: {
      alertReceiver: alertReceiverAuthMode ? {
        url: alertReceiverUrl.replace(/\/$/, ""),
        authMode: alertReceiverAuthMode,
        token: alertReceiverAuthMode === "bearer" ? alertReceiverToken : null,
        timeoutMs: env.ALERT_RECEIVER_TIMEOUT_MS
      } : null
    },
    providers: {
      defaultProvider: env.DEFAULT_PROVIDER,
      mockBaseUrl: env.MOCK_PROVIDER_BASE_URL.replace(/\/$/, ""),
      veniceBaseUrl: env.VENICE_BASE_URL.replace(/\/$/, ""),
      veniceInferenceKey,
      veniceKeys,
      veniceKeysetOverlayFile: env.VENICE_KEYSET_OVERLAY_FILE,
      veniceDefaultModel: env.VENICE_DEFAULT_MODEL,
      fireworksBaseUrl: env.FIREWORKS_BASE_URL.replace(/\/$/, ""),
      fireworksApiKey,
      deepinfraBaseUrl: env.DEEPINFRA_BASE_URL.replace(/\/$/, ""),
      deepinfraApiKey,
      chutesBaseUrl: env.CHUTES_BASE_URL.replace(/\/$/, ""),
      chutesAttestationBaseUrl: env.CHUTES_ATTESTATION_BASE_URL.replace(/\/$/, ""),
      chutesApiKey,
      tinfoilBaseUrl: env.TINFOIL_BASE_URL.replace(/\/$/, ""),
      tinfoilApiKey,
      tinfoilConfigRepo: env.TINFOIL_CONFIG_REPO,
      nearBaseUrl: env.NEAR_BASE_URL.replace(/\/$/, ""),
      nearEndpointsUrl: env.NEAR_ENDPOINTS_URL.replace(/\/$/, ""),
      nearApiKey,
      phalaAiBaseUrl: env.PHALA_AI_BASE_URL.replace(/\/$/, ""),
      phalaAiApiKey,
      bedrockEnabled: env.BEDROCK_ENABLED ?? false,
      bedrockRegion: env.BEDROCK_REGION,
      bedrockBaseUrl: (env.BEDROCK_BASE_URL ?? `https://bedrock-mantle.${env.BEDROCK_REGION}.api.aws/v1`).replace(/\/$/, ""),
      bedrockAwsProfile: env.BEDROCK_AWS_PROFILE ?? "",
      bedrockRetentionCheckTtlSeconds: env.BEDROCK_RETENTION_CHECK_TTL_SECONDS
    },
    internal: {
      role: env.RUNTIME_ROLE,
      controlRpcUrl: env.CONTROL_RPC_URL.replace(/\/$/, ""),
      workerRpcUrl: env.WORKER_RPC_URL.replace(/\/$/, ""),
      fireworksWorkerRpcUrl: env.FIREWORKS_WORKER_RPC_URL.replace(/\/$/, ""),
      bedrockWorkerRpcUrl: env.BEDROCK_WORKER_RPC_URL.replace(/\/$/, ""),
      deepinfraWorkerRpcUrl: env.DEEPINFRA_WORKER_RPC_URL.replace(/\/$/, ""),
      chutesWorkerRpcUrl: env.CHUTES_WORKER_RPC_URL.replace(/\/$/, ""),
      tinfoilWorkerRpcUrl: env.TINFOIL_WORKER_RPC_URL.replace(/\/$/, ""),
      nearWorkerRpcUrl: env.NEAR_WORKER_RPC_URL.replace(/\/$/, ""),
      phalaAiWorkerRpcUrl: env.PHALA_AI_WORKER_RPC_URL.replace(/\/$/, ""),
      // Empty by default: operator key lifecycle stays disabled until control
      // is explicitly pointed at the credential worker.
      veniceWorkerUrl: env.VENICE_WORKER_URL?.trim().replace(/\/$/, "") ?? "",
      providerCredentialAdminMode: env.PROVIDER_CREDENTIAL_ADMIN_MODE,
      providerCapabilitySigningKey: env.PROVIDER_CAPABILITY_SIGNING_KEY?.trim() ?? "",
      providerCapabilitySigningKeyId: env.PROVIDER_CAPABILITY_SIGNING_KEY_ID,
      relayIngressUrl: env.RELAY_INGRESS_URL.replace(/\/$/, ""),
      controlMetadataUrl: env.CONTROL_METADATA_URL.replace(/\/$/, ""),
      catalogSyncIntervalSeconds: env.CATALOG_SYNC_INTERVAL_SECONDS,
      catalogSyncEnabled: env.CATALOG_SYNC_ENABLED,
      modelHealthProbeIntervalSeconds: env.MODEL_HEALTH_PROBE_INTERVAL_SECONDS,
      modelHealthProbeEnabled: env.MODEL_HEALTH_PROBE_ENABLED,
      relayRpcToken,
      workerRpcToken,
      metadataRpcToken,
      // Per-provider metadata tokens keyed by provider name (AR-02). Only
      // configured providers appear; an empty map means single-token mode.
      providerMetadataTokens,
      metadataDeploymentScopes,
      confidentialDeploymentId: env.CONFIDENTIAL_DEPLOYMENT_ID,
      credentialAdmin: {
        mode: env.CREDENTIAL_ADMIN_MODE,
        capabilitySigners: env.CREDENTIAL_CAPABILITY_SIGNERS,
        tlsSpkiSha256: env.CONTENT_TLS_SPKI_SHA256,
        consumedCapabilityFile: env.CONSUMED_CAPABILITY_FILE
      },
      // The metadata token this worker role presents (per-provider when set,
      // else the shared token). Irrelevant for non-worker roles.
      workerMetadataToken,
      compatRpcToken,
      // Only honored outside production; production relay/control fail closed.
      allowInlineTicket: env.NODE_ENV === "production" ? false : env.ALLOW_INLINE_TICKET,
      // Production-enableable, default false: the compat broker and the control
      // mint RPC both fail closed unless this is true AND the key carries the
      // opt-in `compat` scope.
      allowCompatMode: env.ALLOW_COMPAT_MODE,
      // Split image generation is a global capability flag (default off). Role
      // ownership is explicit at wiring time: the relay/api serve the route, the
      // worker holds the credential, and control authorizes+settles — but every
      // role reads the SAME flag so control's authorization, the relay's route,
      // and any future compat path each fail closed independently. The catalog
      // listing an image model never implies it is callable; this flag does.
      imageGenerationEnabled: env.IMAGE_GENERATION_ENABLED,
      controlRpcTimeoutMs: env.CONTROL_RPC_TIMEOUT_MS,
      workerRpcTimeoutMs: env.WORKER_RPC_TIMEOUT_MS,
      relayForwardTimeoutMs: env.RELAY_FORWARD_TIMEOUT_MS,
      gatewayAttestation: {
        enabled: env.GATEWAY_ATTESTATION_ENABLED,
        publicOrigins: gatewayPublicOrigins(env.GATEWAY_PUBLIC_ORIGIN),
        releaseId: env.GATEWAY_RELEASE_ID?.trim() ?? "",
        transport: env.GATEWAY_TRANSPORT,
        // NO SNI HERE ANY MORE. It used to be derived once from the single
        // public origin, which was right while there was one name and one
        // certificate. dstack-ingress issues a SEPARATE certificate per name and
        // selects it by SNI, so a single baked servername would make every
        // attestation report the canonical name's SPKI regardless of which name
        // the caller used -- and the alias would fail
        // `tls_certificate_bound_to_quote` at every verifier that observes its
        // own connection. The service derives the SNI from the origin it is
        // binding; see src/gateway/service.ts.
        tlsTerminator: parseTlsTerminator(env.GATEWAY_TLS_TERMINATOR),
        dstackEndpoint: env.DSTACK_ENDPOINT?.trim() || undefined
      },
      // Same role ownership and fail-closed semantics as image: the relay serves
      // /v1/audio/speech, the worker holds the credential, control authorizes +
      // settles, and every role reads this same flag independently.
      speechGenerationEnabled: env.SPEECH_GENERATION_ENABLED
    },
    billing: {
      registeredFreeCreditsUsd: env.REGISTERED_FREE_CREDITS_USD,
      freeTierDailyTokens: env.FREE_TIER_DAILY_TOKENS,
      trialChat: {
        enabled: env.TRIAL_CHAT_ENABLED,
        modelId: env.TRIAL_CHAT_MODEL,
        providerId: env.TRIAL_CHAT_PROVIDER,
        replies: env.TRIAL_CHAT_REPLIES,
        maxOutputTokens: env.TRIAL_CHAT_MAX_OUTPUT_TOKENS,
        inputTokenBudget: env.TRIAL_CHAT_INPUT_TOKEN_BUDGET,
        spendCeilingUsd: env.TRIAL_CHAT_SPEND_CEILING_USD,
        days: env.TRIAL_CHAT_DAYS
      },
      promotions: {
        maxCreditCents: env.PROMOTION_MAX_CREDIT_CENTS,
        maxCampaignCents: env.PROMOTION_MAX_CAMPAIGN_CENTS
      },
      payments: {
        mode: env.PAYMENTS_MODE,
        purchasesEnabled: stripePurchasesEnabled,
        autoTopUpEnabled: stripeAutoTopUpEnabled,
        appBaseUrl: env.APP_BASE_URL.replace(/\/$/, ""),
        minimumCreditPurchaseUsd: env.MINIMUM_CREDIT_PURCHASE_USD,
        maximumCreditPurchaseUsd: env.MAXIMUM_CREDIT_PURCHASE_USD,
        stripeApiKey,
        stripePublishableKey,
        stripeWebhookSecret
      },
      cryptoPayments: {
        mode: env.CRYPTO_PAYMENTS_MODE,
        invoicesEnabled: cryptoInvoicesEnabled,
        enabledRails: cryptoEnabledRails,
        maxDailyCreditUsd: env.CRYPTO_MAX_DAILY_CREDIT_USD,
        btcpayInternalUrl,
        btcpayPublicUrl,
        btcpayStoreId,
        btcpayApiKey,
        btcpayWebhookSecret
      }
    },
    routing: {
      enabled: env.ROUTER_ENABLED,
      modelCacheDir: env.ROUTER_MODEL_CACHE_DIR,
      artifactPath: env.ROUTER_ARTIFACT_PATH,
      allowRemoteModels: env.ROUTER_ALLOW_REMOTE_MODELS,
      confidenceThreshold: env.ROUTER_CONFIDENCE_THRESHOLD,
      maxInputChars: env.ROUTER_MAX_INPUT_CHARS,
      timeoutMs: env.ROUTER_TIMEOUT_MS,
      maxQueue: env.ROUTER_MAX_QUEUE
    },
    mockProvider: {
      port: env.MOCK_PROVIDER_PORT,
      host: env.MOCK_PROVIDER_HOST
    }
  };
}
