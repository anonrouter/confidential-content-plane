// The configuration boundary of the confidential content plane.
//
// D-22 established that the plaintext-capable workload is a separate image from
// the monolith. This type is the same boundary applied to configuration: it
// names, exhaustively, the settings a role that can see a prompt is allowed to
// read.
//
// WHY A TYPE AND NOT A SEPARATE PARSER
//
// A second parser would be a second source of truth for the same environment,
// and the two would drift silently. Instead there is one parser, `loadConfig()`,
// which no longer knows anything about the database, and this type narrows what
// content-plane code can reach. `AppConfig` structurally satisfies
// `ContentPlaneConfig`, so the monolith passes its own config to shared code
// unchanged, while content-plane code that reaches for `config.db`,
// `config.auth`, `config.billing`, `config.admin` or `config.connect` fails to
// compile.
//
// WHAT IS DELIBERATELY ABSENT
//
//   db          the content plane has no database. Not narrowed: removed. The
//               settings are not in the shared schema at all (src/db/config.ts).
//   redis       rate limiting is a control-plane concern.
//   auth        sessions, cookies, SMTP, OAuth: control plane.
//   admin       the operator console never runs beside a prompt.
//   billing     payments, Stripe, BTCPay, trial and promotion budgets.
//   connect     the OAuth issuer and its signing keys.
//   monitoring  the alert receiver and its bearer token.
//   security    CSRF and captcha, which guard browser-facing control routes.
//   secondaryControlInstance, mockProvider  control-side only.
//
// `secrets` is narrowed rather than removed: the content plane needs
// `appSecret` for daily-rotating network fingerprints, and must not hold the
// cookie secret, the admin access token, or the email hashing and encryption
// keys.

import type { SharedConfig } from "./config.js";

export type ContentPlaneConfig = Pick<
  SharedConfig,
  "env" | "runtimeRole" | "server" | "logging" | "providers" | "internal" | "routing"
> & {
  readonly secrets: {
    readonly appSecret: string;
  };
};
