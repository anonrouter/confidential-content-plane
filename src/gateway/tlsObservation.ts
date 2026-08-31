// Observe the certificate our own in-CVM TLS terminator actually presents.
//
// WHY THIS EXISTS
//
// The attestation binding carries `tls_spki_sha256`, and a verifier compares it
// against the SPKI it independently observed on its own connection. That check
// is only worth anything if the value in the quote came from the TD rather than
// from the deployer.
//
// It previously came from GATEWAY_TLS_SPKI_SHA256, an environment value.
// Environment values are NOT measured, so an operator could set
// GATEWAY_TRANSPORT=in-tee-tls and paste in the fingerprint of a certificate
// whose private key they hold on some other machine. Every check would pass:
// the client observes that SPKI, the quote repeats that SPKI, they match. The
// quote would be genuine, the measurements real, and the conclusion false. The
// TD would have attested to owning a key it had never seen.
//
// The fix is to stop taking the value as input. This module opens a real TLS
// connection to the terminator inside the trust domain and reads the SPKI out
// of the certificate that terminator actually served in a completed handshake.
// The handshake is the proof of possession: a party that cannot use the private
// key cannot finish it. Nothing an operator writes into the environment can
// change what comes back.
//
// WHAT THIS STILL DOES NOT PROVE
//
// It proves the endpoint at the configured address holds the key. That address
// is a literal in the measured compose and resolves on an `internal: true`
// Docker network with no route out, so it names a container in this same TD
// running a digest-pinned image. It does not, by itself, prove the terminator
// never exported the key; that follows from the terminator generating it
// itself and from the reviewed image, not from this observation.

import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { createHash } from "node:crypto";

export class TlsObservationError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "TlsObservationError";
  }
}

export interface ObservedTlsIdentity {
  /** Lowercase hex SHA-256 over the DER SubjectPublicKeyInfo. */
  spkiSha256: string;
  /** Lowercase hex SHA-256 over the full DER certificate, for logging/audit. */
  certSha256: string;
  subject: string;
  validToMs: number;
  observedAtMs: number;
}

export interface TlsObservationOptions {
  host: string;
  port: number;
  /** SNI to present, when the terminator selects a certificate by name. */
  servername?: string;
  timeoutMs?: number;
}

/**
 * Complete a TLS handshake against our own terminator and return its identity.
 *
 * `rejectUnauthorized` is false ON PURPOSE and it is not a weakening: the
 * terminator's certificate is self-signed or issued by an in-CVM CA, so chain
 * validation is meaningless here and would only fail. What is being extracted
 * is the public key of whoever completed the handshake, which is exactly as
 * trustworthy whether or not a chain validates. The caller must not use this
 * function to decide whether to TRUST a remote party.
 */
export async function observeLocalTlsIdentity(
  options: TlsObservationOptions
): Promise<ObservedTlsIdentity> {
  const timeoutMs = options.timeoutMs ?? 5_000;
  return await new Promise<ObservedTlsIdentity>((resolve, reject) => {
    let settled = false;
    const finish = (error: Error | null, value?: ObservedTlsIdentity): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error); else resolve(value!);
    };

    const socket: TLSSocket = tlsConnect({
      host: options.host,
      port: options.port,
      servername: options.servername ?? options.host,
      rejectUnauthorized: false,
      // ALPN is deliberately omitted: we want the certificate, not a protocol.
      timeout: timeoutMs
    });

    socket.setTimeout(timeoutMs, () => finish(new TlsObservationError("timed out observing the local TLS terminator")));
    socket.once("error", (error: Error) => finish(new TlsObservationError(`could not reach the local TLS terminator: ${error.message}`)));

    socket.once("secureConnect", () => {
      const certificate = socket.getPeerX509Certificate();
      if (!certificate) {
        finish(new TlsObservationError("the local TLS terminator presented no certificate"));
        return;
      }
      let spkiDer: Buffer;
      try {
        spkiDer = certificate.publicKey.export({ type: "spki", format: "der" }) as Buffer;
      } catch (error) {
        finish(new TlsObservationError(`could not export the terminator's SPKI: ${(error as Error).message}`));
        return;
      }
      finish(null, {
        spkiSha256: createHash("sha256").update(spkiDer).digest("hex"),
        certSha256: createHash("sha256").update(certificate.raw).digest("hex"),
        subject: certificate.subject,
        validToMs: Date.parse(certificate.validTo),
        observedAtMs: Date.now()
      });
    });
  });
}

/**
 * Cache the observation for a short window.
 *
 * A TLS handshake per attestation call would add a round trip to a route that
 * is already rate-limited for guest-agent reasons, and the certificate does not
 * change between handshakes. The window is short so a rotation is picked up
 * quickly rather than being served stale for the life of the process, and any
 * failure clears the cache rather than being memoized: a terminator that has
 * gone away must make attestation fail, not keep answering from memory.
 */
/** One completed handshake against a named terminator. The injectable seam. */
export type TlsObservation = (options: TlsObservationOptions) => Promise<ObservedTlsIdentity>;

export class TlsIdentityObserver {
  private cached: ObservedTlsIdentity | null = null;
  private inflight: Promise<ObservedTlsIdentity> | null = null;
  private readonly observe: TlsObservation;

  constructor(
    private readonly options: TlsObservationOptions,
    private readonly ttlMs = 30_000,
    // `?? observeLocalTlsIdentity` rather than a parameter default, because a
    // caller that forwards an optional seam through passes `undefined`
    // explicitly, and a default only applies to an ARGUMENT THAT IS ABSENT.
    observe?: TlsObservation
  ) {
    this.observe = observe ?? observeLocalTlsIdentity;
  }

  async current(now = Date.now()): Promise<ObservedTlsIdentity> {
    if (this.cached && now - this.cached.observedAtMs < this.ttlMs) return this.cached;
    if (!this.inflight) {
      this.inflight = this.observe(this.options)
        .then((identity) => {
          this.cached = identity;
          return identity;
        })
        .finally(() => {
          this.inflight = null;
        });
    }
    return this.inflight;
  }
}
