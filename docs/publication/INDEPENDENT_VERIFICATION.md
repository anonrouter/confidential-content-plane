# Verifying an AnonRouter confidential deployment yourself

This is the complete procedure for a third party with no relationship to us: what
to fetch, what to build, what to run, what each output proves, and, in the same
detail, what it does not prove.

The last part is not a disclaimer section bolted on at the end. It is the point.
A verification procedure that only tells you what passes teaches you to read a
green result as a stronger claim than it is, and the whole reason this material
is public is that the strong claim is not available yet.

## Read this first: the honest summary

| Question | Answer today |
| --- | --- |
| Can you check the published source says what we say it says? | **Yes**, completely. Clone, read, build, run the suites. |
| Can you check a deployed image was built from that source? | **No.** No CI build has produced a deployed digest, and no build provenance has been published. |
| Can you check a quote is structurally valid and bound to your nonce? | **Yes.** |
| Can you check the quote's signature chains to Intel? | **Yes, but not from this repository.** You need a DCAP verifier, and the one we use is not reproducible yet. |
| Can you check the deployment matches a reviewed set of measurements? | **No.** No production measurement policy exists. See "The measurement policy does not exist yet". |
| Can you check the plaintext-capable third-party components? | **Partly.** Three have no source-to-digest binding at all. |
| Can you check customer TLS terminates inside the trust domain? | **Yes**, and this is the strongest single result available. |

If you take one thing from this document: **the chain is publishable and
incomplete, and the incomplete links are named.**

## What to fetch

| Artifact | Where | Why you need it |
| --- | --- | --- |
| The content-plane source | this repository, at a `content-plane-v*` tag | The code that can touch plaintext |
| `deploy/provenance/plaintext-capable-components.json` | this repository | The state of every third-party binding |
| The signed release manifest | published **with** the release | Binds source commit, image digests and the measured Compose hash |
| The measurement policy | published **independently of the gateway** | The measurements you are willing to accept |
| `dcap-qvl` 0.6.1 | crates.io | Quote signature verification against Intel |
| Intel's DCAP collateral | Intel's PCS | TCB and QE identity, to evaluate the quote |

**The manifest and the policy must never be fetched from the origin you are
verifying.** An origin that serves its own authorization can authorize anything.
`src/gateway/policy.ts` refuses a URL for exactly this reason, and you should
treat any procedure that fetches either one from the gateway as broken rather
than convenient.

## What to build

### 1. The content plane itself

```
git clone <this repository>
cd <repo> && git checkout content-plane-v<version>
npm ci                    # the lockfile, not a fresh resolve
npm run build
npm test
```

**What this proves.** That the published source compiles standalone with no
access to any private monorepo, and that its own boundary suites pass: the module
graph from `src/contentPlane.ts` reaches no control-plane module at runtime or at
compile time, the control RPC contract carries no prompt field, the logger
allowlist holds, and the credential-capability refusals bite.

**What this does not prove.** That any deployed image was built from these bytes.
`npm run build` produces **an** image; nothing here compares it to a deployed
digest. See "The link that is missing" below.

### 2. A DCAP verifier

The content plane ships the verification **logic** (`src/gateway/verify.ts`,
`src/gateway/policy.ts`) but **not** `src/gateway/dcap/`, the chain verifier.
Without one, `verifyGatewayAttestation` returns `verificationLevel:
"provider-attested"` and says so in its own output. That is deliberate: the
verdict is capped rather than quietly upgraded.

Our verifier is a small Rust binary over `dcap-qvl` 0.6.1. Its build manifest
is `native/dcap-verifier/BUILD-MANIFEST.txt`:

| | |
| --- | --- |
| `dcap-qvl` | `=0.6.1` (crates.io, MIT; 0.6.0 is yanked) |
| Enabled features | `_anycrypto, default-x509, rustcrypto, serde_json, std, urlencoding` |
| `Cargo.lock` SHA-256 | `3c4fc0f3ae94ff305e1e83689b98aace511e9a4c855ada45757dcb5eebb877ab` |
| Intel root CA SHA-256 | `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3` |
| Reference build host | `aarch64-apple-darwin`, rustc 1.94.1 (e408947bf 2026-03-25) |
| Reference binary SHA-256 | `c728a123657cbc309bfb9cfa907c059a1ae7c726ac900ab153f137cc93d1a00c` |
| Toolchain pin | `rust-toolchain.toml`, channel `1.94.1` exactly |

**That binary digest is a development build and is still NOT something to match
against.** Do not treat it as authoritative. Three of the six gaps below closed
on 2026-08-25 and three remain; the ones that remain are the ones that would
make a published digest mean anything.

1. ~~A pinned toolchain.~~ **DONE.** `native/dcap-verifier/rust-toolchain.toml`
   pins channel `1.94.1` exactly, and the build refuses to proceed if the
   installed rustc differs or if the pin names a moving channel.
2. ~~`--remap-path-prefix` for the workspace and `CARGO_HOME`.~~ **DONE**, and
   checked on the built artifact rather than inferred from the flags: the binary
   is grepped for both paths and contains neither.
3. ~~`SOURCE_DATE_EPOCH` and a fixed `CARGO_HOME` layout.~~ **DONE**, derived
   from the last commit touching the crate so it is the same on every machine.
4. A digest-pinned container for the Linux targets, so linker and libc are fixed.
   **Open, and now known to be mandatory rather than tidy.**
5. **Two independent builders producing the same digest. Open.** A
   reproducibility claim verified once on one machine is not a reproducibility
   claim. Two clean builds on one host are now proven byte-identical, which is a
   strictly weaker property.
6. Signed release artifacts, with the digest distributed the way the measurement
   policy is: independently of the gateway being verified. **Open.**

**Why you should still build your own, stated precisely.** Measured on
2026-08-25, identical source built at two different absolute paths on macOS
produces binaries of identical size that differ in exactly two regions totalling
48 bytes: the Mach-O `LC_UUID` and the ad-hoc code-signature hash covering it.
All 750,080 other bytes match. Suppressing the UUID is not an option, because
`-Wl,-no_uuid` makes cargo's own build scripts unloadable and the build fails.
So **a macOS digest is not comparable between two builders at all**, and any
match you get would be luck. Run
`scripts/dcap-verify-build.sh --cross-path` to reproduce that measurement
yourself.

`rustcrypto` was chosen over `ring` on purpose: pure Rust, no C toolchain, no
assembly or build script to vary across hosts. `ring` is more battle-tested and
materially harder to build reproducibly.

**You are better off building your own verifier than trusting ours.** `dcap-qvl`
is MIT and the inputs above are enough to reconstruct the configuration. If your
independently built verifier disagrees with ours about a quote, your verifier is
the one to believe, and we want to hear about it.

**One upstream defect to know about**: `dcap-qvl` 0.6.1 declares
`wasm-bindgen-futures` as an unconditional, non-optional dependency instead of
gating it on `cfg(target_arch = "wasm32")`. It is inert on native targets but
drags `wasm-bindgen` and `js-sys` into every native build, enlarging the surface
you have to review. It does not add network access: the build script separately
asserts no HTTP client is present.

## What to run

### Step 1. Get evidence bound to a nonce you chose

```
nonce=$(openssl rand -hex 32)
curl -sS -X POST https://<origin>/v1/tee/attestation \
  -H 'content-type: application/json' \
  --data "{\"nonce\":\"${nonce}\"}" > evidence.json
```

**Proves:** the response is about this request. Without a nonce you have a
document, not evidence: a genuine quote from a state the deployment is no longer
in replays perfectly.

**Does not prove:** anything about the contents yet. Everything below is a check
on this one file plus the connection that delivered it.

### Step 2. Verify the quote signature against Intel

Run your DCAP verifier over `evidence.json`'s quote with fresh Intel collateral.

**Proves:** the quote was produced by a genuine Intel TDX platform, and the TCB
status is what the verifier computed rather than what the deployment claimed.

**Does not prove:** anything about what is running inside the TD. A genuine
platform can run anything. That is what step 4 is for.

**Insist on `UpToDate`.** `ConfigurationNeeded` and `OutOfDate` are findings
about a real machine, not warnings to carry forward. If you see the TCB status
only as a JSON field in `evidence.json` and never computed it yourself, you have
read the deployment's opinion of itself.

### Step 3. Observe the TLS key, do not read it

```
echo | openssl s_client -connect <host>:443 -servername <host> 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | xxd -p -c 256
```

Compare to `binding.tls_spki_sha256` in the evidence.

**Proves, and this is the strongest single result available today:** the TD that
produced the quote holds the private key of the certificate your connection
actually used. Completing a handshake requires the key. So customer TLS
terminates inside the trust domain, and the platform operator's gateway forwards
raw TCP rather than terminating.

Note what the design does **not** do here. There is no way to hand the
attestation service a fingerprint. An earlier revision had one, an unmeasured
environment value, which let a deployer claim in-TEE TLS while naming a
certificate whose private key sat on another machine: the client observes that
SPKI, the quote repeats it, every check agrees, and the trust domain has attested
to owning a key it never saw. The service now completes a real handshake against
the terminator and publishes what it observed.

**Does not prove:** that plaintext is not exfiltrated by the workload after
decryption. That is the boundary the source and its suites address, not this
check.

### Step 4. Verify the measurements and the manifest

```
node --input-type=module -e '
  import { readFileSync } from "node:fs";
  const { loadGatewayPolicy } = await import("./dist/src/gateway/policy.js");
  const { verifyGatewayAttestation } = await import("./dist/src/gateway/verify.js");
  const result = verifyGatewayAttestation(
    JSON.parse(readFileSync("evidence.json", "utf8")),
    {
      nonce: process.env.NONCE,
      origin: process.env.ORIGIN,
      policy: loadGatewayPolicy(JSON.parse(readFileSync("policy.json", "utf8"))),
      now: Date.now(),
      observedTlsSpkiSha256: process.env.OBSERVED_SPKI
    }
  );
  console.log(result.status, result.verificationLevel, result.reason ?? "");
'
```

**Proves, when `status` is `ok`:** the served `app_compose` hashes to the measured
Compose hash in the quote; the manifest declares `public_logs: false` and
digest-pinned images; the transport is the measured literal `in-tee-tls`; the
evidence is fresh and bound to your nonce and origin; and the measurements match
the policy you supplied.

**`verificationLevel` is the sentence that matters.** `provider-attested` means
no DCAP chain verifier was supplied and the quote's signature was never checked.
It is not a lesser flavour of `hardware-verified`; it is a different claim.

### Step 5. Check the release manifest against the running deployment

Compare the manifest's `compose.measured_hash` to `binding.compose_hash` in your
evidence, its `release_id` to the commit you checked out, and confirm that commit
resolves in this public repository (`git cat-file -e <sha>^{commit}`).

**Proves:** the deployment you measured is the one the manifest describes, and
the manifest names a commit anyone can fetch.

**Does not prove:** that the image digests in that manifest were built from that
commit. That is the missing link, next.

## The link that is missing, stated plainly

**No source-to-digest binding exists for our own image.**

A verifier can get from "some reviewed build is running" to "THIS Compose is
running" today. Getting to "this Compose was built from THAT commit" requires a
CI build that signs its output against a pinned OIDC identity, and no such build
has produced a deployed digest.

Two specific reasons, both worth knowing:

1. **There is no public CI yet.** The workflows are written and inert in
   `.github/workflows/`. They refuse to run while their placeholders are
   unfilled, and the repository identity they pin does not exist.
2. **The currently deployed image was not built from a Dockerfile at all.** It is
   the previous image with one deterministic layer appended by `crane append`,
   carrying a fresh `dist/` and migrations. Docker could not build locally, and
   the guest's measured egress allowlist does not include Docker Hub, so
   `FROM node:22-bookworm-slim` times out. Unlocking egress to pull a base image
   would have traded a real control for convenience.

The consequence is concrete and it is not softened here: **running `npm ci &&
npm run build` from this repository will not reproduce the deployed digest.** A
CI build under the provenance policy will produce a different digest again, which
means signing the deployed artifact requires a rebuild and a redeploy.

Once such a build exists, the check is:

```
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity <exact job_workflow_ref at the release tag> \
  <registry>/<image>@sha256:<digest>

cosign verify-attestation --type slsaprovenance1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity <exact job_workflow_ref at the release tag> \
  <registry>/<image>@sha256:<digest>
```

Two things about that command, both easy to get wrong:

- **`--certificate-identity` is an exact match, never a prefix.** Verifying
  against whatever identity the bundle happens to carry proves only that someone
  signed it.
- **The workflow ref is not enough.** It names a workflow file at a ref a tag can
  move: delete the tag, recreate it against different content, and the ref still
  matches. You must also pin `job_workflow_sha`, the workflow file's own commit.
  Two distinct commits are being pinned and they are easy to conflate:

  | Pin | What it fixes |
  | --- | --- |
  | Source commit | The content-plane code that was built |
  | `job_workflow_sha` | The build logic that built it |

  Confirm the claim encoding against the current Fulcio specification (the
  `1.3.6.1.4.1.57264.1.*` extension arc) rather than trusting the OID numbers or
  tool flags repeated in any document, including this one.

Also require a **Rekor inclusion proof** against a pinned Rekor public key. An
unlogged signature is not acceptable: it can be produced and discarded, leaving
nothing anyone else can audit.

## The three third-party gaps

Three components can touch plaintext and are not built from this source. For all
three, the source-to-digest binding is **NOT established**. The authoritative
record is `deploy/provenance/plaintext-capable-components.json`; this is a
summary of it.

| Component | Role | What exists | What that is not |
| --- | --- | --- | --- |
| `dstack-ingress` | Terminates customer TLS in-TD. Every request arrives through it | Upstream source pinned to commit `b1a90408c314b3bccf8aa529585c01de2fe0fa56`, all 34 files re-hashed against that commit's tree, licence confirmed Apache-2.0, build inputs extracted. Deployed at `sha256:d05a7b34…` | A **source pin**. It says which bytes we intend to build. It says nothing about which bytes are running |
| `node:22-bookworm-slim` | Base image of the content plane. Runs every line of code that handles a prompt | Pinned to the linux/amd64 **image manifest** digest `sha256:a17d50af…`, plus an unsigned registry SLSA statement naming `nodejs/docker-node@bc0a422b`, path `22/bookworm-slim` | An **unsigned registry attestation**. Its trust root is registry push access, not an identity we pinned. Anyone who can push can attach one |
| `caddy:2.11.4-alpine` | Base image of the in-CVM L7 edge, which proxies bodies after TLS terminates in-TD | Pinned to the linux/amd64 image manifest digest `sha256:98eb57d8…`, plus an unsigned registry SLSA statement naming `caddyserver/caddy-docker@fba28535`, path `2.11/alpine` | The same. Useful for telling a rebuilder what to build; not evidence about what ran |

What the pins **do** buy, and it is not nothing: they are **image manifest**
digests, not tags and not multi-arch index digests. A tag moves. An index digest
is immutable but still resolves to a different image per builder architecture, so
two builds of identical source could differ with nothing recording which ran.
Pinning the amd64 child means every build gets the base that actually ships.

If you want to close one of these yourself, the unsigned registry statements name
the exact commit to rebuild and compare. That is their entire value, and it is a
real one: it turns a gap nobody can act on into one with a defined next step.

**A near miss is not a partial pass.** The deployed `dstack-ingress` digest is
upstream's published image, and upstream did not necessarily build it from the
pinned commit under conditions anyone can reproduce. If a faithful rebuild
produces a different digest, the correct outcome is that the binding stays
unestablished and the discrepancy is recorded.

## The measurement policy does not exist yet

There is no production measurement policy to check a deployment against, and this
is not an oversight.

A policy binds an **origin** and the **TLS SPKI observed on that origin**, along
with `mrTd`, `rtmr0` to `rtmr2`, `osImageHash`, the app id, the Compose hash and
the release id. The production origin does not exist until the DNS cutover.
Generating a policy now against the preprod hostname would create an artifact
that must be discarded at cutover, and an artifact that looks authoritative and
is not is worse than an absent one.

The only policy in the repository, `deploy/phala/measurement-policy.production.json`,
is marked `$superseded`: it describes a legacy Amsterdam identity that is not part
of the intended launch architecture. **Do not use it.** It was never published
externally and no live endpoint serves it.

Until a production policy exists, step 4 above has nothing to check measurements
against. You can still verify structure, freshness, nonce binding and the TLS
observation. You cannot verify that the measurements are ones anybody reviewed.

## What a fully green run still does not prove

Even with every step above passing, and with the missing links closed:

- **Not that the code is correct or free of vulnerabilities.** Attestation
  proves which code ran. Reading it is your job and ours; neither is finished by
  a signature.
- **Not that the operator cannot change the deployment later.** It proves what
  was running when your nonce was answered. Re-verify on an interval you choose;
  that is what `verifyProxy`'s bounded revalidation does.
- **Not that Intel's attestation infrastructure is trustworthy.** The root of
  trust is Intel's. If you do not accept that root, no amount of verification
  below it helps.
- **Not that side channels, physical attacks or platform firmware bugs are
  absent.** TDX has a threat model and it has known limits.
- **Not that the control plane behaves as described.** It runs elsewhere and is
  not published. What is published and enforced is that it cannot receive
  content: the RPC contract carries no prompt field and
  `tests/unit/rpc-boundary-contract.test.ts` fails if one appears. That is a
  claim about the boundary, not about the other side of it.
- **Not that we cannot see your prompts by some route not modelled here.** This
  procedure checks the routes we have modelled. It is evidence, not a proof of a
  negative, and anyone who tells you otherwise about any confidential-computing
  system is overselling it.

## If a check fails

Do not route around it. Specifically:

- A `SKIP` is not a `PASS`. If a step could not run, the link is unverified, and
  a summary that reports "no failures" over a run full of skips is the failure
  mode this whole design is organised against.
- If the observed TLS SPKI does not match the attested one, stop. That is the
  single check that would catch a terminator outside the trust domain.
- If the manifest names a digest the deployment is not running, stop. Neither
  document is authoritative over the other; they disagree, and until you know
  why, you know nothing.

Contradictory evidence is worth reporting to us and worth publishing. We would
rather be corrected in public than be trusted by default.
