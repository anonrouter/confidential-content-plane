# AnonRouter confidential content plane

Every component that can touch prompt or response plaintext inside the Intel
TDX trust domain, and the tests that enforce the boundary.

## What this repository is for, and what it is not

Attestation proves **which code ran**. It never proves what that code does.
This repository exists so the second question has an answer a stranger can
check by reading rather than by trusting: this is the source, and these are
the tests that hold the boundary it describes.

**It does not, by itself, prove that the image running in the trust domain was
built from these bytes.** That is a separate artifact, a source-to-digest
binding, and it is produced by a CI build that signs its output against a
pinned OIDC identity. Until such a build has produced a digest equal to the one
a deployment is measured against, the honest statement is:

> This repository shows what the code says. It does not yet show what the
> deployment ran.

Running `npm ci && npm run build` here produces **an** image. Nothing in this
repository asserts that it equals any deployed digest, and you should not
assume it does. The build is deterministic in its inputs, which is a
precondition for that binding and is not the binding.

## The boundary, component by component

For every component that can touch a prompt, a reader can either read the
source here or follow a reference to pinned upstream source. Which applies:

| Component | Can touch plaintext | Where the source is |
| --- | --- | --- |
| `relay` | full request and response bodies, transiently | here |
| classifier (in-process on the relay) | the truncated latest user turn | here |
| `compat` broker | full bodies **and** the caller's static `ar_` key | here |
| `<provider>-worker` | full bodies plus one provider credential | here |
| `edge` (in-CVM L7 router) | full bodies, after TLS terminates in-TD | here (configuration); its base image is **UPSTREAM, caddyserver/caddy-docker. Apache-2.0. Source-to-digest binding NOT established; see the gaps below** |
| `<provider>-egress` | ciphertext only (SNI passthrough) | here (configuration) |
| `gateway-attestation` | **no content at all** | here |
| `dstack-ingress` | ciphertext, then the plaintext stream in transit | **UPSTREAM, Dstack-TEE/dstack-examples. Apache-2.0. Rebuilt in this repository's CI from pinned upstream source, byte-identical to the deployed digest; see below** |

The `relay`, `compat`, `worker` and `gateway-attestation` roles are all the
same first-party image, selected by `RUNTIME_ROLE`. Its **base image** is
upstream: it runs every line of code in this repository, so it is
plaintext-capable whatever the code above it does, and it is covered by the
ledger like any other third-party component.

### What a binding is

Exactly one of two things. Nothing else counts, and in particular a pinned
digest is not one, a stated Git revision is not one, and an unsigned
attestation published by a registry is not one:

- **Rebuild.** Build the component in our public CI from pinned upstream source
  and confirm the digest equals the deployed one. A near miss is not a partial
  pass, and a laptop build is a rehearsal rather than evidence, because the
  point is that a reader can check it without trusting whoever ran it.
- **Verified upstream provenance.** Verify an upstream signature against a
  **pinned** upstream identity, both certificate identity and OIDC issuer, over
  the digest actually deployed.

### 1 established binding

**`dstack-ingress`** Terminates customer TLS inside the trust domain. This is the serving path, not an optional one: every request arrives through it. Production runs `ghcr.io/anonrouter/anonrouter-dstack-ingress@sha256:bb6fbf4f89b1f12442c2ae0cbb3f640562fa7362adc6c7ef2bb3d898c02906bd`, an AnonRouter image built FROM `dstacktee/dstack-ingress:2.3@sha256:527c53523b9226782a11dbd800a3ff55e8a1f0b88e6224e8f7e4db7419769fbe`. So the upstream artifact is a build-time dependency and not a runtime one: nothing is pulled from the upstream registry at boot. Its provenance is still the question this entry is about, because the derived image contains it.

Rebuilt by `https://github.com/anonrouter/confidential-content-plane/.github/workflows/dstack-ingress-rebuild.yml@refs/heads/main` (workflow commit
`f65f11652a97c29412863398309946289a6f59f9`) from `Dstack-TEE/dstack-examples@b322d14e74920c6523dc7ac7e2974e0414df82d0`,
producing `sha256:527c53523b9226782a11dbd800a3ff55e8a1f0b88e6224e8f7e4db7419769fbe`, which is the deployed digest.

The commit was not chosen. It was read from `/etc/.GIT_REV` inside the deployed
image before any source was fetched, so it is a property of the artifact rather than a claim about it.

### The 2 unproven links, stated rather than rounded up

2 plaintext-capable components in this deployment are not built from this
source, and for each of them the source-to-digest binding is **NOT established**: `caddy-edge-base`, `node-base-image`.

**`caddy-edge-base`** Base image of the in-CVM L7 edge, which proxies customer plaintext after TLS terminates inside the trust domain. Deployed at `caddy:2.11.4-alpine@sha256:98eb57d882ccd5213d1688764db10c1ca2c58a1ca3a6717a3411ad798f7a423a`.

The registry publishes an **unsigned** in-toto SLSA statement whose subject is that exact
digest, naming upstream commit `fba2853501d36e8a72f946ac8cb7ff64d07e48f2`
(`2.11/alpine`). That is useful and it is **not a binding**:
its trust root is whoever can push to that registry repository, not an identity we pinned.
It tells a rebuilder exactly which commit to build and compare. It does not tell anyone that
the image in service came from that commit.

**This gap has been measured, and it is not "not attempted yet".** AnonRouter's public CI replayed
upstream's own recorded build invocation for this exact digest, natively on `linux/amd64`, with every
argument read out of the deployed image's own SLSA statement rather than from any file in this
repository. Result on 2026-09-02: `NOT-REPRODUCED-RECIPE-NONDETERMINISTIC`.

Two **identical** invocations, minutes apart on the same runner with a cold cache, produced
`sha256:814143b2fffc1e6d557976099a3e32914668bb203a5a43c23c8aa989325a7a87` and `sha256:eec80ff07eb230cb95bc5e53bc63729f85e09a07d0b7ff05507c0230e85425d8`. Those are different images, so the
**published recipe is not deterministic**, and no replay of it can match a fixed digest whoever runs
the replay. Why, precisely:

- **`recipe-nondeterministic`** Two identical native linux/amd64 invocations, minutes apart with a cold cache, produced sha256:814143b2 and sha256:eec80ff0. The published recipe is not deterministic, so no replay of it can match a fixed digest, whoever runs the replay.
- **`build-clock-in-layer-content`** /var/log/apk.log ships inside the image and its first line records the second the build ran: 'Running `apk add --no-cache ca-certificates curl libcap mailcap` at 2026-06-22 20:09:02'. File content, not metadata, so no normalisation flag rewrites it.
- **`build-clock-in-image-config`** 21 history timestamps differ between two runs of the same recipe, at sub-second precision.
- **`build-clock-in-manifest-annotation`** org.opencontainers.image.created is derived from `env.SOURCE_DATE_EPOCH // now` by docker-library's meta.jq, and the recorded build set no epoch. The annotation is manifest bytes, so it is part of the digest.
- **`mutable-archive`** `apk add --no-cache` resolves against Alpine v3.23's live repository. Against the deployed image the rebuild differs by c-ares 1.34.6 -> 1.34.7, a rebuilt curl and libcurl, and the matching lib/apk/db/installed entries. The contents were never recoverable from the source after the fact.
- **`option-b-absent`** No OCI referrer on the child or the index, no cosign .sig sibling tag, no GitHub attestation under docker-library. One Rekor entry names this digest and carries a bare public key rather than a certificate, so it attests to no identity at all.

Full comparison, layer by layer and path by path: [`.evidence/doi-base-rebuild/caddy-edge-base-verdict.json`](.evidence/doi-base-rebuild/caddy-edge-base-verdict.json).
The run is public: https://github.com/anonrouter/confidential-content-plane/actions/runs/33689328190

Option B was measured on the same run and found nothing qualifying **as of 2026-09-02**: no OCI
referrer, no cosign signature tag, no attestation under the builder's GitHub org. Where the Sigstore
transparency log carries an entry over the digest at all, it is a bare public key with no certificate,
so it names nobody and cannot be pinned to an upstream identity. A check that asked only whether the
digest appears in the log would have accepted it.

**What this does and does not establish:**

WHAT THIS ESTABLISHES: replaying the recipe docker-library publishes for this
digest did not reproduce it, and two identical replays of that recipe disagreed
with each other, so the published recipe is not deterministic. No signature
meeting this project's option B bar existed for the digest on the date below.

WHAT IT DOES NOT ESTABLISH, and an earlier revision of this entry overstated
exactly here by phrasing a scoped negative as a universal one: this does not
show the digest is permanently unbindable. Upstream could publish a
qualifying signature, which would close
this with no rebuild at all; a party holding build inputs outside the published
recipe could produce evidence this run cannot; and this project could accept a
different kind of evidence after review. The claim is scoped to the published
recipe, the inputs reachable from it, and the measurement date.

**There is a replacement candidate. It is integrated in source and NOT deployed.**
`ghcr.io/anonrouter/mirror/anonrouter-caddy-base@sha256:62c3df7708bf00f13240cb028cba40d44757ea5c6c8584bc8867e288a61555f5` is built by AnonRouter from
`anonrouter/confidential-content-plane@8e79c05de21e8efcfad4a04a45d267eb2009fd9b`, reproduced independently by a second CI job at the same
digest, and signed against a pinned identity and issuer:

```
cosign verify \
  --certificate-identity 'https://github.com/anonrouter/confidential-content-plane/.github/workflows/anonrouter-base-build.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/anonrouter/mirror/anonrouter-caddy-base@sha256:62c3df7708bf00f13240cb028cba40d44757ea5c6c8584bc8867e288a61555f5
```

**It inherits no container base image.** `inheritedBaseImages` is empty and the ledger schema will
not accept a non-empty one. Everything in it is a release artifact pinned by a digest upstream
publishes, a file from a Debian package pinned by a sha256 that also appears in the index Debian's
OpenPGP-signed `Release` covers, or a literal in a published assembly script.

It is not zero-dependency, and the remainder is named rather than omitted. These images BUILD it
and none of their bytes ship:

- `debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867` — the unpack stage runs dpkg-deb and ldconfig. None of its bytes reach the shipped image, every input it consumes is hash-pinned before it runs, and two independent CI jobs must agree on the output digest. A weaker exposure than an inherited rootfs, and not zero.

**Compatibility was measured, not asserted.** `scripts/provenance/edge-compat-harness.sh` builds the same source on
the base this replaces and on the candidate, runs an identical matrix under the real deployment
policy, and requires them to agree: 24 checks, 0 differing. A deliberately broken
variant is the control, and the matrix detected it in 1 check(s) — without that, agreement
would be consistent with a matrix that cannot tell two images apart. Evidence:
[`.evidence/base-image-compat/edge-compat-local.json`](.evidence/base-image-compat/edge-compat-local.json).

It proves **nothing about the artifact above**. A replacement is not a binding for the thing in
service, and saying otherwise would be the exact rounding-up this document exists to refuse.
Referenced now by `deploy/phala/images/edge/Dockerfile`, so the NEXT build uses it;
nothing running does. Promoting it moves the measured Compose hash, the app id and the attestation
policy, which makes it a measured-release decision rather than a documentation edit.

**`node-base-image`** Base image of the content-plane image; runs every line of code that handles plaintext. Deployed at `node:22-bookworm-slim@sha256:a17d50af28002a160548bd4225b3cfcb12c5efcb171f79e68758f2885fb1b066`.

The registry publishes an **unsigned** in-toto SLSA statement whose subject is that exact
digest, naming upstream commit `bc0a422bce0f729dd85790639d9f1918143f1235`
(`22/bookworm-slim`). That is useful and it is **not a binding**:
its trust root is whoever can push to that registry repository, not an identity we pinned.
It tells a rebuilder exactly which commit to build and compare. It does not tell anyone that
the image in service came from that commit.

**This gap has been measured, and it is not "not attempted yet".** AnonRouter's public CI replayed
upstream's own recorded build invocation for this exact digest, natively on `linux/amd64`, with every
argument read out of the deployed image's own SLSA statement rather than from any file in this
repository. Result on 2026-09-02: `NOT-REPRODUCED-RECIPE-NONDETERMINISTIC`.

Two **identical** invocations, minutes apart on the same runner with a cold cache, produced
`sha256:6babfba1586e01cc2da1e051f5c879b37c259f0f83db9f03370bcd8498d24953` and `sha256:c1d12a978b22af8334fe0a8001e93c8f9b41a20558fd7e5ed642d22ab498c921`. Those are different images, so the
**published recipe is not deterministic**, and no replay of it can match a fixed digest whoever runs
the replay. Why, precisely:

- **`recipe-nondeterministic`** Two identical native linux/amd64 invocations, minutes apart with a cold cache, produced sha256:6babfba1 and sha256:c1d12a97. The published recipe is not deterministic, so no replay of it can match a fixed digest, whoever runs the replay.
- **`build-clock-in-layer-content`** The ENTIRE difference between those two runs is four shipped log files: /var/log/dpkg.log, /var/log/alternatives.log, /var/log/apt/history.log and /var/log/apt/term.log. apt and dpkg write the wall clock into them and the image ships them. The deployed dpkg.log carries 1,052 such stamps. File content, not metadata.
- **`build-clock-in-image-config`** 9 history timestamps differ between two runs of the same recipe.
- **`build-clock-in-manifest-annotation`** org.opencontainers.image.created is derived from `env.SOURCE_DATE_EPOCH // now` by docker-library's meta.jq, and the recorded build set no epoch.
- **`build-day-in-etc-shadow`** /etc/shadow differs from the deployed image because the node account's last-changed field is a count of days since the epoch. Day resolution, so two runs on the same day agree and a rebuild on any other day cannot.
- **`option-b-absent`** No OCI referrer on the child or the index, no cosign .sig sibling tag, no GitHub attestation under docker-library, and no Sigstore transparency-log entry over this digest at all.

Full comparison, layer by layer and path by path: [`.evidence/doi-base-rebuild/node-base-image-verdict.json`](.evidence/doi-base-rebuild/node-base-image-verdict.json).
The run is public: https://github.com/anonrouter/confidential-content-plane/actions/runs/33689328190

Option B was measured on the same run and found nothing qualifying **as of 2026-09-02**: no OCI
referrer, no cosign signature tag, no attestation under the builder's GitHub org. Where the Sigstore
transparency log carries an entry over the digest at all, it is a bare public key with no certificate,
so it names nobody and cannot be pinned to an upstream identity. A check that asked only whether the
digest appears in the log would have accepted it.

**What this does and does not establish:**

WHAT THIS ESTABLISHES: replaying the recipe docker-library publishes for this
digest did not reproduce it, and two identical replays of that recipe disagreed
with each other, so the published recipe is not deterministic. No signature
meeting this project's option B bar existed for the digest on the date below.

WHAT IT DOES NOT ESTABLISH, and an earlier revision of this entry overstated
exactly here by phrasing a scoped negative as a universal one: this does not
show the digest is permanently unbindable. Upstream could publish a
qualifying signature, which would close
this with no rebuild at all; a party holding build inputs outside the published
recipe could produce evidence this run cannot; and this project could accept a
different kind of evidence after review. The claim is scoped to the published
recipe, the inputs reachable from it, and the measurement date.

**There is a replacement candidate. It is integrated in source and NOT deployed.**
`ghcr.io/anonrouter/mirror/anonrouter-node-base@sha256:e8f6e5faabd917808380efd228046d3a6593ccfe982b2af454e02080546e338d` is built by AnonRouter from
`anonrouter/confidential-content-plane@7814865e24ff0caa9d28e25a8fa917710c1f2768`, reproduced independently by a second CI job at the same
digest, and signed against a pinned identity and issuer:

```
cosign verify \
  --certificate-identity 'https://github.com/anonrouter/confidential-content-plane/.github/workflows/anonrouter-base-build.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ghcr.io/anonrouter/mirror/anonrouter-node-base@sha256:e8f6e5faabd917808380efd228046d3a6593ccfe982b2af454e02080546e338d
```

**It inherits no container base image.** `inheritedBaseImages` is empty and the ledger schema will
not accept a non-empty one. Everything in it is a release artifact pinned by a digest upstream
publishes, a file from a Debian package pinned by a sha256 that also appears in the index Debian's
OpenPGP-signed `Release` covers, or a literal in a published assembly script.

It is not zero-dependency, and the remainder is named rather than omitted. These images BUILD it
and none of their bytes ship:

- `debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867` — the unpack stage runs dpkg-deb and ldconfig. None of its bytes reach the shipped image, every input it consumes is hash-pinned before it runs, and two independent CI jobs must agree on the output digest. A weaker exposure than an inherited rootfs, and not zero.

**Compatibility was measured, not asserted.** `scripts/provenance/content-plane-compat-harness.sh` builds the same source on
the base this replaces and on the candidate, runs an identical matrix under the real deployment
policy, and requires them to agree: 13 checks, 0 differing. A deliberately broken
variant is the control, and the matrix detected it in 1 check(s) — without that, agreement
would be consistent with a matrix that cannot tell two images apart. Evidence:
[`.evidence/base-image-compat/content-plane-compat-local.json`](.evidence/base-image-compat/content-plane-compat-local.json).

It proves **nothing about the artifact above**. A replacement is not a binding for the thing in
service, and saying otherwise would be the exact rounding-up this document exists to refuse.
Referenced now by `the production stage of the Dockerfile generated by scripts/export-content-plane.ts`, so the NEXT build uses it;
nothing running does. Promoting it moves the measured Compose hash, the app id and the attestation
policy, which makes it a measured-release decision rather than a documentation edit.

This is stated here, in the README, because a transparency chain that quietly
rounds an unverifiable link up to "verified" is worse than no chain: it
launders an assumption into an apparent proof. Someone told the chain is
incomplete can reason about the residual risk. Someone told it is complete
cannot.

The machine-readable version of the same statement is
`deploy/provenance/plaintext-capable-components.json`, published here, and it
is what the signed release manifest carries. **This section is generated from
that file**, so the two cannot drift: `tests/unit/third-party-provenance.test.ts`,
also published here, fails if this README names fewer gaps than the ledger
records or lets a source pin read as a binding. Run `npm test` and check.

## What is deliberately NOT here

The control plane: accounts, authentication, API keys, billing, payments,
admin and the database. None of it can touch a prompt, and none of it is
reachable from the entry point this image runs. That is enforced, not asserted:
`tests/unit/content-plane-closure.test.ts` computes the module graph from
`src/contentPlane.ts` and fails if any control-plane module becomes reachable,
at runtime or at compile time.

The **content-free control RPC schemas** ARE here, in
`src/routes/internal/rpcSchemas.ts`, even though the server that serves them
runs elsewhere. They are the boundary contract, and publishing them is what
lets a reader check the boundary carries no prompt field rather than take it
on trust. `tests/unit/rpc-boundary-contract.test.ts` enforces it.

Some enforcement suites stay in the private monorepo because they assert
against files this repository deliberately does not contain. They are listed,
with the reason for each, in `EXPORT-MANIFEST.json` under `monorepoOnlySuites`,
so the reduction is visible rather than silent.

## Verifying

```
npm ci
npm run build      # single-platform linux/amd64 Docker v2 manifest
npm test           # the boundary and privacy suites
```

That checks this repository against itself. Verifying a **live deployment**
against it is a different procedure with different limits, and the limits are
the important part. See `docs/publication/INDEPENDENT_VERIFICATION.md`.

## Licence

Apache-2.0. See LICENSE and NOTICE.
