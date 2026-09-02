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

**This gap has been measured, and it is not "not done yet".** AnonRouter's public CI replayed
upstream's own recorded build invocation for this exact digest, natively on `linux/amd64`, with every
argument read out of the deployed image's own SLSA statement rather than from any file in this
repository. Result: `NOT-REPRODUCED-RECIPE-NONDETERMINISTIC`.

Two **identical** invocations, minutes apart on the same runner with a cold cache, produced
`sha256:814143b2fffc1e6d557976099a3e32914668bb203a5a43c23c8aa989325a7a87` and `sha256:eec80ff07eb230cb95bc5e53bc63729f85e09a07d0b7ff05507c0230e85425d8`. Those are different images, so no
rebuild by any party can match a fixed digest. Option A is **unavailable for this artifact**, not
merely unattempted, and trying harder does not change that. Why, precisely:

- **`recipe-nondeterministic`** Two identical native linux/amd64 invocations, minutes apart with a cold cache, produced sha256:814143b2 and sha256:eec80ff0. No rebuild by any party can match a fixed digest.
- **`build-clock-in-layer-content`** /var/log/apk.log ships inside the image and its first line records the second the build ran: 'Running `apk add --no-cache ca-certificates curl libcap mailcap` at 2026-06-22 20:09:02'. File content, not metadata, so no normalisation flag rewrites it.
- **`build-clock-in-image-config`** 21 history timestamps differ between two runs of the same recipe, at sub-second precision.
- **`build-clock-in-manifest-annotation`** org.opencontainers.image.created is derived from `env.SOURCE_DATE_EPOCH // now` by docker-library's meta.jq, and the recorded build set no epoch. The annotation is manifest bytes, so it is part of the digest.
- **`mutable-archive`** `apk add --no-cache` resolves against Alpine v3.23's live repository. Against the deployed image the rebuild differs by c-ares 1.34.6 -> 1.34.7, a rebuilt curl and libcurl, and the matching lib/apk/db/installed entries. The contents were never recoverable from the source after the fact.
- **`option-b-absent`** No OCI referrer on the child or the index, no cosign .sig sibling tag, no GitHub attestation under docker-library. One Rekor entry names this digest and carries a bare public key rather than a certificate, so it attests to no identity at all.

Full comparison, layer by layer and path by path: [`.evidence/doi-base-rebuild/caddy-edge-base-verdict.json`](.evidence/doi-base-rebuild/caddy-edge-base-verdict.json).
The run is public: https://github.com/anonrouter/confidential-content-plane/actions/runs/33689328190

Option B was measured on the same run and is also unavailable: no OCI referrer, no cosign signature
tag, no attestation under the builder's GitHub org. Where the Sigstore transparency log carries an
entry over the digest at all, it is a bare public key with no certificate, so it names nobody and
cannot be pinned to an upstream identity. A check that asked only whether the digest appears in the
log would have accepted it.

**There is a replacement candidate, and it is NOT deployed.** `ghcr.io/anonrouter/mirror/anonrouter-caddy-base@sha256:d4d19b5aca911b75005f21d5b20da5ed884e2bf9865dbfc3c7d8f797ae023a46` is built by
AnonRouter from `anonrouter/confidential-content-plane@642d158e664520361311dfaa79953e110bc776d6` and reproduced independently by a second CI
run at the same digest. It has a real source-to-digest binding because it was built to be
reproducible.

It proves **nothing about the artifact above**. A replacement is not a binding for the thing in
service, and saying otherwise would be the exact rounding-up this document exists to refuse.
Promoting it changes the measured Compose, the app id and the attestation policy, so it is a
measured-release decision rather than a documentation edit.

**`node-base-image`** Base image of the content-plane image; runs every line of code that handles plaintext. Deployed at `node:22-bookworm-slim@sha256:a17d50af28002a160548bd4225b3cfcb12c5efcb171f79e68758f2885fb1b066`.

The registry publishes an **unsigned** in-toto SLSA statement whose subject is that exact
digest, naming upstream commit `bc0a422bce0f729dd85790639d9f1918143f1235`
(`22/bookworm-slim`). That is useful and it is **not a binding**:
its trust root is whoever can push to that registry repository, not an identity we pinned.
It tells a rebuilder exactly which commit to build and compare. It does not tell anyone that
the image in service came from that commit.

**This gap has been measured, and it is not "not done yet".** AnonRouter's public CI replayed
upstream's own recorded build invocation for this exact digest, natively on `linux/amd64`, with every
argument read out of the deployed image's own SLSA statement rather than from any file in this
repository. Result: `NOT-REPRODUCED-RECIPE-NONDETERMINISTIC`.

Two **identical** invocations, minutes apart on the same runner with a cold cache, produced
`sha256:6babfba1586e01cc2da1e051f5c879b37c259f0f83db9f03370bcd8498d24953` and `sha256:c1d12a978b22af8334fe0a8001e93c8f9b41a20558fd7e5ed642d22ab498c921`. Those are different images, so no
rebuild by any party can match a fixed digest. Option A is **unavailable for this artifact**, not
merely unattempted, and trying harder does not change that. Why, precisely:

- **`recipe-nondeterministic`** Two identical native linux/amd64 invocations, minutes apart with a cold cache, produced sha256:6babfba1 and sha256:c1d12a97. No rebuild by any party can match a fixed digest.
- **`build-clock-in-layer-content`** The ENTIRE difference between those two runs is four shipped log files: /var/log/dpkg.log, /var/log/alternatives.log, /var/log/apt/history.log and /var/log/apt/term.log. apt and dpkg write the wall clock into them and the image ships them. The deployed dpkg.log carries 1,052 such stamps. File content, not metadata.
- **`build-clock-in-image-config`** 9 history timestamps differ between two runs of the same recipe.
- **`build-clock-in-manifest-annotation`** org.opencontainers.image.created is derived from `env.SOURCE_DATE_EPOCH // now` by docker-library's meta.jq, and the recorded build set no epoch.
- **`build-day-in-etc-shadow`** /etc/shadow differs from the deployed image because the node account's last-changed field is a count of days since the epoch. Day resolution, so two runs on the same day agree and a rebuild on any other day cannot.
- **`option-b-absent`** No OCI referrer on the child or the index, no cosign .sig sibling tag, no GitHub attestation under docker-library, and no Sigstore transparency-log entry over this digest at all.

Full comparison, layer by layer and path by path: [`.evidence/doi-base-rebuild/node-base-image-verdict.json`](.evidence/doi-base-rebuild/node-base-image-verdict.json).
The run is public: https://github.com/anonrouter/confidential-content-plane/actions/runs/33689328190

Option B was measured on the same run and is also unavailable: no OCI referrer, no cosign signature
tag, no attestation under the builder's GitHub org. Where the Sigstore transparency log carries an
entry over the digest at all, it is a bare public key with no certificate, so it names nobody and
cannot be pinned to an upstream identity. A check that asked only whether the digest appears in the
log would have accepted it.

**There is a replacement candidate, and it is NOT deployed.** `ghcr.io/anonrouter/mirror/anonrouter-node-base@sha256:5a2c48b28e876edaa8d0dcc7a85db244004dd641af89521c37ac9097c3785879` is built by
AnonRouter from `anonrouter/confidential-content-plane@642d158e664520361311dfaa79953e110bc776d6` and reproduced independently by a second CI
run at the same digest. It has a real source-to-digest binding because it was built to be
reproducible.

It proves **nothing about the artifact above**. A replacement is not a binding for the thing in
service, and saying otherwise would be the exact rounding-up this document exists to refuse.
Promoting it changes the measured Compose, the app id and the attestation policy, so it is a
measured-release decision rather than a documentation edit.

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
