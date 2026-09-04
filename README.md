# AnonRouter confidential content plane

Every component that can touch prompt or response plaintext inside the Intel
TDX trust domain, and the tests that enforce the boundary.

## What this repository is for, and what it is not

Attestation proves **which code ran**. It never proves what that code does.
This repository exists so the second question has an answer a stranger can
check by reading rather than by trusting: this is the source, and these are
the tests that hold the boundary it describes.

The repository also carries reproducible build evidence for the images it
publishes. Verifying a particular running service is a separate step: compare
fresh hardware attestation with that release's signed manifest and policy.

## The boundary, component by component

For every component that can touch a prompt, a reader can either read the
source here or follow a reference to pinned upstream source. Which applies:

| Component | Can touch plaintext | Where the source is |
| --- | --- | --- |
| `relay` | full request and response bodies, transiently | here |
| classifier (in-process on the relay) | the truncated latest user turn | here |
| `compat` broker | full bodies **and** the caller's static `ar_` key | here |
| `<provider>-worker` | full bodies plus one provider credential | here |
| `edge` (in-CVM L7 router) | full bodies, after TLS terminates in-TD | here (configuration); its base image is caddyserver/caddy-docker (Apache-2.0); binding not established, AnonRouter FROM-scratch replacement available; see Build provenance |
| `<provider>-egress` | ciphertext only (SNI passthrough) | here (configuration) |
| `gateway-attestation` | **no content at all** | here |
| `dstack-ingress` | ciphertext, then the plaintext stream in transit | Dstack-TEE/dstack-examples (Apache-2.0); reproducibly rebuilt by AnonRouter CI |

The `relay`, `compat`, `worker` and `gateway-attestation` roles are all the
same first-party image, selected by `RUNTIME_ROLE`. Its **base image** is
upstream: it runs every line of code in this repository, so it is
plaintext-capable whatever the code above it does, and it is covered by the
ledger like any other third-party component.

## Build provenance

This is the stable build status of the artifacts maintained by this repository.
It is intentionally not a production status page.

- **Caddy edge base (`caddy-edge-base`): reproducible AnonRouter build, NOT DEPLOYED.**
  The tracked artifact is `caddyserver/caddy-docker` (Apache-2.0), source-to-digest binding NOT established.
  The replacement FROM-scratch image is reproduced by two independent CI jobs, signed,
  and passes 24/24 compatibility checks with a working negative control.
- **Dstack ingress (`dstack-ingress`): reproducibly bound.** Public CI rebuilt
  `Dstack-TEE/dstack-examples@b322d14e74920c6523dc7ac7e2974e0414df82d0` and reproduced the recorded image
  digest byte for byte. The result is signed against a pinned workflow identity.
- **Node runtime base (`node-base-image`): reproducible AnonRouter build, NOT DEPLOYED.**
  The tracked artifact is `nodejs/docker-node` (MIT), source-to-digest binding NOT established.
  The replacement FROM-scratch image is reproduced by two independent CI jobs, signed,
  and passes 13/13 compatibility checks with a working negative control.

A digest pin or an unsigned registry statement alone is not treated as a source
binding. Exact digests, build identities, attestations, compatibility evidence
and remaining trust dependencies are recorded in
`deploy/provenance/plaintext-capable-components.json` and enforced by
`tests/unit/third-party-provenance.test.ts`.

## Verifying a deployment

This README deliberately does not say which release production currently runs.
Verify a particular deployment using its independently distributed signed release
manifest and attestation policy, then require fresh hardware evidence to match them.
Repository build evidence answers where an image came from; deployment attestation
answers whether that image is the one running.

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
