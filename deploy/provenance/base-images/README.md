# AnonRouter-controlled base images

**Nothing here is deployed, and nothing here proves anything about the images
that are.** These are replacement candidates for two plaintext-capable
components whose upstream artifacts cannot be bound to their source by any
means. Read that sentence before reading anything else on this page: a
reproducible replacement is not retroactive evidence about the artifact in
service, and treating it as one would be the exact rounding-up the provenance
ledger exists to refuse.

## Why they exist

`deploy/provenance/plaintext-capable-components.json` records two RECORDED GAPS:

| Component | Deployed | Binding |
| --- | --- | --- |
| `caddy-edge-base` | `caddy:2.11.4-alpine@sha256:98eb57d8…` | NONE |
| `node-base-image` | `node:22-bookworm-slim@sha256:a17d50af…` | NONE |

On 2026-09-02 both were measured in public CI rather than left open. The result
is not "no rebuild has been attempted". It is that **no rebuild by anyone can
succeed**: two identical replays of docker-library's own recorded invocation,
minutes apart on the same runner with a cold cache, produced different images.

The cause is the same in both, and it is not fixable from outside: each image
ships a file whose **content** records when the build ran.

- `caddy` carries `/var/log/apk.log`, whose first line is
  `Running \`apk add --no-cache ca-certificates curl libcap mailcap\` at 2026-06-22 20:09:02`.
- `node` carries `/var/log/dpkg.log` with 1,052 stamps, plus
  `/var/log/alternatives.log`, `/var/log/apt/history.log` and
  `/var/log/apt/term.log`.

`SOURCE_DATE_EPOCH` and buildkit's `rewrite-timestamp` normalise metadata.
Neither reaches inside a log file. Option B is unavailable too, measured on the
same run: no signature exists that verifies against a pinned upstream identity.

So closing these gaps means **replacing the artifact**, and that is what these
are.

## What is different, and what that costs

Both images are built to be reproducible on purpose, which means fixing exactly
what the measurement found:

| Obstruction found upstream | What these do instead |
| --- | --- |
| build clock written into shipped log files | the logs are removed in the same layer that creates them |
| build day written into `/etc/shadow` | the created account's last-changed field is set to a fixed value |
| package versions resolved against a live archive | every package comes from a pinned `snapshot.debian.org` timestamp |
| downloads verified by keyserver GPG at build time | every download is pinned by digest in the Dockerfile |
| `org.opencontainers.image.created` taken from `now` | `SOURCE_DATE_EPOCH` is set, so it is derived from the source |
| per-step config timestamps at wall-clock precision | the same epoch normalises all of them |

**`anonrouter-caddy-base` is Debian-based where upstream is Alpine.** That is
not a preference. The Alpine measurement found a second, independent
obstruction: `apk add --no-cache` resolves against Alpine v3.23's **live**
repository, and by the time the rebuild ran, `c-ares` had moved 1.34.6 to
1.34.7 and `curl` had been rebuilt. Alpine publishes no snapshot archive, so
there is no way to pin what a future build will install. Debian does, so the
base moves. The Caddy binary itself is unaffected: it is a static Go binary and
is byte-identical to the one in the official image (see below).

The costs are real and are not hidden: a larger image, glibc rather than musl,
and a different shell. Anything that depends on Alpine specifics would have to
be revisited before this could be deployed.

## The downloads are pinned, and the pins were corroborated

Every artifact these images fetch is pinned by digest. More than that, each pin
was checked against the **artifact already in service**, which is a source of
truth that did not come from the party serving the download:

| Artifact | Pinned digest | Corroboration |
| --- | --- | --- |
| `node-v22.23.2-linux-x64.tar.xz` | `sha256:d60acfe0…` | the `node` binary inside it hashes to `3517c2df…`, which is byte-identical to `/usr/local/bin/node` inside the deployed `node:22-bookworm-slim@sha256:a17d50af…` |
| `caddy_2.11.4_linux_amd64.tar.gz` | `sha512:8220d1f0…` | the same value `caddyserver/caddy-docker` pins at commit `fba28535`; the `caddy` binary inside hashes to `b7105518…`, byte-identical to `/usr/bin/caddy` in the deployed `caddy:2.11.4-alpine@sha256:98eb57d8…` |
| upstream `Caddyfile` and `index.html` | `sha256:66177d46…`, `sha256:70a45d66…` | byte-identical to the copies in the deployed caddy image |
| `yarn-v1.22.22.tar.gz` | `sha256:88268464…` | byte-identical to the tree under `/opt/yarn-v1.22.22` in the deployed node image |

That corroboration matters because upstream verifies these downloads with GPG
against keys fetched from a keyserver at build time, which is neither
reproducible nor pinnable. Pinning the digest and checking it against the
running artifact keeps the guarantee and drops the network dependency.

## Reproducibility is claimed only after two independent runs

`.github/workflows/anonrouter-base-build.yml` builds each image **twice**, in
two jobs that share nothing, and refuses to publish unless the two digests are
equal. One build on one machine is not a reproducibility claim; the honest bar,
which this project already wrote down in `docs/DCAP_VERIFIER_PHASE_ONE.md`
section 7, is two independent builders producing the same digest.

The ledger enforces the same thing structurally: `controlledEquivalent` will not
parse unless `independentlyReproducedDigest` equals `digest`, and it will not
parse if it names the pinned upstream digest, because that would make a
replacement read as a binding.

## What is still unproven

The chain does not bottom out. These images are built `FROM
debian:bookworm-slim`, pinned to its `linux/amd64` child manifest, and **that**
image has the same class of unprovable provenance as the ones it replaces. What
changes is the size of the unverified surface: the Node runtime, npm, yarn, the
Caddy binary, the CA bundle and every package version become things a reader can
rebuild and compare. The Debian base layer does not.

Recording that here rather than letting it be discovered: this is a reduction,
not an elimination, and a page that claimed otherwise would be worse than this
one.

## Status

**Undeployed. Not release-reviewed. Not wired into any Dockerfile.**

Promoting either image changes the content-plane image digest, the measured
Compose hash, the app id and the attestation policy. That is a measured-release
decision with its own gates, not a documentation edit, and it is an owner action.
