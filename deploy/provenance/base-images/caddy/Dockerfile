# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# AnonRouter's replacement candidate for caddy:2.11.4-alpine, built FROM
# scratch.
#
# =============================================================================
# NOT DEPLOYED, AND NOT EVIDENCE ABOUT WHAT IS
# =============================================================================
#
# The image this replaces, caddy:2.11.4-alpine@sha256:98eb57d8..., is the base
# of the in-CVM L7 edge, which proxies customer requests after TLS terminates
# inside the trust domain. Replaying the recipe docker-library publishes for it
# does not reproduce it: two identical replays, minutes apart on the same
# runner, produced different images. Nothing here changes that or says anything
# about that digest.
#
# =============================================================================
# WHY `FROM scratch`, AND WHY THE PREVIOUS VERSION OF THIS FILE WAS NOT ENOUGH
# =============================================================================
#
# The first version of this candidate was `FROM debian:bookworm-slim@sha256:...`.
# It was reproducible, signed, and it did not close anything: `debian:bookworm-slim`
# is a Docker Official Image with exactly the same unbound provenance as the
# image being replaced. The gap moved down one layer and the paperwork moved
# with it.
#
# Caddy is a statically linked Go binary -- `ldd` reports "not a dynamic
# executable" -- so the edge needs no libc, no shell and no package manager at
# runtime. Every byte in the shipped image is therefore either:
#
#   * the caddy release binary, pinned by the sha512 caddyserver/caddy-docker
#     itself pins, and byte-identical to /usr/bin/caddy inside the deployed
#     image;
#   * a file extracted from a Debian .deb pinned by sha256, where that sha256 is
#     also the value in the `Packages` index that Debian's `Release` file
#     covers with an OpenPGP signature; or
#   * a handful of literal text files written below, which a reader can see in
#     full.
#
# There is no inherited rootfs left to account for.
#
# =============================================================================
# THE TRUST DEPENDENCY THAT REMAINS, NAMED RATHER THAN OMITTED
# =============================================================================
#
# The `unpack` stage below runs on the pinned debian:bookworm-slim image because
# something has to run `dpkg-deb -x`. That is a BUILD TOOL, not an inherited
# base: none of its bytes reach the shipped image, every input it consumes is
# hash-pinned before it runs, and two independent CI jobs on separate runners
# must produce the same output digest for anything to be published. A builder
# that tampered would have to tamper identically twice and still land on files
# whose hashes we pinned in this file.
#
# It is a weaker exposure than inheriting a rootfs, and it is not zero. It is
# recorded in deploy/provenance/plaintext-capable-components.json under
# `controlledEquivalent.buildToolDependencies` rather than left for a reader to
# notice.
#
# =============================================================================
# COMPATIBILITY WITH THE ACTUAL DEPLOYMENT
# =============================================================================
#
# The edge runs under `read_only: true`, `cap_drop: ALL`,
# `no-new-privileges:true` and `init: true`, with tmpfs at /tmp, /config and
# /data and a read-only `evidences` volume. Its Caddyfile listens on `:8080`
# with no hostname, which disables automatic HTTPS, and every upstream is plain
# HTTP to a container name. So it needs no ACME, no certificate storage and no
# outbound TLS.
#
# It does need: writable XDG dirs (tmpfs supplies them), name resolution
# (Go's resolver plus /etc/nsswitch.conf), a non-root account to match the
# deployment's expectations, and `file_server browse` for /evidences, whose
# template is compiled into the binary.
#
# NO setcap. The stock binary carries cap_net_bind_service as a file capability,
# which is why deploy/phala/images/edge/Dockerfile exists to strip it under
# `cap_drop: ALL`. This image never sets it, so the strip becomes unnecessary
# rather than undone, and the edge Dockerfile loses its only RUN -- which it
# must, because there is no shell here to run it in.
#
# Licence: derived from caddyserver/caddy-docker (Apache-2.0) at commit
# fba2853501d36e8a72f946ac8cb7ff64d07e48f2. See LICENSE.upstream.

# -----------------------------------------------------------------------------
# unpack: a build tool. Nothing from this stage is shipped.
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867 AS unpack

# Every download is verified by BuildKit before the layer exists. The URLs are
# snapshot paths, which are immutable: the same URL returns the same bytes in a
# year or 404s, and never different bytes.
#
# `http` rather than `https` is deliberate and is not a weakening. Integrity
# here comes from these sha256 values, each of which also appears in the
# `Packages` index that Debian's OpenPGP-signed `Release` file covers. TLS would
# add confidentiality about which packages a public build downloads, which is
# not a property this needs.
ADD --checksum=sha256:527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9 \
    https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz \
    /in/caddy.tar.gz
ADD --checksum=sha256:66177d46fa761acb07208065db9b0274cb1b12c02ac43b9bfc9857b698b1ccfe \
    https://raw.githubusercontent.com/caddyserver/dist/33ae08ff08d168572df2956ed14fbc4949880d94/config/Caddyfile \
    /in/Caddyfile
ADD --checksum=sha256:70a45d667679109cd6b25502554597f21536ee995ada0549251167bd171533b9 \
    https://raw.githubusercontent.com/caddyserver/dist/33ae08ff08d168572df2956ed14fbc4949880d94/welcome/index.html \
    /in/index.html
# ca-certificates comes from bookworm-SECURITY, not from bookworm main.
#
# A first pass at these pins read only `bookworm main` and got
# 20230311+deb12u1, which carries 142 root certificates. The image being
# replaced installs 20250419~deb12u1 and carries 150. Eight missing roots is a
# TLS handshake that works in one image and fails in the other, found by
# comparing the two rather than by reading either. The pins now come from
# scripts/provenance/pin-debian-packages.ts, which reads all three suites and
# orders versions the way Debian does.
ADD --checksum=sha256:62b08a77d985d4253894b1f69aebda5925034ca4e294add364167fad8cb64a44 \
    http://snapshot.debian.org/archive/debian-security/20260901T000000Z/pool/updates/main/c/ca-certificates/ca-certificates_20250419~deb12u1_all.deb \
    /in/ca-certificates.deb
ADD --checksum=sha256:aaa46dcb3b39948ae2e0fdb72cfcb2f48c0b59f19785a3da8045c05eb19955dd \
    http://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/m/media-types/media-types_10.0.0_all.deb \
    /in/media-types.deb

COPY assemble.sh /in/assemble.sh
RUN ["/bin/sh", "/in/assemble.sh"]

# -----------------------------------------------------------------------------
# the shipped image: nothing but the assembled tree
# -----------------------------------------------------------------------------
FROM scratch

COPY --from=unpack /out/ /

# PATH is set explicitly because a scratch image has none, and the image this
# replaces inherits one from Alpine. Without it `docker exec <container> caddy`
# resolves differently from the stock image, which is a behavioural difference
# in the deployment for no reason at all. Same value the stock image carries.
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV CADDY_VERSION=v2.11.4
ENV XDG_CONFIG_HOME=/config
ENV XDG_DATA_HOME=/data
# Go reads this before its built-in candidate list, so the bundle is found even
# if a future layer moves it. The stock image does not set it because Alpine
# puts the bundle where Go already looks; setting it here costs nothing and
# removes a dependency on that default.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# The label set is deliberately smaller than the stock image's, because every
# label here has to be true OF THIS IMAGE.
#
# This one previously read `image.source=https://github.com/caddyserver/caddy-docker`,
# copied from the image being replaced so the two would look alike. On the stock
# image that is true. Here it is false: caddy-docker's Dockerfile does not
# produce these bytes and cannot, and `image.source` is defined by the OCI spec
# as the URL to get the source code FOR BUILDING THE IMAGE. Shipping a pointer
# to a repository that did not build the artifact, inside the artifact whose
# entire purpose is a source-to-digest binding, is the exact failure this work
# exists to remove -- and it would have been the only false provenance statement
# in the chain. tests/unit/base-image-labels.test.ts now refuses it.
#
# The dropped labels (description, documentation, url, vendor) are all about the
# Caddy project rather than about this image. They are not false so much as not
# ours to assert, and the four that remain are checkable: the binary IS caddy
# v2.11.4, released under Apache-2.0, and the recipe IS in the repository named.
LABEL org.opencontainers.image.version=v2.11.4
LABEL org.opencontainers.image.title=Caddy
LABEL org.opencontainers.image.licenses=Apache-2.0
LABEL org.opencontainers.image.source="https://github.com/anonrouter/confidential-content-plane"

EXPOSE 80
EXPOSE 443
EXPOSE 443/udp
EXPOSE 2019

WORKDIR /srv

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
