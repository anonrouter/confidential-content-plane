# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# AnonRouter's replacement candidate for node:22-bookworm-slim, built FROM
# scratch.
#
# =============================================================================
# NOT DEPLOYED, AND NOT EVIDENCE ABOUT WHAT IS
# =============================================================================
#
# The image this replaces, node:22-bookworm-slim@sha256:a17d50af..., runs every
# line of code that handles prompt plaintext. Replaying the recipe
# docker-library publishes for it does not reproduce it: two identical replays
# produced different images. Nothing here changes that or says anything about
# that digest.
#
# =============================================================================
# WHY `FROM scratch`, AND WHY THE PREVIOUS VERSION WAS NOT ENOUGH
# =============================================================================
#
# The first version of this candidate was `FROM debian:bookworm-slim@sha256:...`.
# It was reproducible and signed and it closed nothing: that image is a Docker
# Official Image with the same unbound provenance as the one being replaced. A
# replacement that inherits an unbound rootfs has moved the gap down a layer,
# not closed it.
#
# So the rootfs is assembled here from parts that ARE bound:
#
#   * the Node release tarball, pinned by the sha256 nodejs.org publishes in its
#     signed SHASUMS256.txt, and independently corroborated: the `node` binary
#     inside it hashes to 3517c2df..., byte-identical to /usr/local/bin/node in
#     the deployed image;
#   * Debian .debs, each pinned by a sha256 that also appears in the `Packages`
#     index that Debian's OpenPGP-signed `Release` file covers, fetched from an
#     immutable snapshot path;
#   * a handful of literal text files, written in assemble.sh where a reader can
#     read them.
#
# WHAT IT ACTUALLY NEEDS was measured, not guessed. `ldd` over the node binary
# and over every native module the PRODUCTION dependency set installs
# (onnxruntime-node, @img/sharp-linux-x64, libvips-cpp, argon2) names exactly
# three packages: libc6, libgcc-s1, libstdc++6. Nothing else, no libgomp, no
# system libvips.
#
# =============================================================================
# WHAT WAS DROPPED, AND WHY THAT IS A CHOICE RATHER THAN AN OVERSIGHT
# =============================================================================
#
#   yarn        the content plane never invokes it. It is ~5 MB of JavaScript
#               with network reach in an image whose whole point is that it
#               handles plaintext. Shipping it for drop-in parity with an image
#               nobody else consumes is the wrong trade.
#   apt, dpkg   nothing installs packages at runtime, and after the change to
#               the application Dockerfile nothing installs them at build time
#               in this image either.
#   /etc/shadow the deployed image's copy records the build DAY in its
#               last-changed field, which is one of the obstructions that made
#               the original irreproducible. `USER node` needs /etc/passwd, not
#               /etc/shadow, so the file is absent by construction rather than
#               normalised by a sed.
#
# =============================================================================
# THE TRUST DEPENDENCY THAT REMAINS, NAMED RATHER THAN OMITTED
# =============================================================================
#
# The `unpack` stage runs on the pinned Debian image because something has to
# run `dpkg-deb -x` and `ldconfig`. That is a build TOOL: none of its bytes
# reach the shipped image, every input it consumes is hash-pinned before it
# runs, and two independent CI jobs must produce the same output digest.
# Recorded in deploy/provenance/plaintext-capable-components.json under
# `controlledEquivalent.buildToolDependencies`.
#
# Licence: derived from nodejs/docker-node (MIT) at commit
# bc0a422bce0f729dd85790639d9f1918143f1235. See LICENSE.upstream.

# -----------------------------------------------------------------------------
# unpack: a build tool. Nothing from this stage is shipped.
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867 AS unpack

# Verified by BuildKit before the layer exists. `http` for the snapshot paths is
# deliberate: the base ships no CA bundle, integrity comes from these sha256
# values, and each of them also appears in the Packages index that Debian's
# OpenPGP-signed Release covers.
ADD --checksum=sha256:d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307 \
    https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-x64.tar.xz /in/node.tar.xz
ADD --checksum=sha256:a15ac9589c04baf9da95b08e0e79b5cf1d75ab8dc64e06a5e68e4ceb0ad7c8ea \
    https://raw.githubusercontent.com/nodejs/docker-node/bc0a422bce0f729dd85790639d9f1918143f1235/22/bookworm-slim/docker-entrypoint.sh \
    /in/docker-entrypoint.sh
ADD --checksum=sha256:ba4f88f73dbc3ae9055f3c20f4523bfdbaf1ad13ff95e258924f77d20b4fbedf \
    http://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/g/glibc/libc6_2.36-9+deb12u14_amd64.deb /in/libc6.deb
ADD --checksum=sha256:3016e62cb4b7cd8038822870601f5ed131befe942774d0f745622cc77d8a88f7 \
    http://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/g/gcc-12/libgcc-s1_12.2.0-14+deb12u1_amd64.deb /in/libgcc-s1.deb
ADD --checksum=sha256:5cd3171216d4ab0fc911cfe9c35509bf2dd8f47761c43b7f6a4296701551a24d \
    http://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/g/gcc-12/libstdc++6_12.2.0-14+deb12u1_amd64.deb /in/libstdc++6.deb
ADD --checksum=sha256:33ea40061da2f1a861ec46212b2b6a34f0776a049b1a3f0abce2fb8cb994258f \
    http://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/d/dash/dash_0.5.12-2_amd64.deb /in/dash.deb
ADD --checksum=sha256:62b08a77d985d4253894b1f69aebda5925034ca4e294add364167fad8cb64a44 \
    http://snapshot.debian.org/archive/debian-security/20260901T000000Z/pool/updates/main/c/ca-certificates/ca-certificates_20250419~deb12u1_all.deb /in/ca-certificates.deb
ADD --checksum=sha256:29b23c48c0fe6f878e56c5ddc9f65d1c05d729360f3690a593a8c795031cd867 \
    http://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/n/netbase/netbase_6.4_all.deb /in/netbase.deb
ADD --checksum=sha256:0edb49f4dffe0d5608069f7e4ba4d69544d3b9e86fc314dd8b75e9958d8e5e98 \
    http://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/t/tzdata/tzdata_2026b-0+deb12u1_all.deb /in/tzdata.deb
# A BUILD TOOL, not a shipped file. debian:bookworm-slim has no `xz`, and the
# Node release tarball is .tar.xz. Pinned like everything else rather than
# apt-installed, so the unpack stage runs no package manager at all and its
# only network inputs are these checksummed URLs.
ADD --checksum=sha256:cc6dc501e0c06be3f89e9a7f8dfd7a97f92aadfd9daa60fad19b90d6a5558b80 \
    http://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/x/xz-utils/xz-utils_5.4.1-1+deb12u1_amd64.deb /in/xz-utils.deb
# TWO binaries out of coreutils, and only two. npm's entry point is a script
# whose shebang is `#!/usr/bin/env node`, so without /usr/bin/env the image has
# node and cannot run npm. Every provider worker also decodes its sealed
# credential into tmpfs with `base64 -d`; omitting that production startup
# dependency caused the first scratch-base promotion to exit 127 on TDX. Both
# are exercised by the chroot checks at the end of assemble.sh.
ADD --checksum=sha256:61038f857e346e8500adf53a2a0a20859f4d3a3b51570cc876b153a2d51a3091 \
    http://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/c/coreutils/coreutils_9.1-1_amd64.deb /in/coreutils.deb

# /etc/gai.conf and /etc/host.conf live here, not in libc6. Without gai.conf
# getaddrinfo falls back to glibc's built-in precedence table, and the
# difference is observable: `dns.lookup("localhost")` returned ::1 on the image
# the content plane runs today and 127.0.0.1 on the first version of this one.
# A base that resolves to a different address family is not a drop-in base.
ADD --checksum=sha256:e667401af91fad95f15b3ebd25d1abd8373fd18b00dc32219678413170544e84 \
    http://snapshot.debian.org/archive/debian/20260901T000000Z/pool/main/g/glibc/libc-bin_2.36-9+deb12u14_amd64.deb /in/libc-bin.deb

COPY assemble.sh /in/assemble.sh
RUN ["/bin/sh", "/in/assemble.sh"]

# -----------------------------------------------------------------------------
# the shipped image
# -----------------------------------------------------------------------------
FROM scratch

COPY --from=unpack /out/ /

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV NODE_VERSION=22.23.2
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

WORKDIR /app

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node"]
