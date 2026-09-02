# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# AnonRouter's reproducible replacement candidate for caddy:2.11.4-alpine.
#
# =============================================================================
# NOT DEPLOYED, AND NOT EVIDENCE ABOUT WHAT IS
# =============================================================================
#
# The image this replaces, caddy:2.11.4-alpine@sha256:98eb57d8..., is the base
# of the in-CVM L7 edge, which proxies customer requests after TLS terminates
# inside the trust domain. Its source-to-digest binding is a RECORDED GAP that
# cannot be closed: two identical replays of docker-library's own recorded
# invocation, minutes apart, produced different images.
#
# Building something reproducible here proves nothing about that image.
#
# =============================================================================
# WHY THIS IS DEBIAN WHERE UPSTREAM IS ALPINE, WHICH IS NOT A PREFERENCE
# =============================================================================
#
# The caddy measurement found TWO independent obstructions, not one.
#
# The first is the same clock-in-content problem the Node base has:
# /var/log/apk.log ships inside the image and its first line reads "Running
# `apk add --no-cache ca-certificates curl libcap mailcap` at 2026-06-22
# 20:09:02". That alone was the whole difference between two runs.
#
# The second cannot be fixed on Alpine at all. `apk add --no-cache` resolves
# against Alpine v3.23's LIVE repository. By the time the rebuild ran, c-ares
# had moved 1.34.6 to 1.34.7 and curl and libcurl had been rebuilt, so the
# rebuild differed from the deployed image in five paths that have nothing to do
# with time. Alpine publishes no snapshot archive, so there is no way to pin
# what a future build will install, and pinning exact versions only converts
# irreproducibility into breakage when those versions are pruned.
#
# Debian publishes snapshot.debian.org. That is the reason for the base change
# and the only one.
#
# THE COSTS ARE REAL AND NOT HIDDEN: a larger image, glibc rather than musl, a
# different shell, and different package names. Anything depending on Alpine
# specifics has to be revisited before this could be deployed. What does NOT
# change is Caddy: it is a static Go binary, and the one installed here is
# byte-identical to the one in the official image (see below).
#
# =============================================================================
# THE PINS WERE CORROBORATED AGAINST THE ARTIFACT IN SERVICE
# =============================================================================
#
#   caddy tarball -> sha512 8220d1f0..., the same value caddyserver/caddy-docker
#                    pins at commit fba28535. Its `caddy` binary hashes to
#                    b7105518..., byte-identical to /usr/bin/caddy inside
#                    caddy:2.11.4-alpine@sha256:98eb57d8
#   Caddyfile     -> 66177d46..., byte-identical to /etc/caddy/Caddyfile there
#   index.html    -> 70a45d66..., byte-identical to /usr/share/caddy/index.html
#
# =============================================================================
# ONE DELIBERATE BEHAVIOURAL DIFFERENCE
# =============================================================================
#
# The stock image sets cap_net_bind_service=+ep as a FILE capability on the
# caddy binary. Under `cap_drop: ALL` the bounding set is empty, execve refuses
# to grant an effective capability it cannot, and the container dies before
# Caddy runs. deploy/phala/images/edge/Dockerfile exists partly to strip it
# again. This image never sets it, so the strip becomes unnecessary rather than
# undone. The edge binds 8080 and 8443, so the capability was never needed.
#
# Licence: derived from caddyserver/caddy-docker (Apache-2.0) at commit
# fba2853501d36e8a72f946ac8cb7ff64d07e48f2. See LICENSE.upstream.

ARG DEBIAN_BASE=debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

# -----------------------------------------------------------------------------
# fetch: unpacks the pinned downloads, and is never shipped
# -----------------------------------------------------------------------------
FROM ${DEBIAN_BASE} AS fetch

ADD --checksum=sha256:527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9 \
    https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz \
    /tmp/caddy.tar.gz
ADD --checksum=sha256:66177d46fa761acb07208065db9b0274cb1b12c02ac43b9bfc9857b698b1ccfe \
    https://raw.githubusercontent.com/caddyserver/dist/33ae08ff08d168572df2956ed14fbc4949880d94/config/Caddyfile \
    /tmp/Caddyfile
ADD --checksum=sha256:70a45d667679109cd6b25502554597f21536ee995ada0549251167bd171533b9 \
    https://raw.githubusercontent.com/caddyserver/dist/33ae08ff08d168572df2956ed14fbc4949880d94/welcome/index.html \
    /tmp/index.html

RUN set -eux; \
    mkdir -p /out/usr/bin /out/etc/caddy /out/usr/share/caddy; \
    tar -xzf /tmp/caddy.tar.gz -C /out/usr/bin caddy; \
    chmod 0755 /out/usr/bin/caddy; \
    install -m 0644 /tmp/Caddyfile /out/etc/caddy/Caddyfile; \
    install -m 0644 /tmp/index.html /out/usr/share/caddy/index.html

# -----------------------------------------------------------------------------
# the shipped image
# -----------------------------------------------------------------------------
FROM ${DEBIAN_BASE}

# Unlike the Node base, this one needs packages IN the shipped image: Caddy
# cannot complete an outbound TLS handshake or an ACME order without a trust
# store, and media-types is where /etc/mime.types comes from (Debian renamed mime-support to
# media-types in bookworm; the Alpine package is called mailcap).
#
# So the apt logs exist here and are removed in the SAME layer that creates
# them. Removing them in a later layer would leave them in the earlier one,
# where they would still be part of a digest and still record the build clock.
ARG DEBIAN_SNAPSHOT=20260901T000000Z
# `http`, not `https`, and deliberately. debian:bookworm-slim ships no CA
# bundle, so apt cannot complete a TLS handshake until ca-certificates is
# installed, which is the package being fetched. Integrity here does not come
# from TLS anyway: apt verifies the Release file's OpenPGP signature against
# debian-archive-keyring, which IS in the base image, and every package against
# the hashes in that signed file. TLS would add confidentiality about which
# packages a public build installs, which is not a property this needs.
RUN set -eux; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    { \
      echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main"; \
      echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main"; \
      echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm-updates main"; \
    } > /etc/apt/sources.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates media-types; \
    rm -rf \
      /var/lib/apt/lists/* \
      /var/log/apt \
      /var/log/dpkg.log \
      /var/log/alternatives.log \
      /var/cache/debconf/config.dat-old \
      /var/cache/debconf/templates.dat-old \
      /var/cache/ldconfig/aux-cache \
      /etc/apt/sources.list; \
    # The sources.list is removed on purpose. It names a snapshot timestamp that
    # will not be right for anyone editing this image later, and an image that
    # silently installs from a stale snapshot is worse than one that refuses.
    :

COPY --from=fetch /out/usr/bin/caddy /usr/bin/caddy
COPY --from=fetch /out/etc/caddy/Caddyfile /etc/caddy/Caddyfile
COPY --from=fetch /out/usr/share/caddy/index.html /usr/share/caddy/index.html

RUN set -eux; \
    mkdir -p /config/caddy /data/caddy; \
    chmod 1777 /config/caddy /data/caddy; \
    # Deliberately NO setcap. See the header. There is no assertion here that
    # the capability is absent, because the tool that would check it
    # (libcap2-bin's getcap) is not installed, and a check that silently cannot
    # run is worse than none: `! getcap ... | grep -q ...` passes when getcap
    # does not exist. The real assertion runs in
    # .github/workflows/anonrouter-base-build.yml against the exported layer,
    # with the stock caddy image as the control that proves it can fail.
    caddy version

ENV CADDY_VERSION=v2.11.4
ENV XDG_CONFIG_HOME=/config
ENV XDG_DATA_HOME=/data

LABEL org.opencontainers.image.version=v2.11.4
LABEL org.opencontainers.image.title=Caddy
LABEL org.opencontainers.image.licenses=Apache-2.0
LABEL org.opencontainers.image.source="https://github.com/caddyserver/caddy-docker"

EXPOSE 80
EXPOSE 443
EXPOSE 443/udp
EXPOSE 2019

WORKDIR /srv

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
