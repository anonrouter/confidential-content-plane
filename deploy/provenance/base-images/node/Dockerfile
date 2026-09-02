# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# AnonRouter's reproducible replacement candidate for node:22-bookworm-slim.
#
# =============================================================================
# NOT DEPLOYED, AND NOT EVIDENCE ABOUT WHAT IS
# =============================================================================
#
# The image this replaces, node:22-bookworm-slim@sha256:a17d50af..., runs every
# line of code that handles prompt plaintext, and its source-to-digest binding
# is a RECORDED GAP that cannot be closed. Measured in public CI on 2026-09-02:
# two identical replays of docker-library's own recorded invocation, minutes
# apart on the same runner with a cold cache, produced different images.
#
# Building something reproducible here proves nothing whatsoever about that
# image. It is a replacement, and the ledger records it as one.
#
# =============================================================================
# WHAT MAKES THIS ONE REPRODUCIBLE, POINT BY POINT AGAINST WHAT WAS MEASURED
# =============================================================================
#
# The entire difference between the two upstream runs was four files:
# /var/log/dpkg.log, /var/log/alternatives.log, /var/log/apt/history.log and
# /var/log/apt/term.log. apt and dpkg write the wall clock into them and the
# image ships them. Zero other paths differed anywhere in 5,759 files, and the
# Debian archive had not moved. So the recipe is deterministic in every respect
# except its own clock, and the clock is in file CONTENT where SOURCE_DATE_EPOCH
# and rewrite-timestamp cannot reach.
#
#   1. NO APT IN THE SHIPPED IMAGE AT ALL. Everything that needs a package
#      manager happens in a `fetch` stage that is never shipped, and the final
#      stage receives directories. There is therefore no dpkg log to delete and
#      no chance of one reappearing when a future edit adds a package.
#   2. /etc/shadow's last-changed field is a count of days since the epoch, so
#      an account created on a different day changes the file. It is set to a
#      fixed value.
#   3. Every download is pinned by digest and fetched by BuildKit's own
#      verified ADD, so there is no curl, no wget, no gnupg and no keyserver
#      round trip in the build at all. Upstream verifies these with GPG keys
#      fetched from a keyserver at build time, which is neither reproducible nor
#      pinnable.
#   4. The base is pinned to the linux/amd64 CHILD MANIFEST. An index digest is
#      immutable and still resolves to a different image per builder
#      architecture.
#
# The build must additionally set SOURCE_DATE_EPOCH and export with
# rewrite-timestamp=true. See .github/workflows/anonrouter-base-build.yml, which
# builds this twice in unrelated jobs and refuses to publish unless the two
# digests are equal.
#
# =============================================================================
# THE PINS WERE CORROBORATED AGAINST THE ARTIFACT IN SERVICE
# =============================================================================
#
# Each digest below was checked against the image actually running, which is a
# source of truth that did not come from the party serving the download:
#
#   node tarball  -> its `node` binary hashes to 3517c2df..., byte-identical to
#                    /usr/local/bin/node inside node:22-bookworm-slim@sha256:a17d50af
#   yarn tarball  -> bin/yarn.js hashes to 148e19db..., byte-identical to
#                    /opt/yarn-v1.22.22/bin/yarn.js in the same image
#   entrypoint    -> a15ac958..., byte-identical to the copy in the same image
#
# Licence: the Dockerfile logic below is derived from nodejs/docker-node
# (MIT) at commit bc0a422bce0f729dd85790639d9f1918143f1235. See LICENSE.upstream.

ARG DEBIAN_BASE=debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

# -----------------------------------------------------------------------------
# fetch: has a package manager, and is never shipped
# -----------------------------------------------------------------------------
FROM ${DEBIAN_BASE} AS fetch

# A pinned snapshot rather than the live archive. `deb.debian.org` serves
# whatever is current, so a build a month from now installs different bytes and
# nothing records which. This stage is not shipped, but xz-utils decides how the
# tarball is unpacked, so it is pinned like everything else.
ARG DEBIAN_SNAPSHOT=20260901T000000Z
# `http`, not `https`. The base ships no CA bundle, so apt cannot complete a TLS
# handshake before ca-certificates is installed. Integrity does not depend on
# TLS here: apt verifies the Release file's OpenPGP signature against
# debian-archive-keyring, which IS present, and every package against the hashes
# in that signed file.
RUN set -eux; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    { \
      echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main"; \
      echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main"; \
      echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm-updates main"; \
    } > /etc/apt/sources.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends xz-utils

ARG NODE_VERSION=22.23.2
ARG YARN_VERSION=1.22.22

# BuildKit verifies these before the layer is created. A mismatch fails the
# build rather than producing an image somebody has to notice is wrong.
ADD --checksum=sha256:d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307 \
    https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-x64.tar.xz /tmp/node.tar.xz
ADD --checksum=sha256:88268464199d1611fcf73ce9c0a6c4d44c7d5363682720d8506f6508addf36a0 \
    https://yarnpkg.com/downloads/1.22.22/yarn-v1.22.22.tar.gz /tmp/yarn.tar.gz
ADD --checksum=sha256:a15ac9589c04baf9da95b08e0e79b5cf1d75ab8dc64e06a5e68e4ceb0ad7c8ea \
    https://raw.githubusercontent.com/nodejs/docker-node/bc0a422bce0f729dd85790639d9f1918143f1235/22/bookworm-slim/docker-entrypoint.sh \
    /tmp/docker-entrypoint.sh

RUN set -eux; \
    mkdir -p /out/usr/local /out/opt; \
    tar -xJf /tmp/node.tar.xz -C /out/usr/local --strip-components=1 --no-same-owner; \
    tar -xzf /tmp/yarn.tar.gz -C /out/opt --no-same-owner; \
    # Upstream drops the OpenSSL headers for other architectures, saving ~34 MB.
    # Kept here so the shipped tree matches what the replaced image contains.
    find /out/usr/local/include/node/openssl/archs -mindepth 1 -maxdepth 1 \
      ! -name 'linux-x86_64' -exec rm -rf {} +; \
    install -m 0755 /tmp/docker-entrypoint.sh /out/usr/local/bin/docker-entrypoint.sh; \
    test -x /out/usr/local/bin/node

# -----------------------------------------------------------------------------
# the shipped image: the pinned base, plus directories
# -----------------------------------------------------------------------------
FROM ${DEBIAN_BASE}

COPY --from=fetch /out/usr/local /usr/local
COPY --from=fetch /out/opt /opt

ENV NODE_VERSION=22.23.2
ENV YARN_VERSION=1.22.22

RUN set -eux; \
    groupadd --gid 1000 node; \
    useradd --uid 1000 --gid node --shell /bin/bash --create-home node; \
    # THE BUILD DAY LEAKS HERE, and it is the second of the two obstructions
    # this image exists to remove. /etc/shadow's third field is the number of
    # days since 1970-01-01 on which the password last changed, so an account
    # created on any other day produces a different file. 20000 is 2024-10-04,
    # chosen only because it is fixed and in the past.
    sed -ri 's/^(node:[^:]*:)[0-9]*:/\120000:/' /etc/shadow; \
    ln -s /usr/local/bin/node /usr/local/bin/nodejs; \
    ln -s /opt/yarn-v${YARN_VERSION}/bin/yarn /usr/local/bin/yarn; \
    ln -s /opt/yarn-v${YARN_VERSION}/bin/yarnpkg /usr/local/bin/yarnpkg; \
    # useradd writes these, and both record the moment it ran.
    rm -f /var/log/faillog /var/log/lastlog /var/log/tallylog; \
    # smoke tests, so a broken tree fails here rather than in a deployment
    node --version; \
    npm --version; \
    yarn --version; \
    # THE SMOKE TESTS THEMSELVES ARE NOT DETERMINISTIC, which two local builds
    # of this file demonstrated before it said so: npm enables Node 22's V8
    # compile cache, so running it writes ~70 files under
    # /tmp/node-compile-cache/ whose contents differ run to run. Upstream ends
    # both of its RUN steps with the same `rm -rf /tmp/*` and this is why.
    rm -rf /tmp/*

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node"]
