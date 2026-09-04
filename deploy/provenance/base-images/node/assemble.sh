#!/bin/sh
# Assemble the shipped rootfs for the scratch-based Node base.
#
# A separate file rather than a long RUN, because it decides every byte in an
# image with no base layer to hide anything in, and that is the part a reviewer
# has to read.
#
# Everything consumed here was verified by BuildKit's `ADD --checksum` before
# this ran. Everything produced is copied from those inputs or written literally
# below.

set -eu

IN=/in
OUT=/out

mkdir -p \
  "$OUT/bin" "$OUT/lib" "$OUT/lib64" "$OUT/usr/bin" "$OUT/usr/lib" \
  "$OUT/usr/local" "$OUT/etc/ssl/certs" "$OUT/usr/share/ca-certificates" \
  "$OUT/app" "$OUT/home/node" "$OUT/tmp" "$OUT/var/tmp"

unpack() { # unpack <deb> <destination>
  mkdir -p "$2"
  dpkg-deb -x "$1" "$2"
}

# `xz` first, into the BUILDER's own filesystem. It never reaches $OUT: the Node
# release tarball is .tar.xz and debian:bookworm-slim ships no xz, so this is a
# tool the unpack stage needs and not a runtime dependency. Installing it from a
# pinned .deb rather than with apt keeps the unpack stage free of any package
# manager and of any resolution against a live index.
unpack "$IN/xz-utils.deb" /tmp/xz
cp -a /tmp/xz/usr/bin/xz /usr/local/bin/xz
xz --version >/dev/null

# ---------------------------------------------------------------------------
# The C runtime.
#
# MEASURED, not guessed. `ldd` over /usr/local/bin/node and over every native
# module the PRODUCTION dependency set installs -- onnxruntime_binding.node,
# libonnxruntime.so, sharp-linux-x64.node, libvips-cpp.so, argon2.glibc.node --
# names libc.so.6, libm.so.6, libdl.so.2, libpthread.so.0, librt.so.1,
# libresolv.so.2, libstdc++.so.6, libgcc_s.so.1 and the loader. That is exactly
# these three packages and nothing else.
# ---------------------------------------------------------------------------
unpack "$IN/libc6.deb"      /tmp/libc6
unpack "$IN/libgcc-s1.deb"  /tmp/libgcc
unpack "$IN/libstdc++6.deb" /tmp/libstdcxx

# Each package puts its objects where Debian puts them and the three do NOT
# agree: libc6 and libgcc-s1 ship /lib/x86_64-linux-gnu, libstdc++6 ships
# /usr/lib/x86_64-linux-gnu. Copying both trees at their own paths keeps the
# layout Debian intends rather than inventing one, so a soname that resolves in
# the deployed image resolves here for the same reason.
mkdir -p "$OUT/lib/x86_64-linux-gnu" "$OUT/usr/lib/x86_64-linux-gnu"
for tree in /tmp/libc6 /tmp/libgcc /tmp/libstdcxx; do
  [ -d "$tree/lib/x86_64-linux-gnu" ] && cp -a "$tree/lib/x86_64-linux-gnu/." "$OUT/lib/x86_64-linux-gnu/"
  [ -d "$tree/usr/lib/x86_64-linux-gnu" ] && cp -a "$tree/usr/lib/x86_64-linux-gnu/." "$OUT/usr/lib/x86_64-linux-gnu/"
  true
done

# /lib64/ld-linux-x86-64.so.2 is the path every x86-64 ELF names in its
# PT_INTERP header, and it is a symlink on Debian rather than a file in the
# package. Without it nothing starts at all, with an error that names no library.
ln -sf ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$OUT/lib64/ld-linux-x86-64.so.2"
test -e "$OUT/lib64/ld-linux-x86-64.so.2"

# /etc/ld.so.cache, generated rather than assumed.
#
# glibc's built-in search path for x86-64 is /lib64, /usr/lib64, /lib, /usr/lib.
# Debian puts shared objects in /lib/x86_64-linux-gnu, which is NOT on that
# list, so without a cache the loader would fail to find libstdc++ and the
# failure would appear the first time a native module loaded rather than at
# build time.
mkdir -p "$OUT/etc"
printf '/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu\n' > "$OUT/etc/ld.so.conf"
ldconfig -r "$OUT"
test -s "$OUT/etc/ld.so.cache"

# ---------------------------------------------------------------------------
# A shell. `npm run start` spawns `sh -c`, and the image's own HEALTHCHECK is
# shell form. dash is what /bin/sh already is on Debian, so this is the same
# interpreter the deployed image uses rather than a substitute.
# ---------------------------------------------------------------------------
unpack "$IN/dash.deb" /tmp/dash
cp -a /tmp/dash/bin/dash "$OUT/bin/dash"
ln -sf dash "$OUT/bin/sh"

# /usr/bin/env and /usr/bin/base64, and nothing else from coreutils.
#
# npm's entry point is a script with `#!/usr/bin/env node`, so an image with
# node but no env has npm present and unrunnable. The chroot smoke test at the
# end of this file is what caught it, which is the reason that test is here
# rather than in a later harness.
#
# Every production provider worker receives its credential as an encrypted
# base64 environment value and decodes it into tmpfs before Node starts. The
# first scratch-base promotion omitted this binary, so those workers exited
# 127 on a real TDX guest even though the application-level compatibility
# harnesses passed. Keep the exact production decode primitive in the base and
# exercise it below; it is part of the startup ABI, not optional convenience
# tooling.
#
# Copying two binaries out of a package rather than installing the package is
# deliberate: coreutils is ~7 MB of setuid-adjacent tooling in an image whose
# entire purpose is handling plaintext, and nothing at runtime invokes the
# rest. The cost is that this is now a curated list, so a future dependency on
# `cp` or `mkdir` fails loudly at build time instead of silently shipping.
unpack "$IN/coreutils.deb" /tmp/coreutils
install -m 0755 /tmp/coreutils/usr/bin/env "$OUT/usr/bin/env"
install -m 0755 /tmp/coreutils/usr/bin/base64 "$OUT/usr/bin/base64"

# ---------------------------------------------------------------------------
# CA roots.
#
# The deployed node:22-bookworm-slim ships NONE: ca-certificates is installed
# and then purged by upstream's Dockerfile, which is why the application
# Dockerfile has to `apt-get install ca-certificates` in its production stage
# for aws_signing_helper -- a Go binary that verifies AWS endpoints against the
# OS trust store. Putting the bundle in the base removes that apt call, and with
# it the last package manager invocation from the application build.
#
# Built by sorted concatenation rather than by update-ca-certificates, which
# needs a working dpkg and openssl. Same result: Debian's default configuration
# enables every mozilla/ entry.
# ---------------------------------------------------------------------------
unpack "$IN/ca-certificates.deb" /tmp/ca
cp -a /tmp/ca/usr/share/ca-certificates/. "$OUT/usr/share/ca-certificates/"
find "$OUT/usr/share/ca-certificates" -name '*.crt' | LC_ALL=C sort | while read -r cert; do
  cat "$cert"
done > "$OUT/etc/ssl/certs/ca-certificates.crt"
chmod 0644 "$OUT/etc/ssl/certs/ca-certificates.crt"
certs=$(grep -c 'BEGIN CERTIFICATE' "$OUT/etc/ssl/certs/ca-certificates.crt")
[ "$certs" -ge 100 ] || { echo "REFUSING: only $certs certificates in the bundle." >&2; exit 1; }

# getaddrinfo's own configuration, from libc-bin.
#
# MEASURED, not assumed. Without /etc/gai.conf the first version of this image
# resolved `localhost` to 127.0.0.1 while the image it replaces resolved it to
# ::1, because glibc falls back to a built-in precedence table when the file is
# absent. A base that picks a different address family is not a drop-in base:
# a service listening only on IPv4 is reachable from one and not the other.
unpack "$IN/libc-bin.deb" /tmp/libcbin
cp -a /tmp/libcbin/etc/gai.conf "$OUT/etc/gai.conf"
# /etc/host.conf is NOT in libc-bin's data archive -- it comes from base-files,
# which this image does not install. Two lines, written literally, rather than
# pulling a whole package in for them.
printf 'multi on\n' > "$OUT/etc/host.conf"
chmod 0644 "$OUT/etc/host.conf"

# /etc/services and /etc/protocols. getaddrinfo consults them for named
# services; absent, a lookup by name silently behaves differently from the
# deployed image.
unpack "$IN/netbase.deb" /tmp/netbase
cp -a /tmp/netbase/etc/services /tmp/netbase/etc/protocols /tmp/netbase/etc/rpc "$OUT/etc/"

# Zone data. Node bundles ICU for formatting but reads /usr/share/zoneinfo for
# TZ=, and the deployed image has tzdata installed.
unpack "$IN/tzdata.deb" /tmp/tzdata
mkdir -p "$OUT/usr/share/zoneinfo"
cp -a /tmp/tzdata/usr/share/zoneinfo/. "$OUT/usr/share/zoneinfo/"
cp -a /tmp/tzdata/etc/localtime "$OUT/etc/localtime" 2>/dev/null || \
  ln -sf /usr/share/zoneinfo/Etc/UTC "$OUT/etc/localtime"

# ---------------------------------------------------------------------------
# Node itself.
#
# yarn is deliberately NOT installed: the content plane never invokes it, and it
# is megabytes of JavaScript with network reach inside the image whose entire
# purpose is handling plaintext.
# ---------------------------------------------------------------------------
mkdir -p /tmp/node
tar -xJf "$IN/node.tar.xz" -C /tmp/node --strip-components=1 --no-same-owner
# Upstream drops the OpenSSL headers for other architectures, saving ~34 MB.
find /tmp/node/include/node/openssl/archs -mindepth 1 -maxdepth 1 \
  ! -name 'linux-x86_64' -exec rm -rf {} + 2>/dev/null || true
cp -a /tmp/node/. "$OUT/usr/local/"
ln -sf /usr/local/bin/node "$OUT/usr/local/bin/nodejs"
install -m 0755 "$IN/docker-entrypoint.sh" "$OUT/usr/local/bin/docker-entrypoint.sh"

# ---------------------------------------------------------------------------
# Accounts and resolver configuration, written literally.
#
# The production compose runs the content plane as `USER node`, uid 1000. Only
# /etc/passwd and /etc/group are needed for that; /etc/shadow is deliberately
# absent, and its absence removes an obstruction rather than papering over one:
# the deployed image's /etc/shadow records the build DAY in its last-changed
# field, which is part of why that image cannot be replayed.
#
# /etc/hosts and /etc/resolv.conf are NOT written: the container runtime
# bind-mounts its own over anything in the image, so shipping one would be dead
# weight that reads like configuration.
# ---------------------------------------------------------------------------
cat > "$OUT/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/sh
node:x:1000:1000:node:/home/node:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
EOF
cat > "$OUT/etc/group" <<'EOF'
root:x:0:
node:x:1000:
nogroup:x:65534:
EOF
cat > "$OUT/etc/nsswitch.conf" <<'EOF'
hosts: files dns
EOF
chmod 0644 "$OUT/etc/passwd" "$OUT/etc/group" "$OUT/etc/nsswitch.conf"

chmod 1777 "$OUT/tmp" "$OUT/var/tmp"
chown -R 0:0 "$OUT"
# The node account's home and the workdir must belong to it: the production
# compose runs as uid 1000 with a read-only rootfs, and a HOME it cannot stat is
# a difference from the deployed image for no reason.
chown -R 1000:1000 "$OUT/home/node" "$OUT/app"

# ---------------------------------------------------------------------------
# Prove the assembled tree actually runs before it becomes an image. A rootfs
# that cannot start node is a failure worth having at build time, not at deploy
# time, and the loader path above is exactly the kind of thing that works on the
# builder and not in the result.
# ---------------------------------------------------------------------------
chroot "$OUT" /usr/local/bin/node -e 'console.log("node " + process.version)'
chroot "$OUT" /usr/local/bin/npm --version >/dev/null
chroot "$OUT" /bin/sh -c 'exit 0'
chroot "$OUT" /usr/bin/env node -e 'process.exit(0)'
encoded=$(printf 'anonrouter-provider-credential' | chroot "$OUT" /usr/bin/base64)
[ "$encoded" = "YW5vbnJvdXRlci1wcm92aWRlci1jcmVkZW50aWFs" ] || {
  echo "REFUSING: base64 encoder produced unexpected output." >&2
  exit 1
}
decoded=$(printf '%s' "$encoded" | chroot "$OUT" /usr/bin/base64 -d)
[ "$decoded" = "anonrouter-provider-credential" ] || {
  echo "REFUSING: base64 decoder failed the production startup contract." >&2
  exit 1
}

# THE SMOKE TEST IS NOT FREE, and this is the second time the comparison tool
# has caught it. Running npm enables Node 22's V8 compile cache, which writes
# ~70 non-deterministic files under /tmp/node-compile-cache -- inside $OUT,
# because the chroot IS $OUT. Two builds then differ by exactly those files.
#
# Clearing /tmp afterwards is the same discipline upstream's own Dockerfile
# applies with `rm -rf /tmp/*`, for the same reason.
rm -rf "$OUT"/tmp/* "$OUT"/tmp/.[!.]* "$OUT"/var/tmp/* 2>/dev/null || true
chmod 1777 "$OUT/tmp" "$OUT/var/tmp"
[ -z "$(ls -A "$OUT/tmp")" ] || { echo "REFUSING: /tmp is not empty after the smoke tests." >&2; exit 1; }

echo "assembled $(find "$OUT" -type f | wc -l) files"
