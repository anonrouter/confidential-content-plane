#!/bin/sh
# Assemble the shipped tree for the scratch-based caddy base.
#
# A separate file rather than a long RUN, because it is the part a reviewer
# actually has to read: it decides every byte that ends up in an image with no
# base layer to hide anything in.
#
# Everything it consumes was verified by BuildKit's `ADD --checksum` before this
# ran. Everything it produces is either copied from those inputs or written
# literally below.

set -eu

IN=/in
OUT=/out

mkdir -p \
  "$OUT/usr/bin" \
  "$OUT/etc/caddy" \
  "$OUT/etc/ssl/certs" \
  "$OUT/usr/share/caddy" \
  "$OUT/usr/share/ca-certificates" \
  "$OUT/config/caddy" \
  "$OUT/data/caddy" \
  "$OUT/srv" \
  "$OUT/tmp"

# ---------------------------------------------------------------------------
# The caddy binary. Static: `ldd` reports "not a dynamic executable", which is
# what makes a scratch image possible at all.
# ---------------------------------------------------------------------------
tar -xzf "$IN/caddy.tar.gz" -C "$OUT/usr/bin" caddy
chmod 0755 "$OUT/usr/bin/caddy"

# The check is here rather than in a comment. If a future caddy release links
# against libc, this image would ship a binary that cannot start and the failure
# would appear at deploy time instead of build time.
if [ -n "$(readelf -l "$OUT/usr/bin/caddy" 2>/dev/null | grep -F 'Requesting program interpreter' || true)" ]; then
  echo "REFUSING: the caddy binary is dynamically linked; a scratch image cannot run it." >&2
  exit 1
fi

install -m 0644 "$IN/Caddyfile" "$OUT/etc/caddy/Caddyfile"
install -m 0644 "$IN/index.html" "$OUT/usr/share/caddy/index.html"

# ---------------------------------------------------------------------------
# CA roots.
#
# The .deb ships the individual certificates; the concatenated bundle is
# normally produced by update-ca-certificates in a postinst, which needs a
# working dpkg and openssl. Building it here from a SORTED concatenation is
# deterministic, needs neither, and produces the same bundle Debian's default
# configuration would: `ca-certificates.conf` enables every mozilla/ entry.
#
# The edge does not currently need this -- every upstream in its Caddyfile is
# plain HTTP to a container name -- but the stock caddy image has a trust store,
# and a base image that silently drops one turns a future `reverse_proxy
# https://...` into a confusing runtime failure.
# ---------------------------------------------------------------------------
mkdir -p /tmp/ca && dpkg-deb -x "$IN/ca-certificates.deb" /tmp/ca
cp -a /tmp/ca/usr/share/ca-certificates/. "$OUT/usr/share/ca-certificates/"
find "$OUT/usr/share/ca-certificates" -name '*.crt' | LC_ALL=C sort | while read -r cert; do
  cat "$cert"
done > "$OUT/etc/ssl/certs/ca-certificates.crt"
chmod 0644 "$OUT/etc/ssl/certs/ca-certificates.crt"
certs=$(grep -c 'BEGIN CERTIFICATE' "$OUT/etc/ssl/certs/ca-certificates.crt")
if [ "$certs" -lt 100 ]; then
  echo "REFUSING: only $certs certificates in the bundle; the package layout changed." >&2
  exit 1
fi
echo "ca bundle: $certs certificates"

# ---------------------------------------------------------------------------
# MIME types. The Alpine image gets these from `mailcap`; Debian renamed the
# package to `media-types` in bookworm. Caddy's file_server uses /etc/mime.types
# when present and falls back to a built-in table when it is not, so this is
# parity rather than a requirement.
# ---------------------------------------------------------------------------
mkdir -p /tmp/mt && dpkg-deb -x "$IN/media-types.deb" /tmp/mt
install -m 0644 /tmp/mt/etc/mime.types "$OUT/etc/mime.types"

# ---------------------------------------------------------------------------
# Accounts and resolver configuration, written literally.
#
# `nsswitch.conf` matters more than it looks. Go's resolver inspects it; with
# the file absent the behaviour depends on the Go version's fallback rather than
# on anything visible here, and the edge resolves every upstream by container
# name through Docker's embedded DNS.
#
# /etc/hosts and /etc/resolv.conf are deliberately NOT written: the container
# runtime bind-mounts its own over anything in the image, so shipping one would
# be dead weight that reads like configuration.
# ---------------------------------------------------------------------------
cat > "$OUT/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin
EOF
cat > "$OUT/etc/group" <<'EOF'
root:x:0:
nogroup:x:65534:
EOF
cat > "$OUT/etc/nsswitch.conf" <<'EOF'
hosts: files dns
EOF
chmod 0644 "$OUT/etc/passwd" "$OUT/etc/group" "$OUT/etc/nsswitch.conf"

# XDG dirs. Production mounts tmpfs over /config and /data, so these are the
# non-tmpfs fallback and the reason `caddy run` does not fail on a read-only
# rootfs when someone runs it without the production compose.
chmod 1777 "$OUT/config/caddy" "$OUT/data/caddy" "$OUT/tmp"

# Ownership is set explicitly rather than inherited from whatever the build ran
# as: COPY --from preserves uid/gid, and an image whose files belong to a build
# user is a difference nobody intended.
chown -R 0:0 "$OUT"

echo "assembled $(find "$OUT" -type f | wc -l) files"
