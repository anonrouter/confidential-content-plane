#!/usr/bin/env bash
# Does this OCI layer blob record a file capability xattr?
#
# =============================================================================
# TWO WAYS TO GET THIS WRONG, AND BOTH HAPPENED
# =============================================================================
#
# The check exists because the stock caddy binary carries
# cap_net_bind_service as a FILE capability, and under `cap_drop: ALL` execve
# refuses to grant an effective capability the bounding set does not contain, so
# the container dies before Caddy runs. An image intended for that policy must
# not carry one, and the assertion has to be checkable.
#
# FAILURE ONE, `grep -q` under `set -o pipefail`. `gzip -dc blob | grep -q X`
# reports FAILURE when grep MATCHES: grep exits at the first hit, gzip takes
# SIGPIPE, and pipefail surfaces gzip's death as the pipeline's status. The
# check therefore answered "clean" for every image, including the one that is
# not. `grep -c` reads the whole stream, so there is no SIGPIPE to misread.
#
# FAILURE TWO, matching the wrong string. `security.capability` appears as a
# literal inside libcap.so.2 and libcap-ng.so.0, both of which Debian ships, so
# a byte-grep for it matches any image containing libcap whether or not a single
# file carries the xattr. It reported "dirty" for a clean image.
#
# `SCHILY.xattr.security.capability` is the PAX extended-header keyword a layer
# tar uses to record the xattr, so it appears once per file that has one and
# nowhere else. Measured: 1 occurrence in the stock caddy image's binary layer,
# 0 in every candidate layer, 0 in the Debian base layer that contains libcap.
#
# Both failures pointed opposite ways and only a control that had to FAIL caught
# either. That is why this is one committed implementation rather than a snippet
# copied into a workflow: two copies drift, and the drifted one is the one that
# says everything is fine.
#
#   layer-carries-capability.sh <blob>   -> exit 0 if it carries one, 1 if not

set -euo pipefail

BLOB="${1:?usage: layer-carries-capability.sh <layer-blob>}"
KEYWORD="SCHILY.xattr.security.capability"

count_in() { # count_in <reader-command...>
  # `|| true` twice on purpose: gzip fails on a non-gzip blob, and grep exits 1
  # when it finds nothing. Neither is an error here, and under `set -e` both
  # would end the script with a status that reads like "no capability".
  "$@" 2>/dev/null | grep -ac "$KEYWORD" || true
}

# Compressed first, then raw, because a layer may be either and answering only
# for one shape would be a check that silently does not apply.
gz=$( { gzip -dc "$BLOB" 2>/dev/null || true; } | grep -ac "$KEYWORD" || true)
if [ "${gz:-0}" -gt 0 ]; then
  echo "$gz"
  exit 0
fi
raw=$(grep -ac "$KEYWORD" "$BLOB" 2>/dev/null || true)
if [ "${raw:-0}" -gt 0 ]; then
  echo "$raw"
  exit 0
fi
echo 0
exit 1
