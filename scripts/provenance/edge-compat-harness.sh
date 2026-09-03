#!/usr/bin/env bash
# Is a candidate caddy base BEHAVIOURALLY INDISTINGUISHABLE from the one the
# edge runs today, under the exact deployment policy?
#
# =============================================================================
# WHY DIFFERENTIAL, AND NOT A LIST OF ABSOLUTE ASSERTIONS
# =============================================================================
#
# The first version of this harness asserted absolute expectations and produced
# six failures, of which FOUR were properties of the production Caddyfile rather
# than of the base image:
#
#   * `/evidences/x` 404s because the block is `handle` with `root * /evidences`
#     and no `uri strip_prefix`, so the URL maps to /evidences/evidences/x;
#   * an 11 MB body is not refused by a route whose upstream answers without
#     reading the body, because `request_body max_size` bites on read;
#   * `docker stop` can hit its timeout and SIGKILL, because Caddy shuts servers
#     down "with eternal grace period" and a lingering connection blocks it;
#   * the exec check depended on PATH, which a scratch image does not have.
#
# Every one of those would have been reported identically against the image the
# edge runs today. Asserting absolutes meant the harness was testing the
# Caddyfile and calling the result a base-image verdict.
#
# So it runs the SAME matrix against two edges built from the same Caddyfile,
# one on the stock base and one on the candidate, and the claim it can support
# is the claim that matters: the candidate does the same thing. A small set of
# absolute invariants is kept separately, for things that must hold whatever the
# stock image does.
#
# =============================================================================
# A CONTROL ON THE MATRIX ITSELF
# =============================================================================
#
# "Identical" is worthless if the matrix cannot tell two edges apart. A third
# edge is built with one line of the Caddyfile changed, and the run FAILS unless
# the matrix reports it as different from the other two.
#
#   scripts/provenance/edge-compat-harness.sh <candidate-image> [--caddyfile <path>] [--json <out>]
#
# Exits 0 only when candidate == stock on every check, every absolute invariant
# holds, and the mutation control is detected.

set -euo pipefail

CANDIDATE="${1:?usage: edge-compat-harness.sh <candidate-image> [--caddyfile <path>] [--json <out>]}"
shift || true
CADDYFILE="deploy/phala/images/edge-xl/Caddyfile"
JSON_OUT=""
# The base the edge runs today, pinned to its linux/amd64 child manifest exactly
# as deploy/phala/images/edge/Dockerfile pins it.
STOCK_BASE="caddy:2.11.4-alpine@sha256:98eb57d882ccd5213d1688764db10c1ca2c58a1ca3a6717a3411ad798f7a423a"
while [ $# -gt 0 ]; do
  case "$1" in
    --caddyfile) CADDYFILE="$2"; shift 2 ;;
    --json) JSON_OUT="$2"; shift 2 ;;
    --stock-base) STOCK_BASE="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -f "$CADDYFILE" ] || { echo "no Caddyfile at $CADDYFILE" >&2; exit 2; }

TAG=$$
NET="edge-compat-$TAG"
WORK="$(mktemp -d)"
VOL="edge-compat-evidences-$TAG"
STUBS="relay compat attest venice-worker fireworks-worker deepinfra-worker chutes-worker tinfoil-worker near-worker bedrock-worker"
declare -A RESULT

cleanup() {
  for v in stock candidate mutated; do docker rm -f "edge-compat-$v-$TAG" >/dev/null 2>&1 || true; done
  for s in $STUBS; do docker rm -f "edge-compat-${s}-$TAG" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$VOL" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "edge compatibility harness (differential)"
echo "  candidate: ${CANDIDATE}"
echo "  stock:     ${STOCK_BASE}"
echo "  Caddyfile: ${CADDYFILE}"
echo

# ---------------------------------------------------------------------------
# Build the three edges.
#
# The stock one reproduces deploy/phala/images/edge/Dockerfile, INCLUDING the
# capability strip, because without it the stock image cannot start under
# `cap_drop: ALL` at all and the comparison would be against something the
# deployment never runs.
# ---------------------------------------------------------------------------
mkdir -p "$WORK/stock" "$WORK/candidate" "$WORK/mutated"
cp "$CADDYFILE" "$WORK/stock/Caddyfile"
cp "$CADDYFILE" "$WORK/candidate/Caddyfile"
# The mutation control: one route redirected to the wrong upstream. Small enough
# that a matrix which misses it is measuring nothing.
sed 's|reverse_proxy attest:3000|reverse_proxy relay:3000|' "$CADDYFILE" > "$WORK/mutated/Caddyfile"
if cmp -s "$CADDYFILE" "$WORK/mutated/Caddyfile"; then
  echo "REFUSING: the mutation control did not change the Caddyfile." >&2
  exit 1
fi

cat > "$WORK/stock/Dockerfile" <<EOF
FROM ${STOCK_BASE}
RUN apk add --no-cache libcap \\
 && setcap -r /usr/bin/caddy \\
 && apk del libcap \\
 && ! getcap /usr/bin/caddy 2>/dev/null | grep -q cap_net_bind_service
COPY Caddyfile /etc/caddy/Caddyfile
EOF
for v in candidate mutated; do
  cat > "$WORK/$v/Dockerfile" <<EOF
FROM ${CANDIDATE}
COPY Caddyfile /etc/caddy/Caddyfile
EOF
done

for v in stock candidate mutated; do
  docker build --platform linux/amd64 -q -t "edge-compat-$v-image-$TAG" "$WORK/$v" >/dev/null
done
echo "built three edge images (stock, candidate, mutated-control)"

# ---------------------------------------------------------------------------
# Stub upstreams, on the CANDIDATE image, which exercises it as a server too.
# Each answers with its own name, so a proxied response proves WHICH upstream
# served it rather than merely that something did.
# ---------------------------------------------------------------------------
docker network create "$NET" >/dev/null
mkdir -p "$WORK/stub"
for s in $STUBS; do
  cat > "$WORK/stub/Caddyfile" <<EOF
{
	admin off
	auto_https off
}
:3000 {
	respond "upstream=${s}" 200
}
EOF
  cat > "$WORK/stub/Dockerfile" <<EOF
FROM ${CANDIDATE}
COPY Caddyfile /etc/caddy/Caddyfile
EOF
  docker build --platform linux/amd64 -q -t "edge-compat-stub-${s}-$TAG" "$WORK/stub" >/dev/null
  docker run -d --name "edge-compat-${s}-$TAG" --network "$NET" --network-alias "$s" \
    --platform linux/amd64 --read-only --cap-drop ALL --security-opt no-new-privileges:true --init \
    --tmpfs /tmp:size=8m,nosuid,nodev --tmpfs /config:size=8m,nosuid,nodev --tmpfs /data:size=8m,nosuid,nodev \
    "edge-compat-stub-${s}-$TAG" >/dev/null
done
echo "started $(echo $STUBS | wc -w | tr -d ' ') stub upstreams on the candidate image"

# The read-only evidences volume. The Caddyfile uses `handle` with
# `root * /evidences` and NO `uri strip_prefix`, so /evidences/x resolves to
# /evidences/evidences/x. The fixture is placed where the config actually looks,
# rather than where a reader might assume.
docker volume create "$VOL" >/dev/null
docker run --rm -v "$VOL:/e" --platform linux/amd64 \
  debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867 \
  sh -c 'mkdir -p /e/evidences && printf "evidence-fixture\n" > /e/evidences/release.json' >/dev/null

start_edge() { # start_edge <variant> <hostport>
  docker run -d --name "edge-compat-$1-$TAG" --network "$NET" -p "$2:8080" \
    --platform linux/amd64 --read-only --cap-drop ALL --security-opt no-new-privileges:true --init \
    --tmpfs /tmp:size=16m,nosuid,nodev \
    --tmpfs /config:size=8m,nosuid,nodev \
    --tmpfs /data:size=8m,nosuid,nodev \
    -v "$VOL:/evidences:ro" --memory 96m \
    "edge-compat-$1-image-$TAG" >/dev/null
  for _ in $(seq 1 60); do
    curl -s -o /dev/null "http://127.0.0.1:$2/v1/models" 2>/dev/null && return 0
    sleep 0.25
  done
  return 0
}

record() { RESULT["$1|$2"]="$3"; }

probe() { # probe <variant> <port>
  local v="$1" p="$2" b
  record "$v" "state"          "$(docker inspect -f '{{.State.Status}}' "edge-compat-$v-$TAG")"
  record "$v" "restarts"       "$(docker inspect -f '{{.RestartCount}}' "edge-compat-$v-$TAG")"
  record "$v" "models"         "$(curl -s "http://127.0.0.1:$p/v1/models")"
  record "$v" "compat"         "$(curl -s -X POST "http://127.0.0.1:$p/compat/v1/chat/completions")"
  record "$v" "attest"         "$(curl -s "http://127.0.0.1:$p/v1/gateway/attestation")"
  record "$v" "cred-venice"    "$(curl -s "http://127.0.0.1:$p/v1/credentials/venice/identity")"
  record "$v" "cred-bedrock"   "$(curl -s "http://127.0.0.1:$p/v1/credentials/bedrock/identity")"
  record "$v" "cred-chutes"    "$(curl -s "http://127.0.0.1:$p/v1/credentials/chutes/identity")"
  record "$v" "evidence-file"  "$(curl -s "http://127.0.0.1:$p/evidences/release.json")"
  record "$v" "evidence-browse" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/evidences/")"
  record "$v" "preflight"      "$(curl -s -X OPTIONS -H 'Origin: https://anonrouter.ai' -H 'Access-Control-Request-Method: GET' "http://127.0.0.1:$p/v1/models")"
  record "$v" "internal-404"   "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/internal/control/x")"
  record "$v" "readyz-404"     "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/readyz")"
  record "$v" "cryptohz-404"   "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/healthz/crypto")"
  record "$v" "admin-404"      "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/v1/admin/anything")"
  record "$v" "unrouted-404"   "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/definitely/not/a/route")"
  record "$v" "admin-api-off"  "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$p/../../config/" || echo 000)"
  # exec without a shell: the image has no /bin/sh, so this is exec-form only.
  if docker exec "edge-compat-$v-$TAG" caddy version >/dev/null 2>&1; then b=yes; else b=no; fi
  record "$v" "exec-path"      "$b"
  if docker exec "edge-compat-$v-$TAG" /usr/bin/caddy version >/dev/null 2>&1; then b=yes; else b=no; fi
  record "$v" "exec-abs"       "$b"
  record "$v" "readonly"       "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "edge-compat-$v-$TAG")"
  record "$v" "capdrop"        "$(docker inspect -f '{{json .HostConfig.CapDrop}}' "edge-compat-$v-$TAG")"

  # LAST, because it is the only probe that can perturb the others. An 11 MB
  # body against `mem_limit: 96m` pushes the cgroup hard enough that a probe
  # taken afterwards is measuring the aftermath rather than the image. It is
  # sent to the route that actually reads the body; `respond` upstreams do not,
  # which is why the absolute version of this check reported 200 for the stock
  # image too.
  local big; big="$(mktemp)"; dd if=/dev/zero of="$big" bs=1048576 count=11 >/dev/null 2>&1
  record "$v" "body-11mb"      "$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST --data-binary @"$big" -H 'Content-Type: application/json' "http://127.0.0.1:$p/v1/chat/completions" || echo 000)"
  rm -f "$big"
  record "$v" "oom-after-11mb" "$(docker inspect -f '{{.State.OOMKilled}}' "edge-compat-$v-$TAG")"
}

MATRIX="state restarts models compat attest cred-venice cred-bedrock cred-chutes evidence-file evidence-browse preflight internal-404 readyz-404 cryptohz-404 admin-404 unrouted-404 admin-api-off exec-path exec-abs readonly capdrop body-11mb oom-after-11mb"

start_edge stock 18080
start_edge candidate 18081
start_edge mutated 18082
probe stock 18080
probe candidate 18081
probe mutated 18082

echo
echo "DIFFERENTIAL MATRIX  (candidate must equal stock)"
printf '  %-18s %-24s %-24s %s\n' check stock candidate verdict
differs=0
for k in $MATRIX; do
  s="${RESULT[stock|$k]:-}"; c="${RESULT[candidate|$k]:-}"
  if [ "$s" = "$c" ]; then verdict=same; else verdict=DIFFERS; differs=$((differs+1)); fi
  printf '  %-18s %-24.24s %-24.24s %s\n' "$k" "$s" "$c" "$verdict"
done

echo
echo "CONTROL ON THE MATRIX: the mutated edge must NOT look the same"
mutated_diffs=0
for k in $MATRIX; do
  [ "${RESULT[stock|$k]:-}" = "${RESULT[mutated|$k]:-}" ] || mutated_diffs=$((mutated_diffs+1))
done
echo "  the mutated control differs from stock in ${mutated_diffs} check(s)"

echo
echo "ABSOLUTE INVARIANTS, which must hold whatever the stock image does"
abs_fail=0
absolute() { if [ "$2" = "$3" ]; then printf '  PASS  %s (%s)\n' "$1" "$3"; else printf '  FAIL  %s: expected %s, got %s\n' "$1" "$2" "$3"; abs_fail=$((abs_fail+1)); fi }
absolute "candidate runs under cap_drop ALL" "running" "${RESULT[candidate|state]}"
absolute "candidate never restarted"         "0"       "${RESULT[candidate|restarts]}"
# NOT an absolute invariant, deliberately. The stock image is OOM killed by the
# same probe, so requiring `false` here would fail the candidate for a property
# of the deployment's 96m cap rather than of the image -- exactly the mistake
# the differential design exists to prevent. It is reported instead.
absolute "internal surface is 404"           "404"     "${RESULT[candidate|internal-404]}"
absolute "readyz is 404"                     "404"     "${RESULT[candidate|readyz-404]}"
absolute "admin surface is 404"              "404"     "${RESULT[candidate|admin-404]}"
absolute "credential routes are not cross-wired" "upstream=chutes-worker" "${RESULT[candidate|cred-chutes]}"
# The image must not carry the file capability that stops the stock binary
# starting under an empty bounding set.
if docker run --rm --platform linux/amd64 --cap-drop ALL --entrypoint /usr/bin/caddy "edge-compat-candidate-image-$TAG" version >/dev/null 2>&1; then
  printf '  PASS  %s\n' "the candidate binary starts with an empty bounding set"
else
  printf '  FAIL  %s\n' "the candidate binary refuses to start under cap_drop ALL"; abs_fail=$((abs_fail+1))
fi

if [ "${RESULT[candidate|oom-after-11mb]}" = "true" ] || [ "${RESULT[stock|oom-after-11mb]}" = "true" ]; then
  echo
  echo "  OBSERVATION, pre-existing and NOT introduced by the candidate:"
  echo "  an 11 MB request body OOM-kills the edge cgroup under \`mem_limit: 96m\`"
  echo "  (stock=${RESULT[stock|oom-after-11mb]}, candidate=${RESULT[candidate|oom-after-11mb]}). The Caddyfile's own"
  echo "  ceiling is 10 MB, so a body just under it reaches the proxy. This is a"
  echo "  sizing question for the compose file, not a base-image question, and it"
  echo "  is recorded here because the harness is where it became visible."
fi

echo
echo "SIGNALS, measured on both because Caddy shuts down with an eternal grace period"
sig() { # sig <variant>
  docker stop -t 20 "edge-compat-$1-$TAG" >/dev/null 2>&1 || true
  local code; code="$(docker inspect -f '{{.State.ExitCode}}' "edge-compat-$1-$TAG")"
  local graceful=no
  docker logs "edge-compat-$1-$TAG" 2>&1 | grep -qi 'shutdown complete' && graceful=yes
  echo "$code/$graceful"
}
stock_sig="$(sig stock)"; cand_sig="$(sig candidate)"; : "$(sig mutated)"
printf '  stock exit/graceful:     %s\n' "$stock_sig"
printf '  candidate exit/graceful: %s\n' "$cand_sig"
if [ "$stock_sig" = "$cand_sig" ]; then
  printf '  PASS  shutdown behaviour is identical\n'
else
  printf '  FAIL  shutdown behaviour differs\n'; abs_fail=$((abs_fail+1))
fi

if [ -n "$JSON_OUT" ]; then
  {
    printf '{\n  "schema": "anonrouter-edge-compat-v1",\n'
    printf '  "candidate": "%s",\n  "stock": "%s",\n  "caddyfile": "%s",\n' "$CANDIDATE" "$STOCK_BASE" "$CADDYFILE"
    printf '  "differingChecks": %s,\n  "mutationControlDiffs": %s,\n  "absoluteFailures": %s,\n' "$differs" "$mutated_diffs" "$abs_fail"
    printf '  "shutdown": {"stock": "%s", "candidate": "%s"},\n' "$stock_sig" "$cand_sig"
    printf '  "matrix": {\n'
    first=1
    for k in $MATRIX; do
      [ $first -eq 1 ] || printf ',\n'; first=0
      printf '    "%s": {"stock": %s, "candidate": %s, "mutated": %s}' "$k" \
        "$(printf '%s' "${RESULT[stock|$k]:-}" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')" \
        "$(printf '%s' "${RESULT[candidate|$k]:-}" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')" \
        "$(printf '%s' "${RESULT[mutated|$k]:-}" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')"
    done
    printf '\n  }\n}\n'
  } > "$JSON_OUT"
  echo "  evidence written to $JSON_OUT"
fi

echo
echo "================================================================"
status=0
[ "$differs" -eq 0 ]        || { echo "  ${differs} check(s) differ from the stock image."; status=1; }
[ "$mutated_diffs" -gt 0 ]  || { echo "  The matrix could not tell a MUTATED edge from the stock one, so"; echo "  'identical' means nothing here."; status=1; }
[ "$abs_fail" -eq 0 ]       || { echo "  ${abs_fail} absolute invariant(s) failed."; status=1; }
if [ "$status" -eq 0 ]; then
  echo "  The candidate is behaviourally indistinguishable from the base the"
  echo "  edge runs today, on every check, under the production policy, and the"
  echo "  matrix demonstrably detects a difference when there is one."
else
  echo "  NOT production compatible. Do not record it as one."
fi
echo "================================================================"
exit $status
