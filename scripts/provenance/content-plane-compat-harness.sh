#!/usr/bin/env bash
# Does the REAL content-plane image build and run on a candidate Node base?
#
# =============================================================================
# WHAT THIS HAS TO ANSWER, AND WHY A VERSION PRINT DOES NOT
# =============================================================================
#
# The Node base runs every line of code that handles prompt plaintext. Swapping
# it is not a packaging change: the production dependency set carries four
# native modules with prebuilt binaries compiled against glibc -- argon2,
# onnxruntime-node, @img/sharp-linux-x64 and its bundled libvips -- and a Go
# binary, aws_signing_helper, that verifies AWS endpoints against the OS trust
# store rather than Node's bundled roots.
#
# A base that starts `node --version` and cannot dlopen libvips is a base that
# fails on the first image request, in production, after the measurement has
# been sealed.
#
# =============================================================================
# DIFFERENTIAL, FOR THE SAME REASON AS THE EDGE HARNESS
# =============================================================================
#
# It builds the SAME application source twice -- once on the base the content
# plane runs today, once on the candidate -- and requires them to behave
# identically. Absolute expectations would keep rediscovering properties of the
# application rather than of the base, which is what the first edge harness did
# four times over.
#
# A third image is built with a deliberately broken base (the CA bundle removed)
# and the run FAILS unless the matrix detects it. "Identical" means nothing from
# a matrix that cannot tell two images apart.
#
#   scripts/provenance/content-plane-compat-harness.sh <candidate-base> [--context <dir>] [--json <out>]
#
# The context must be a content-plane tree with a Dockerfile: the export
# directory locally, the repository root in public CI.

set -euo pipefail
# A failing harness must say WHERE. Without this the first run died silently
# after "probing stock..." and the log carried no reason at all.
trap 'echo "HARNESS ABORTED at line ${LINENO}" >&2' ERR

CANDIDATE="${1:?usage: content-plane-compat-harness.sh <candidate-base> [--context <dir>] [--json <out>]}"
shift || true
CONTEXT="."
JSON_OUT=""
STOCK_BASE="node:22-bookworm-slim@sha256:a17d50af28002a160548bd4225b3cfcb12c5efcb171f79e68758f2885fb1b066"
while [ $# -gt 0 ]; do
  case "$1" in
    --context) CONTEXT="$2"; shift 2 ;;
    --json) JSON_OUT="$2"; shift 2 ;;
    --stock-base) STOCK_BASE="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -f "$CONTEXT/Dockerfile" ] || { echo "no Dockerfile in $CONTEXT" >&2; exit 2; }

TAG=$$
NET="cp-compat-$TAG"
WORK="$(mktemp -d)"
declare -A RESULT
cleanup() {
  for v in stock candidate broken; do docker rm -f "cp-compat-$v-$TAG" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "content-plane compatibility harness (differential)"
echo "  candidate base: ${CANDIDATE}"
echo "  stock base:     ${STOCK_BASE}"
echo "  context:        ${CONTEXT}"
echo

# ---------------------------------------------------------------------------
# Three Dockerfiles from the real one.
#
# The BUILD stage keeps the stock Node image in every variant, deliberately. It
# is a build tool that never ships, it is not plaintext-capable, and holding it
# constant is what makes the comparison about the RUNTIME base rather than about
# two different compilers.
#
# The router-model download is skipped and ROUTER_ENABLED is off at runtime.
# It is a ~100 MB fetch that exercises nothing about the base, and leaving it in
# would make this harness a network test.
# ---------------------------------------------------------------------------
mkdir -p "$WORK"
make_dockerfile() { # make_dockerfile <runtime-base> <out>
  python3 - "$1" "$2" "$CONTEXT/Dockerfile" <<'PY'
import re, sys
runtime, out, src = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src).read()
lines = text.split("\n")
result, seen_production = [], False
for line in lines:
    if line.startswith("FROM ") and line.rstrip().endswith("AS production"):
        seen_production = True
        result.append(f"FROM {runtime} AS production")
        continue
    # The router model is a ~100 MB network fetch that exercises nothing about
    # the base. Skipping it means skipping the COPY that consumes it too, or the
    # production stage fails on a path the build stage never created -- which is
    # exactly how the first run of this harness failed, identically on all three
    # variants, and therefore silently.
    if "prepare-router-model" in line or "router:model:prepare" in line:
        result.append("  && true")
        continue
    if "anonrouter-router-model" in line and line.startswith("COPY"):
        continue
    # the base under test already carries the CA bundle; on the stock base the
    # apt call is what puts it there, so it stays for the stock variant and is
    # harmless (and impossible) on a scratch base.
    result.append(line)
out_text = "\n".join(result)
if not seen_production:
    raise SystemExit("no `AS production` stage in the Dockerfile")
open(out, "w").write(out_text)
PY
}

# =============================================================================
# THE STOCK VARIANT HAS TO BE THE ARRANGEMENT THAT IS DEPLOYED
# =============================================================================
#
# This used to STRIP an `apt-get install ca-certificates` block from the
# candidate and broken variants, keeping it for stock, because a scratch base
# has no apt and the deployed image gets its trust store that way.
#
# Then the exporter moved the trust store into the base and deleted the apt
# block, and the strip became a no-op nobody noticed. The stock variant was
# suddenly `node:22-bookworm-slim` with NO OS trust store -- an arrangement
# that has never been deployed and could not be, since aws_signing_helper is a
# Go binary that verifies AWS endpoints against that store. The harness then
# reported `tls-roots: stock=absent, candidate=150` and called the candidate
# incompatible, when what it had actually measured was the candidate being
# correct and the comparison being broken.
#
# That failure is worth more than the fix: a differential is only as good as
# its baseline, and a baseline derived by SUBTRACTING from the current source
# tracks the source rather than the deployment. So the block is now INSERTED
# into the stock variant rather than retained in it, and the harness refuses to
# report anything if the stock variant does not end up with a trust store.
insert_apt_ca_certificates() {
  python3 - "$1" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().split("\n")
if any("apt-get install" in l and "ca-certificates" in l for l in lines):
    raise SystemExit(0)  # already there; nothing to reproduce
out, done = [], False
for line in lines:
    out.append(line)
    if not done and line.startswith("FROM ") and line.rstrip().endswith("AS production"):
        out += [
            "# INSERTED BY THE HARNESS, to reproduce the arrangement that is deployed:",
            "# the slim base omits the OS CA trust store, and the deployed image installs",
            "# it here. The candidate gets the same store from its base instead, and",
            "# whether those two arrangements are equivalent is the question being asked.",
            "RUN apt-get update \\",
            "  && apt-get install -y --no-install-recommends ca-certificates \\",
            "  && rm -rf /var/lib/apt/lists/*",
        ]
        done = True
if not done:
    raise SystemExit("no `AS production` stage to insert into")
open(p, "w").write("\n".join(out))
PY
}

mkdir -p "$WORK/df"
make_dockerfile "$STOCK_BASE" "$WORK/df/stock"; insert_apt_ca_certificates "$WORK/df/stock"
make_dockerfile "$CANDIDATE" "$WORK/df/candidate"
# The broken control: same candidate base with the CA bundle emptied. It must
# change at least one observable, or the matrix is not measuring the base.
cat > "$WORK/df/broken-base" <<EOF
FROM ${CANDIDATE}
COPY --from=${CANDIDATE} /etc/passwd /etc/ssl/certs/ca-certificates.crt
EOF
docker build --platform linux/amd64 -q -t "cp-compat-brokenbase-$TAG" -f "$WORK/df/broken-base" "$WORK/df" >/dev/null
make_dockerfile "cp-compat-brokenbase-$TAG" "$WORK/df/broken"

for v in stock candidate broken; do
  echo "building the content-plane image on the ${v} base..."
  if ! docker build --platform linux/amd64 -q -t "cp-compat-$v-image-$TAG" -f "$WORK/df/$v" "$CONTEXT" > "$WORK/$v.build" 2>&1; then
    echo "  BUILD FAILED for ${v}:"; tail -25 "$WORK/$v.build"
    RESULT["$v|build"]=failed
  else
    RESULT["$v|build"]=ok
  fi
done

docker network create "$NET" >/dev/null

# ---------------------------------------------------------------------------
# The runtime environment, taken from the relay service in
# deploy/phala/docker-compose.prod5-xl.yml.
#
# THE TOKENS ARE 48 HEX CHARACTERS AND CONTAIN NO PLACEHOLDER WORD, and both
# properties are load-bearing rather than cosmetic. `loadConfig` refuses a
# split-role configuration whose RPC tokens are shorter than 32 bytes or look
# like placeholders, so the first version of this harness -- with tokens
# reading "harness-dummy-relay-token" -- never booted the application at all
# and reported `boot-healthz: down` for every variant, identically, which is
# the shape of result that looks like a clean differential and measures
# nothing.
#
# They are still not credentials: they authorise nothing, no control plane is
# reachable from this network, and they exist only to get past a length check.
# ---------------------------------------------------------------------------
ENVFILE="$WORK/env"
cat > "$ENVFILE" <<'EOF'
NODE_ENV=production
RUNTIME_ROLE=relay
PORT=3000
HOST=0.0.0.0
LOG_LEVEL=warn
TRUST_PROXY_HOPS=1
CORS_ORIGIN=https://anonrouter.ai
ALLOW_INLINE_TICKET=false
IMAGE_GENERATION_ENABLED=true
SPEECH_GENERATION_ENABLED=true
ROUTER_ENABLED=false
REQUEST_BODY_LIMIT_BYTES=10000000
CONTROL_RPC_URL=http://control.invalid:8444
WORKER_RPC_URL=http://venice-worker:3000
ALLOW_COMPAT_MODE=true
CONTROL_RPC_TIMEOUT_MS=15000
WORKER_RPC_TIMEOUT_MS=620000
GATEWAY_ATTESTATION_ENABLED=false
EOF

# The three RPC tokens are GENERATED HERE rather than written above, and that
# is a deliberate consequence of what the export scanner is for. `loadConfig`
# refuses a split-role configuration whose tokens are shorter than 32 bytes or
# look like placeholders, so they have to be long and unplaceholder-like -- and
# a committed literal with those properties is indistinguishable from a leaked
# credential to any entropy scanner, which is exactly what the publication scan
# reported when they were hardcoded.
#
# Generating them means nothing secret-shaped is committed and nothing is
# waived. They authorise nothing: no control plane is reachable from this
# network and they exist only to get past a length check.
for var in RELAY_RPC_TOKEN WORKER_RPC_TOKEN COMPAT_RPC_TOKEN; do
  printf '%s=%s\n' "$var" "$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')" >> "$ENVFILE"
done

run_probe() { # run_probe <variant> <script>
  docker run --rm --platform linux/amd64 --network "$NET" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true --init \
    --tmpfs /tmp:size=64m,noexec,nosuid,nodev --memory 1536m \
    --entrypoint /usr/local/bin/node "cp-compat-$1-image-$TAG" -e "$2" 2>&1 | tail -1
}

probe() { # probe <variant>
  local v="$1"
  if [ "${RESULT[$v|build]}" != "ok" ]; then
    for k in deps-load native-sharp native-onnx tls-roots aws-helper dns uid workdir boot-healthz sigterm write-app write-tmp; do
      RESULT["$v|$k"]="build-failed"
    done
    return
  fi
  # EVERY production dependency: RESOLVED, then loaded, and a load error is only
  # counted when it is the kind a base image can cause.
  #
  # `@noble/curves` throws "root module cannot be imported: import submodules
  # instead" by design, and the first version of this probe reported that as a
  # failure on both images -- a module doing exactly what it intends, recorded
  # as a base-image defect. Resolution proves the package is installed;
  # classifying the load error by whether it names a native artifact, a
  # missing module or a linker failure is what separates "this base cannot run
  # it" from "this package objects to being imported that way".
  #
  # Driven by the image's own package.json
  # rather than a list in this file, because the two contexts this harness runs
  # in do not ship the same set: the monorepo has argon2 and pg, the exported
  # content plane does not, and a hardcoded list quietly reports a missing
  # module as a base-image failure. The first run of this harness did exactly
  # that with argon2.
  RESULT["$v|deps-load"]="$(run_probe "$v" 'const d=Object.keys(require("/app/package.json").dependencies||{});const bad=[];for(const m of d){try{require.resolve(m)}catch(e){bad.push(m+" UNRESOLVED");continue}try{require(m)}catch(e){const msg=String(e&&e.message||e);if(/MODULE_NOT_FOUND|\.node\b|libstdc|libgcc|GLIBC|dlopen|cannot open shared object|ELF/i.test(msg))bad.push(m+": "+msg.split("\n")[0])}}console.log(bad.length?("ERR "+bad[0]):("ok "+d.length))')"
  # The two with prebuilt glibc binaries. Loading is the whole point: a base
  # with the wrong libstdc++ fails here and nowhere earlier.
  RESULT["$v|native-sharp"]="$(run_probe "$v" 'const s=require("sharp");s({create:{width:2,height:2,channels:3,background:"#000"}}).png().toBuffer().then(b=>console.log(b.length>0?"ok":"bad")).catch(e=>console.log("ERR "+e.message))')"
  RESULT["$v|native-onnx"]="$(run_probe "$v" 'try{require("onnxruntime-node");console.log("ok")}catch(e){console.log("ERR "+e.message)}')"
  # The OS trust store, which Node does not use and aws_signing_helper does.
  RESULT["$v|tls-roots"]="$(run_probe "$v" 'const fs=require("fs");const p="/etc/ssl/certs/ca-certificates.crt";console.log(fs.existsSync(p)?String((fs.readFileSync(p,"utf8").match(/BEGIN CERTIFICATE/g)||[]).length):"absent")')"
  RESULT["$v|dns"]="$(run_probe "$v" 'require("dns").promises.lookup("localhost").then(r=>console.log("ok "+r.address)).catch(e=>console.log("ERR "+e.code))')"
  RESULT["$v|uid"]="$(run_probe "$v" 'console.log(process.getuid()+":"+process.getgid())')"
  RESULT["$v|workdir"]="$(run_probe "$v" 'console.log(process.cwd())')"
  RESULT["$v|write-app"]="$(run_probe "$v" 'try{require("fs").writeFileSync("/app/x","x");console.log("WRITABLE")}catch(e){console.log("refused")}')"
  RESULT["$v|write-tmp"]="$(run_probe "$v" 'try{require("fs").writeFileSync("/tmp/x","x");console.log("ok")}catch(e){console.log("ERR "+e.code)}')"
  # The Go binary. It needs glibc and, for a real call, the OS trust store.
  RESULT["$v|aws-helper"]="$(docker run --rm --platform linux/amd64 --entrypoint /usr/local/bin/aws_signing_helper "cp-compat-$v-image-$TAG" version 2>&1 | head -1 | tr -d '\r' | cut -c1-40)"

  # The application itself, under the production policy, with the relay role's
  # own environment. `docker stop` afterwards measures signal handling on the
  # same process rather than on a synthetic one.
  docker run -d --name "cp-compat-$v-$TAG" --network "$NET" --env-file "$ENVFILE" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true --init \
    --tmpfs /tmp:size=64m,noexec,nosuid,nodev --memory 1536m \
    "cp-compat-$v-image-$TAG" >/dev/null 2>&1 || true
  local up=down
  for _ in $(seq 1 60); do
    if docker exec "cp-compat-$v-$TAG" /usr/local/bin/node -e 'fetch("http://127.0.0.1:3000/healthz").then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))' >/dev/null 2>&1; then up=ok; break; fi
    sleep 1
  done
  RESULT["$v|boot-healthz"]="$up"
  docker stop -t 20 "cp-compat-$v-$TAG" >/dev/null 2>&1 || true
  RESULT["$v|sigterm"]="$(docker inspect -f '{{.State.ExitCode}}' "cp-compat-$v-$TAG" 2>/dev/null || echo missing)"
  docker rm -f "cp-compat-$v-$TAG" >/dev/null 2>&1 || true
}

for v in stock candidate broken; do echo "probing ${v}..."; probe "$v"; done

MATRIX="build deps-load native-sharp native-onnx tls-roots dns uid workdir write-app write-tmp aws-helper boot-healthz sigterm"

# THE BASELINE HAS TO BE THE DEPLOYED ARRANGEMENT, and once it silently was not.
#
# A differential reports "identical" or "differs" with equal confidence whether
# or not its baseline resembles anything that runs. When the exporter moved the
# CA store into the base, the stock variant lost its trust store, and the
# harness dutifully reported a difference in the one check where the candidate
# was RIGHT. Nothing failed; the number was simply about a different question.
#
# So the baseline is now asserted before any verdict is printed. A stock variant
# without an OS trust store is not the content plane as deployed -- Bedrock
# could not obtain credentials in it -- and a run that produced one has measured
# nothing worth reading.
case "${RESULT[stock|tls-roots]:-absent}" in
  ''|absent|*[!0-9]*)
    echo
    echo "REFUSING TO REPORT: the stock variant has no OS trust store"
    echo "  tls-roots on stock: ${RESULT[stock|tls-roots]:-absent}"
    echo
    echo "  That arrangement has never been deployed and could not be: the"
    echo "  Bedrock worker's aws_signing_helper verifies AWS endpoints against"
    echo "  that store. The baseline is wrong, so every 'same' below would be"
    echo "  a comparison against something nobody ships."
    exit 1
    ;;
esac

echo
echo "DIFFERENTIAL MATRIX  (candidate must equal stock)"
printf '  %-16s %-26s %-26s %s\n' check stock candidate verdict
differs=0
for k in $MATRIX; do
  s="${RESULT[stock|$k]:-}"; c="${RESULT[candidate|$k]:-}"
  if [ "$s" = "$c" ]; then verdict=same; else verdict=DIFFERS; differs=$((differs+1)); fi
  printf '  %-16s %-26.26s %-26.26s %s\n' "$k" "$s" "$c" "$verdict"
done

echo
echo "CONTROL: an image on a DELIBERATELY BROKEN base must not look the same"
broken_diffs=0
for k in $MATRIX; do
  [ "${RESULT[stock|$k]:-}" = "${RESULT[broken|$k]:-}" ] || broken_diffs=$((broken_diffs+1))
done
echo "  the broken-base control differs in ${broken_diffs} check(s) (tls-roots: ${RESULT[broken|tls-roots]:-?})"

echo
echo "ABSOLUTE INVARIANTS"
abs_fail=0
absolute() { if [ "$2" = "$3" ]; then printf '  PASS  %s (%s)\n' "$1" "$3"; else printf '  FAIL  %s: expected %s, got %s\n' "$1" "$2" "$3"; abs_fail=$((abs_fail+1)); fi }
absolute "the image builds on the candidate base" "ok"   "${RESULT[candidate|build]}"
case "${RESULT[candidate|deps-load]}" in
  ok\ *) printf '  PASS  every production dependency loads (%s)\n' "${RESULT[candidate|deps-load]}" ;;
  *) printf '  FAIL  a production dependency does not load: %s\n' "${RESULT[candidate|deps-load]}"; abs_fail=$((abs_fail+1)) ;;
esac
absolute "sharp loads and encodes"                "ok"   "${RESULT[candidate|native-sharp]}"
absolute "onnxruntime-node loads"                 "ok"   "${RESULT[candidate|native-onnx]}"
absolute "runs as uid:gid 1000:1000"              "1000:1000" "${RESULT[candidate|uid]}"
absolute "workdir is /app"                        "/app" "${RESULT[candidate|workdir]}"
absolute "the rootfs is read-only"                "refused" "${RESULT[candidate|write-app]}"
absolute "/tmp is writable"                       "ok"   "${RESULT[candidate|write-tmp]}"
absolute "the application boots and answers /healthz" "ok" "${RESULT[candidate|boot-healthz]}"
# NOT an absolute invariant. The application exits 143 on SIGTERM -- 128+15,
# the shell's encoding of "died from the signal" -- on the stock base too, so
# requiring 0 would fail the candidate for a property of the application. It is
# reported below instead, because it is worth knowing and is not this lane's to
# fix.
case "${RESULT[candidate|tls-roots]}" in
  ''|*[!0-9]*) printf '  FAIL  the OS trust store is present: got %s\n' "${RESULT[candidate|tls-roots]}"; abs_fail=$((abs_fail+1)) ;;
  *) if [ "${RESULT[candidate|tls-roots]}" -ge 100 ]; then printf '  PASS  the OS trust store holds %s certificates\n' "${RESULT[candidate|tls-roots]}";
     else printf '  FAIL  the OS trust store holds only %s certificates\n' "${RESULT[candidate|tls-roots]}"; abs_fail=$((abs_fail+1)); fi ;;
esac

if [ "${RESULT[candidate|sigterm]}" = "143" ] || [ "${RESULT[stock|sigterm]}" = "143" ]; then
  echo
  echo "  OBSERVATION, pre-existing and NOT introduced by the candidate:"
  echo "  the content plane exits 143 on SIGTERM (stock=${RESULT[stock|sigterm]}, candidate=${RESULT[candidate|sigterm]}), which is"
  echo "  128+15: the process is terminated by the signal rather than handling it"
  echo "  and exiting 0. Docker treats that as a normal stop, and it does mean an"
  echo "  in-flight request is dropped on every deploy rather than drained. A"
  echo "  graceful-shutdown handler is an application change, not a base-image one."
fi

if [ -n "$JSON_OUT" ]; then
  {
    printf '{\n  "schema": "anonrouter-content-plane-compat-v1",\n'
    printf '  "candidateBase": "%s",\n  "stockBase": "%s",\n' "$CANDIDATE" "$STOCK_BASE"
    printf '  "differingChecks": %s,\n  "brokenBaseControlDiffs": %s,\n  "absoluteFailures": %s,\n' "$differs" "$broken_diffs" "$abs_fail"
    printf '  "matrix": {\n'
    first=1
    for k in $MATRIX; do
      [ $first -eq 1 ] || printf ',\n'; first=0
      printf '    "%s": {"stock": %s, "candidate": %s, "brokenBase": %s}' "$k" \
        "$(printf '%s' "${RESULT[stock|$k]:-}" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')" \
        "$(printf '%s' "${RESULT[candidate|$k]:-}" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')" \
        "$(printf '%s' "${RESULT[broken|$k]:-}" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')"
    done
    printf '\n  }\n}\n'
  } > "$JSON_OUT"
  echo "  evidence written to $JSON_OUT"
fi

echo
echo "================================================================"
status=0
[ "$differs" -eq 0 ]       || { echo "  ${differs} check(s) differ from the stock base."; status=1; }
[ "$broken_diffs" -gt 0 ]  || { echo "  The matrix could not tell a BROKEN base from the stock one."; status=1; }
[ "$abs_fail" -eq 0 ]      || { echo "  ${abs_fail} absolute invariant(s) failed."; status=1; }
if [ "$status" -eq 0 ]; then
  echo "  The real content-plane image builds and runs on the candidate base,"
  echo "  behaves identically to the base it runs today on every check, and the"
  echo "  matrix demonstrably detects a broken base."
else
  echo "  NOT production compatible. Do not record it as one."
fi
echo "================================================================"
exit $status
