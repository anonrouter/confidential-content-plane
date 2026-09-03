#!/usr/bin/env bash
# Pre-deploy gate for the measured CVM compose.
#
# The compose hash is only as meaningful as what the compose text actually
# names. Everything checked here is a way for the measurement to look sound
# while committing to nothing, and every one of these was a REAL defect in this
# file at some point rather than a hypothetical:
#
#   - a `${VAR}` image reference, which measures the literal string and lets the
#     real digest arrive at boot from unmeasured environment
#   - an all-zero placeholder digest that no registry can serve
#   - a `file:` config reference, which dstack neither uploads nor measures, so
#     the service starts with a config nobody attested (or not at all)
#   - a mutable tag, which lets an operator swap code without changing the hash
#
# Structural, not whole-file grep: an earlier version passed a compose with an
# extra dstack.sock holder and a literal credential because it only asked
# whether each pattern appeared ANYWHERE.
#
# Usage: deploy/phala/verify-compose-pinning.sh [compose-file ...]

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

files=("$@")
if [ ${#files[@]} -eq 0 ]; then
  files=(docker-compose.dev.yml)
  [ -f docker-compose.attest-only.yml ] && files+=(docker-compose.attest-only.yml)
  [ -f docker-compose.poc.yml ] && files+=(docker-compose.poc.yml)
  [ -f docker-compose.yml ] && files+=(docker-compose.yml)
  # Every rendered artifact present, so a stale or mis-rendered one is caught
  # rather than sitting on disk waiting to be deployed.
  for rendered in *.rendered.yml; do
    [ -f "$rendered" ] && files+=("$rendered")
  done
  # And the generated production set, which was absent from this list. It is
  # the file that is actually deployed and the one a candidate is diffed
  # against; a hardening gate that skips it checks the least important composes
  # in the directory. The candidate is included for the same reason: a
  # regression introduced with a base swap would otherwise be measured into the
  # app id before anything looked at it.
  for generated in docker-compose.prod5-xl.yml docker-compose.prod5-xl-preprod.yml \
                   docker-compose.prod5-xl.candidate.yml; do
    [ -f "$generated" ] && files+=("$generated")
  done
fi

fail=0
note() { printf '%s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; fail=1; }
ok()   { printf 'PASS  %s\n' "$*"; }

# Emit "service<TAB>key<TAB>value" for every top-level services entry, so each
# check can be scoped to the service it is really about.
service_fields() {
  awk '
    /^services:/ { in_services = 1; next }
    /^[a-z]/     { in_services = 0 }
    in_services && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
      svc = $1; sub(":", "", svc); next
    }
    in_services && svc != "" { print svc "\t" $0 }
  ' "$1"
}

for file in "${files[@]}"; do
  note "== $file =="
  [ -f "$file" ] || { bad "$file does not exist"; continue; }

  rendered=0
  case "$file" in *rendered*) rendered=1 ;; esac

  # --- Image references ------------------------------------------------------
  unpinned=0
  variable=0
  zero=0
  while IFS=$'\t' read -r svc line; do
    case "$line" in *"image:"*) ;; *) continue ;; esac
    reference=$(printf '%s' "$line" | sed -E 's/.*image:[[:space:]]*//' | tr -d '"'"'" | tr -d '\r')
    case "$reference" in
      *'${'*)
        # Tolerated ONLY in the template, where it is a documented tripwire.
        if [ "$rendered" -eq 1 ]; then
          bad "[$file] $svc: rendered compose still has a variable image: $reference"
        else
          note "      $svc: template placeholder ($reference); render before deploy"
        fi
        variable=$((variable + 1))
        ;;
      *@sha256:0000000000000000000000000000000000000000000000000000000000000000)
        bad "[$file] $svc: all-zero placeholder digest resolves to no manifest"
        zero=$((zero + 1))
        ;;
      *@sha256:*)
        digest=${reference##*@sha256:}
        if ! printf '%s' "$digest" | grep -qE '^[0-9a-f]{64}$'; then
          bad "[$file] $svc: malformed digest: $reference"
          unpinned=$((unpinned + 1))
        fi
        ;;
      *)
        bad "[$file] $svc: image is not digest-pinned: $reference"
        unpinned=$((unpinned + 1))
        ;;
    esac
  done < <(service_fields "$file")
  [ "$unpinned" -eq 0 ] && [ "$zero" -eq 0 ] && ok "[$file] every literal image reference is a well-formed digest"
  [ "$rendered" -eq 1 ] && [ "$variable" -eq 0 ] && ok "[$file] rendered compose contains no variable image reference"

  # --- Configs must be inline, never file: -----------------------------------
  # dstack uploads only the compose text. A `file:` reference is neither
  # transferred nor measured, so the service starts with an unattested config or
  # does not start at all.
  if ! grep -q '^configs:' "$file"; then
    ok "[$file] declares no configs"
  elif awk '/^configs:/{c=1;next} /^[a-z]/{c=0} c && /^[[:space:]]+file:[[:space:]]/{found=1} END{exit(found?0:1)}' "$file"; then
    bad "[$file] a top-level config uses file:; dstack ships only the compose text, so it would be neither transferred nor measured"
  else
    ok "[$file] every config is declared with inline content"
  fi

  # --- No build: -------------------------------------------------------------
  if grep -qE '^[[:space:]]*build:' "$file"; then
    bad "[$file] contains a build: stanza; dstack pulls images and never builds"
  else
    ok "[$file] contains no build: stanza"
  fi

  # --- The dstack socket, per service ---------------------------------------
  # The socket is an app-wide key oracle, so the holder set must be a SUBSET of
  # the two services that legitimately need it, and must include the attestation
  # service. Written as a subset rather than an exact match so a reduced compose
  # (for example the attestation-only variant) is checked just as strictly.
  socket_services=$(service_fields "$file" | grep -F '/var/run/dstack.sock' | cut -f1 | sort -u | tr '\n' ' ')
  socket_bad=0
  for svc in $socket_services; do
    case "$svc" in
      attest|ingress) ;;
      *) bad "[$file] $svc mounts dstack.sock; only ingress and attest may"; socket_bad=1 ;;
    esac
  done
  case " $socket_services " in
    *" attest "*) ;;
    *) bad "[$file] the attestation service does not mount dstack.sock"; socket_bad=1 ;;
  esac
  [ "$socket_bad" -eq 0 ] && ok "[$file] dstack.sock holders are [$socket_services]"

  # --- Hardening, per service ------------------------------------------------
  # The anchor merge means the flags do not appear textually under each service,
  # so check that every AnonRouter service either merges the anchor or declares
  # them itself.
  # Only the services this file actually declares. `ingress` is exempt: it is a
  # third-party image that writes certificate state and cannot run read-only.
  for svc in $(service_fields "$file" | cut -f1 | sort -u); do
    [ "$svc" = "ingress" ] && continue
    if service_fields "$file" | awk -F'\t' -v s="$svc" '$1==s' | grep -qE '(<<: \*hardened|read_only: true)'; then
      ok "[$file] $svc is hardened"
    else
      bad "[$file] $svc does not merge the hardening anchor"
    fi
  done

  # --- No literal secret material -------------------------------------------
  if service_fields "$file" \
     | grep -EI '(api[_-]?key|secret|token|password)[[:space:]]*:[[:space:]]*["'"'"']?[A-Za-z0-9/_+.-]{16,}' \
     | grep -v '\${' | grep -q .; then
    bad "[$file] appears to contain a literal credential; every secret must be a \${VAR} reference"
  else
    ok "[$file] contains no literal credential"
  fi

  # --- amd64 on every service ------------------------------------------------
  missing_platform=""
  for svc in $(service_fields "$file" | cut -f1 | sort -u); do
    if ! service_fields "$file" | awk -F'\t' -v s="$svc" '$1==s' | grep -q 'platform: linux/amd64'; then
      missing_platform="$missing_platform $svc"
    fi
  done
  if [ -n "$missing_platform" ]; then
    bad "[$file] missing platform: linux/amd64 on:$missing_platform (Phala Cloud is x86_64 only)"
  else
    ok "[$file] every service pins linux/amd64"
  fi

  # --- Nothing holding content or a credential on a routable network --------
  # `internal: true` is the only thing keeping the content tier off the
  # Internet, so a service that quietly joins the routable network defeats the
  # SNI egress allowlist entirely.
  routable=$(awk '
    /^networks:/ { in_nets = 1; next }
    /^[a-z]/     { in_nets = 0 }
    in_nets && /^  [A-Za-z0-9_-]+:/ { name = $1; sub(":", "", name); internal[name] = 0 }
    in_nets && /internal: true/ { internal[name] = 1 }
    END { for (n in internal) if (!internal[n]) print n }
  ' "$file")
  for svc in $(service_fields "$file" | cut -f1 | sort -u); do
    case "$svc" in relay|attest|venice-worker) ;; *) continue ;; esac
    for net in $routable; do
      if service_fields "$file" | awk -F'\t' -v s="$svc" '$1==s' | grep -qE "^[^\t]*\t[[:space:]]*-?[[:space:]]*${net}(:|$)"; then
        bad "[$file] $svc is attached to routable network '$net'; the SNI egress allowlist is then bypassable"
      fi
    done
  done
  ok "[$file] no content or credential service is on a routable network"
done

# --- The deployed image variable, when set, must itself be a digest ---------
if [ -n "${ANONROUTER_IMAGE:-}" ]; then
  case "$ANONROUTER_IMAGE" in
    *@sha256:0000000000000000000000000000000000000000000000000000000000000000)
      bad "ANONROUTER_IMAGE is the all-zero placeholder" ;;
    *@sha256:*) ok "ANONROUTER_IMAGE is digest-pinned" ;;
    *) bad "ANONROUTER_IMAGE is not digest-pinned: $ANONROUTER_IMAGE" ;;
  esac
fi

echo "----"
if [ "$fail" -ne 0 ]; then
  echo "COMPOSE PINNING CHECKS FAILED"
  exit 1
fi
echo "ALL COMPOSE PINNING CHECKS PASSED"
