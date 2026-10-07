FROM dstacktee/dstack-ingress:2.3@sha256:527c53523b9226782a11dbd800a3ff55e8a1f0b88e6224e8f7e4db7419769fbe

COPY route53_challenge_cname.py /scripts/anonrouter-route53-challenge-cname.py

# Run the one AnonRouter-owned static delegation write only after upstream has
# installed boto3, created the source profile and assumed the scoped Route53
# role. The pinned upstream script must contain this exact insertion point;
# fail the image build if its startup sequence changes.
RUN chmod 0555 /scripts/anonrouter-route53-challenge-cname.py && \
    python3 - <<'PY'
from pathlib import Path

path = Path("/scripts/dns01.sh")
text = path.read_text()
needle = "setup_py_env\nsetup_certbot_env\nload_dstack_identity"
replacement = (
    "setup_py_env\n"
    "setup_certbot_env\n"
    "/scripts/anonrouter-route53-challenge-cname.py\n"
    "load_dstack_identity"
)
if text.count(needle) != 1:
    raise SystemExit("pinned dns01.sh insertion point changed")
text = text.replace(needle, replacement)

# Upstream's first pass also waits for the final application CNAME and
# app-address TXT. Those records cannot move before cutover and are not needed
# for DNS-01 issuance; upstream's own comment says only challenge-cname blocks
# issuance. Keep verification enabled, but narrow the first pass to that exact
# record instead of bypassing DNS checks with DNS_SETUP_MODE=print.
first_pass = (
    "        local want=challenge-cname\n"
    "        if [ \"$FIRST_PASS\" = \"true\" ]; then\n"
    "            want=delegated\n"
    "        fi"
)
if text.count(first_pass) != 1:
    raise SystemExit("pinned dns01.sh first-pass gate changed")
text = text.replace(first_pass, "        local want=challenge-cname")

# Traffic selection belongs to the release operator. Starting or renewing a
# spare must never rewrite the app-address TXT and take customer connections.
# Keep ACME challenge delegation independent of that record. A future release
# must pin the serving instance before starting a second CVM; this image alone
# does not provide a cutover command or prove Phala's cache behavior.
delegation_routing = (
    '    dnsman.py set_alias --domain "$target" --content "$GATEWAY_DOMAIN" || return 1\n'
    '\n'
    '    txt_name="$(txt_record_name "$domain").${DELEGATION_ZONE}"\n'
    '    dnsman.py set_txt --domain "$txt_name" --content "$(txt_record_value)" || return 1'
)
if text.count(delegation_routing) != 1:
    raise SystemExit("pinned dns01.sh delegated routing writer changed")
text = text.replace(delegation_routing,
    '    echo "Serving routing records are release-owned; leaving them unchanged"\n'
    '    return 0')
direct_routing = '        set_alias_record "$domain"\n        set_txt_record "$domain"'
if text.count(direct_routing) != 1:
    raise SystemExit("pinned dns01.sh direct routing writer changed")
text = text.replace(direct_routing,
    '        echo "Serving routing records are release-owned; leaving them unchanged"')

# Route53 cannot place CAA beside the delegated target's CNAME. Upstream's
# non-delegated path honors SET_CAA=false, but its delegated path deliberately
# ignores the flag and therefore fails after successful issuance. Preserve the
# account-pinned CAA path when requested; allow the measured production compose
# to use the zone ancestor's existing Let's Encrypt authorization instead.
caa_gate = (
    '    if [ -n "${DELEGATION_ZONE:-}" ]; then\n'
    '        if ! delegation_publish_caa "$domain"; then'
)
caa_replacement = (
    '    if [ -n "${DELEGATION_ZONE:-}" ]; then\n'
    '        if [ "$SET_CAA" != "true" ]; then\n'
    '            echo "Skipping delegated CAA record setup"\n'
    '            return\n'
    '        fi\n'
    '        if ! delegation_publish_caa "$domain"; then'
)
if text.count(caa_gate) != 1:
    raise SystemExit("pinned dns01.sh delegated CAA gate changed")
text = text.replace(caa_gate, caa_replacement)
path.write_text(text)

# Certbot chooses a suffixed lineage (for example, api.anonrouter.ai-0001)
# when a previous attempt left renewal state behind. Upstream later loads only
# /etc/letsencrypt/live/<exact-domain>/, so a successfully issued certificate
# in that suffixed lineage is invisible to HAProxy. Pin the certificate name
# explicitly in delegation mode; fail the image build if the reviewed command
# construction changes.
certman_path = Path("/scripts/certman.py")
certman = certman_path.read_text()
certonly_domain = '                base_cmd.extend(["-d", domain])'
certonly_named = '                base_cmd.extend(["--cert-name", domain, "-d", domain])'
if certman.count(certonly_domain) != 1:
    raise SystemExit("pinned certman.py delegated certonly command changed")
certman = certman.replace(certonly_domain, certonly_named)
# The capability installer pins the in-TD TLS public key. Routine ACME renewal
# must preserve that key rather than silently invalidating credential installs.
# Explicit key replacement remains a separately reviewed content release.
for original in (
    'base_cmd = certbot_cmd + [action, "--non-interactive", "-v"]',
    'base_cmd = certbot_cmd + [action, "-a",\n                                  plugin, "--non-interactive", "-v"]',
):
    if certman.count(original) != 1:
        raise SystemExit("pinned certman.py renewal command changed")
    certman = certman.replace(original, original[:-1] + ', "--reuse-key"]')
certman_path.write_text(certman)
PY
