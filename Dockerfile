# syntax=docker/dockerfile:1
#
# The confidential content plane. Built from THIS repository and nothing else.
#
# Single-platform linux/amd64 Docker v2 manifest. Do NOT enable inline BuildKit
# provenance or SBOM attestations for this registry path: Phala's registry could
# not pull an OCI image index, serving the index by digest and returning 404 for
# the child manifest, and the CVM failed with `manifest unknown`. Signatures,
# SBOM and provenance are published as DETACHED artifacts keyed to the digest.

# THE BUILD STAGE IS A TOOL. IT NEVER SHIPS.
#
# It stays on the Docker Official Image deliberately: it needs a compiler
# toolchain and a package manager, it cannot touch a prompt because it does
# not run in the trust domain, and holding it constant is what makes a
# comparison of the RUNTIME base a comparison of the runtime base. Its
# provenance is a supply-chain input, recorded in the ledger as
# `controlledEquivalent.buildToolDependencies`, not a plaintext-capable
# component.
#
# It is pinned to the linux/amd64 IMAGE MANIFEST digest, not the multi-arch
# index digest and not the tag, so two builds of identical source cannot
# silently consume different bytes. Resolved by
# scripts/resolve-base-image-digest.ts, which walks index -> amd64 entry ->
# child manifest -> config blob and recomputes every hash locally.
FROM node:22-bookworm-slim@sha256:a17d50af28002a160548bd4225b3cfcb12c5efcb171f79e68758f2885fb1b066 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build \
  && node scripts/prepare-router-model.mjs --cache-dir=/opt/anonrouter-router-model --download-only

# Production dependencies are installed HERE, in a stage that never ships,
# and copied into the runtime below.
#
# It used to happen in the production stage. That worked only because the
# runtime base carried a package manager and a full userland, which is
# exactly what a plaintext-capable image should not carry: `npm ci` runs
# dependency lifecycle scripts, and running them in the image that later
# handles prompts puts arbitrary install-time code in the same artifact.
FROM build AS prod-deps
WORKDIR /prod
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# THE RUNTIME BASE IS ANONROUTER'S OWN, BUILT FROM SCRATCH.
#
# node:22-bookworm-slim is a RECORDED GAP: replaying the recipe
# docker-library publishes for it does not reproduce it, and no qualifying
# upstream signature existed when that was measured on 2026-09-02. Its
# replacement is assembled from a Node release tarball pinned by the sha256
# nodejs.org signs and Debian packages pinned by sha256 values that appear in
# the Packages index Debian's OpenPGP-signed Release covers. No inherited
# container base remains. Reproduced by two independent CI jobs at this
# digest and signed against a pinned OIDC identity:
#
#   cosign verify \
#     --certificate-identity 'https://github.com/anonrouter/confidential-content-plane/.github/workflows/anonrouter-base-build.yml@refs/heads/main' \
#     --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
#     ghcr.io/anonrouter/mirror/anonrouter-node-base@sha256:f2733ab9f12c25be029bb307b19dc02671dc6d797ece67bd906f238a308f0bf9
#
# Compatibility evidence, against the base this replaces, under the real
# runtime policy: .evidence/base-image-compat/content-plane-compat-local.json.
# 13 of 13 differential checks identical, every production dependency loads,
# sharp encodes, onnxruntime loads, the application answers /healthz.
FROM ghcr.io/anonrouter/mirror/anonrouter-node-base@sha256:f2733ab9f12c25be029bb307b19dc02671dc6d797ece67bd906f238a308f0bf9 AS production
ENV NODE_ENV=production \
    ROUTER_MODEL_CACHE_DIR=/opt/anonrouter-router-model \
    ROUTER_ARTIFACT_PATH=/app/src/routing/artifacts/embeddinggemma-q4-v1.json \
    ROUTER_ALLOW_REMOTE_MODELS=false
WORKDIR /app
COPY package*.json ./
COPY --from=prod-deps /prod/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/config/confidential-route-policy.json ./config/confidential-route-policy.json
COPY --from=build /app/src/routing/artifacts ./src/routing/artifacts
COPY --from=build /opt/anonrouter-router-model /opt/anonrouter-router-model

# The CA trust store now comes from the BASE, which is why there is no
# apt-get here any more. aws_signing_helper is a Go binary that verifies AWS
# endpoints against the OS store rather than Node's bundled roots, so the
# store has to exist; the slim image it replaced shipped none, which is why
# this stage used to install it.
#
# The base carries the same 150 roots the previous apt call produced. That
# was checked rather than assumed: an earlier version of the base pinned
# ca-certificates from `bookworm main` and shipped 142.

# THE WORKERS' STATE DIRECTORY, owned by the account they run as.
#
# Every bearer-key worker, and the pool worker, mounts the `credential-state`
# named volume at /var/lib/anonrouter-worker and writes its replay log and the
# Venice keyset overlay there as `node`. Up to v1.0.25 the path did not exist
# in this image, so Docker created the mount point, and with it a fresh
# volume, owned by root; every capability-gated credential write then failed
# closed with 503 capability_replay_log_unavailable (POOL_CVM_TEST_RESULTS.md
# in the private repository, finding 2). Docker initialises an EMPTY named volume
# from the image's directory at the mount path, ownership and mode included,
# so a fresh volume now starts out node's, 0700. A volume that already exists
# keeps what it has: the pooled compose runs a one-shot credential-state-init
# for that, and the per-provider compose has none.
#
# Done with node because the runtime base has no mkdir, chown or chmod. 1000
# is the base's own `node` account (its assemble.sh writes /etc/passwd), and
# the step re-reads /etc/passwd and the result, so a base whose account
# differs fails this build instead of shipping a directory nobody can write.
RUN ["/usr/local/bin/node","-e","const fs = require('fs'); const node = fs.readFileSync('/etc/passwd', 'utf8').split(String.fromCharCode(10)) .map((line) => line.split(':')).find((fields) => fields[0] === 'node'); if (!node || node[2] !== '1000' || node[3] !== '1000') throw new Error('node is not 1000:1000 in the runtime base'); fs.mkdirSync('/var/lib', { recursive: true, mode: 0o755 }); fs.mkdirSync('/var/lib/anonrouter-worker', { mode: 0o700 }); fs.chownSync('/var/lib/anonrouter-worker', 1000, 1000); fs.chmodSync('/var/lib/anonrouter-worker', 0o700); const made = fs.statSync('/var/lib/anonrouter-worker'); if (made.uid !== 1000 || made.gid !== 1000 || (made.mode & 0o7777) !== 0o700) throw new Error('state directory is not node-owned 0700');"]

# IAM Roles Anywhere credential helper. Only the Bedrock worker invokes it;
# other roles have neither the workload certificate nor an AWS config. The
# binary is versioned and integrity-pinned exactly as in the private build.
ARG AWS_SIGNING_HELPER_VERSION=1.8.4
ADD --chmod=0755 \
    --checksum=sha256:b7568acd6e1517a4e1adaee68d52bfd6284a0e5305677166cd83d43a07c815c9 \
    https://rolesanywhere.amazonaws.com/releases/${AWS_SIGNING_HELPER_VERSION}/X86_64/Linux/Amzn2023/aws_signing_helper \
    /usr/local/bin/aws_signing_helper
EXPOSE 3000
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

# The content plane serves ONLY content roles. RUNTIME_ROLE selects which.
CMD ["node", "dist/src/contentPlane.js"]
