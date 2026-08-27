# syntax=docker/dockerfile:1
#
# The confidential content plane. Built from THIS repository and nothing else.
#
# Single-platform linux/amd64 Docker v2 manifest. Do NOT enable inline BuildKit
# provenance or SBOM attestations for this registry path: Phala's registry could
# not pull an OCI image index, serving the index by digest and returning 404 for
# the child manifest, and the CVM failed with `manifest unknown`. Signatures,
# SBOM and provenance are published as DETACHED artifacts keyed to the digest.

# The base image is pinned to the linux/amd64 IMAGE MANIFEST digest, not to the
# multi-arch index digest and not to the mutable tag.
#
# WO-07 section 2.2 treats the base image as a plaintext-capable third-party
# component: it runs every line of code that handles a prompt. A tag is not a
# pin, and an index digest still resolves to a different image per builder
# architecture, so two builds of identical source could produce different
# images with nothing recording which one ran.
#
# Pinning the amd64 child means every build produces the base that actually
# ships, on any builder. The cost is that building on an arm64 host runs the
# amd64 base under emulation; that is deliberate, because the confidential
# deployment is linux/amd64 and a locally-faster image nobody deploys is not
# the thing we want reproduced.
#
# Resolved and verified by scripts/resolve-base-image-digest.ts, which walks
# index bytes -> amd64 entry -> child bytes -> config blob and recomputes every
# hash rather than trusting a registry header. Recorded in
# deploy/provenance/plaintext-capable-components.json.
FROM node:22-bookworm-slim@sha256:a17d50af28002a160548bd4225b3cfcb12c5efcb171f79e68758f2885fb1b066 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-bookworm-slim@sha256:a17d50af28002a160548bd4225b3cfcb12c5efcb171f79e68758f2885fb1b066 AS production
ENV NODE_ENV=production \
    ROUTER_MODEL_CACHE_DIR=/opt/anonrouter-router-model \
    ROUTER_ARTIFACT_PATH=/app/src/routing/artifacts/embeddinggemma-q4-v1.json \
    ROUTER_ALLOW_REMOTE_MODELS=false
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY --from=build /app/src/routing/artifacts ./src/routing/artifacts

# The slim base omits the OS CA trust store. Node carries its own roots, but
# aws_signing_helper is a Go binary and needs the OS store for Roles Anywhere
# and STS. Without it the Bedrock worker cannot obtain short-lived credentials.
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# IAM Roles Anywhere credential helper. Only the Bedrock worker invokes it;
# other roles have neither the workload certificate nor an AWS config. The
# binary is versioned and integrity-pinned exactly as in the private build.
ARG AWS_SIGNING_HELPER_VERSION=1.8.3
ADD --chmod=0755 \
    --checksum=sha256:2517d3b7853c39c0004d27cbb03c51a5ec0e87b12f4046c86929f5c8fca4c9c1 \
    https://rolesanywhere.amazonaws.com/releases/${AWS_SIGNING_HELPER_VERSION}/X86_64/Linux/Amzn2023/aws_signing_helper \
    /usr/local/bin/aws_signing_helper
EXPOSE 3000
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

# The content plane serves ONLY content roles. RUNTIME_ROLE selects which.
CMD ["node", "dist/src/contentPlane.js"]
