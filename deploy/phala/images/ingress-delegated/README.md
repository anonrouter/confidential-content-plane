# AnonRouter changes to the pinned dstack ingress

This context builds on upstream `dstacktee/dstack-ingress:2.3`, pinned in the
Dockerfile by digest. Upstream software is from Phala/Dstack-TEE, under
Apache-2.0; AnonRouter's changes are the exact source patches in the Dockerfile
and the separate Route53 challenge-delegation helper. Existing upstream
attribution/licensing stays in the base image. The upstream rebuild workflow
and provenance ledger describe the upstream component; they do not establish
the provenance of an image built with these additional patches.

The candidate patches retain certificate issuance and static ACME challenge
delegation, leave serving aliases and app-address TXT records to the release
operator, pin Certbot's certificate lineage name and use `--reuse-key` for
issuance/renewal. Each patch requires exactly the reviewed upstream insertion
point and refuses a changed script. The helper changes only the static ACME
challenge CNAME named in its source, using the existing assumed DNS profile;
it neither handles nor prints credentials.

Publishing this context lets readers inspect all AnonRouter modifications to
the TLS terminator. It does not build, publish or pin a deployment image.
Production provenance must cover the exact resulting image in addition to the
base, and real ACME renewal/key reuse and Phala gateway routing/drain still need
independent acceptance. Starting a production spare while an old ingress can
still rewrite serving records remains unsafe. Never invoke the helper as part
of a local source review or ordinary export.
