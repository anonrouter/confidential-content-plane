#!/usr/bin/env python3
"""Create the private alias's static ACME challenge delegation.

The public api.anonrouter.ai CNAME is owner-managed in Namecheap. This is the
one corresponding record inside the already delegated private.anonrouter.ai
Route53 zone. It runs after upstream has assumed the existing scoped DNS role.
No credential is read or printed here; boto3 uses the prepared certbot profile.
"""

import boto3

HOSTED_ZONE_ID = "Z038591930Q5D7SAKSKC"
RECORD_NAME = "_acme-challenge.api.private.anonrouter.ai."
RECORD_TARGET = (
    "_acme-challenge.api.private.anonrouter.ai."
    "public-api.private.anonrouter.ai."
)

client = boto3.client("route53")
response = client.change_resource_record_sets(
    HostedZoneId=HOSTED_ZONE_ID,
    ChangeBatch={
        "Comment": "AnonRouter measured ACME challenge delegation",
        "Changes": [
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": RECORD_NAME,
                    "Type": "CNAME",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": RECORD_TARGET}],
                },
            }
        ],
    },
)
status = response.get("ChangeInfo", {}).get("Status")
if status not in {"PENDING", "INSYNC"}:
    raise SystemExit(f"Route53 returned unexpected change status: {status!r}")
print("Private API ACME challenge delegation accepted by Route53")
