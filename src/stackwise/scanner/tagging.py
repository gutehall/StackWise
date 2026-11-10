"""Tagged resources from the Resource Groups Tagging API, shared by cost and discovery."""

from __future__ import annotations

import logging

from stackwise.store.db import ScanDB

logger = logging.getLogger(__name__)


def store_tagged_resources(db: ScanDB, scan_id: str, region: str, mappings: list[dict]) -> int:
    """Store each tag mapping under its full ARN and return how many rows were new.

    The ARN is the only identity that can't collide: two ECS services named "api", or
    an SNS topic and an SQS queue with the same name, share the ARN's last segment.
    Cost and discovery both call GetResources, so a mapping the other module already
    stored isn't counted again.
    """
    count = 0
    for res in mappings:
        arn = res.get("ResourceARN") or ""
        if not arn:
            # Nothing identifies it, and every blank one would collapse into one row.
            logger.debug("Skipping a tag mapping with no ARN in %s", region)
            continue
        if db.insert_resource_if_new(
            scan_id=scan_id,
            service="resourcegroupstaggingapi",
            resource_type="tagged_resource",
            resource_id=arn,
            region=region,
            arn=arn,
            metadata={"ResourceARN": arn, "Tags": res.get("Tags", [])},
        ):
            count += 1
    return count
