"""Discovery scanners: AWS Config, Resource Groups Tagging."""

from __future__ import annotations

import logging

import boto3

from stackwise.scanner.base import BaseScanner
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate, regional_client

logger = logging.getLogger(__name__)


class DiscoveryScanner(BaseScanner):
    """Scan AWS Config recorders and tagged resources (discovery/cost overlap)."""

    name = "discovery"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0

        # ── AWS Config recorders ───────────────────────────────
        try:
            config = regional_client(session, "config", region)
            recorders = config.describe_configuration_recorders()
            for rec in recorders.get("ConfigurationRecorders", []):
                rec_name = rec.get("name", "default")
                db.insert_resource(
                    scan_id=scan_id,
                    service="config",
                    resource_type="recorder",
                    resource_id=rec_name,
                    region=region,
                    arn=(
                        f"arn:aws:config:{region}:"
                        f"{rec.get('roleARN', '').split(':')[4]}:config-recorder/{rec_name}"
                    ),
                    metadata={
                        "name": rec_name,
                        "recording": rec.get("recording", False),
                        "roleARN": rec.get("roleARN"),
                    },
                )
                count += 1
        except Exception:
            logger.debug("Config recorder scan failed in %s", region, exc_info=True)

        # ── Tagged resources (same as cost, but discovery rules use it too) ─
        # Cost scanner already runs get_resources; discovery DSC-002 uses same
        # resource type. We could skip here to avoid duplicates, but get_resources
        # returns all tagged resources - cost and discovery both need them.
        # The cost scanner runs in cost module, discovery in discovery module.
        # If user runs only discovery, they won't get tagged resources from cost.
        # So we need to run get_resources in discovery too when discovery is enabled.
        try:
            tag_client = regional_client(session, "resourcegroupstaggingapi", region)
            resources = paginate(
                tag_client,
                "get_resources",
                "ResourceTagMappingList",
            )
            for res in resources:
                arn = res.get("ResourceARN", "")
                res_id = arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]
                if not res_id:
                    res_id = arn
                db.insert_resource(
                    scan_id=scan_id,
                    service="resourcegroupstaggingapi",
                    resource_type="tagged_resource",
                    resource_id=res_id,
                    region=region,
                    arn=arn,
                    metadata={
                        "ResourceARN": arn,
                        "Tags": res.get("Tags", []),
                    },
                )
                count += 1
        except Exception:
            logger.debug("Tagged resources scan failed in %s", region, exc_info=True)

        return count


DISCOVERY_SCANNERS: list[BaseScanner] = [DiscoveryScanner()]
