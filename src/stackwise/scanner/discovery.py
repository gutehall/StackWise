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
            recording_by_name: dict[str, bool] = {}
            try:
                statuses = config.describe_configuration_recorder_status()
                for st in statuses.get("ConfigurationRecordersStatus", []):
                    recording_by_name[st.get("name", "")] = st.get("recording", False)
            except Exception:
                logger.debug(
                    "describe_configuration_recorder_status failed in %s", region, exc_info=True
                )

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
                        "recording": recording_by_name.get(rec_name, False),
                        "roleARN": rec.get("roleARN"),
                    },
                )
                count += 1
        except Exception:
            logger.debug("Config recorder scan failed in %s", region, exc_info=True)

        # ── Tagged resources (same as cost, but discovery rules use it too) ─
        # Cost scanner also runs get_resources, since discovery DSC-002 and cost
        # CST-001 both key off tagged_resource and a user may run either module
        # alone. ScanDB.insert_resource dedups by (scan_id, service,
        # resource_type, resource_id, region), so running both modules in the
        # same scan stores each tagged resource once, not twice.
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
