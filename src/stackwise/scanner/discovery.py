"""Discovery scanners: AWS Config, Resource Groups Tagging."""

from __future__ import annotations

import logging

import boto3

from stackwise.scanner.base import BaseScanner
from stackwise.scanner.tagging import store_tagged_resources
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate, regional_client

logger = logging.getLogger(__name__)

# Resource id of the row stored for a region with no recorder, so DSC-001 can report it.
_NO_RECORDER_ID = "no-recorder"


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
            status_check_failed = False
            try:
                statuses = config.describe_configuration_recorder_status()
                for st in statuses.get("ConfigurationRecordersStatus", []):
                    recording_by_name[st.get("name", "")] = st.get("recording", False)
            except Exception:
                logger.debug(
                    "describe_configuration_recorder_status failed in %s", region, exc_info=True
                )
                status_check_failed = True

            recorder_list = recorders.get("ConfigurationRecorders", [])
            if not recorder_list:
                # The list succeeded and is empty, so Config was never enabled here.
                db.insert_resource(
                    scan_id=scan_id,
                    service="config",
                    resource_type="recorder",
                    resource_id=_NO_RECORDER_ID,
                    region=region,
                    metadata={
                        "recording": False,
                        "RecorderAbsent": True,
                        "RecordingCheckFailed": False,
                    },
                )
                count += 1

            for rec in recorder_list:
                rec_name = rec.get("name", "default")
                # roleARN is normally "arn:aws:iam::<account>:role/...", account is
                # segment [4]. Guard against a malformed/missing roleARN so one bad
                # recorder doesn't raise IndexError and abort the whole region's scan.
                role_arn_parts = rec.get("roleARN", "").split(":")
                account_id = role_arn_parts[4] if len(role_arn_parts) > 4 else ""
                metadata = {
                    "name": rec_name,
                    "roleARN": rec.get("roleARN"),
                    "RecorderAbsent": False,
                    "RecordingCheckFailed": status_check_failed,
                }
                if not status_check_failed:
                    metadata["recording"] = recording_by_name.get(rec_name, False)
                db.insert_resource(
                    scan_id=scan_id,
                    service="config",
                    resource_type="recorder",
                    resource_id=rec_name,
                    region=region,
                    arn=f"arn:aws:config:{region}:{account_id}:config-recorder/{rec_name}",
                    metadata=metadata,
                )
                count += 1
        except Exception as e:
            logger.debug("Config recorder scan failed in %s", region, exc_info=True)
            self._record_list_failure(db, scan_id, region, "describe_configuration_recorders", e)

        # ── Tagged resources (same as cost, but discovery rules use it too) ─
        # Cost scanner also runs get_resources, since discovery DSC-002 and cost
        # CST-001 both key off tagged_resource and a user may run either module
        # alone. Both store by full ARN, and only a new row is counted, so running
        # both modules in one scan stores and counts each tagged resource once.
        try:
            tag_client = regional_client(session, "resourcegroupstaggingapi", region)
            resources = paginate(
                tag_client,
                "get_resources",
                "ResourceTagMappingList",
            )
            count += store_tagged_resources(db, scan_id, region, resources)
        except Exception as e:
            logger.debug("Tagged resources scan failed in %s", region, exc_info=True)
            self._record_list_failure(db, scan_id, region, "get_resources", e)

        return count


DISCOVERY_SCANNERS: list[BaseScanner] = [DiscoveryScanner()]
