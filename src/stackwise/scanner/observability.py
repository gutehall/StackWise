"""Observability scanners: CloudWatch Alarms, CloudWatch Logs."""

from __future__ import annotations

import logging

import boto3

from stackwise.scanner.base import BaseScanner
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate, regional_client

logger = logging.getLogger(__name__)


class ObservabilityScanner(BaseScanner):
    """Scan CloudWatch alarms and log groups."""

    name = "observability"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0

        # ── CloudWatch Alarms ────────────────────────────────
        try:
            cw = regional_client(session, "cloudwatch", region)
            alarms = paginate(cw, "describe_alarms", "MetricAlarms")
            for alarm in alarms:
                alarm_name = alarm["AlarmName"]
                db.insert_resource(
                    scan_id=scan_id,
                    service="cloudwatch",
                    resource_type="alarm",
                    resource_id=alarm_name,
                    region=region,
                    arn=alarm.get("AlarmArn"),
                    metadata={
                        "AlarmName": alarm_name,
                        "StateValue": alarm.get("StateValue"),
                        "AlarmActions": alarm.get("AlarmActions", []),
                        "OKActions": alarm.get("OKActions", []),
                        "EvaluationPeriods": alarm.get("EvaluationPeriods"),
                    },
                )
                count += 1
        except Exception:
            logger.debug("CloudWatch alarms scan failed in %s", region, exc_info=True)

        # ── CloudWatch Logs ──────────────────────────────────
        try:
            logs = regional_client(session, "logs", region)
            log_groups = paginate(logs, "describe_log_groups", "logGroups")
            for lg in log_groups:
                lg_name = lg["logGroupName"]
                db.insert_resource(
                    scan_id=scan_id,
                    service="logs",
                    resource_type="log_group",
                    resource_id=lg_name,
                    region=region,
                    arn=lg.get("arn"),
                    metadata={
                        "logGroupName": lg_name,
                        "retentionInDays": lg.get("retentionInDays"),
                        "kmsKeyId": lg.get("kmsKeyId"),
                    },
                )
                count += 1
        except Exception:
            logger.debug("Log groups scan failed in %s", region, exc_info=True)

        return count


OBSERVABILITY_SCANNERS: list[BaseScanner] = [ObservabilityScanner()]
