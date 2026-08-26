"""Tests for the observability scanner (CloudWatch alarms and log groups)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

from stackwise.scanner.observability import ObservabilityScanner
from stackwise.store.db import ScanDB


@mock_aws
def test_cloudwatch_alarm_is_scanned(scan_db: ScanDB):
    """A CloudWatch alarm should be stored with its state and actions."""
    session = boto3.Session(region_name="us-east-1")
    cw = session.client("cloudwatch", region_name="us-east-1")
    cw.put_metric_alarm(
        AlarmName="high-cpu",
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=3,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        AlarmActions=["arn:aws:sns:us-east-1:123456789012:alerts"],
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["observability"])
    scanner = ObservabilityScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    alarms = [
        r
        for r in scan_db.get_resources(scan.id, service="cloudwatch")
        if r.resource_type == "alarm"
    ]
    assert len(alarms) == 1
    assert alarms[0].resource_id == "high-cpu"
    assert alarms[0].metadata["EvaluationPeriods"] == 3
    assert alarms[0].metadata["AlarmActions"] == ["arn:aws:sns:us-east-1:123456789012:alerts"]


@mock_aws
def test_log_group_is_scanned(scan_db: ScanDB):
    """A log group should be stored with its retention and KMS key settings."""
    session = boto3.Session(region_name="us-east-1")
    logs = session.client("logs", region_name="us-east-1")
    logs.create_log_group(logGroupName="/app/service")
    logs.put_retention_policy(logGroupName="/app/service", retentionInDays=30)

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["observability"])
    scanner = ObservabilityScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    log_groups = [
        r for r in scan_db.get_resources(scan.id, service="logs") if r.resource_type == "log_group"
    ]
    assert len(log_groups) == 1
    assert log_groups[0].resource_id == "/app/service"
    assert log_groups[0].metadata["retentionInDays"] == 30
    assert log_groups[0].metadata["kmsKeyId"] is None


@mock_aws
def test_log_group_without_retention_reports_none(scan_db: ScanDB):
    """A log group with no retention policy set (never expires) should report
    retentionInDays=None — OBS-004 keys off this to flag it."""
    session = boto3.Session(region_name="us-east-1")
    logs = session.client("logs", region_name="us-east-1")
    logs.create_log_group(logGroupName="/app/no-retention")

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["observability"])
    scanner = ObservabilityScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    log_groups = [
        r for r in scan_db.get_resources(scan.id, service="logs") if r.resource_type == "log_group"
    ]
    assert len(log_groups) == 1
    assert log_groups[0].metadata["retentionInDays"] is None


def test_top_level_api_failures_degrade_gracefully(scan_db: ScanDB):
    """Both sections (alarms, log groups) are independently wrapped — an API
    failure in one must not take down the other or raise out of _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["observability"])

    with (
        patch("stackwise.scanner.observability.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.observability.paginate", side_effect=RuntimeError("boom")),
    ):
        count = ObservabilityScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0
    assert scan_db.get_resources(scan.id) == []
