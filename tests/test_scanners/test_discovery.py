"""Tests for the discovery scanner (AWS Config recorder status) using moto mocking."""

from __future__ import annotations

import boto3
from moto import mock_aws

from stackwise.scanner.discovery import DiscoveryScanner
from stackwise.store.db import ScanDB


@mock_aws
def test_active_recorder_reported_as_recording(scan_db: ScanDB):
    """A started Config recorder should be reported with recording=True."""
    session = boto3.Session(region_name="us-east-1")
    config = session.client("config", region_name="us-east-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
        }
    )
    config.put_delivery_channel(
        DeliveryChannel={"name": "default", "s3BucketName": "my-config-bucket"}
    )
    config.start_configuration_recorder(ConfigurationRecorderName="default")

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["discovery"])
    scanner = DiscoveryScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="config")
    recorders = [r for r in resources if r.resource_type == "recorder"]
    assert len(recorders) == 1
    assert recorders[0].metadata["recording"] is True


@mock_aws
def test_stopped_recorder_reported_as_not_recording(scan_db: ScanDB):
    """A recorder that was never started should be reported with recording=False."""
    session = boto3.Session(region_name="us-east-1")
    config = session.client("config", region_name="us-east-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config-role",
        }
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["discovery"])
    scanner = DiscoveryScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="config")
    recorders = [r for r in resources if r.resource_type == "recorder"]
    assert len(recorders) == 1
    assert recorders[0].metadata["recording"] is False
