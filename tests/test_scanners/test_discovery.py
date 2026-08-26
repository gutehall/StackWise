"""Tests for the discovery scanner (AWS Config recorder status) using moto mocking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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


def test_recorder_with_malformed_role_arn_does_not_abort_region(scan_db: ScanDB):
    """A recorder with an empty/malformed roleARN must not raise IndexError while
    building its ARN and take out every other resource in the region — real AWS
    always sets roleARN, but a malformed response shouldn't crash the scan."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["discovery"])

    config = MagicMock()
    config.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": [{"name": "default", "roleARN": ""}]
    }
    config.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [{"name": "default", "recording": False}]
    }

    with patch("stackwise.scanner.discovery.regional_client", return_value=config), patch(
        "stackwise.scanner.discovery.paginate", return_value=[]
    ):
        DiscoveryScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    recorders = [
        r
        for r in scan_db.get_resources(scan.id, service="config")
        if r.resource_type == "recorder"
    ]
    assert len(recorders) == 1
    assert recorders[0].arn == "arn:aws:config:us-east-1::config-recorder/default"


def test_recorder_status_lookup_failure_still_stores_recorder(scan_db: ScanDB):
    """A describe_configuration_recorder_status failure is narrower than the
    outer Config try/except — the recorder must still be stored, defaulting
    to recording=False rather than being dropped."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["discovery"])

    config = MagicMock()
    config.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": [
            {"name": "default", "roleARN": "arn:aws:iam::123456789012:role/config-role"}
        ]
    }
    config.describe_configuration_recorder_status.side_effect = RuntimeError("boom")

    with (
        patch("stackwise.scanner.discovery.regional_client", return_value=config),
        patch("stackwise.scanner.discovery.paginate", return_value=[]),
    ):
        DiscoveryScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    recorders = [
        r
        for r in scan_db.get_resources(scan.id, service="config")
        if r.resource_type == "recorder"
    ]
    assert len(recorders) == 1
    assert recorders[0].metadata["recording"] is False


def test_config_recorder_top_level_failure_does_not_raise(scan_db: ScanDB):
    """describe_configuration_recorders failing entirely must not raise out of
    _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["discovery"])

    config = MagicMock()
    config.describe_configuration_recorders.side_effect = RuntimeError("boom")

    with (
        patch("stackwise.scanner.discovery.regional_client", return_value=config),
        patch("stackwise.scanner.discovery.paginate", return_value=[]),
    ):
        count = DiscoveryScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0


def test_tagged_resource_with_malformed_arn_falls_back(scan_db: ScanDB):
    """A malformed/empty ResourceARN (no '/' or ':') must not crash resource_id
    derivation — it falls back to using the raw ARN string."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["discovery"])

    config = MagicMock()
    config.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}

    with (
        patch("stackwise.scanner.discovery.regional_client", return_value=config),
        patch(
            "stackwise.scanner.discovery.paginate",
            side_effect=lambda client, method, key, **kw: (
                [{"ResourceARN": "", "Tags": []}] if method == "get_resources" else []
            ),
        ),
    ):
        DiscoveryScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    tagged = [
        r
        for r in scan_db.get_resources(scan.id, service="resourcegroupstaggingapi")
        if r.resource_type == "tagged_resource"
    ]
    assert len(tagged) == 1
    assert tagged[0].resource_id == ""


def test_tagged_resources_top_level_failure_does_not_raise(scan_db: ScanDB):
    """get_resources failing entirely must not raise out of _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["discovery"])

    config = MagicMock()
    config.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}

    with (
        patch("stackwise.scanner.discovery.regional_client", return_value=config),
        patch("stackwise.scanner.discovery.paginate", side_effect=RuntimeError("boom")),
    ):
        count = DiscoveryScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0
