"""Tests for the security scanner's IAM check-failure visibility."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from stackwise.scanner.security import SecurityScanner
from stackwise.store.db import ScanDB


def _throttle_error(op_name: str) -> ClientError:
    return ClientError({"Error": {"Code": "Throttling", "Message": "rate exceeded"}}, op_name)


def test_iam_user_mfa_check_failure_is_flagged_not_swallowed(scan_db: ScanDB):
    """A throttled list_mfa_devices call should not silently look like 'no MFA'."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    iam = MagicMock()
    iam.list_mfa_devices.side_effect = _throttle_error("ListMFADevices")
    iam.list_user_policies.return_value = {"PolicyNames": []}

    with patch("stackwise.scanner.security.regional_client", return_value=iam), patch(
        "stackwise.scanner.security.paginate",
        side_effect=lambda client, method, key, **kw: (
            [{"UserName": "alice", "Arn": "arn:aws:iam::1:user/alice"}]
            if method == "list_users"
            else []
        ),
    ):
        SecurityScanner()._scan_iam(session, scan_db, scan.id, "us-east-1")

    users = [
        r
        for r in scan_db.get_resources(scan.id, service="iam")
        if r.resource_type == "user"
    ]
    assert len(users) == 1
    assert users[0].metadata["MFACheckFailed"] is True
    assert users[0].metadata["MFADevices"] == []


def test_guardduty_findings_are_scanned(scan_db: ScanDB):
    """GuardDuty findings should be stored as their own resource_type so
    SEC-010 ('GuardDuty has findings') can actually fire — moto doesn't
    implement list_findings/get_findings, so this uses a direct mock client."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    gd = MagicMock()
    gd.get_detector.return_value = {"Status": "ENABLED", "Service": {"AccountId": "1"}}
    gd.list_detectors.return_value = {"DetectorIds": ["det-1"]}
    gd.get_paginator.return_value.paginate.return_value = [
        {"FindingIds": ["finding-1"]}
    ]
    gd.get_findings.return_value = {
        "Findings": [
            {"Id": "finding-1", "Type": "Recon:EC2/PortProbeUnprotectedPort", "Severity": 5.0}
        ]
    }

    with patch("stackwise.scanner.security.regional_client", return_value=gd), patch(
        "stackwise.scanner.security.paginate",
        side_effect=lambda client, method, key, **kw: (
            ["det-1"] if method == "list_detectors" else ["finding-1"]
        ),
    ):
        SecurityScanner()._scan_guardduty(session, scan_db, scan.id, "us-east-1")

    findings_resources = [
        r
        for r in scan_db.get_resources(scan.id, service="guardduty")
        if r.resource_type == "finding"
    ]
    assert len(findings_resources) == 1
    assert findings_resources[0].metadata["Severity"] == 5.0
