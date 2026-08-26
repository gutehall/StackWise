"""Tests for the security scanner's IAM check-failure visibility."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from stackwise.scanner.security import SecurityScanner
from stackwise.store.db import ScanDB

_ASSUME_ROLE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
)


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


def test_kms_key_metadata_preserved_when_rotation_check_fails(scan_db: ScanDB):
    """describe_key data (Arn, KeyManager, KeyState) must survive even when the
    separate get_key_rotation_status call fails — rotation status is unsupported
    for asymmetric/HMAC keys, imported key material, and custom key stores, and
    that failure must not blank out data the first call already fetched."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    kms = MagicMock()
    kms.describe_key.return_value = {
        "KeyMetadata": {
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/abc",
            "KeyManager": "CUSTOMER",
            "KeyState": "Enabled",
        }
    }
    kms.get_key_rotation_status.side_effect = ClientError(
        {"Error": {"Code": "UnsupportedOperationException", "Message": "not supported"}},
        "GetKeyRotationStatus",
    )

    with patch("stackwise.scanner.security.regional_client", return_value=kms), patch(
        "stackwise.scanner.security.paginate",
        side_effect=lambda client, method, key, **kw: (
            [{"KeyId": "abc"}] if method == "list_keys" else []
        ),
    ):
        SecurityScanner()._scan_kms_regional(session, scan_db, scan.id, "us-east-1")

    keys = [r for r in scan_db.get_resources(scan.id, service="kms") if r.resource_type == "key"]
    assert len(keys) == 1
    assert keys[0].metadata["KeyManager"] == "CUSTOMER"
    assert keys[0].metadata["Arn"] == "arn:aws:kms:us-east-1:123456789012:key/abc"
    assert keys[0].metadata["KeyRotationCheckFailed"] is True


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


@mock_aws
def test_iam_role_and_user_happy_path(scan_db: ScanDB):
    """A role with an inline policy + permissions boundary, and a user with an
    MFA device + inline policy, should be scanned without any CheckFailed flags."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName="my-role",
        AssumeRolePolicyDocument=_ASSUME_ROLE_POLICY,
        PermissionsBoundary="arn:aws:iam::123456789012:policy/boundary",
    )
    iam.put_role_policy(
        RoleName="my-role", PolicyName="inline1", PolicyDocument=_ASSUME_ROLE_POLICY
    )

    iam.create_user(UserName="alice")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="alice-mfa")[
        "VirtualMFADevice"
    ]
    iam.enable_mfa_device(
        UserName="alice",
        SerialNumber=device["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="123456",
    )
    iam.put_user_policy(
        UserName="alice", PolicyName="inline1", PolicyDocument=_ASSUME_ROLE_POLICY
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])
    SecurityScanner()._scan_iam(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="iam")
    roles = [r for r in resources if r.resource_type == "role"]
    assert len(roles) == 1
    assert roles[0].metadata["InlinePoliciesCount"] == 1
    assert roles[0].metadata["InlinePoliciesCheckFailed"] is False
    assert roles[0].metadata["PermissionsBoundary"] == "arn:aws:iam::123456789012:policy/boundary"

    users = [r for r in resources if r.resource_type == "user"]
    assert len(users) == 1
    assert users[0].metadata["InlinePoliciesCount"] == 1
    assert users[0].metadata["MFACheckFailed"] is False
    assert len(users[0].metadata["MFADevices"]) == 1


def test_iam_role_enrichment_failure_is_flagged_not_swallowed(scan_db: ScanDB):
    """A get_role/list_role_policies failure must fall back to the list_roles
    summary (for Arn) and flag InlinePoliciesCheckFailed, not silently look
    like a role with zero inline policies."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    iam = MagicMock()
    iam.get_role.side_effect = _throttle_error("GetRole")
    iam.list_users.return_value = {"Users": []}

    with (
        patch("stackwise.scanner.security.regional_client", return_value=iam),
        patch(
            "stackwise.scanner.security.paginate",
            side_effect=lambda client, method, key, **kw: (
                [{"RoleName": "my-role", "Arn": "arn:aws:iam::1:role/my-role"}]
                if method == "list_roles"
                else []
            ),
        ),
    ):
        SecurityScanner()._scan_iam(session, scan_db, scan.id, "us-east-1")

    roles = [
        r for r in scan_db.get_resources(scan.id, service="iam") if r.resource_type == "role"
    ]
    assert len(roles) == 1
    assert roles[0].metadata["InlinePoliciesCheckFailed"] is True
    assert roles[0].metadata["Arn"] == "arn:aws:iam::1:role/my-role"


def test_iam_user_inline_policy_failure_is_flagged_not_swallowed(scan_db: ScanDB):
    """A list_user_policies failure (independent of the MFA check) must flag
    InlinePoliciesCheckFailed rather than silently reporting zero policies."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    iam = MagicMock()
    iam.list_roles.return_value = {"Roles": []}
    iam.list_mfa_devices.return_value = {"MFADevices": []}
    iam.list_user_policies.side_effect = _throttle_error("ListUserPolicies")

    with (
        patch("stackwise.scanner.security.regional_client", return_value=iam),
        patch(
            "stackwise.scanner.security.paginate",
            side_effect=lambda client, method, key, **kw: (
                [{"UserName": "alice", "Arn": "arn:aws:iam::1:user/alice"}]
                if method == "list_users"
                else []
            ),
        ),
    ):
        SecurityScanner()._scan_iam(session, scan_db, scan.id, "us-east-1")

    users = [
        r for r in scan_db.get_resources(scan.id, service="iam") if r.resource_type == "user"
    ]
    assert len(users) == 1
    assert users[0].metadata["InlinePoliciesCheckFailed"] is True
    assert users[0].metadata["MFACheckFailed"] is False


def test_iam_top_level_failure_does_not_raise(scan_db: ScanDB):
    """list_roles failing entirely must not raise out of _scan_iam."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    with (
        patch("stackwise.scanner.security.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.security.paginate", side_effect=RuntimeError("boom")),
    ):
        count = SecurityScanner()._scan_iam(session, scan_db, scan.id, "us-east-1")

    assert count == 0


def test_kms_describe_key_failure_defaults_metadata(scan_db: ScanDB):
    """A describe_key failure must not crash the scan — the key is still stored
    with blank metadata rather than dropped."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    kms = MagicMock()
    kms.describe_key.side_effect = RuntimeError("boom")
    kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}

    with (
        patch("stackwise.scanner.security.regional_client", return_value=kms),
        patch(
            "stackwise.scanner.security.paginate",
            side_effect=lambda client, method, key, **kw: (
                [{"KeyId": "abc"}] if method == "list_keys" else []
            ),
        ),
    ):
        SecurityScanner()._scan_kms_regional(session, scan_db, scan.id, "us-east-1")

    keys = [r for r in scan_db.get_resources(scan.id, service="kms") if r.resource_type == "key"]
    assert len(keys) == 1
    assert keys[0].metadata["Arn"] is None
    assert keys[0].metadata["KeyManager"] is None
    assert keys[0].metadata["KeyRotationCheckFailed"] is False


def test_kms_top_level_failure_does_not_raise(scan_db: ScanDB):
    """list_keys failing entirely must not raise out of _scan_kms_regional."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    with (
        patch("stackwise.scanner.security.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.security.paginate", side_effect=RuntimeError("boom")),
    ):
        count = SecurityScanner()._scan_kms_regional(session, scan_db, scan.id, "us-east-1")

    assert count == 0


@mock_aws
def test_secrets_manager_happy_path(scan_db: ScanDB):
    """A secret with rotation enabled should be stored with its rotation
    metadata."""
    session = boto3.Session(region_name="us-east-1")
    sm = session.client("secretsmanager", region_name="us-east-1")
    sm.create_secret(Name="db-password", SecretString="hunter2")

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])
    SecurityScanner()._scan_secrets(session, scan_db, scan.id, "us-east-1")

    secrets = [
        r for r in scan_db.get_resources(scan.id, service="secretsmanager")
        if r.resource_type == "secret"
    ]
    assert len(secrets) == 1
    assert secrets[0].metadata["Name"] == "db-password"


def test_secrets_manager_top_level_failure_does_not_raise(scan_db: ScanDB):
    """list_secrets failing entirely must not raise out of _scan_secrets."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    with (
        patch("stackwise.scanner.security.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.security.paginate", side_effect=RuntimeError("boom")),
    ):
        count = SecurityScanner()._scan_secrets(session, scan_db, scan.id, "us-east-1")

    assert count == 0


def test_guardduty_get_detector_failure_skips_detector(scan_db: ScanDB):
    """A get_detector failure for one detector must skip just that detector,
    not raise out of _scan_guardduty."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    gd = MagicMock()
    gd.get_detector.side_effect = RuntimeError("boom")

    with (
        patch("stackwise.scanner.security.regional_client", return_value=gd),
        patch(
            "stackwise.scanner.security.paginate",
            side_effect=lambda client, method, key, **kw: (
                ["det-1"] if method == "list_detectors" else []
            ),
        ),
    ):
        count = SecurityScanner()._scan_guardduty(session, scan_db, scan.id, "us-east-1")

    assert count == 0
    assert scan_db.get_resources(scan.id, service="guardduty") == []


def test_guardduty_top_level_failure_does_not_raise(scan_db: ScanDB):
    """list_detectors failing entirely must not raise out of _scan_guardduty."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    with (
        patch("stackwise.scanner.security.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.security.paginate", side_effect=RuntimeError("boom")),
    ):
        count = SecurityScanner()._scan_guardduty(session, scan_db, scan.id, "us-east-1")

    assert count == 0


def test_guardduty_findings_scan_failure_does_not_raise(scan_db: ScanDB):
    """A list_findings failure must not raise out of _scan_guardduty_findings —
    the detector itself (scanned by the caller) is unaffected."""
    gd = MagicMock()

    with patch(
        "stackwise.scanner.security.paginate",
        side_effect=RuntimeError("boom"),
    ):
        count = SecurityScanner()._scan_guardduty_findings(
            gd, scan_db, "scan-1", "us-east-1", "det-1"
        )

    assert count == 0


@mock_aws
def test_scan_region_runs_iam_and_guardduty_in_us_east_1(scan_db: ScanDB):
    """_scan_region must dispatch to IAM and GuardDuty (in addition to KMS and
    Secrets Manager) when the region is us-east-1."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="my-role", AssumeRolePolicyDocument=_ASSUME_ROLE_POLICY)
    gd = session.client("guardduty", region_name="us-east-1")
    gd.create_detector(Enable=True)

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])
    SecurityScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id)
    assert [r for r in resources if r.service == "iam"] != []
    assert [r for r in resources if r.service == "guardduty"] != []


@mock_aws
def test_scan_region_skips_iam_and_guardduty_outside_us_east_1(scan_db: ScanDB):
    """IAM and GuardDuty are global/mostly-global — _scan_region must only run
    them in us-east-1, while KMS and Secrets Manager run in every region."""
    session = boto3.Session(region_name="eu-west-1")
    kms = session.client("kms", region_name="eu-west-1")
    kms.create_key(Description="test-key")

    scan = scan_db.create_scan("123456789012", ["eu-west-1"], ["security"])
    SecurityScanner()._scan_region(session, scan_db, scan.id, "eu-west-1")

    resources = scan_db.get_resources(scan.id)
    assert [r for r in resources if r.service == "iam"] == []
    assert [r for r in resources if r.service == "guardduty"] == []
    assert [r for r in resources if r.service == "kms"] != []
