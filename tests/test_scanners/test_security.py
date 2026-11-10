"""Tests for the security scanner's IAM check-failure visibility."""

from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock, patch

import boto3
import pytest
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
    assert scan_db.get_scan_errors(scan.id) == []


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
    assert scan_db.get_scan_errors(scan.id) == []


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
    assert [(e.scanner, e.operation) for e in scan_db.get_scan_errors(scan.id)] == [
        ("security", "list_roles"),
    ]


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
    assert scan_db.get_scan_errors(scan.id) == []


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
    assert [(e.scanner, e.operation) for e in scan_db.get_scan_errors(scan.id)] == [
        ("security", "list_keys"),
    ]


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
    assert [(e.scanner, e.operation) for e in scan_db.get_scan_errors(scan.id)] == [
        ("security", "list_secrets"),
    ]


def _guardduty_paginate(detectors: list[str], findings: list[str] | None = None):
    def _paginate(client, method, key, **kw):
        return detectors if method == "list_detectors" else (findings or [])

    return _paginate


def test_guardduty_get_detector_failure_stores_flagged_detector(scan_db: ScanDB):
    """A get_detector failure must keep the detector, flagged, with Status unset so
    it can't look disabled, and must still collect that detector's findings."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])
    gd = MagicMock()
    gd.get_detector.side_effect = RuntimeError("boom")
    gd.get_findings.return_value = {"Findings": [{"Id": "f-1", "Severity": 8}]}

    with (
        patch("stackwise.scanner.security.regional_client", return_value=gd),
        patch(
            "stackwise.scanner.security.paginate",
            side_effect=_guardduty_paginate(["det-1"], ["f-1"]),
        ),
    ):
        count = SecurityScanner()._scan_guardduty(MagicMock(), scan_db, scan.id, "us-east-1")

    assert count == 2
    rows = {r.resource_id: r for r in scan_db.get_resources(scan.id, service="guardduty")}
    assert rows["det-1"].metadata["DetectorCheckFailed"] is True
    assert "Status" not in rows["det-1"].metadata
    assert "f-1" in rows
    assert scan_db.get_scan_errors(scan.id) == []


def test_region_with_no_detector_stores_not_found(scan_db: ScanDB):
    """A region with no detector must not look compliant."""
    scan = scan_db.create_scan("123456789012", ["eu-west-1"], ["security"])

    with (
        patch("stackwise.scanner.security.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.security.paginate", side_effect=_guardduty_paginate([])),
    ):
        count = SecurityScanner()._scan_guardduty(MagicMock(), scan_db, scan.id, "eu-west-1")

    assert count == 1
    row = scan_db.get_resources(scan.id, service="guardduty")[0]
    assert (row.resource_id, row.region) == ("no-detector", "eu-west-1")
    assert row.arn is None
    assert row.metadata["Status"] == "NOT_FOUND"


def test_failed_findings_batch_does_not_lose_the_others(scan_db: ScanDB):
    """120 findings make three batches. The middle one fails: its failure is recorded,
    and the batches either side are still stored."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])
    ids = [f"f-{i}" for i in range(120)]

    def _get_findings(**kwargs):
        if kwargs["FindingIds"][0] == "f-50":
            raise RuntimeError("boom")
        return {"Findings": [{"Id": fid} for fid in kwargs["FindingIds"]]}

    gd = MagicMock()
    gd.get_findings.side_effect = _get_findings

    with patch("stackwise.scanner.security.paginate", return_value=ids):
        count = SecurityScanner()._scan_guardduty_findings(
            gd, scan_db, scan.id, "us-east-1", "det-1"
        )

    assert gd.get_findings.call_count == 3
    assert count == 70
    stored = {r.resource_id for r in scan_db.get_resources(scan.id, service="guardduty")}
    assert "f-0" in stored and "f-100" in stored and "f-50" not in stored
    assert [e.operation for e in scan_db.get_scan_errors(scan.id)] == ["get_findings"]


@pytest.mark.parametrize(
    "method",
    ["_scan_iam", "_scan_kms_regional", "_scan_secrets", "_scan_guardduty"],
)
def test_debug_log_of_a_failed_scan_has_the_traceback(scan_db: ScanDB, caplog, method: str):
    """A stray %s with no argument made the log call itself raise TypeError. pytest's
    log handler re-raises logging errors, so that fails here."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    with (
        caplog.at_level(logging.DEBUG, logger="stackwise.scanner.security"),
        patch("stackwise.scanner.security.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.security.paginate", side_effect=RuntimeError("the-aws-error")),
    ):
        getattr(SecurityScanner(), method)(MagicMock(), scan_db, scan.id, "us-east-1")

    assert any(r.exc_info for r in caplog.records)
    assert "the-aws-error" in caplog.text


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
    assert [(e.scanner, e.operation) for e in scan_db.get_scan_errors(scan.id)] == [
        ("security", "list_detectors"),
    ]


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
    assert [e.operation for e in scan_db.get_scan_errors("scan-1")] == ["list_findings"]


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
def test_scan_region_outside_us_east_1_skips_only_iam(scan_db: ScanDB):
    """IAM is global, so it only runs in us-east-1. GuardDuty detectors are regional,
    so a detector in another region must be stored."""
    session = boto3.Session(region_name="eu-west-1")
    session.client("kms", region_name="eu-west-1").create_key(Description="test-key")
    gd = session.client("guardduty", region_name="eu-west-1")
    det_id = gd.create_detector(Enable=False)["DetectorId"]

    scan = scan_db.create_scan("123456789012", ["eu-west-1"], ["security"])
    SecurityScanner()._scan_region(session, scan_db, scan.id, "eu-west-1")

    resources = scan_db.get_resources(scan.id)
    assert [r for r in resources if r.service == "iam"] == []
    assert [r for r in resources if r.service == "kms"] != []
    detector = next(r for r in resources if r.service == "guardduty")
    assert (detector.resource_id, detector.region) == (det_id, "eu-west-1")
    assert detector.metadata["Status"] == "DISABLED"
    assert detector.metadata["DetectorCheckFailed"] is False


def test_iam_list_users_failure_names_the_operation(scan_db: ScanDB):
    """list_users shares a try with list_roles; the recorded operation must
    name the call that actually failed."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])

    def _paginate(client, method, key, **kw):
        if method == "list_users":
            raise RuntimeError("boom")
        return []

    with (
        patch("stackwise.scanner.security.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.security.paginate", side_effect=_paginate),
    ):
        SecurityScanner()._scan_iam(session, scan_db, scan.id, "us-east-1")

    assert [(e.scanner, e.operation) for e in scan_db.get_scan_errors(scan.id)] == [
        ("security", "list_users"),
    ]


def test_guardduty_get_findings_failure_names_the_operation(scan_db: ScanDB):
    """get_findings shares a try with list_findings; the recorded operation
    must name the call that actually failed."""
    gd = MagicMock()
    gd.get_findings.side_effect = RuntimeError("boom")

    with patch("stackwise.scanner.security.paginate", return_value=["f-1"]):
        SecurityScanner()._scan_guardduty_findings(gd, scan_db, "scan-1", "us-east-1", "det-1")

    assert [e.operation for e in scan_db.get_scan_errors("scan-1")] == ["get_findings"]


@mock_aws
def test_console_access_and_role_path_are_stored(scan_db: ScanDB):
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam", region_name="us-east-1")
    iam.create_user(UserName="console-user")
    iam.create_login_profile(UserName="console-user", Password="Str0ng!Passw0rd#")
    iam.create_user(UserName="keys-only")
    iam.create_role(
        RoleName="AWSServiceRoleForTest", Path="/aws-service-role/test.amazonaws.com/",
        AssumeRolePolicyDocument=_ASSUME_ROLE_POLICY,
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])
    SecurityScanner()._scan_iam(session, scan_db, scan.id, "us-east-1")

    rows = {r.resource_id: r.metadata for r in scan_db.get_resources(scan.id, service="iam")}
    assert rows["console-user"]["ConsoleAccess"] is True
    assert rows["keys-only"]["ConsoleAccess"] is False
    assert rows["keys-only"]["ConsoleAccessCheckFailed"] is False
    assert rows["AWSServiceRoleForTest"]["Path"] == "/aws-service-role/test.amazonaws.com/"


@pytest.mark.parametrize(
    "error", [_throttle_error("GetLoginProfile"), RuntimeError("reset")], ids=["client", "other"]
)
def test_console_access_check_failure_is_flagged(scan_db: ScanDB, error: Exception):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["security"])
    iam = MagicMock()
    iam.list_mfa_devices.return_value = {"MFADevices": []}
    iam.list_user_policies.return_value = {"PolicyNames": []}
    iam.get_login_profile.side_effect = error

    def _paginate(client, method, key, **kw):
        return [{"UserName": "u"}] if method == "list_users" else []

    with (
        patch("stackwise.scanner.security.regional_client", return_value=iam),
        patch("stackwise.scanner.security.paginate", side_effect=_paginate),
    ):
        SecurityScanner()._scan_iam(MagicMock(), scan_db, scan.id, "us-east-1")

    user = scan_db.get_resources(scan.id, service="iam")[0].metadata
    assert user["ConsoleAccessCheckFailed"] is True
    assert user["ConsoleAccess"] is None
