"""Tests for data scanners (S3, RDS) using moto mocking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from stackwise.scanner.data import EFSScanner, RDSScanner, S3Scanner
from stackwise.store.db import ScanDB


@mock_aws
def test_s3_scanner_collects_buckets(scan_db: ScanDB):
    """S3Scanner should find buckets when run in us-east-1."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="my-test-bucket")

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    scanner = S3Scanner()
    count = scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count >= 1
    resources = scan_db.get_resources(scan.id, service="s3")
    buckets = [r for r in resources if r.resource_type == "bucket"]
    assert len(buckets) >= 1
    assert any(r.resource_id == "my-test-bucket" for r in buckets)


@mock_aws
def test_s3_scanner_skips_non_us_east_1(scan_db: ScanDB):
    """S3Scanner should return 0 when region is not us-east-1."""
    session = boto3.Session(region_name="us-west-2")
    scan = scan_db.create_scan("123456789012", ["us-west-2"], ["data"])
    scanner = S3Scanner()
    count = scanner._scan_region(session, scan_db, scan.id, "us-west-2")
    assert count == 0


@mock_aws
def test_rds_scanner_collects_instances(scan_db: ScanDB):
    """RDSScanner should find DB instances."""
    session = boto3.Session(region_name="us-east-1")
    client = session.client("rds", region_name="us-east-1")
    client.create_db_instance(
        DBInstanceIdentifier="my-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="secret123",
        AllocatedStorage=20,
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    scanner = RDSScanner()
    count = scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count >= 1
    resources = scan_db.get_resources(scan.id, service="rds")
    instances = [r for r in resources if r.resource_type == "db_instance"]
    assert len(instances) >= 1
    assert instances[0].resource_id == "my-db"
    assert instances[0].metadata["Engine"] == "postgres"


@mock_aws
def test_s3_encryption_not_configured_is_not_a_check_failure(scan_db: ScanDB):
    """A bucket with no encryption configured (the common real-world case)
    should report EncryptionCheckFailed=False, not True."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="unencrypted-bucket")

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    S3Scanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="s3")
    bucket = next(r for r in resources if r.resource_id == "unencrypted-bucket")
    assert bucket.metadata["EncryptionCheckFailed"] is False
    assert bucket.metadata["ServerSideEncryptionConfiguration"] == {}


def test_s3_permission_error_is_flagged_as_check_failure(scan_db: ScanDB):
    """An AccessDenied on get_bucket_encryption must not look like 'no encryption'."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    s3_client = MagicMock()
    s3_client.list_buckets.return_value = {"Buckets": [{"Name": "locked-bucket"}]}
    s3_client.get_bucket_location.return_value = {"LocationConstraint": None}
    s3_client.get_bucket_versioning.return_value = {}
    s3_client.get_bucket_encryption.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetBucketEncryption"
    )
    s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}
    }
    s3_client.get_bucket_lifecycle_configuration.return_value = {"Rules": []}

    with patch("stackwise.scanner.data.regional_client", return_value=s3_client):
        S3Scanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="s3")
    bucket = next(r for r in resources if r.resource_id == "locked-bucket")
    assert bucket.metadata["EncryptionCheckFailed"] is True


@mock_aws
def test_efs_scanner_collects_lifecycle_policies(scan_db: ScanDB):
    """EFSScanner should report actual lifecycle policies, not filesystem state."""
    session = boto3.Session(region_name="us-east-1")
    efs = session.client("efs", region_name="us-east-1")
    fs_id = efs.create_file_system(CreationToken="tok1", Encrypted=True)["FileSystemId"]
    efs.put_lifecycle_configuration(
        FileSystemId=fs_id,
        LifecyclePolicies=[{"TransitionToIA": "AFTER_30_DAYS"}],
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    EFSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="efs")
    fs = next(r for r in resources if r.resource_id == fs_id)
    assert fs.metadata["LifecyclePolicies"] == [{"TransitionToIA": "AFTER_30_DAYS"}]


@mock_aws
def test_rds_scanner_empty_region(scan_db: ScanDB):
    """RDSScanner should handle empty regions gracefully."""
    session = boto3.Session(region_name="us-east-1")
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    scanner = RDSScanner()
    count = scanner._scan_region(session, scan_db, scan.id, "us-east-1")
    assert count == 0
