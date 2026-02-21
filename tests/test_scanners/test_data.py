"""Tests for data scanners (S3, RDS) using moto mocking."""

from __future__ import annotations

import boto3
from moto import mock_aws

from stackwise.scanner.data import RDSScanner, S3Scanner
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
def test_rds_scanner_empty_region(scan_db: ScanDB):
    """RDSScanner should handle empty regions gracefully."""
    session = boto3.Session(region_name="us-east-1")
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    scanner = RDSScanner()
    count = scanner._scan_region(session, scan_db, scan.id, "us-east-1")
    assert count == 0
