"""Tests for data scanners (S3, RDS) using moto mocking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from stackwise.scanner.data import (
    DynamoDBScanner,
    EFSScanner,
    ElastiCacheScanner,
    RDSScanner,
    S3Scanner,
)
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


def test_s3_list_buckets_top_level_failure_returns_zero(scan_db: ScanDB):
    """A list_buckets failure must return 0, not raise out of _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    s3_client = MagicMock()
    s3_client.list_buckets.side_effect = RuntimeError("boom")

    with patch("stackwise.scanner.data.regional_client", return_value=s3_client):
        count = S3Scanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0


def test_s3_get_bucket_location_failure_defaults_region(scan_db: ScanDB):
    """A get_bucket_location failure must fall back to us-east-1 rather than
    dropping the bucket."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    s3_client = MagicMock()
    s3_client.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
    s3_client.get_bucket_location.side_effect = RuntimeError("boom")
    s3_client.get_bucket_versioning.return_value = {}
    s3_client.get_bucket_encryption.side_effect = ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": ""}},
        "GetBucketEncryption",
    )
    s3_client.get_public_access_block.side_effect = ClientError(
        {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": ""}},
        "GetPublicAccessBlock",
    )
    s3_client.get_bucket_lifecycle_configuration.side_effect = ClientError(
        {"Error": {"Code": "NoSuchLifecycleConfiguration", "Message": ""}},
        "GetBucketLifecycleConfiguration",
    )

    with patch("stackwise.scanner.data.regional_client", return_value=s3_client):
        S3Scanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="s3")
    bucket = next(r for r in resources if r.resource_id == "test-bucket")
    assert bucket.region == "us-east-1"


def test_s3_versioning_check_failure_is_flagged(scan_db: ScanDB):
    """An AccessDenied on get_bucket_versioning must not look like 'disabled'."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    s3_client = MagicMock()
    s3_client.list_buckets.return_value = {"Buckets": [{"Name": "locked-bucket"}]}
    s3_client.get_bucket_location.return_value = {"LocationConstraint": None}
    s3_client.get_bucket_versioning.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetBucketVersioning"
    )
    s3_client.get_bucket_encryption.side_effect = ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": ""}},
        "GetBucketEncryption",
    )
    s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}
    }
    s3_client.get_bucket_lifecycle_configuration.return_value = {"Rules": []}

    with patch("stackwise.scanner.data.regional_client", return_value=s3_client):
        S3Scanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="s3")
    bucket = next(r for r in resources if r.resource_id == "locked-bucket")
    assert bucket.metadata["VersioningCheckFailed"] is True


@mock_aws
def test_s3_bucket_with_encryption_configured(scan_db: ScanDB):
    """A bucket with default encryption configured should report the real
    encryption rules, not an empty/failed check."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="enc-bucket")
    s3.put_bucket_encryption(
        Bucket="enc-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    S3Scanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="s3")
    bucket = next(r for r in resources if r.resource_id == "enc-bucket")
    assert bucket.metadata["EncryptionCheckFailed"] is False
    assert bucket.metadata["ServerSideEncryptionConfiguration"]["Rules"]


@mock_aws
def test_rds_cluster_is_scanned(scan_db: ScanDB):
    """RDSScanner should find Aurora DB clusters with their MultiAZ/encryption
    settings, not just single instances."""
    session = boto3.Session(region_name="us-east-1")
    rds = session.client("rds", region_name="us-east-1")
    rds.create_db_cluster(
        DBClusterIdentifier="my-cluster",
        Engine="aurora-postgresql",
        MasterUsername="admin",
        MasterUserPassword="secret1234",
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    RDSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="rds")
    clusters = [r for r in resources if r.resource_type == "db_cluster"]
    assert len(clusters) == 1
    assert clusters[0].resource_id == "my-cluster"
    assert clusters[0].metadata["Engine"] == "aurora-postgresql"


def test_rds_describe_db_instances_failure_does_not_abort_scan(scan_db: ScanDB):
    """A describe_db_instances failure must not stop DB clusters from still
    being scanned."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    def _paginate(client, method, key, **kw):
        if method == "describe_db_instances":
            raise RuntimeError("boom")
        return []

    with (
        patch("stackwise.scanner.data.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.data.paginate", side_effect=_paginate),
    ):
        count = RDSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0


def test_rds_describe_db_clusters_failure_does_not_raise(scan_db: ScanDB):
    """A describe_db_clusters failure must not raise out of _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    def _paginate(client, method, key, **kw):
        if method == "describe_db_clusters":
            raise RuntimeError("boom")
        return []

    with (
        patch("stackwise.scanner.data.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.data.paginate", side_effect=_paginate),
    ):
        count = RDSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0


@mock_aws
def test_dynamodb_table_with_pitr_is_scanned(scan_db: ScanDB):
    """DynamoDBScanner should report point-in-time recovery status alongside
    table metadata."""
    session = boto3.Session(region_name="us-east-1")
    ddb = session.client("dynamodb", region_name="us-east-1")
    ddb.create_table(
        TableName="my-table",
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.update_continuous_backups(
        TableName="my-table",
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    DynamoDBScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="dynamodb")
    tables = [r for r in resources if r.resource_type == "table"]
    assert len(tables) == 1
    assert tables[0].resource_id == "my-table"
    assert (
        tables[0].metadata["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
        == "ENABLED"
    )


@mock_aws
def test_dynamodb_table_without_pitr_reports_disabled(scan_db: ScanDB):
    """A table with PITR never enabled must report the real 'DISABLED' status
    (not None from misreading a level-too-shallow field) — DAT-011 depends on
    telling this apart from an actually-enabled table."""
    session = boto3.Session(region_name="us-east-1")
    ddb = session.client("dynamodb", region_name="us-east-1")
    ddb.create_table(
        TableName="no-pitr-table",
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    DynamoDBScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="dynamodb")
    table = next(r for r in resources if r.resource_id == "no-pitr-table")
    assert (
        table.metadata["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
        == "DISABLED"
    )


def test_dynamodb_describe_table_failure_does_not_abort_scan(scan_db: ScanDB):
    """A describe_table failure for one table must not stop the scan of
    others (or raise out of _scan_region)."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    ddb = MagicMock()
    ddb.describe_table.side_effect = RuntimeError("boom")

    with (
        patch("stackwise.scanner.data.regional_client", return_value=ddb),
        patch(
            "stackwise.scanner.data.paginate",
            side_effect=lambda client, method, key, **kw: (
                ["broken-table"] if method == "list_tables" else []
            ),
        ),
    ):
        count = DynamoDBScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0
    assert scan_db.get_resources(scan.id, service="dynamodb") == []


def test_dynamodb_top_level_failure_does_not_raise(scan_db: ScanDB):
    """list_tables failing entirely must not raise out of _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    with (
        patch("stackwise.scanner.data.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.data.paginate", side_effect=RuntimeError("boom")),
    ):
        count = DynamoDBScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0


def test_efs_lifecycle_lookup_failure_still_stores_filesystem(scan_db: ScanDB):
    """A describe_lifecycle_configuration failure must not drop the file
    system — it should still be stored with an empty LifecyclePolicies list."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    efs = MagicMock()
    efs.describe_lifecycle_configuration.side_effect = RuntimeError("boom")

    with (
        patch("stackwise.scanner.data.regional_client", return_value=efs),
        patch(
            "stackwise.scanner.data.paginate",
            side_effect=lambda client, method, key, **kw: (
                [{"FileSystemId": "fs-1"}] if method == "describe_file_systems" else []
            ),
        ),
    ):
        EFSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="efs")
    fs = next(r for r in resources if r.resource_id == "fs-1")
    assert fs.metadata["LifecyclePolicies"] == []


def test_efs_top_level_failure_does_not_raise(scan_db: ScanDB):
    """describe_file_systems failing entirely must not raise out of
    _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    with (
        patch("stackwise.scanner.data.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.data.paginate", side_effect=RuntimeError("boom")),
    ):
        count = EFSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0


@mock_aws
def test_elasticache_cluster_and_replication_group_scanned(scan_db: ScanDB):
    """ElastiCacheScanner should find both standalone cache clusters and
    replication groups with their encryption settings."""
    session = boto3.Session(region_name="us-east-1")
    ec = session.client("elasticache", region_name="us-east-1")
    ec.create_cache_cluster(
        CacheClusterId="cc1", Engine="redis", CacheNodeType="cache.t3.micro", NumCacheNodes=1
    )
    ec.create_replication_group(
        ReplicationGroupId="rg1",
        ReplicationGroupDescription="test",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=2,
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    ElastiCacheScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="elasticache")
    clusters = [r for r in resources if r.resource_type == "cache_cluster"]
    assert any(r.resource_id == "cc1" for r in clusters)

    repl_groups = [r for r in resources if r.resource_type == "replication_group"]
    assert any(r.resource_id == "rg1" for r in repl_groups)


def test_elasticache_top_level_failure_does_not_raise(scan_db: ScanDB):
    """describe_cache_clusters failing entirely must not raise out of
    _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    with (
        patch("stackwise.scanner.data.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.data.paginate", side_effect=RuntimeError("boom")),
    ):
        count = ElastiCacheScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0
