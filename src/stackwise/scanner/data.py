"""Data scanners: S3, RDS."""

from __future__ import annotations

import logging

import boto3

from stackwise.scanner.base import BaseScanner
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate, regional_client

logger = logging.getLogger(__name__)


class S3Scanner(BaseScanner):
    """Scan S3 buckets (global list, per-bucket attributes)."""

    name = "s3"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        # S3 list_buckets is global; only run in us-east-1 to avoid duplicates
        if region != "us-east-1":
            return 0

        s3_client = regional_client(session, "s3", "us-east-1")
        count = 0
        try:
            buckets = s3_client.list_buckets().get("Buckets", [])
        except Exception:
            logger.exception("S3 list_buckets failed")
            return 0

        for bucket in buckets:
            bucket_name = bucket["Name"]
            metadata: dict = {
                "Name": bucket_name,
                "CreationDate": str(bucket.get("CreationDate", "")),
            }

            try:
                loc = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = loc.get("LocationConstraint") or "us-east-1"
            except Exception:
                bucket_region = "us-east-1"

            try:
                ver = s3_client.get_bucket_versioning(Bucket=bucket_name)
                metadata["Versioning"] = ver
            except Exception:
                metadata["Versioning"] = {}

            try:
                enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
                metadata["ServerSideEncryptionConfiguration"] = enc.get(
                    "ServerSideEncryptionConfiguration", {}
                )
            except Exception:
                metadata["ServerSideEncryptionConfiguration"] = {}

            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)
                metadata["PublicAccessBlock"] = pab.get(
                    "PublicAccessBlockConfiguration", {}
                )
            except Exception:
                metadata["PublicAccessBlock"] = {}

            try:
                lc = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                metadata["LifecycleRules"] = lc.get("Rules", [])
            except Exception:
                metadata["LifecycleRules"] = []

            db.insert_resource(
                scan_id=scan_id,
                service="s3",
                resource_type="bucket",
                resource_id=bucket_name,
                region=bucket_region,
                arn=f"arn:aws:s3:::{bucket_name}",
                metadata=metadata,
            )
            count += 1

        return count


class RDSScanner(BaseScanner):
    """Scan RDS instances and clusters."""

    name = "rds"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        client = regional_client(session, "rds", region)

        # DB instances
        try:
            instances = paginate(client, "describe_db_instances", "DBInstances")
            for inst in instances:
                inst_id = inst["DBInstanceIdentifier"]
                db.insert_resource(
                    scan_id=scan_id,
                    service="rds",
                    resource_type="db_instance",
                    resource_id=inst_id,
                    region=region,
                    arn=inst.get("DBInstanceArn"),
                    metadata={
                        "DBInstanceIdentifier": inst_id,
                        "DBInstanceClass": inst.get("DBInstanceClass"),
                        "Engine": inst.get("Engine"),
                        "EngineVersion": inst.get("EngineVersion"),
                        "MultiAZ": inst.get("MultiAZ"),
                        "StorageEncrypted": inst.get("StorageEncrypted"),
                        "PubliclyAccessible": inst.get("PubliclyAccessible"),
                        "DBInstanceStatus": inst.get("DBInstanceStatus"),
                    },
                )
                count += 1
        except Exception:
            logger.debug("RDS describe_db_instances failed in %s", region, exc_info=True)

        # DB clusters (Aurora)
        try:
            clusters = paginate(client, "describe_db_clusters", "DBClusters")
            for cluster in clusters:
                cluster_id = cluster["DBClusterIdentifier"]
                db.insert_resource(
                    scan_id=scan_id,
                    service="rds",
                    resource_type="db_cluster",
                    resource_id=cluster_id,
                    region=region,
                    arn=cluster.get("DBClusterArn"),
                    metadata={
                        "DBClusterIdentifier": cluster_id,
                        "Engine": cluster.get("Engine"),
                        "EngineVersion": cluster.get("EngineVersion"),
                        "MultiAZ": cluster.get("MultiAZ"),
                        "StorageEncrypted": cluster.get("StorageEncrypted"),
                        "Status": cluster.get("Status"),
                    },
                )
                count += 1
        except Exception:
            logger.debug("RDS describe_db_clusters failed in %s", region, exc_info=True)

        return count


class DynamoDBScanner(BaseScanner):
    """Scan DynamoDB tables."""

    name = "dynamodb"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        try:
            ddb = regional_client(session, "dynamodb", region)
            tables = paginate(ddb, "list_tables", "TableNames")
            for table_name in tables:
                try:
                    desc = ddb.describe_table(TableName=table_name)
                    tbl = desc.get("Table", {})
                    pitr = ddb.describe_continuous_backups(TableName=table_name)
                    pitr_desc = pitr.get("ContinuousBackupsDescription", {})
                    pitr_status = pitr_desc.get("PointInTimeRecoveryStatus")
                    db.insert_resource(
                        scan_id=scan_id,
                        service="dynamodb",
                        resource_type="table",
                        resource_id=table_name,
                        region=region,
                        arn=tbl.get("TableArn"),
                        metadata={
                            "TableName": table_name,
                            "TableStatus": tbl.get("TableStatus"),
                            "BillingModeSummary": tbl.get("BillingModeSummary"),
                            "SSEDescription": tbl.get("SSEDescription"),
                            "PointInTimeRecoveryDescription": {
                                "PointInTimeRecoveryStatus": pitr_status,
                            },
                        },
                    )
                    count += 1
                except Exception:
                    logger.debug("describe_table failed for %s", table_name)
        except Exception:
            logger.debug("DynamoDB scan failed in %s", region, exc_info=True)
        return count


class EFSScanner(BaseScanner):
    """Scan EFS file systems."""

    name = "efs"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        try:
            efs = regional_client(session, "elasticfilesystem", region)
            filesystems = paginate(efs, "describe_file_systems", "FileSystems")
            for fs in filesystems:
                fs_id = fs.get("FileSystemId", "")
                db.insert_resource(
                    scan_id=scan_id,
                    service="efs",
                    resource_type="file_system",
                    resource_id=fs_id,
                    region=region,
                    arn=fs.get("FileSystemArn"),
                    metadata={
                        "FileSystemId": fs_id,
                        "Name": fs.get("Name"),
                        "Encrypted": fs.get("Encrypted"),
                        "LifeCycleState": fs.get("LifeCycleState"),
                    },
                )
                count += 1
        except Exception:
            logger.debug("EFS scan failed in %s", region, exc_info=True)
        return count


class ElastiCacheScanner(BaseScanner):
    """Scan ElastiCache clusters and replication groups."""

    name = "elasticache"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        try:
            ec = regional_client(session, "elasticache", region)
            clusters = paginate(ec, "describe_cache_clusters", "CacheClusters")
            for cluster in clusters:
                cluster_id = cluster.get("CacheClusterId", "")
                db.insert_resource(
                    scan_id=scan_id,
                    service="elasticache",
                    resource_type="cache_cluster",
                    resource_id=cluster_id,
                    region=region,
                    arn=cluster.get("ARN"),
                    metadata={
                        "CacheClusterId": cluster_id,
                        "ReplicationGroupId": cluster.get("ReplicationGroupId"),
                        "AtRestEncryptionEnabled": cluster.get("AtRestEncryptionEnabled"),
                        "CacheNodeType": cluster.get("CacheNodeType"),
                    },
                )
                count += 1

            repl_groups = paginate(
                ec, "describe_replication_groups", "ReplicationGroups"
            )
            for rg in repl_groups:
                rg_id = rg.get("ReplicationGroupId", "")
                db.insert_resource(
                    scan_id=scan_id,
                    service="elasticache",
                    resource_type="replication_group",
                    resource_id=rg_id,
                    region=region,
                    arn=rg.get("ARN"),
                    metadata={
                        "ReplicationGroupId": rg_id,
                        "AtRestEncryptionEnabled": rg.get("AtRestEncryptionEnabled"),
                        "Status": rg.get("Status"),
                    },
                )
                count += 1
        except Exception:
            logger.debug("ElastiCache scan failed in %s", region, exc_info=True)
        return count


DATA_SCANNERS: list[BaseScanner] = [
    S3Scanner(),
    RDSScanner(),
    DynamoDBScanner(),
    EFSScanner(),
    ElastiCacheScanner(),
]
