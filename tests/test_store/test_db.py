"""Tests for the SQLite data store."""

import logging
import sqlite3
from pathlib import Path

from stackwise.store.db import ScanDB


def test_create_and_get_scan(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    assert scan.account_id == "123456789012"
    assert scan.regions == ["us-east-1"]

    fetched = scan_db.get_scan(scan.id)
    assert fetched is not None
    assert fetched.id == scan.id


def test_latest_scan(scan_db: ScanDB):
    scan_db.create_scan("111111111111", ["eu-west-1"], ["compute"])
    scan2 = scan_db.create_scan("111111111111", ["us-east-1"], ["compute", "data"])

    latest = scan_db.latest_scan()
    assert latest is not None
    assert latest.id == scan2.id


def test_get_scan_returns_none_for_unknown_id(scan_db: ScanDB):
    assert scan_db.get_scan("does-not-exist") is None


def test_latest_scan_returns_none_when_no_scans(scan_db: ScanDB):
    assert scan_db.latest_scan() is None


def test_insert_and_get_resources(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    scan_db.insert_resource(
        scan_id=scan.id,
        service="ec2",
        resource_type="instance",
        resource_id="i-abc123",
        region="us-east-1",
        metadata={"InstanceType": "t3.micro", "State": "running"},
    )

    resources = scan_db.get_resources(scan.id)
    assert len(resources) == 1
    assert resources[0].resource_id == "i-abc123"
    assert resources[0].metadata["InstanceType"] == "t3.micro"


def test_get_resources_filtered_by_service(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(scan.id, "ec2", "instance", "i-1", "us-east-1")
    scan_db.insert_resource(scan.id, "lambda", "function", "fn-1", "us-east-1")

    ec2_only = scan_db.get_resources(scan.id, service="ec2")
    assert len(ec2_only) == 1
    assert ec2_only[0].service == "ec2"


def test_insert_and_get_findings(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    scan_db.insert_finding(
        scan_id=scan.id,
        severity="HIGH",
        title="Public IP detected",
        rule_id="CMP-001",
        detail="i-abc123 in us-east-1",
        remediation="Remove public IP",
    )
    scan_db.insert_finding(
        scan_id=scan.id,
        severity="CRITICAL",
        title="Open SSH",
        rule_id="SEC-001",
    )

    findings = scan_db.get_findings(scan.id)
    assert len(findings) == 2
    # Should be ordered CRITICAL first
    assert findings[0].severity == "CRITICAL"
    assert findings[1].severity == "HIGH"


def test_get_findings_filtered_by_severity(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_finding(scan_id=scan.id, severity="HIGH", title="High finding")
    scan_db.insert_finding(scan_id=scan.id, severity="LOW", title="Low finding")

    high_only = scan_db.get_findings(scan.id, severity="HIGH")
    assert len(high_only) == 1
    assert high_only[0].title == "High finding"


def test_insert_and_get_recommendations(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    scan_db.insert_recommendation(
        scan_id=scan.id,
        source="llm",
        category="cost",
        title="Right-size instances",
        detail="Several instances are over-provisioned",
        impact="high",
        effort="low",
    )

    recs = scan_db.get_recommendations(scan.id)
    assert len(recs) == 1
    assert recs[0].source == "llm"
    assert recs[0].impact == "high"


def test_insert_resource_dedups_same_identity(scan_db: ScanDB):
    """Two scanner modules inserting the same resource in one scan should
    produce a single row, not a duplicate."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost", "discovery"])

    first = scan_db.insert_resource(
        scan.id, "resourcegroupstaggingapi", "tagged_resource", "res-1", "us-east-1",
        metadata={"Tags": []},
    )
    second = scan_db.insert_resource(
        scan.id, "resourcegroupstaggingapi", "tagged_resource", "res-1", "us-east-1",
        metadata={"Tags": []},
    )

    assert first.id == second.id
    resources = scan_db.get_resources(scan.id)
    assert len(resources) == 1


def test_insert_resource_allows_same_id_different_region(scan_db: ScanDB):
    """Same service/type/resource_id in a different region is a distinct resource."""
    scan = scan_db.create_scan("123456789012", ["us-east-1", "eu-west-1"], ["compute"])

    scan_db.insert_resource(scan.id, "ec2", "vpc", "vpc-1", "us-east-1")
    scan_db.insert_resource(scan.id, "ec2", "vpc", "vpc-1", "eu-west-1")

    assert len(scan_db.get_resources(scan.id)) == 2


def test_summary(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(scan.id, "ec2", "instance", "i-1", "us-east-1")
    scan_db.insert_resource(scan.id, "ec2", "instance", "i-2", "us-east-1")
    scan_db.insert_finding(scan.id, "HIGH", "Test finding")
    scan_db.insert_finding(scan.id, "HIGH", "Another finding")
    scan_db.insert_finding(scan.id, "LOW", "Minor thing")

    summary = scan_db.summary(scan.id)
    assert summary["resources"] == 2
    assert summary["findings"]["HIGH"] == 2
    assert summary["findings"]["LOW"] == 1
    assert summary["recommendations"] == 0


def test_opening_db_with_preexisting_duplicate_resources_warns_not_raises(
    tmp_path: Path, caplog
):
    """A scan DB written before the unique-resource-identity index existed may
    already have duplicate (scan_id, service, resource_type, resource_id,
    region) rows — opening it must log a warning and stay usable, not raise."""
    db_path = tmp_path / "legacy.db"

    # Build the pre-constraint schema by hand (no unique index) and insert two
    # rows that would violate it, before ScanDB ever gets to create the index.
    raw = sqlite3.connect(str(db_path))
    raw.executescript(
        """
        CREATE TABLE resources (
            id TEXT PRIMARY KEY, scan_id TEXT, service TEXT, resource_type TEXT,
            resource_id TEXT, region TEXT, arn TEXT, metadata_json TEXT
        );
        """
    )
    raw.execute(
        "INSERT INTO resources VALUES ('id1','scan1','ec2','instance','i-1','us-east-1',NULL,'{}')"
    )
    raw.execute(
        "INSERT INTO resources VALUES ('id2','scan1','ec2','instance','i-1','us-east-1',NULL,'{}')"
    )
    raw.commit()
    raw.close()

    with caplog.at_level(logging.WARNING):
        db = ScanDB(db_path)

    assert "duplicate rows" in caplog.text
    assert len(db.get_resources("scan1")) == 2  # both rows still readable
    db.close()
