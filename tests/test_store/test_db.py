"""Tests for the SQLite data store."""

import logging
import os
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

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


def test_insert_and_get_scan_errors(scan_db: ScanDB):
    """Rows are scoped to their scan and come back in insertion order."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    other = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])

    first = scan_db.insert_scan_error(scan.id, "s3", "us-east-1", "list_buckets", "denied")
    second = scan_db.insert_scan_error(scan.id, "rds", "eu-west-1", "describe_db_clusters", "slow")
    scan_db.insert_scan_error(other.id, "efs", "us-east-1", "describe_file_systems", "boom")

    assert scan_db.get_scan_errors(scan.id) == [first, second]
    assert (first.scanner, first.region, first.operation, first.message) == (
        "s3", "us-east-1", "list_buckets", "denied",
    )


def test_get_scan_errors_empty_for_clean_scan(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    assert scan_db.get_scan_errors(scan.id) == []


def test_insert_scan_error_takes_the_shared_lock(scan_db: ScanDB):
    """Worker threads share one connection, so the write must hold _lock."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["data"])
    scan_db._lock = MagicMock()

    scan_db.insert_scan_error(scan.id, "s3", "us-east-1", "list_buckets", "denied")

    scan_db._lock.__enter__.assert_called_once()


def test_opening_legacy_db_without_scan_errors_table_works(tmp_path: Path):
    """A scan file written before scan_errors existed must still open, keep its
    data, and read back as having no errors."""
    db_path = tmp_path / "legacy.db"
    raw = sqlite3.connect(str(db_path))
    raw.executescript(
        """
        CREATE TABLE scans (
            id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, account_id TEXT NOT NULL,
            regions TEXT NOT NULL, modules TEXT NOT NULL
        );
        INSERT INTO scans VALUES ('scan1', '2024-01-01', '123456789012', '[]', '[]');
        """
    )
    raw.commit()
    raw.close()

    db = ScanDB(db_path)
    try:
        assert db.get_scan("scan1") is not None
        assert db.get_scan_errors("scan1") == []
    finally:
        db.close()


@pytest.mark.parametrize("mode", ["rw", "ro"])
def test_opening_a_missing_file_raises_and_creates_nothing(tmp_path: Path, mode: str):
    path = tmp_path / "missing" / "scan.db"

    with pytest.raises(FileNotFoundError, match="Scan database not found"):
        ScanDB(path, mode=mode)

    assert not path.parent.exists()


def test_read_only_open_cannot_write_and_keeps_mtime(tmp_path: Path):
    path = tmp_path / "scan.db"
    db = ScanDB(path)
    scan = db.create_scan("123456789012", ["us-east-1"], ["compute"])
    db.close()
    os.utime(path, (1_000_000, 1_000_000))

    ro = ScanDB(path, mode="ro")
    try:
        assert ro.get_scan(scan.id) is not None
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            ro.create_scan("123456789012", ["us-east-1"], ["compute"])
    finally:
        ro.close()

    assert path.stat().st_mtime == 1_000_000


def test_read_write_open_adds_newer_tables_to_an_existing_file(tmp_path: Path):
    """Analyze writes to old scan files, so "rw" still applies the additive schema."""
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE unrelated (id TEXT)")
    conn.commit()
    conn.close()

    db = ScanDB(path, mode="rw")
    try:
        assert db.get_scan_errors("any") == []
    finally:
        db.close()


def test_path_with_uri_characters_opens_read_only(tmp_path: Path):
    path = tmp_path / "a b?c#d%e.db"
    ScanDB(path).close()

    ScanDB(path, mode="ro").close()


def test_in_progress_scan_is_incomplete_until_marked(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"], in_progress=True)
    assert scan_db.is_complete() is False

    scan_db.mark_scan_complete(scan.id)

    assert scan_db.is_complete() is True


def test_scan_with_scan_errors_is_incomplete(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    assert scan_db.is_complete() is True

    scan_db.insert_scan_error(scan.id, "ec2", "us-east-1", "describe_instances", "boom")

    assert scan_db.is_complete() is False


def test_file_older_than_the_marker_tables_counts_as_complete(tmp_path: Path):
    """A read-only open doesn't add newer tables, and older scans have no marker."""
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE scans (id TEXT)")
    conn.commit()
    conn.close()

    db = ScanDB(path, mode="ro")
    try:
        assert db.is_complete() is True
    finally:
        db.close()


def test_old_file_opened_writable_still_counts_as_complete(tmp_path: Path):
    """Analyze opens old scans writable, which adds empty marker tables."""
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE unrelated (id TEXT)")
    conn.commit()
    conn.close()

    db = ScanDB(path, mode="rw")
    try:
        assert db.is_complete() is True
    finally:
        db.close()


def test_scan_connection_uses_wal_and_returns_to_one_file_on_close(tmp_path: Path):
    path = tmp_path / "scan.db"
    db = ScanDB(path)
    assert db.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"

    db.close()

    assert [p.name for p in tmp_path.iterdir()] == ["scan.db"]
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    conn.close()


def test_busy_timeout_is_set_on_the_connection(tmp_path: Path):
    db = ScanDB(tmp_path / "scan.db")
    try:
        assert db.conn.execute("PRAGMA busy_timeout").fetchone()[0] == 10_000
    finally:
        db.close()


def test_failed_resource_write_is_kept_after_being_swallowed(tmp_path: Path):
    db = ScanDB(tmp_path / "scan.db")
    scan = db.create_scan("123456789012", ["us-east-1"], ["compute"])
    holder = sqlite3.connect(db.db_path)
    holder.execute("BEGIN IMMEDIATE")
    db.conn.execute("PRAGMA busy_timeout = 1")
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            db.insert_resource(scan.id, "ec2", "instance", "i-1", "us-east-1", metadata={})
        assert db.write_failures == {"database is locked"}
        # Close can't leave WAL while another connection holds it. That must not raise.
        db.close()
    finally:
        holder.close()


def test_scan_left_in_wal_by_a_crash_still_opens_read_only(tmp_path: Path):
    path = tmp_path / "crashed.db"
    db = ScanDB(path)
    scan = db.create_scan("123456789012", ["us-east-1"], ["compute"])
    # No close: the -wal file stays behind, as it would after the process dies.
    db.conn.commit()

    ro = ScanDB(path, mode="ro")
    try:
        assert ro.get_scan(scan.id) is not None
    finally:
        ro.close()
        db.conn.close()


def test_insert_resource_if_new_reports_whether_it_created_a_row(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    args = (scan.id, "ec2", "instance", "i-1", "us-east-1")

    assert scan_db.insert_resource_if_new(*args, metadata={"a": 1}) is True
    assert scan_db.insert_resource_if_new(*args, metadata={"a": 2}) is False
    assert [r.metadata for r in scan_db.get_resources(scan.id)] == [{"a": 1}]
