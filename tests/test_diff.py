"""Tests for scan diff / drift detection."""

from __future__ import annotations

from pathlib import Path

from stackwise.diff import diff_scans
from stackwise.store.db import ScanDB


def test_diff_scans_resources_added_removed(tmp_path: Path):
    """Diff should detect added and removed resources."""
    db1 = ScanDB(tmp_path / "scan1.db")
    db2 = ScanDB(tmp_path / "scan2.db")

    s1 = db1.create_scan("123", ["us-east-1"], ["compute"])
    s2 = db2.create_scan("123", ["us-east-1"], ["compute"])

    db1.insert_resource(s1.id, "ec2", "instance", "i-1", "us-east-1", metadata={})
    db1.insert_resource(s1.id, "ec2", "instance", "i-2", "us-east-1", metadata={})

    db2.insert_resource(s2.id, "ec2", "instance", "i-2", "us-east-1", metadata={})
    db2.insert_resource(s2.id, "ec2", "instance", "i-3", "us-east-1", metadata={})

    result = diff_scans(tmp_path / "scan1.db", tmp_path / "scan2.db")

    assert len(result.resources_added) == 1
    assert result.resources_added[0].resource_id == "i-3"
    assert len(result.resources_removed) == 1
    assert result.resources_removed[0].resource_id == "i-1"

    db1.close()
    db2.close()


def test_diff_scans_findings(tmp_path: Path):
    """Diff should detect added and removed findings."""
    db1 = ScanDB(tmp_path / "scan1.db")
    db2 = ScanDB(tmp_path / "scan2.db")

    s1 = db1.create_scan("123", ["us-east-1"], ["compute"])
    s2 = db2.create_scan("123", ["us-east-1"], ["compute"])

    r1 = db1.insert_resource(s1.id, "ec2", "instance", "i-1", "us-east-1", metadata={})
    r2 = db2.insert_resource(s2.id, "ec2", "instance", "i-1", "us-east-1", metadata={})

    db1.insert_finding(s1.id, "HIGH", "Old finding", resource_id=r1.id, rule_id="R1")
    db2.insert_finding(s2.id, "HIGH", "New finding", resource_id=r2.id, rule_id="R2")

    result = diff_scans(tmp_path / "scan1.db", tmp_path / "scan2.db")

    assert len(result.findings_added) == 1
    assert result.findings_added[0].rule_id == "R2"
    assert len(result.findings_removed) == 1
    assert result.findings_removed[0].rule_id == "R1"

    db1.close()
    db2.close()
