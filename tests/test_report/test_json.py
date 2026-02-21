"""Tests for JSON report output."""

from __future__ import annotations

import json

from stackwise.report.generator import generate_report
from stackwise.store.db import ScanDB


def test_generate_report_json(scan_db: ScanDB, settings):
    """Report with format json should produce valid JSON file."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1",
        metadata={"InstanceId": "i-1"},
    )
    scan_db.insert_finding(
        scan.id, "MEDIUM", "Test finding",
        rule_id="CMP-001", detail="Detail",
    )

    path = generate_report(settings, scan_db, scan.id, "engineering", "json")
    assert path.exists()
    assert path.suffix == ".json"

    data = json.loads(path.read_text())
    assert "scan" in data
    assert "findings" in data
    assert "recommendations" in data
    assert "summary" in data
    assert data["scan"]["account_id"] == "123456789012"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "CMP-001"
