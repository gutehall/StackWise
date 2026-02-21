"""Tests for configurable rule suppression."""

from __future__ import annotations

from stackwise.analyzer.rules import evaluate_rules, load_rules
from stackwise.store.db import ScanDB


def test_suppressed_rules_not_evaluated(scan_db: ScanDB):
    """Suppressed rules should not produce findings."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])

    # Resource that only triggers CMP-001 (public IP); satisfy CMP-008/CMP-009 to isolate
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-public", "us-east-1",
        metadata={
            "PublicIpAddress": "1.2.3.4",
            "MetadataOptions": {"HttpTokens": "required"},
            "LaunchTemplate": {"LaunchTemplateId": "lt-123"},
        },
    )

    count = evaluate_rules(rules, scan_db, scan.id, suppressed_rules=["CMP-001"])
    findings = scan_db.get_findings(scan.id)

    assert count == 0
    assert len(findings) == 0


def test_non_suppressed_rules_still_evaluate(scan_db: ScanDB):
    """Non-suppressed rules should still produce findings."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])

    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-public", "us-east-1",
        metadata={"PublicIpAddress": "1.2.3.4"},
    )

    count = evaluate_rules(rules, scan_db, scan.id, suppressed_rules=["CMP-002"])
    findings = scan_db.get_findings(scan.id)

    assert count >= 1
    cmp001 = [f for f in findings if f.rule_id == "CMP-001"]
    assert len(cmp001) == 1
