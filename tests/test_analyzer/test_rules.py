"""Tests for YAML rule loading and evaluation."""

from __future__ import annotations

from stackwise.analyzer.rules import evaluate_rules, load_rules
from stackwise.store.db import ScanDB


def test_load_rules_includes_priority():
    """Rules should load optional priority from YAML."""
    rules = load_rules()
    cmp001 = next(r for r in rules if r.id == "CMP-001")
    assert cmp001.priority == 1
    # Rules without priority get default 999
    cmp002 = next(r for r in rules if r.id == "CMP-002")
    assert cmp002.priority == 999


def test_safe_builtins_allow_len_and_any(scan_db: ScanDB):
    """Rule conditions can use len() and any() from safe builtins."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    # NET-005 uses any() - need security_group with 0.0.0.0/0
    scan_db.insert_resource(
        scan.id, "ec2", "security_group", "sg-123", "us-east-1",
        metadata={
            "IpPermissions": [
                {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 80, "ToPort": 80}
            ]
        },
    )
    evaluate_rules(rules, scan_db, scan.id)
    net005 = [f for f in scan_db.get_findings(scan.id) if f.rule_id == "NET-005"]
    assert len(net005) >= 1


def test_load_rules_from_default_dir():
    """Should load rules from the rules/ directory."""
    rules = load_rules()
    assert len(rules) > 0
    # compute.yaml should have CMP-001
    ids = [r.id for r in rules]
    assert "CMP-001" in ids


def test_evaluate_public_ip_rule(scan_db: ScanDB):
    """CMP-001 should fire when an instance has a public IP."""
    rules = load_rules()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    # Instance WITH public IP → should trigger
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-public", "us-east-1",
        metadata={"PublicIpAddress": "1.2.3.4", "EbsOptimized": True, "Monitoring": "enabled"},
    )
    # Instance WITHOUT public IP → should not trigger
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-private", "us-east-1",
        metadata={"PublicIpAddress": None, "EbsOptimized": True, "Monitoring": "enabled"},
    )

    evaluate_rules(rules, scan_db, scan.id)
    findings = scan_db.get_findings(scan.id)

    # CMP-001 should fire for i-public
    cmp001 = [f for f in findings if f.rule_id == "CMP-001"]
    assert len(cmp001) == 1
    assert "i-public" in cmp001[0].detail


def test_evaluate_deprecated_runtime_rule(scan_db: ScanDB):
    """CMP-004 should fire for deprecated Lambda runtimes."""
    rules = load_rules()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    scan_db.insert_resource(
        scan.id, "lambda", "function", "old-fn", "us-east-1",
        metadata={"Runtime": "python3.8", "MemorySize": 256, "Timeout": 30},
    )
    scan_db.insert_resource(
        scan.id, "lambda", "function", "new-fn", "us-east-1",
        metadata={"Runtime": "python3.12", "MemorySize": 256, "Timeout": 30},
    )

    evaluate_rules(rules, scan_db, scan.id)
    findings = scan_db.get_findings(scan.id)

    cmp004 = [f for f in findings if f.rule_id == "CMP-004"]
    assert len(cmp004) == 1
    assert "old-fn" in cmp004[0].detail


def test_data_rule_s3_versioning(scan_db: ScanDB):
    """DAT-001 should fire when S3 bucket has versioning disabled."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["data"])
    scan_db.insert_resource(
        scan.id, "s3", "bucket", "my-bucket", "us-east-1",
        metadata={"Name": "my-bucket", "Versioning": {"Status": "Suspended"}},
    )
    scan_db.insert_resource(
        scan.id, "s3", "bucket", "versioned-bucket", "us-east-1",
        metadata={"Name": "versioned-bucket", "Versioning": {"Status": "Enabled"}},
    )
    evaluate_rules(rules, scan_db, scan.id)
    findings = scan_db.get_findings(scan.id)
    dat001 = [f for f in findings if f.rule_id == "DAT-001"]
    assert len(dat001) == 1
    assert "my-bucket" in dat001[0].detail
