"""Tests for the SQLite data store."""

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
