"""Tests for report generation."""

from __future__ import annotations

from stackwise.report.generator import generate_report
from stackwise.store.db import ScanDB


def test_generate_engineering_report_html(scan_db: ScanDB, settings):
    """Engineering report should generate HTML file."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1",
        metadata={"InstanceId": "i-1", "InstanceType": "t3.micro"},
    )
    scan_db.insert_finding(
        scan.id, "MEDIUM", "Test finding",
        resource_id=None, rule_id="CMP-001", detail="Detail",
    )

    path = generate_report(settings, scan_db, scan.id, "engineering", "html")
    assert path.exists()
    assert path.suffix == ".html"
    content = path.read_text()
    assert "StackWise Engineering Report" in content
    assert "123456789012" in content
    assert "Test finding" in content


def test_generate_executive_report_html(scan_db: ScanDB, settings):
    """Executive report should generate HTML with charts."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1",
        metadata={"InstanceId": "i-1"},
    )

    path = generate_report(settings, scan_db, scan.id, "executive", "html")
    assert path.exists()
    content = path.read_text()
    assert "StackWise Executive Report" in content
    assert "data:image/png;base64," in content


def test_generate_architecture_report_html(scan_db: ScanDB, settings):
    """Architecture report should generate topology."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1",
        metadata={"InstanceId": "i-1", "VpcId": "vpc-123", "SubnetId": "subnet-456"},
    )

    path = generate_report(settings, scan_db, scan.id, "architecture", "html")
    assert path.exists()
    content = path.read_text()
    assert "StackWise Architecture Report" in content
    assert "us-east-1" in content
    assert "i-1" in content
    assert "vpc-123" in content


def test_generate_report_markdown(scan_db: ScanDB, settings):
    """Report should generate Markdown for all types."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(scan.id, "ec2", "instance", "i-1", "us-east-1", metadata={})

    for report_type in ("engineering", "executive", "architecture"):
        path = generate_report(settings, scan_db, scan.id, report_type, "md")
        assert path.exists()
        assert path.suffix == ".md"
        content = path.read_text()
        assert "StackWise" in content
        assert "123456789012" in content
