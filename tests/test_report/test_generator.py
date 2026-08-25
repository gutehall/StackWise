"""Tests for report generation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

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


def test_architecture_report_writes_utf8_regardless_of_locale(scan_db: ScanDB, settings):
    """The architecture report embeds a literal '→' character; writing it must
    not depend on the platform's default locale encoding (which may not be
    UTF-8 in Docker/CI). Every write_text call must pin encoding='utf-8'."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1",
        metadata={"InstanceId": "i-1", "VpcId": "vpc-123", "SubnetId": "subnet-456"},
    )

    real_write_text = Path.write_text
    calls = []

    def spy(self, data, *args, **kwargs):
        calls.append(kwargs)
        return real_write_text(self, data, *args, **kwargs)

    with patch.object(Path, "write_text", spy):
        for output_format in ("html", "md", "json"):
            generate_report(settings, scan_db, scan.id, "architecture", output_format)

    assert calls
    assert all(kw.get("encoding") == "utf-8" for kw in calls)


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
