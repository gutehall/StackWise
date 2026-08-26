"""Tests for report generation."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

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


def test_cost_chart_generated_from_cost_summary_resource(scan_db: ScanDB, settings):
    """A ce/cost_summary resource with real cost data should produce a
    non-empty cost pie chart, not just the resource-count fallback chart."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost"])
    scan_db.insert_resource(
        scan.id, "ce", "cost_summary", "cost-summary-1", "us-east-1",
        metadata={
            "Groups": [
                {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "10.0"}}},
            ]
        },
    )

    path = generate_report(settings, scan_db, scan.id, "executive", "html")
    content = path.read_text()
    # Two base64 PNG images: severity chart + cost chart (no resource chart
    # fallback needed since cost data exists).
    assert content.count("data:image/png;base64,") >= 2


def test_generate_report_unknown_template_raises(scan_db: ScanDB, settings):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    with pytest.raises(Exception):  # noqa: B017 — jinja2.TemplateNotFound
        generate_report(settings, scan_db, scan.id, "bogus-report-type", "html")


def test_generate_report_unsupported_output_format_raises(scan_db: ScanDB, settings):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    with pytest.raises(ValueError, match="Unsupported output format"):
        generate_report(settings, scan_db, scan.id, "engineering", "bogus-format")


def test_generate_report_pdf_produces_valid_output(scan_db: ScanDB, settings):
    """WeasyPrint needs system libs (pango/cairo/gobject) that aren't
    guaranteed present on every CI runner (only the shipped Docker image
    installs them) — so either a real PDF comes out, or the documented
    OSError fallback to HTML kicks in. Both are correct; only a crash isn't."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(scan.id, "ec2", "instance", "i-1", "us-east-1", metadata={})

    path = generate_report(settings, scan_db, scan.id, "engineering", "pdf")
    assert path.exists()
    assert path.suffix in (".pdf", ".html")
    if path.suffix == ".pdf":
        assert path.read_bytes()[:4] == b"%PDF"


def test_generate_report_pdf_falls_back_to_html_when_weasyprint_missing(
    scan_db: ScanDB, settings
):
    """If weasyprint can't be imported (not installed, or missing system
    libs raising OSError), the PDF request must fall back to writing HTML
    instead of crashing."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(scan.id, "ec2", "instance", "i-1", "us-east-1", metadata={})

    with patch.dict(sys.modules, {"weasyprint": None}):
        path = generate_report(settings, scan_db, scan.id, "engineering", "pdf")

    assert path.suffix == ".html"
    assert path.exists()


def test_markdown_executive_report_includes_severity_breakdown(scan_db: ScanDB, settings):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_finding(scan.id, "HIGH", "High finding", detail="d", remediation="r")
    scan_db.insert_finding(scan.id, "LOW", "Low finding")

    path = generate_report(settings, scan_db, scan.id, "executive", "md")
    content = path.read_text()
    assert "HIGH: 1" in content
    assert "LOW: 1" in content


def test_markdown_findings_include_detail_and_remediation(scan_db: ScanDB, settings):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_finding(
        scan.id, "HIGH", "Public IP found", detail="i-1 in us-east-1",
        remediation="Remove the public IP",
    )

    path = generate_report(settings, scan_db, scan.id, "engineering", "md")
    content = path.read_text()
    assert "Public IP found" in content
    assert "i-1 in us-east-1" in content
    assert "Remove the public IP" in content


def test_markdown_recommendations_section(scan_db: ScanDB, settings):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_recommendation(
        scan_id=scan.id, source="llm", category="cost", title="Right-size instances",
        detail="Several instances over-provisioned", impact="high", effort="low",
    )

    path = generate_report(settings, scan_db, scan.id, "engineering", "md")
    content = path.read_text()
    assert "Recommendations (1)" in content
    assert "Right-size instances" in content
    assert "Impact: high | Effort: low" in content
