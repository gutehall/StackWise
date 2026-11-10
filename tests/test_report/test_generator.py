"""Tests for report generation."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from stackwise.report.generator import ReportFormatUnavailableError, generate_report
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


def _scan_with_one_instance(scan_db: ScanDB) -> str:
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_resource(scan.id, "ec2", "instance", "i-1", "us-east-1", metadata={})
    return scan.id


def _weasyprint_works() -> bool:
    try:
        from weasyprint import HTML

        HTML(string="<p>x</p>").write_pdf()
        return True
    except (ImportError, OSError):
        return False


def test_generate_report_pdf_is_a_real_pdf_or_a_clear_failure(scan_db: ScanDB, settings):
    """WeasyPrint needs Pango and Cairo, which not every CI runner has. With them,
    the file must be a real PDF. Without them, it must fail, not hand back HTML."""
    scan_id = _scan_with_one_instance(scan_db)

    if _weasyprint_works():
        path = generate_report(settings, scan_db, scan_id, "engineering", "pdf")
        assert path.suffix == ".pdf"
        assert path.read_bytes()[:4] == b"%PDF"
    else:
        with pytest.raises(ReportFormatUnavailableError):
            generate_report(settings, scan_db, scan_id, "engineering", "pdf")
        assert list(settings.output_dir.glob("*")) == []


def test_missing_weasyprint_fails_instead_of_writing_html(scan_db: ScanDB, settings):
    scan_id = _scan_with_one_instance(scan_db)

    with (
        patch.dict(sys.modules, {"weasyprint": None}),
        pytest.raises(ReportFormatUnavailableError, match="--format html"),
    ):
        generate_report(settings, scan_db, scan_id, "engineering", "pdf")

    assert list(settings.output_dir.glob("*")) == []


@pytest.mark.parametrize("error", [OSError("cairo crashed"), ValueError("bad css")])
def test_a_failed_pdf_write_removes_the_partial_file(scan_db: ScanDB, settings, error):
    scan_id = _scan_with_one_instance(scan_db)

    def _write_half_then_fail(path):
        Path(path).write_bytes(b"%PDF-1.7 partial")
        raise error

    fake = MagicMock()
    fake.HTML.return_value.write_pdf.side_effect = _write_half_then_fail
    with (
        patch.dict(sys.modules, {"weasyprint": fake}),
        pytest.raises((ReportFormatUnavailableError, ValueError)),
    ):
        generate_report(settings, scan_db, scan_id, "engineering", "pdf")

    assert list(settings.output_dir.glob("*.pdf")) == []


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


def test_markdown_shows_a_partial_llm_run(scan_db: ScanDB, settings):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_recommendation(
        scan_id=scan.id, source="llm", category="cost", title="Right-size instances",
    )
    scan_db.set_analysis_status(scan.id, "partial", ["compute", "data"])

    content = generate_report(settings, scan_db, scan.id, "engineering", "md").read_text()

    assert "LLM analysis was partial; these categories failed: compute, data" in content


def test_markdown_shows_a_partial_llm_run_with_no_recommendations(scan_db: ScanDB, settings):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.set_analysis_status(scan.id, "partial", ["compute"])

    content = generate_report(settings, scan_db, scan.id, "engineering", "md").read_text()

    assert "Recommendations (0)" in content
    assert "these categories failed: compute" in content


def test_markdown_has_no_partial_line_for_a_complete_run(scan_db: ScanDB, settings):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scan_db.insert_recommendation(
        scan_id=scan.id, source="llm", category="cost", title="Right-size instances",
    )
    scan_db.set_analysis_status(scan.id, "complete", [])

    content = generate_report(settings, scan_db, scan.id, "engineering", "md").read_text()

    assert "partial" not in content


def _scan_with_many_services_and_bad_costs(scan_db: ScanDB, n_services: int = 15) -> str:
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute", "cost"])
    for i in range(n_services):
        scan_db.insert_resource(scan.id, f"svc{i}", "thing", f"r{i}", "us-east-1", metadata={})
    groups = [
        {"Keys": [f"Service {i}"], "Metrics": {"UnblendedCost": {"Amount": str(i + 1)}}}
        for i in range(n_services)
    ]
    groups += [
        {"Keys": ["Null amount"], "Metrics": {"UnblendedCost": {"Amount": None}}},
        {"Keys": ["Text amount"], "Metrics": {"UnblendedCost": {"Amount": "n/a"}}},
        "not a dict",
        {"Keys": ["No metrics"]},
    ]
    scan_db.insert_resource(
        scan.id, "ce", "cost_summary", "cost-summary", "us-east-1", metadata={"Groups": groups}
    )
    return scan.id


@pytest.mark.parametrize("output_format", ["json", "md", "html"])
@pytest.mark.parametrize("report_type", ["engineering", "executive", "architecture"])
def test_many_services_and_bad_cost_rows_do_not_abort_the_report(
    scan_db: ScanDB, settings, output_format: str, report_type: str
):
    scan_id = _scan_with_many_services_and_bad_costs(scan_db)

    path = generate_report(settings, scan_db, scan_id, report_type, output_format)

    assert path.exists() and path.stat().st_size > 0


def test_unreadable_cost_rows_are_skipped():
    from stackwise.report.generator import _cost_by_service

    meta = {"Groups": [
        {"Keys": ["EC2"], "Metrics": {"UnblendedCost": {"Amount": "2.5"}}},
        {"Keys": ["EC2"], "Metrics": {"UnblendedCost": {"Amount": "1"}}},
        {"Keys": ["S3"], "Metrics": {"UnblendedCost": {"Amount": None}}},
        {"Keys": [], "Metrics": {"UnblendedCost": {"Amount": "4"}}},
        None,
    ]}

    assert _cost_by_service(meta) == {"EC2": 3.5, "Other": 4.0}
    assert _cost_by_service({"Groups": "nope"}) == {}
    assert _cost_by_service({}) == {}


def test_json_and_markdown_draw_no_charts(scan_db: ScanDB, settings):
    scan_id = _scan_with_many_services_and_bad_costs(scan_db)

    with patch("stackwise.report.generator.severity_bar_chart") as chart:
        generate_report(settings, scan_db, scan_id, "executive", "json")
        generate_report(settings, scan_db, scan_id, "executive", "md")

    chart.assert_not_called()


def test_two_scans_on_the_same_day_get_separate_reports(scan_db: ScanDB, settings):
    first = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    second = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    assert first.timestamp[:10] == second.timestamp[:10]

    a = generate_report(settings, scan_db, first.id, "engineering", "json")
    b = generate_report(settings, scan_db, second.id, "engineering", "json")

    assert a != b
    assert a.exists() and b.exists()


@pytest.mark.parametrize("output_format", ["html", "md", "json"])
def test_a_crash_during_the_write_keeps_the_previous_report(
    scan_db: ScanDB, settings, output_format: str
):
    scan_id = _scan_with_one_instance(scan_db)
    path = generate_report(settings, scan_db, scan_id, "engineering", output_format)
    before = path.read_bytes()

    real_write = Path.write_text

    def _half_write_then_crash(self, text, *args, **kwargs):
        real_write(self, text[: len(text) // 2], *args, **kwargs)
        raise OSError("disk full")

    with (
        patch.object(Path, "write_text", _half_write_then_crash),
        pytest.raises(OSError, match="disk full"),
    ):
        generate_report(settings, scan_db, scan_id, "engineering", output_format)

    assert path.read_bytes() == before
    assert sorted(p.name for p in settings.output_dir.iterdir()) == [path.name]


def test_a_missing_scan_raises_before_rendering(scan_db: ScanDB, settings):
    with pytest.raises(ValueError, match="not found"):
        generate_report(settings, scan_db, "no-such-scan", "engineering", "json")
