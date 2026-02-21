"""Report generator: renders Jinja2 templates to HTML, PDF, Markdown, and JSON."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from stackwise.analyzer.rules import load_rules
from stackwise.config import Settings
from stackwise.report.charts import (
    resource_distribution_chart,
    severity_bar_chart,
)
from stackwise.store.db import ScanDB

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _get_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )


def _build_context(db: ScanDB, scan_id: str) -> dict:
    """Collect all data needed by report templates."""
    scan = db.get_scan(scan_id)
    resources = db.get_resources(scan_id)
    findings = db.get_findings(scan_id)
    recommendations = db.get_recommendations(scan_id)
    summary = db.summary(scan_id)

    # Order findings by severity then rule priority
    rules = load_rules()
    rule_priority = {r.id: r.priority for r in rules}
    findings = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 99),
            rule_priority.get(f.rule_id or "", 999),
        ),
    )

    # Group resources by service
    resources_by_service: dict[str, list] = {}
    cost_by_service: dict[str, float] = {}
    for r in resources:
        resources_by_service.setdefault(r.service, []).append(r)
        if r.service == "ce" and r.resource_type == "cost_summary":
            # Cost Explorer metadata may have Groups or ResultsByTime
            meta = r.metadata or {}
            if "Groups" in meta:
                for g in meta.get("Groups", []):
                    svc = g.get("Keys", [""])[0] if g.get("Keys") else "Other"
                    cost_by_service[svc] = cost_by_service.get(svc, 0) + float(
                        g.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0)
                    )

    # Chart data (base64 PNG)
    findings_by_sev = summary.get("findings", {})
    severity_chart = severity_bar_chart(findings_by_sev)
    resource_chart = resource_distribution_chart(resources_by_service)
    cost_chart = ""
    if cost_by_service:
        from stackwise.report.charts import cost_pie_chart
        cost_chart = cost_pie_chart(cost_by_service)

    total_findings = sum(summary.get("findings", {}).values())

    # Build topology for architecture report: region -> service -> resources
    topology: dict[str, dict[str, list]] = {}
    connections: list[tuple[str, str, str]] = []
    for r in resources:
        topology.setdefault(r.region, {})
        topology[r.region].setdefault(r.service, []).append(r)
        if r.service == "ec2" and r.resource_type == "instance":
            meta = r.metadata or {}
            if meta.get("VpcId"):
                sub = meta.get("SubnetId", "")
                connections.append((r.resource_id, meta["VpcId"], sub))

    return {
        "scan": scan,
        "resources": resources,
        "resources_by_service": resources_by_service,
        "findings": findings,
        "recommendations": recommendations,
        "summary": summary,
        "total_findings": total_findings,
        "severity_chart": severity_chart,
        "resource_chart": resource_chart,
        "cost_chart": cost_chart,
        "topology": topology,
        "connections": connections,
    }


def generate_report(
    settings: Settings,
    db: ScanDB,
    scan_id: str,
    report_type: str = "engineering",
    output_format: str = "html",
) -> Path:
    """Generate a report and write it to the output directory.

    Args:
        report_type: 'engineering', 'executive', or 'architecture'.
        output_format: 'html', 'pdf', or 'md'.

    Returns:
        Path to the generated report file.
    """
    settings.output_dir.mkdir(parents=True, exist_ok=True)

    env = _get_env()
    template_name = f"{report_type}.html"

    try:
        template = env.get_template(template_name)
    except Exception:
        logger.error("Template '%s' not found in %s", template_name, TEMPLATES_DIR)
        raise

    context = _build_context(db, scan_id)
    context["report_type"] = report_type
    html_content = template.render(**context)

    scan = context["scan"]
    base_name = f"stackwise-{report_type}-{scan.account_id}-{scan.timestamp[:10]}"

    if output_format == "html":
        out_path = settings.output_dir / f"{base_name}.html"
        out_path.write_text(html_content)
        logger.info("HTML report written to %s", out_path)
        return out_path

    if output_format == "pdf":
        try:
            from weasyprint import HTML as WeasyHTML  # noqa: N811

            out_path = settings.output_dir / f"{base_name}.pdf"
            base_url = Path(__file__).parent.as_uri() + "/"
            WeasyHTML(string=html_content, base_url=base_url).write_pdf(str(out_path))
            logger.info("PDF report written to %s", out_path)
            return out_path
        except ImportError:
            logger.error(
                "WeasyPrint is not installed or system deps are missing. "
                "Falling back to HTML output."
            )
            out_path = settings.output_dir / f"{base_name}.html"
            out_path.write_text(html_content)
            return out_path

    if output_format == "md":
        out_path = settings.output_dir / f"{base_name}.md"
        md = _html_to_markdown(context, report_type)
        out_path.write_text(md)
        logger.info("Markdown report written to %s", out_path)
        return out_path

    if output_format == "json":
        out_path = settings.output_dir / f"{base_name}.json"
        payload = _build_json_payload(context)
        out_path.write_text(json.dumps(payload, indent=2, default=str))
        logger.info("JSON report written to %s", out_path)
        return out_path

    raise ValueError(f"Unsupported output format: {output_format}")


def _build_json_payload(context: dict) -> dict:
    """Build CI/CD-friendly JSON payload from report context."""
    scan = context["scan"]
    findings = context["findings"]
    recommendations = context["recommendations"]
    summary = context["summary"]
    return {
        "scan": {
            "id": scan.id,
            "account_id": scan.account_id,
            "timestamp": scan.timestamp,
            "regions": scan.regions,
            "modules": scan.modules,
        },
        "summary": {
            "resources": summary["resources"],
            "findings": summary["findings"],
            "findings_total": sum(summary["findings"].values()),
            "recommendations": summary["recommendations"],
        },
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "remediation": f.remediation,
                "resource_id": f.resource_id,
            }
            for f in findings
        ],
        "recommendations": [
            {
                "id": r.id,
                "source": r.source,
                "category": r.category,
                "title": r.title,
                "detail": r.detail,
                "impact": r.impact,
                "effort": r.effort,
            }
            for r in recommendations
        ],
    }


def _html_to_markdown(context: dict, report_type: str = "engineering") -> str:
    """Quick plaintext/Markdown report from context (no HTML dependency)."""
    scan = context["scan"]
    findings = context["findings"]
    recs = context["recommendations"]
    summary = context["summary"]
    total_findings = context.get("total_findings", sum(summary["findings"].values()))

    title = {
        "engineering": "Engineering Report",
        "executive": "Executive Report",
        "architecture": "Architecture Report",
    }.get(report_type, "Report")

    lines = [
        f"# stackwise {title}",
        "",
        f"**Account:** {scan.account_id}  ",
        f"**Scan:** {scan.timestamp}  ",
        f"**Regions:** {', '.join(scan.regions)}  ",
        f"**Resources scanned:** {summary['resources']}  ",
        "",
    ]

    if report_type == "executive":
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Resources:** {summary['resources']}")
        lines.append(f"- **Findings:** {total_findings}")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            c = summary["findings"].get(sev, 0)
            if c:
                lines.append(f"  - {sev}: {c}")
        lines.append(f"- **AI Recommendations:** {summary['recommendations']}")
        lines.append("")

    if report_type == "architecture":
        topology = context.get("topology", {})
        lines.append("## Topology")
        lines.append("")
        for region, services in topology.items():
            lines.append(f"### {region}")
            for svc, res_list in services.items():
                ids = ", ".join(r.resource_id for r in res_list[:10])
                suffix = "..." if len(res_list) > 10 else ""
                lines.append(f"- **{svc}** ({len(res_list)}): {ids}{suffix}")
            lines.append("")
        if context.get("connections"):
            lines.append("### Connections")
            for res_id, vpc_id, subnet_id in context["connections"]:
                subnet_suffix = f" ({subnet_id})" if subnet_id else ""
                lines.append(f"- EC2 {res_id} → VPC {vpc_id}{subnet_suffix}")
            lines.append("")
        lines.append("---")
        lines.append("")

    lines.append(f"## Findings ({total_findings} total)")
    lines.append("")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev_findings = [f for f in findings if f.severity == sev]
        if sev_findings:
            lines.append(f"### {sev} ({len(sev_findings)})")
            lines.append("")
            for f in sev_findings:
                lines.append(f"- **{f.title}**")
                if f.detail:
                    lines.append(f"  {f.detail}")
                if f.remediation:
                    lines.append(f"  *Remediation:* {f.remediation}")
                lines.append("")

    if recs:
        lines.append(f"## Recommendations ({len(recs)})")
        lines.append("")
        for r in recs:
            lines.append(f"- **[{r.category}]** {r.title}")
            if r.detail:
                lines.append(f"  {r.detail}")
            if r.impact:
                lines.append(f"  Impact: {r.impact} | Effort: {r.effort or 'unknown'}")
            lines.append("")

    return "\n".join(lines)
