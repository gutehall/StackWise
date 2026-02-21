"""Analysis engine: rules → LLM enrichment → scored findings."""

from __future__ import annotations

import logging

from rich.console import Console

from stackwise.analyzer.llm_client import OllamaClient
from stackwise.analyzer.rules import evaluate_rules, load_rules
from stackwise.config import Engine, Settings
from stackwise.store.db import ScanDB

logger = logging.getLogger(__name__)
console = Console(stderr=True)

# Map scanner services → analysis category
_SERVICE_CATEGORY = {
    "ec2": "compute",
    "lambda": "compute",
    "ecs": "compute",
    "eks": "compute",
    "rds": "data",
    "dynamodb": "data",
    "s3": "data",
    "efs": "data",
    "elasticache": "data",
    "elasticloadbalancing": "network",
    "elbv2": "network",
    "apigateway": "network",
    "iam": "security",
    "kms": "security",
    "secretsmanager": "security",
    "guardduty": "security",
    "securityhub": "security",
    "cloudwatch": "observability",
    "logs": "observability",
    "ce": "cost",
    "compute-optimizer": "cost",
    "resourcegroupstaggingapi": "discovery",
    "config": "discovery",
}


def run_analysis(settings: Settings, db: ScanDB, scan_id: str) -> dict:
    """Run full analysis pipeline: rules then optional LLM enrichment.

    Returns:
        Summary dict with counts.
    """
    # ── Step 1: Rule-based analysis ────────────────────────
    console.print("[bold]Running rule-based analysis…[/bold]")
    rules = load_rules()
    rule_findings = evaluate_rules(
        rules, db, scan_id,
        suppressed_rules=getattr(settings, "suppressed_rules", None),
    )
    console.print(f"  Rules produced [yellow]{rule_findings}[/yellow] findings")

    # ── Step 2: LLM enrichment (if available) ──────────────
    llm_recs = 0

    if settings.engine == Engine.RULES_ONLY:
        console.print("[dim]LLM engine disabled — skipping AI analysis[/dim]")
    else:
        # MLX not yet implemented; fall back to Ollama when MLX selected
        if settings.engine == Engine.MLX:
            console.print(
                "[dim]MLX engine not yet implemented — using Ollama[/dim]"
            )
        client = OllamaClient(settings)
        if not client.is_available():
            console.print("[yellow]⚠ Ollama not reachable — skipping AI analysis[/yellow]")
        elif not client.ensure_model():
            console.print(
                f"[yellow]⚠ Model '{settings.model}' not found in Ollama — "
                f"run 'ollama pull {settings.model}' first[/yellow]"
            )
        else:
            console.print(f"[bold]Running LLM analysis with {settings.model}…[/bold]")
            llm_recs = _run_llm_analysis(client, db, scan_id, settings)
            console.print(f"  LLM produced [green]{llm_recs}[/green] recommendations")

    return {
        "rule_findings": rule_findings,
        "llm_recommendations": llm_recs,
    }


def _run_llm_analysis(
    client: OllamaClient, db: ScanDB, scan_id: str, settings: Settings
) -> int:
    """Group resources by category, chunk if needed, and ask the LLM for recommendations."""
    resources = db.get_resources(scan_id)
    findings = db.get_findings(scan_id)

    # Group resources by category
    categories: dict[str, list[dict]] = {}
    for res in resources:
        cat = _SERVICE_CATEGORY.get(res.service, "other")
        categories.setdefault(cat, []).append(res.metadata)

    # Group findings by category (via their resource)
    resource_map = {r.id: r for r in resources}
    finding_by_cat: dict[str, list[dict]] = {}
    for f in findings:
        cat = "other"
        if f.resource_id and f.resource_id in resource_map:
            r = resource_map[f.resource_id]
            cat = _SERVICE_CATEGORY.get(r.service, "other")
        finding_by_cat.setdefault(cat, []).append({
            "title": f.title,
            "severity": f.severity,
            "detail": f.detail,
        })

    chunk_size = settings.llm_chunk_size
    max_chunks = settings.llm_max_chunks

    total = 0
    for category, res_list in categories.items():
        cat_findings = finding_by_cat.get(category, [])

        # Chunk resources for large categories
        chunks: list[list[dict]] = []
        if len(res_list) <= chunk_size:
            chunks = [res_list]
        else:
            for i in range(0, min(len(res_list), chunk_size * max_chunks), chunk_size):
                chunks.append(res_list[i : i + chunk_size])
                if len(chunks) >= max_chunks:
                    break

        category_recs: list[dict] = []
        for chunk_idx, chunk in enumerate(chunks):
            chunk_context = (
                {"chunk_index": chunk_idx, "total_chunks": len(chunks)}
                if len(chunks) > 1
                else {}
            )
            prompt = client.build_category_prompt(
                category, chunk, cat_findings, **chunk_context
            )

            if len(chunks) > 1:
                console.print(
                    f"  Analyzing [cyan]{category}[/cyan] "
                    f"({len(chunk)} resources, chunk {chunk_idx + 1}/{len(chunks)})…"
                )
            else:
                console.print(
                    f"  Analyzing [cyan]{category}[/cyan] ({len(chunk)} resources)…"
                )

            raw = client.generate(prompt)
            if not raw:
                continue

            recs = client.parse_recommendations(raw)
            category_recs.extend(recs)

        # Deduplicate by (category, normalized_title); keep first occurrence
        seen: set[tuple[str, str]] = set()
        for rec in category_recs:
            norm_title = (rec.get("title") or "").lower().strip()
            key = (rec.get("category", category), norm_title)
            if key in seen or not norm_title:
                continue
            seen.add(key)
            db.insert_recommendation(
                scan_id=scan_id,
                source="llm",
                category=rec.get("category", category),
                title=rec.get("title", "Untitled"),
                detail=rec.get("detail"),
                impact=rec.get("impact"),
                effort=rec.get("effort"),
            )
            total += 1

    return total
