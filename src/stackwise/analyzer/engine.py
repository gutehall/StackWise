"""Analysis engine: rules → LLM enrichment → scored findings."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, NamedTuple

from rich.console import Console

from stackwise.analyzer.llm_client import OllamaClient, fit_resources
from stackwise.analyzer.rules import RulesLoadError, evaluate_rules, load_rules_checked
from stackwise.config import Engine, Settings
from stackwise.store.db import ResourceRecord, ScanDB

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

# Tag/resource-inventory noise (resourcegroupstaggingapi listings) — rules
# already cover tagging gaps, and this category adds little cross-cutting
# LLM value while often being the largest by resource count.
_LLM_SKIP_CATEGORIES = {"discovery"}


# Finding id for "custom rules failed to load". Not a rule in any YAML file.
RULES_LOAD_FINDING_ID = "RULES-LOAD"

# What counts as an LLM recommendation "citing" a resource: an ARN, or an id with a
# common AWS prefix. A cited token that isn't in the chunk the model was shown is
# made up (or from another chunk), so the recommendation is dropped.
_ARN_RE = re.compile(r"arn:aws[\w-]*:[^\s\"'),;]+")
_AWS_ID_RE = re.compile(
    r"\b(?:i|sg|vpc|subnet|vol|eni|nat|igw|rtb|lt|acl|ami|snap|lb|tg|db|fs|eipalloc)"
    r"-[0-9a-f]{8,17}\b"
)


class _ChunkTask(NamedTuple):
    category: str
    chunk_idx: int
    total_chunks: int
    chunk: list[ResourceRecord]
    omitted: int  # resources dropped from the chunk to fit the prompt


class LLMRunResult(NamedTuple):
    count: int
    failed_categories: list[str]


def _cited_tokens(text: str) -> set[str]:
    # Sentence punctuation can trail an ARN in prose. An ARN whose account field is
    # "aws" is AWS-owned, such as a managed policy to attach, and never a resource in
    # the scan, so naming it isn't a claim about a resource.
    arns = {
        arn for arn in (m.rstrip(".:") for m in _ARN_RE.findall(text))
        if (arn.split(":") + [""] * 5)[4] != "aws"
    }
    return arns | set(_AWS_ID_RE.findall(text))


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _strings(v)


def _known_tokens(chunk: list[ResourceRecord]) -> set[str]:
    """Every id/ARN the model was shown for this chunk."""
    known: set[str] = set()
    for res in chunk:
        for text in (res.resource_id, res.arn or "", *_strings(res.metadata)):
            known.add(text)
            known |= _cited_tokens(text)
    return known


def _normalize_title(title: str) -> str:
    """Lowercase, punctuation stripped, whitespace collapsed."""
    return " ".join(re.sub(r"[^\w\s]", " ", title.lower()).split())


def run_analysis(settings: Settings, db: ScanDB, scan_id: str) -> dict:
    """Run full analysis pipeline: rules then optional LLM enrichment.

    Replaces the scan's findings. LLM recommendations are replaced only when the LLM
    runs; a rules-only run, or one where Ollama is unavailable, keeps the previous ones,
    which may refer to findings from the run that produced them. Raises, with the
    previous results kept, if anything fails before the new ones are committed.
    A failed LLM chunk is not such a failure: the other chunks' recommendations are
    kept and the scan's analysis status is recorded as partial.

    Returns:
        Summary dict with counts.
    """
    # Replace the previous results in one transaction: a re-run must not append a
    # second set, and a failure part-way must leave the previous set in place.
    with db.transaction():
        db.clear_findings(scan_id)

        # ── Step 1: Rule-based analysis ────────────────────────
        console.print("[bold]Running rule-based analysis…[/bold]")
        loaded = load_rules_checked()
        if loaded.problems and not loaded.is_override:
            # A broken packaged file would silently drop a whole domain, such as every
            # SEC-* rule, and the report would read as clean.
            raise RulesLoadError(
                f"packaged rules failed to load from {loaded.rules_dir}: "
                + ", ".join(loaded.problems)
            )
        rule_findings = evaluate_rules(
            loaded.rules, db, scan_id,
            suppressed_rules=getattr(settings, "suppressed_rules", None),
        )
        if loaded.problems:
            # A custom rules directory is the user's own: run what loaded, but say
            # what didn't, so the missing checks don't read as passes.
            db.insert_finding(
                scan_id=scan_id,
                severity="INFO",
                title="Some custom rules could not be loaded",
                rule_id=RULES_LOAD_FINDING_ID,
                detail=f"Skipped from {loaded.rules_dir}: " + ", ".join(loaded.problems),
                remediation=(
                    "Fix or remove the listed rules in STACKWISE_RULES_DIR. "
                    "Their checks did not run."
                ),
            )
            rule_findings += 1
            console.print(
                f"  [yellow]⚠ Skipped custom rules: {', '.join(loaded.problems)}[/yellow]"
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
                # Only replaced when the LLM actually runs: a rules-only run, or one where
                # Ollama is down, keeps the previous recommendations instead of losing them.
                db.clear_llm_recommendations(scan_id)
                llm_result = _run_llm_analysis(client, db, scan_id, settings)
                llm_recs = llm_result.count
                failed = sorted(set(llm_result.failed_categories))
                db.set_analysis_status(scan_id, "partial" if failed else "complete", failed)
                if failed:
                    console.print(
                        f"  [yellow]⚠ LLM analysis was partial: failed for "
                        f"{', '.join(failed)}. Stored {llm_recs} recommendations "
                        f"from the other categories.[/yellow]",
                        soft_wrap=True,
                    )
                else:
                    console.print(f"  LLM produced [green]{llm_recs}[/green] recommendations")

    return {
        "rule_findings": rule_findings,
        "llm_recommendations": llm_recs,
    }


def _run_llm_analysis(
    client: OllamaClient, db: ScanDB, scan_id: str, settings: Settings
) -> LLMRunResult:
    """Group resources by category, chunk if needed, and ask the LLM for recommendations.

    A chunk that fails is recorded under its category and skipped; the rest still run.
    """
    resources = db.get_resources(scan_id)
    findings = db.get_findings(scan_id)

    # Group resources by category
    categories: dict[str, list[ResourceRecord]] = {}
    for res in resources:
        cat = _SERVICE_CATEGORY.get(res.service, "other")
        categories.setdefault(cat, []).append(res)

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

    # Build every (category, chunk) task up front so independent Ollama
    # requests can run concurrently instead of one at a time.
    tasks: list[_ChunkTask] = []
    for category, res_list in categories.items():
        if category in _LLM_SKIP_CATEGORIES:
            console.print(
                f"  Skipping [dim]{category}[/dim] "
                f"({len(res_list)} resources — low LLM value, rules already cover it)"
            )
            continue

        capped = res_list[: chunk_size * max_chunks]
        if len(capped) < len(res_list):
            console.print(
                f"  [yellow]⚠ {category}: analyzing {len(capped)}/{len(res_list)} "
                f"resources — chunk cap reached, {len(res_list) - len(capped)} skipped[/yellow]"
            )

        chunks = [capped[i : i + chunk_size] for i in range(0, len(capped), chunk_size)]
        for idx, chunk in enumerate(chunks):
            # Exactly the resources that fit in the prompt: recommendations are
            # validated against these.
            kept = fit_resources([r.metadata for r in chunk])
            tasks.append(_ChunkTask(
                category, idx, len(chunks), chunk[: len(kept)], len(chunk) - len(kept)
            ))

    def _run_task(task: _ChunkTask) -> str:
        chunk_context: dict[str, int] = (
            {"chunk_index": task.chunk_idx, "total_chunks": task.total_chunks}
            if task.total_chunks > 1
            else {}
        )
        if task.omitted:
            chunk_context["omitted_resources"] = task.omitted
        prompt = client.build_category_prompt(
            task.category, [r.metadata for r in task.chunk],
            finding_by_cat.get(task.category, []), **chunk_context,
        )
        return client.generate(prompt)

    # Recommendations per task, kept in task order so dedup is deterministic.
    results: dict[int, list[dict]] = {}
    failed: list[str] = []
    max_workers = max(1, settings.llm_max_workers)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_task, task): n for n, task in enumerate(tasks)}
        for done, future in enumerate(as_completed(futures), start=1):
            n = futures[future]
            category, chunk_idx, total_chunks, chunk, _ = tasks[n]
            label = (
                f"chunk {chunk_idx + 1}/{total_chunks}" if total_chunks > 1 else "single chunk"
            )
            try:
                raw = future.result()
            except Exception:
                logger.warning(
                    "LLM analysis failed for %s (%s)", category, label, exc_info=True
                )
                failed.append(category)
                console.print(
                    f"  [{done}/{len(tasks)}] [red]Failed[/red] [cyan]{category}[/cyan] "
                    f"({len(chunk)} resources, {label})"
                )
                continue
            console.print(
                f"  [{done}/{len(tasks)}] Analyzed [cyan]{category}[/cyan] "
                f"({len(chunk)} resources, {label})"
            )
            if raw:
                results[n] = client.parse_recommendations(raw)

    # Rule findings already cover these; the LLM restating one adds nothing.
    seen = {_normalize_title(f.title) for f in findings}
    total = 0
    for n in sorted(results):
        category, _, _, chunk, _ = tasks[n]
        known = _known_tokens(chunk)
        for rec in results[n]:
            title = rec.get("title") or ""
            norm_title = _normalize_title(title)
            if not norm_title or norm_title in seen:
                continue
            unknown = _cited_tokens(f"{title} {rec.get('detail') or ''}") - known
            if unknown:
                logger.info(
                    "Dropped LLM recommendation %r: cites resources outside its chunk: %s",
                    title, ", ".join(sorted(unknown)),
                )
                continue
            seen.add(norm_title)
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

    return LLMRunResult(total, failed)
