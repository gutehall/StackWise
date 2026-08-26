"""StackWise CLI — Typer application with scan, analyze, report commands."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from stackwise import __version__
from stackwise.config import resolve_settings
from stackwise.utils.logging import setup_logging

app = typer.Typer(
    name="stackwise",
    help="AWS infrastructure scanner with local AI-powered recommendations.",
    no_args_is_help=True,
)
console = Console(stderr=True)


# ── Shared options ─────────────────────────────────────────

def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"stackwise {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V",
        callback=_version_callback, is_eager=True,
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
) -> None:
    """stackwise: scan → analyze → report."""
    setup_logging(verbose=verbose)


# ── scan ───────────────────────────────────────────────────

@app.command()
def scan(
    profile: str | None = typer.Option(None, "--profile", "-p", help="AWS profile name"),
    regions: str | None = typer.Option(None, "--regions", "-r", help="Comma-separated regions"),
    modules: str | None = typer.Option(
        None, "--modules", "-m",
        help="Comma-separated scanner modules",
    ),
    skip_cost_explorer: bool = typer.Option(
        False, "--skip-cost-explorer",
        help="Skip the Cost Explorer call in the cost module — it's the one scanner "
        "API that isn't free (ce:GetCostAndUsage bills $0.01/request).",
    ),
) -> None:
    """Scan AWS account and store results."""
    from stackwise.scanner.compute import COMPUTE_SCANNERS
    from stackwise.store.db import ScanDB
    from stackwise.utils.aws import create_session, get_account_id

    try:
        settings = resolve_settings(
            profile=profile, regions=regions, modules=modules,
            skip_cost_explorer=skip_cost_explorer,
        )
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    session = create_session(settings)

    console.print(f"[bold]stackwise v{__version__}[/bold] — scanning AWS account")

    try:
        account_id = get_account_id(session)
    except Exception as e:
        console.print(f"[red]Failed to get AWS account ID: {e}[/red]")
        console.print("Check your AWS credentials and profile configuration.")
        raise typer.Exit(1)

    console.print(f"  Account: [cyan]{account_id}[/cyan]")
    console.print(f"  Regions: {', '.join(settings.regions)}")
    console.print(f"  Modules: {', '.join(settings.modules)}")

    # Open DB
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    db_path = settings.scans_dir(account_id) / f"{ts}.db"
    db = ScanDB(db_path)
    scan_rec = db.create_scan(account_id, settings.regions, settings.modules)
    console.print(f"  Scan ID: [green]{scan_rec.id}[/green]")
    console.print(f"  DB: {db_path}")

    # Run scanners
    scanners = []
    if "compute" in settings.modules:
        scanners.extend(COMPUTE_SCANNERS)
    if "data" in settings.modules:
        from stackwise.scanner.data import DATA_SCANNERS
        scanners.extend(DATA_SCANNERS)
    if "network" in settings.modules:
        from stackwise.scanner.network import NETWORK_SCANNERS
        scanners.extend(NETWORK_SCANNERS)
    if "security" in settings.modules:
        from stackwise.scanner.security import SECURITY_SCANNERS
        scanners.extend(SECURITY_SCANNERS)
    if "observability" in settings.modules:
        from stackwise.scanner.observability import OBSERVABILITY_SCANNERS
        scanners.extend(OBSERVABILITY_SCANNERS)
    if "cost" in settings.modules:
        from stackwise.scanner.cost import CostScanner
        scanners.append(CostScanner(skip_cost_explorer=settings.skip_cost_explorer))
    if "discovery" in settings.modules:
        from stackwise.scanner.discovery import DISCOVERY_SCANNERS
        scanners.extend(DISCOVERY_SCANNERS)

    total_resources = 0
    max_workers = getattr(settings, "scan_max_workers", 1)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        for scanner in scanners:
            count = scanner.scan(
                session, db, scan_rec.id, settings.regions, progress,
                max_workers=max_workers,
            )
            total_resources += count

    console.print(
        f"\n[bold green]Scan complete:[/bold green] "
        f"{total_resources} resources collected"
    )
    db.close()

    # Store scan ID for subsequent commands
    _write_latest_scan(settings, account_id, scan_rec.id, db_path)


# ── analyze ────────────────────────────────────────────────

@app.command()
def analyze(
    profile: str | None = typer.Option(None, "--profile", "-p"),
    account: str | None = typer.Option(
        None, "--account", "-a",
        help="AWS account ID to analyze (default: last scanned account)",
    ),
    model: str | None = typer.Option(None, "--model", help="Ollama model name"),
    engine: str | None = typer.Option(None, "--engine", help="LLM engine: ollama, mlx, rules-only"),
    suppress: str | None = typer.Option(
        None, "--suppress", "-s",
        help="Comma-separated rule IDs to suppress (e.g. CMP-001,DAT-002)",
    ),
) -> None:
    """Run rule-based + AI analysis on the latest scan."""
    from stackwise.analyzer.engine import run_analysis
    from stackwise.store.db import ScanDB

    settings = resolve_settings(
        profile=profile, model=model, engine=engine,
        suppressed_rules=suppress,
    )
    db_path, scan_id = _read_latest_scan(settings, account_id=account)
    if not db_path:
        console.print("[red]No scan found. Run 'stackwise scan' first.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Analyzing scan {scan_id}[/bold] from {db_path}")
    db = ScanDB(db_path)
    run_analysis(settings, db, scan_id)
    db.close()

    console.print("\n[bold green]Analysis complete.[/bold green]")


# ── report ─────────────────────────────────────────────────

@app.command()
def report(
    report_type: str = typer.Option(
        "engineering", "--type", "-t",
        help="Report type: engineering, executive, architecture, all",
    ),
    output_format: str = typer.Option(
        "html", "--format", "-f",
        help="Output: html, pdf, md, json",
    ),
    output_dir: str | None = typer.Option(None, "--output-dir", "-o"),
    profile: str | None = typer.Option(None, "--profile", "-p"),
    account: str | None = typer.Option(
        None, "--account", "-a",
        help="AWS account ID (default: last scanned account)",
    ),
) -> None:
    """Generate reports from the latest analyzed scan."""
    from stackwise.report.generator import generate_report
    from stackwise.store.db import ScanDB

    settings = resolve_settings(profile=profile, output_dir=output_dir)
    db_path, scan_id = _read_latest_scan(settings, account_id=account)
    if not db_path:
        console.print("[red]No scan found. Run 'stackwise scan' first.[/red]")
        raise typer.Exit(1)

    db = ScanDB(db_path)

    types = ["engineering", "executive", "architecture"] if report_type == "all" else [report_type]
    any_failed = False
    for rt in types:
        try:
            path = generate_report(
                settings, db, scan_id,
                report_type=rt, output_format=output_format,
            )
            console.print(f"  [green]✓[/green] {rt} report → {path}")
        except Exception as e:
            console.print(f"  [red]✗[/red] {rt} report failed: {e}")
            any_failed = True

    db.close()

    if any_failed:
        raise typer.Exit(1)


# ── run (convenience) ──────────────────────────────────────

@app.command()
def run(
    profile: str | None = typer.Option(None, "--profile", "-p"),
    regions: str | None = typer.Option(None, "--regions", "-r"),
    modules: str | None = typer.Option(None, "--modules", "-m"),
    skip_cost_explorer: bool = typer.Option(
        False, "--skip-cost-explorer",
        help="Skip the Cost Explorer call in the cost module — it's the one scanner "
        "API that isn't free (ce:GetCostAndUsage bills $0.01/request).",
    ),
    model: str | None = typer.Option(None, "--model"),
    engine: str | None = typer.Option(None, "--engine"),
    suppress: str | None = typer.Option(None, "--suppress", "-s"),
    report_type: str = typer.Option("engineering", "--type", "-t"),
    output_format: str = typer.Option("html", "--format", "-f"),
    output_dir: str | None = typer.Option(None, "--output-dir", "-o"),
) -> None:
    """Scan → analyze → report in one command."""
    scan(
        profile=profile, regions=regions, modules=modules,
        skip_cost_explorer=skip_cost_explorer,
    )
    analyze(
        profile=profile,
        model=model,
        engine=engine,
        suppress=suppress,
        account=None,
    )
    report(
        report_type=report_type,
        output_format=output_format,
        output_dir=output_dir,
        profile=profile,
        account=None,
    )


# ── diff ────────────────────────────────────────────────────

@app.command()
def diff(
    profile: str | None = typer.Option(None, "--profile", "-p"),
    base: str | None = typer.Option(
        None, "--base", "-b",
        help="Path to base scan DB (default: previous scan)",
    ),
    compare: str | None = typer.Option(
        None, "--compare", "-c",
        help="Path to compare scan DB (default: latest scan)",
    ),
    output_format: str = typer.Option(
        "text", "--format", "-f",
        help="Output: text or json",
    ),
) -> None:
    """Compare two scans for drift detection (resources and findings)."""
    from stackwise.diff import diff_scans

    settings = resolve_settings(profile=profile)

    if compare:
        compare_path = Path(compare)
        if not compare_path.exists():
            console.print(f"[red]Compare path not found: {compare_path}[/red]")
            raise typer.Exit(1)
    else:
        db_path, scan_id = _read_latest_scan(settings)
        if not db_path or not db_path.exists():
            console.print("[red]No latest scan. Run 'stackwise scan' first.[/red]")
            raise typer.Exit(1)
        compare_path = db_path

    if base:
        base_path = Path(base)
        if not base_path.exists():
            console.print(f"[red]Base path not found: {base_path}[/red]")
            raise typer.Exit(1)
    else:
        # Only consider DBs from the same account as compare
        compare_account_dir = compare_path.parent
        all_dbs: list[tuple[Path, float]] = []
        for db_file in compare_account_dir.glob("*.db"):
            if db_file.resolve() != compare_path.resolve():
                all_dbs.append((db_file, db_file.stat().st_mtime))
        if not all_dbs:
            console.print("[red]No previous scan to compare. Use --base to specify.[/red]")
            raise typer.Exit(1)
        base_path = max(all_dbs, key=lambda x: x[1])[0]

    try:
        result = diff_scans(base_path, compare_path)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    if output_format == "json":
        payload = {
            "base_scan_id": result.base_scan_id,
            "compare_scan_id": result.compare_scan_id,
            "resources_added": [
                {"service": r.service, "resource_type": r.resource_type,
                 "resource_id": r.resource_id, "region": r.region}
                for r in result.resources_added
            ],
            "resources_removed": [
                {"service": r.service, "resource_type": r.resource_type,
                 "resource_id": r.resource_id, "region": r.region}
                for r in result.resources_removed
            ],
            "findings_added": [
                {"rule_id": f.rule_id, "severity": f.severity, "title": f.title}
                for f in result.findings_added
            ],
            "findings_removed": [
                {"rule_id": f.rule_id, "severity": f.severity, "title": f.title}
                for f in result.findings_removed
            ],
            "findings_unchanged": result.findings_unchanged,
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    console.print("[bold]Scan diff[/bold]")
    console.print(f"  Base:    {base_path.name} ({result.base_scan_id})")
    console.print(f"  Compare: {compare_path.name} ({result.compare_scan_id})")
    console.print("")

    console.print("[bold]Resources[/bold]")
    console.print(f"  [green]+{len(result.resources_added)}[/green] added")
    for r in result.resources_added[:10]:
        console.print(f"    + {r.service}/{r.resource_type} {r.resource_id} ({r.region})")
    if len(result.resources_added) > 10:
        console.print(f"    ... and {len(result.resources_added) - 10} more")
    console.print(f"  [red]-{len(result.resources_removed)}[/red] removed")
    for r in result.resources_removed[:10]:
        console.print(f"    - {r.service}/{r.resource_type} {r.resource_id} ({r.region})")
    if len(result.resources_removed) > 10:
        console.print(f"    ... and {len(result.resources_removed) - 10} more")
    console.print("")

    console.print("[bold]Findings[/bold]")
    console.print(f"  [green]+{len(result.findings_added)}[/green] new")
    for f in result.findings_added[:5]:
        console.print(f"    + [{f.severity}] {f.title}")
    if len(result.findings_added) > 5:
        console.print(f"    ... and {len(result.findings_added) - 5} more")
    console.print(f"  [red]-{len(result.findings_removed)}[/red] resolved")
    for f in result.findings_removed[:5]:
        console.print(f"    - [{f.severity}] {f.title}")
    if len(result.findings_removed) > 5:
        console.print(f"    ... and {len(result.findings_removed) - 5} more")
    console.print(f"  [dim]={result.findings_unchanged} unchanged[/dim]")


# ── list-scans ─────────────────────────────────────────────

@app.command("list-scans")
def list_scans(
    profile: str | None = typer.Option(None, "--profile", "-p"),
) -> None:
    """List previous scan snapshots.

    If --profile is given, only shows scans for the account last scanned under
    that profile (scans are stored by account ID, not profile — there's no
    other way to know which account a profile maps to without a live AWS call).
    """
    settings = resolve_settings(profile=profile)
    scans_base = settings.data_dir / "scans"
    if not scans_base.exists():
        console.print("No scans found.")
        raise typer.Exit()

    account_filter: str | None = None
    if profile:
        last_account = _last_account_file(settings)
        if last_account.exists():
            account_filter = last_account.read_text().strip()
        else:
            console.print(
                f"[yellow]No recorded scan for profile '{profile}' — "
                f"showing all accounts.[/yellow]"
            )

    table = Table(title="Scan History")
    table.add_column("Account", style="cyan")
    table.add_column("Timestamp")
    table.add_column("Database")
    table.add_column("Size")

    for account_dir in sorted(scans_base.iterdir()):
        if not account_dir.is_dir():
            continue
        if account_filter and account_dir.name != account_filter:
            continue
        for db_file in sorted(account_dir.glob("*.db"), reverse=True):
            size_kb = db_file.stat().st_size / 1024
            table.add_row(
                account_dir.name,
                db_file.stem,
                str(db_file),
                f"{size_kb:.1f} KB",
            )

    console.print(table)


# ── Helpers ────────────────────────────────────────────────

def _latest_scan_file(settings, account_id: str) -> Path:
    """Path to per-account latest scan marker."""
    return settings.data_dir / "scans" / account_id / ".latest"


def _profile_key(settings) -> str:
    """Filesystem-safe key identifying the active AWS profile (or 'default')."""
    raw = settings.profile or "default"
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in raw)


def _last_account_file(settings) -> Path:
    """Path to file storing the last account scanned under the active profile.

    Scoped per profile so switching --profile doesn't silently resolve
    analyze/report against a stale account scanned under a different profile.
    """
    return settings.data_dir / f".last_account.{_profile_key(settings)}"


def _write_latest_scan(settings, account_id: str, scan_id: str, db_path: Path) -> None:
    f = _latest_scan_file(settings, account_id)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(f"{db_path}\n{scan_id}\n")
    last_account = _last_account_file(settings)
    last_account.parent.mkdir(parents=True, exist_ok=True)
    last_account.write_text(account_id)


def _read_latest_scan(
    settings, account_id: str | None = None
) -> tuple[Path | None, str | None]:
    """Read latest scan. If account_id not given, use last scanned account."""
    if not account_id:
        last_account = _last_account_file(settings)
        if last_account.exists():
            account_id = last_account.read_text().strip()
        else:
            # Migration: old .latest_scan at data_dir root
            legacy = settings.data_dir / ".latest_scan"
            if legacy.exists():
                lines = legacy.read_text().strip().split("\n")
                if len(lines) >= 2:
                    return Path(lines[0]), lines[1]
            return None, None
    f = _latest_scan_file(settings, account_id)
    if not f.exists():
        return None, None
    lines = f.read_text().strip().split("\n")
    if len(lines) < 2:
        return None, None
    return Path(lines[0]), lines[1]
