# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

StackWise scans an AWS account, evaluates the resources against a YAML rule set, optionally
enriches findings with a local LLM (via Ollama — no data leaves the machine), and renders
engineering/executive/architecture reports (HTML/PDF/Markdown/JSON). It also does scan-to-scan
drift diffing. Read-only against AWS — see `docs/iam-policy.json`.

## Commands

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Tests
pytest                                          # full suite
pytest tests/test_analyzer/test_rules.py        # one file
pytest tests/test_analyzer/test_rules.py::test_evaluate_public_ip_rule   # one test
pytest -v --cov=src/stackwise --cov-report=term-missing   # matches CI

# Lint
ruff check src/ tests/

# Run the CLI locally
stackwise scan --profile my-aws-profile --regions eu-west-1,us-east-1 --modules compute
stackwise analyze --profile my-aws-profile
stackwise report --type engineering --format html
stackwise run ...      # scan + analyze + report in one command
stackwise diff          # drift vs. previous scan
stackwise list-scans
```

CI (`.github/workflows/ci.yml`) runs `pytest -v --cov=...` and `ruff check src/ tests/` on
Python 3.11 and 3.12, Ubuntu and macOS. Match that before considering work done.

## Releases

Tagging is manual — nothing auto-tags on merge to main. Run the `/release` skill after landing a
bigger chunk of work (a feature, a batch of fixes, anything a user would want to pin to) to cut a
GitHub release and bump `CHANGELOG.md`. `.github/workflows/docker.yml` reacts to pushed `v*` tags
by building and pushing a matching `ghcr.io/gutehall/stackwise` image tag — releasing is what
makes that happen, not the other way around.

AWS calls in tests are mocked with `moto` (`@mock_aws`) or `unittest.mock` — never hit real AWS.
`tests/conftest.py` sets fake AWS credentials via env vars for every test automatically and
provides `settings` (temp-dir `Settings`) and `scan_db` (temp `ScanDB`) fixtures.

## Architecture

### Pipeline: scan → analyze → report

Each stage is a separate CLI command/DB pass, not one long-lived process:

1. **scan** (`cli.py` → `scanner/*.py`) — creates a new SQLite file at
   `~/.stackwise/scans/{account_id}/{timestamp}.db` (or `$STACKWISE_DATA_DIR`), runs the
   scanner modules requested by `--modules`, writes raw AWS resources into it. Also updates
   `.last_account.<profile>` and a per-account `.latest` pointer so later commands can find
   "the most recent scan" without re-specifying paths.
2. **analyze** (`analyzer/engine.py`) — loads the scan DB, evaluates YAML rules against stored
   resources (`analyzer/rules.py`), then optionally sends resources+findings to a local Ollama
   model for cross-cutting recommendations (`analyzer/llm_client.py`). Writes `findings` and
   `recommendations` rows back into the same scan DB.
3. **report** (`report/generator.py`) — reads the scan DB, renders one of three Jinja2
   templates (`report/templates/{engineering,executive,architecture}.html`) to HTML, PDF
   (WeasyPrint), Markdown, or JSON.

`stackwise run` just calls scan → analyze → report in sequence with the same flags.

### Scanners

Each AWS service area is a module under `src/stackwise/scanner/` (`compute.py`, `data.py`,
`network.py`, `security.py`, `observability.py`, `cost.py`, `discovery.py`) exporting a
`{MODULE}_SCANNERS: list[BaseScanner]` registry, e.g. `COMPUTE_SCANNERS`. Exception:
`cost.py`'s `CostScanner` isn't used via its registry in `cli.py` — it's constructed directly
so `--skip-cost-explorer`/`Settings.skip_cost_explorer` can be passed in, since
`ce:GetCostAndUsage` is the one scanner call that isn't a free control-plane API (bills
$0.01/request). `cli.py scan()`
imports only the registries for modules the user asked for and lazily adds their scanners to
the run.

`BaseScanner` (`scanner/base.py`) is the only contract: subclasses implement
`_scan_region(session, db, scan_id, region) -> int`. The base `scan()` method fans that out
across regions (optionally via `ThreadPoolExecutor` — `scan_max_workers`) and reports progress.
Global/non-regional services (IAM, S3 bucket listing, Cost Explorer) guard themselves with
`if region != "us-east-1": return 0` inside `_scan_region` rather than being special-cased by
the driver.

`utils/aws.py` centralizes session/client creation: `regional_client()` always applies the
shared adaptive-retry `Config`, `paginate()` wraps a boto3 paginator into a flat list. Use
these instead of calling `session.client()` directly so retry/pagination behavior stays
consistent across scanners.

Resource identity within a scan is `(scan_id, service, resource_type, resource_id, region)` —
enforced by a unique index in `store/db.py`, with `insert_resource()` returning the existing
row on conflict. This matters when two scanner modules can observe the same underlying AWS
resource (e.g. `cost` and `discovery` both call `resourcegroupstaggingapi.get_resources`) —
don't reintroduce duplicate storage by bypassing `insert_resource()`.

### Rules

Rules live in `src/stackwise/rules/*.yaml` (one file per scanner module: `compute.yaml`,
`data.yaml`, etc. — inside the package so they're bundled in built wheels, not just editable
installs),
loaded by `analyzer/rules.py::load_rules()`. Each rule has `id`, `title`, `severity`,
`resource_type`, `service`, a `condition` (a Python expression string), and `remediation`.
`condition` is evaluated with `eval()` against a restricted builtins set (`_SAFE_BUILTINS`) and
`resource` bound to that resource's metadata dict — conditions can use `len`/`any`/`all`/etc.
but not imports or I/O. A resource is matched against a rule only if its `resource_type` (and
`service`, if set) matches.

`STACKWISE_RULES_DIR` env var overrides the rules directory (also used to find `/app/rules` in
the Docker image). When adding a rule, check what fields the corresponding scanner actually
populates in resource metadata — several past bugs here were rules checking a field name that
doesn't match what the scanner stores (see e.g. `EFS`'s `LifecyclePolicies` vs. `LifeCycleState`,
or a boolean flag the scanner never set on API failure). If a check can fail for reasons other
than "the setting is actually disabled" (permissions, throttling), the scanner should record a
`*CheckFailed` flag in metadata and the rule condition should exclude that case — see the
`VersioningCheckFailed`/`EncryptionCheckFailed`/etc. pattern in `scanner/data.py` and
`scanner/security.py` and the corresponding guards in `src/stackwise/rules/data.yaml` /
`src/stackwise/rules/security.yaml`.

### Storage

`store/db.py::ScanDB` wraps one SQLite file per scan (`scans`, `resources`, `findings`,
`recommendations` tables). It's created fresh per `stackwise scan` invocation — there's no
cross-scan schema migration story beyond "the schema is additive and idempotent"; `ScanDB.__init__`
re-runs `CREATE TABLE IF NOT EXISTS` / index creation on every open, so schema changes must stay
backward-compatible with already-written scan files.

### Diff / drift

`diff.py::diff_scans()` opens two `ScanDB` files (default: latest vs. previous scan for the
same account) and computes added/removed resources and findings by identity-key set difference.
Both DB connections are guaranteed closed via `try/finally`, including on error paths.

### Config

`config.py::Settings` / `resolve_settings()` merges CLI flags → env vars → defaults. `us-east-1`
is always force-included in `regions` since several services (IAM, GuardDuty, Cost Explorer) are
only scannable there. `auto_select_engine()` picks MLX on Apple Silicon (if `mlx_lm` installed),
falls back to Ollama, falls back to rules-only — MLX isn't actually implemented yet
(`analyzer/engine.py` falls back to Ollama with a warning if `Engine.MLX` is selected).

### CLI plumbing worth knowing

- `_last_account_file()` / `_read_latest_scan()` / `_write_latest_scan()` in `cli.py` resolve
  "the most recent scan" scoped by AWS profile (`.last_account.<profile>`) so switching
  `--profile` between commands can't silently resolve against the wrong account's data.
- `--modules` is validated against `config.ALL_MODULES`; unknown values raise instead of
  silently running zero scanners.
