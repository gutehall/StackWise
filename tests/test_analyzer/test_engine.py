"""Tests for the analysis engine: chunking, deduplication."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from stackwise.analyzer.engine import (
    EngineUnavailableError,
    _normalize_title,
    _run_llm_analysis,
    run_analysis,
)
from stackwise.analyzer.llm_client import LLMChunkError, OllamaClient
from stackwise.analyzer.rules import RulesLoadError, load_rules_checked
from stackwise.config import Engine, Settings
from stackwise.store.db import ScanDB


def test_llm_analysis_deduplicates_recommendations(scan_db: ScanDB, tmp_path: Path):
    """Duplicate recommendations from same category should be deduplicated."""
    settings = Settings(
        engine=Engine.OLLAMA,
        llm_chunk_size=50,
        llm_max_chunks=10,
        data_dir=tmp_path / "stackwise",
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    # Add two resources
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1",
        metadata={"InstanceId": "i-1", "InstanceType": "t3.micro"},
    )
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-2", "us-east-1",
        metadata={"InstanceId": "i-2", "InstanceType": "t3.micro"},
    )

    client = MagicMock()
    # Simulate same recommendation returned twice (e.g. from two chunks)
    client.generate.return_value = (
        '[{"category": "cost", "title": "Enable S3 versioning", '
        '"detail": "x", "impact": "high", "effort": "low"}]'
    )
    dup_rec = {"category": "cost", "title": "Enable S3 versioning", "detail": "x",
               "impact": "high", "effort": "low"}
    client.parse_recommendations.side_effect = lambda x: [dup_rec, dup_rec]

    count = _run_llm_analysis(client, scan_db, scan.id, settings).count
    recs = scan_db.get_recommendations(scan.id)
    # Should deduplicate to 1
    assert count == 1
    assert len(recs) == 1
    assert recs[0].title == "Enable S3 versioning"


def test_llm_analysis_chunks_large_categories(scan_db: ScanDB, tmp_path: Path):
    """Categories with > chunk_size resources should be processed in chunks."""
    settings = Settings(
        engine=Engine.OLLAMA,
        llm_chunk_size=5,
        llm_max_chunks=10,
        data_dir=tmp_path / "stackwise",
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    for i in range(12):
        scan_db.insert_resource(
            scan.id, "ec2", "instance", f"i-{i}", "us-east-1",
            metadata={"InstanceId": f"i-{i}", "InstanceType": "t3.micro"},
        )

    client = MagicMock()
    client.generate.return_value = (
        '[{"category": "compute", "title": "Right-size", "detail": "y", '
        '"impact": "medium", "effort": "low"}]'
    )
    rightsize = {"category": "compute", "title": "Right-size", "detail": "y",
                 "impact": "medium", "effort": "low"}
    client.parse_recommendations.side_effect = lambda x: [rightsize]

    count = _run_llm_analysis(client, scan_db, scan.id, settings).count
    # Should have been called 3 times (chunks of 5, 5, 2)
    assert client.generate.call_count == 3
    # Should have 3 recommendations (one per chunk, no dedupe since same title)
    recs = scan_db.get_recommendations(scan.id)
    assert len(recs) == 1  # Deduplicated - same title from all chunks
    assert count == 1


def test_llm_analysis_skips_discovery_category(scan_db: ScanDB, tmp_path: Path):
    """Tag/inventory noise should never reach the LLM — rules already cover it."""
    settings = Settings(
        engine=Engine.OLLAMA,
        llm_chunk_size=50,
        llm_max_chunks=10,
        data_dir=tmp_path / "stackwise",
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["discovery"])
    scan_db.insert_resource(
        scan.id, "resourcegroupstaggingapi", "resource", "r-1", "us-east-1",
        metadata={"ResourceARN": "arn:aws:ec2:...:instance/i-1"},
    )

    client = MagicMock()
    count = _run_llm_analysis(client, scan_db, scan.id, settings).count

    client.generate.assert_not_called()
    assert count == 0


def test_llm_analysis_caps_resources_at_chunk_limit(scan_db: ScanDB, tmp_path: Path):
    """Resources beyond chunk_size * max_chunks are dropped, not sent unbounded."""
    settings = Settings(
        engine=Engine.OLLAMA,
        llm_chunk_size=2,
        llm_max_chunks=2,
        data_dir=tmp_path / "stackwise",
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    for i in range(10):
        scan_db.insert_resource(
            scan.id, "ec2", "instance", f"i-{i}", "us-east-1",
            metadata={"InstanceId": f"i-{i}"},
        )

    client = MagicMock()
    client.generate.return_value = "[]"
    client.parse_recommendations.return_value = []

    _run_llm_analysis(client, scan_db, scan.id, settings)

    # chunk_size=2 * max_chunks=2 → at most 4 resources → 2 chunks
    assert client.generate.call_count == 2


def test_llm_analysis_groups_findings_by_resource_category(scan_db: ScanDB, tmp_path: Path):
    """A finding tied to a resource must be grouped into that resource's
    category (not 'other') when building the LLM prompt."""
    settings = Settings(
        engine=Engine.OLLAMA, llm_chunk_size=50, llm_max_chunks=10,
        data_dir=tmp_path / "stackwise",
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    resource = scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1", metadata={"InstanceId": "i-1"}
    )
    scan_db.insert_finding(
        scan_id=scan.id, severity="HIGH", title="Public IP", resource_id=resource.id,
        rule_id="CMP-001",
    )

    client = MagicMock()
    client.generate.return_value = "[]"
    client.parse_recommendations.return_value = []

    _run_llm_analysis(client, scan_db, scan.id, settings)

    call_args = client.build_category_prompt.call_args
    findings_arg = call_args.args[2] if len(call_args.args) > 2 else call_args.kwargs["findings"]
    assert any(f["title"] == "Public IP" for f in findings_arg)


def test_llm_analysis_skips_chunk_with_empty_response(scan_db: ScanDB, tmp_path: Path):
    """An empty string response from the LLM (e.g. Ollama unreachable mid-run)
    must be skipped, not passed to parse_recommendations."""
    settings = Settings(
        engine=Engine.OLLAMA, llm_chunk_size=50, llm_max_chunks=10,
        data_dir=tmp_path / "stackwise",
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1", metadata={"InstanceId": "i-1"}
    )

    client = MagicMock()
    client.generate.return_value = ""

    count = _run_llm_analysis(client, scan_db, scan.id, settings).count

    client.parse_recommendations.assert_not_called()
    assert count == 0


def test_run_analysis_rules_only_skips_llm(scan_db: ScanDB, tmp_path: Path):
    settings = Settings(engine=Engine.RULES_ONLY, data_dir=tmp_path / "stackwise")
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])

    with patch("stackwise.analyzer.engine.OllamaClient") as mock_cls:
        result = run_analysis(settings, scan_db, scan.id)

    mock_cls.assert_not_called()
    assert result["llm_recommendations"] == 0


def test_run_analysis_ollama_unreachable(scan_db: ScanDB, tmp_path: Path):
    settings = Settings(engine=Engine.OLLAMA, data_dir=tmp_path / "stackwise")
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])

    mock_client = MagicMock()
    mock_client.is_available.return_value = False

    with patch("stackwise.analyzer.engine.OllamaClient", return_value=mock_client):
        result = run_analysis(settings, scan_db, scan.id)

    assert result["llm_recommendations"] == 0
    mock_client.ensure_model.assert_not_called()


def test_run_analysis_model_not_found(scan_db: ScanDB, tmp_path: Path):
    settings = Settings(
        engine=Engine.OLLAMA, model="missing-model", data_dir=tmp_path / "stackwise"
    )
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])

    mock_client = MagicMock()
    mock_client.is_available.return_value = True
    mock_client.ensure_model.return_value = False

    with patch("stackwise.analyzer.engine.OllamaClient", return_value=mock_client):
        result = run_analysis(settings, scan_db, scan.id)

    assert result["llm_recommendations"] == 0


@pytest.mark.parametrize(
    ("engine", "available", "has_model", "match"),
    [
        (Engine.MLX, True, True, "MLX engine is not implemented"),
        (Engine.OLLAMA, False, True, "Ollama is not reachable"),
        (Engine.OLLAMA, True, False, "is not in Ollama"),
    ],
    ids=["mlx", "ollama-down", "model-missing"],
)
def test_an_explicit_engine_that_cannot_run_fails_before_any_analysis(
    scan_db: ScanDB, tmp_path: Path, engine, available, has_model, match
):
    settings = Settings(engine=engine, engine_explicit=True, data_dir=tmp_path / "stackwise")
    scan_id = _scan_with_insecure_instances(scan_db)
    run_analysis(Settings(engine=Engine.RULES_ONLY, data_dir=tmp_path / "s"), scan_db, scan_id)
    before = sorted(f.id for f in scan_db.get_findings(scan_id))
    client = MagicMock()
    client.is_available.return_value = available
    client.ensure_model.return_value = has_model

    with (
        patch("stackwise.analyzer.engine.OllamaClient", return_value=client),
        pytest.raises(EngineUnavailableError, match=match),
    ):
        run_analysis(settings, scan_db, scan_id)

    assert sorted(f.id for f in scan_db.get_findings(scan_id)) == before


def test_an_auto_selected_engine_that_is_down_falls_back_to_rules(
    scan_db: ScanDB, tmp_path: Path
):
    settings = Settings(engine=Engine.OLLAMA, engine_explicit=False, data_dir=tmp_path / "s")
    scan_id = _scan_with_insecure_instances(scan_db)
    client = MagicMock()
    client.is_available.return_value = False

    with patch("stackwise.analyzer.engine.OllamaClient", return_value=client):
        result = run_analysis(settings, scan_db, scan_id)

    assert result["llm_recommendations"] == 0
    assert result["rule_findings"] > 0


def test_run_analysis_full_success_path_runs_llm(scan_db: ScanDB, tmp_path: Path):
    settings = Settings(engine=Engine.OLLAMA, data_dir=tmp_path / "stackwise")
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1", metadata={"InstanceId": "i-1"}
    )

    mock_client = MagicMock()
    mock_client.is_available.return_value = True
    mock_client.ensure_model.return_value = True
    mock_client.generate.return_value = "[]"
    mock_client.parse_recommendations.return_value = []

    with patch("stackwise.analyzer.engine.OllamaClient", return_value=mock_client):
        result = run_analysis(settings, scan_db, scan.id)

    assert "llm_recommendations" in result
    mock_client.generate.assert_called()


def _scan_with_insecure_instances(scan_db: ScanDB, n: int = 3) -> str:
    """Instances that allow IMDSv1, so CMP-008 produces one finding each."""
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    for i in range(n):
        scan_db.insert_resource(
            scan.id, "ec2", "instance", f"i-{i}", "us-east-1",
            metadata={"InstanceId": f"i-{i}", "MetadataOptions": {"HttpTokens": "optional"}},
        )
    return scan.id


def _imds_findings(scan_db: ScanDB, scan_id: str) -> list:
    return [f for f in scan_db.get_findings(scan_id) if f.rule_id == "CMP-008"]


def _llm_client(titles: list[str]) -> MagicMock:
    client = MagicMock()
    client.is_available.return_value = True
    client.ensure_model.return_value = True
    client.generate.return_value = "raw"
    client.parse_recommendations.return_value = [{"title": t} for t in titles]
    return client


def test_running_analysis_twice_keeps_one_set_of_findings(scan_db: ScanDB, tmp_path: Path):
    settings = Settings(engine=Engine.RULES_ONLY, data_dir=tmp_path / "stackwise")
    scan_id = _scan_with_insecure_instances(scan_db)

    run_analysis(settings, scan_db, scan_id)
    first = len(scan_db.get_findings(scan_id))
    run_analysis(settings, scan_db, scan_id)

    assert first > 0
    assert len(scan_db.get_findings(scan_id)) == first
    assert len(_imds_findings(scan_db, scan_id)) == 3


def test_a_failed_insert_keeps_the_previous_findings(scan_db: ScanDB, tmp_path: Path):
    settings = Settings(engine=Engine.RULES_ONLY, data_dir=tmp_path / "stackwise")
    scan_id = _scan_with_insecure_instances(scan_db)
    run_analysis(settings, scan_db, scan_id)
    before = sorted(f.id for f in scan_db.get_findings(scan_id))

    real_insert = scan_db.insert_finding
    calls = []

    def _fail_on_second(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise sqlite3.OperationalError("disk I/O error")
        return real_insert(*args, **kwargs)

    with (
        patch.object(scan_db, "insert_finding", side_effect=_fail_on_second),
        pytest.raises(sqlite3.OperationalError, match="disk I/O error"),
    ):
        run_analysis(settings, scan_db, scan_id)

    assert sorted(f.id for f in scan_db.get_findings(scan_id)) == before


def test_a_failed_llm_phase_write_keeps_the_previous_findings_and_recommendations(
    scan_db: ScanDB, tmp_path: Path
):
    """A DB error while storing LLM results still rolls everything back, including
    the new findings already written in this transaction."""
    settings = Settings(engine=Engine.OLLAMA, data_dir=tmp_path / "stackwise")
    scan_id = _scan_with_insecure_instances(scan_db)
    with patch("stackwise.analyzer.engine.OllamaClient", return_value=_llm_client(["Old"])):
        run_analysis(settings, scan_db, scan_id)
    before = sorted(f.id for f in scan_db.get_findings(scan_id))

    with (
        patch("stackwise.analyzer.engine.OllamaClient", return_value=_llm_client(["New"])),
        patch.object(
            scan_db, "insert_recommendation",
            side_effect=sqlite3.OperationalError("disk I/O error"),
        ),
        pytest.raises(sqlite3.OperationalError, match="disk I/O error"),
    ):
        run_analysis(settings, scan_db, scan_id)

    assert sorted(f.id for f in scan_db.get_findings(scan_id)) == before
    assert [r.title for r in scan_db.get_recommendations(scan_id)] == ["Old"]
    assert scan_db.get_analysis_status(scan_id)["llm_status"] == "complete"


def test_llm_recommendations_are_replaced_only_when_the_llm_runs(
    scan_db: ScanDB, tmp_path: Path
):
    scan_id = _scan_with_insecure_instances(scan_db)
    scan_db.insert_recommendation(scan_id=scan_id, source="rule", category="x", title="Rule rec")
    ollama = Settings(engine=Engine.OLLAMA, data_dir=tmp_path / "stackwise")

    with patch("stackwise.analyzer.engine.OllamaClient", return_value=_llm_client(["First"])):
        run_analysis(ollama, scan_db, scan_id)
    with patch("stackwise.analyzer.engine.OllamaClient", return_value=_llm_client(["Second"])):
        run_analysis(ollama, scan_db, scan_id)
    assert sorted(r.title for r in scan_db.get_recommendations(scan_id)) == ["Rule rec", "Second"]

    # A rules-only run produces no recommendations, so it must not delete these.
    run_analysis(
        Settings(engine=Engine.RULES_ONLY, data_dir=tmp_path / "stackwise"), scan_db, scan_id
    )
    assert sorted(r.title for r in scan_db.get_recommendations(scan_id)) == ["Rule rec", "Second"]


_GOOD_RULE = """
- id: TST-001
  title: "Instance allows IMDSv1"
  severity: MEDIUM
  resource_type: instance
  service: ec2
  condition: |
    (resource.get('MetadataOptions') or {}).get('HttpTokens') != 'required'
  remediation: Require IMDSv2.
"""

_REJECTED_RULE = """
- id: TST-002
  title: "Tries an import"
  severity: HIGH
  resource_type: instance
  service: ec2
  condition: |
    __import__('os').system('true')
  remediation: n/a
"""


def _rules_dir(tmp_path: Path, files: dict[str, str]) -> Path:
    d = tmp_path / "rules"
    d.mkdir()
    for name, text in files.items():
        (d / name).write_text(text)
    return d


@pytest.mark.parametrize(
    "files",
    [
        {"good.yaml": _GOOD_RULE, "broken.yaml": "- id: [unclosed"},
        {"good.yaml": _GOOD_RULE + _REJECTED_RULE},
    ],
    ids=["syntax-error", "rejected-rule"],
)
def test_a_broken_packaged_rules_file_aborts_and_keeps_previous_findings(
    scan_db: ScanDB, tmp_path: Path, monkeypatch, files: dict[str, str]
):
    monkeypatch.delenv("STACKWISE_RULES_DIR", raising=False)
    settings = Settings(engine=Engine.RULES_ONLY, data_dir=tmp_path / "stackwise")
    scan_id = _scan_with_insecure_instances(scan_db)
    run_analysis(settings, scan_db, scan_id)
    before = sorted(f.id for f in scan_db.get_findings(scan_id))

    broken = _rules_dir(tmp_path, files)
    with (
        patch("stackwise.analyzer.rules._default_rules_dir", return_value=broken),
        pytest.raises(RulesLoadError, match="packaged rules failed to load"),
    ):
        run_analysis(settings, scan_db, scan_id)

    assert sorted(f.id for f in scan_db.get_findings(scan_id)) == before


def test_a_rejected_override_rule_is_reported_and_the_rest_still_run(
    scan_db: ScanDB, tmp_path: Path, monkeypatch
):
    rules = _rules_dir(
        tmp_path, {"mine.yaml": _GOOD_RULE + _REJECTED_RULE, "bad.yaml": "- id: [unclosed"}
    )
    monkeypatch.setenv("STACKWISE_RULES_DIR", str(rules))
    settings = Settings(engine=Engine.RULES_ONLY, data_dir=tmp_path / "stackwise")
    scan_id = _scan_with_insecure_instances(scan_db, n=2)

    result = run_analysis(settings, scan_db, scan_id)

    findings = scan_db.get_findings(scan_id)
    assert len([f for f in findings if f.rule_id == "TST-001"]) == 2
    notice = [f for f in findings if f.rule_id == "RULES-LOAD"]
    assert len(notice) == 1
    assert notice[0].severity == "INFO"
    assert "TST-002" in notice[0].detail and "bad.yaml" in notice[0].detail
    assert result["rule_findings"] == 3


def test_a_missing_override_directory_is_reported(scan_db: ScanDB, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_RULES_DIR", str(tmp_path / "nope"))
    settings = Settings(engine=Engine.RULES_ONLY, data_dir=tmp_path / "stackwise")
    scan_id = _scan_with_insecure_instances(scan_db, n=1)

    run_analysis(settings, scan_db, scan_id)

    [notice] = scan_db.get_findings(scan_id)
    assert notice.rule_id == "RULES-LOAD"
    assert "directory not found" in notice.detail


def test_the_packaged_rules_load_cleanly():
    """The shipped rules must never trip the abort."""
    loaded = load_rules_checked()
    assert loaded.problems == []
    assert loaded.rules


def test_a_file_that_fails_part_way_contributes_no_rules(tmp_path: Path):
    """It is reported as failed, so none of its rules may run."""
    rules_dir = _rules_dir(
        tmp_path, {"mixed.yaml": _GOOD_RULE + "\n- id: TST-003\n  title: missing fields\n"}
    )

    loaded = load_rules_checked(rules_dir)

    assert [r.id for r in loaded.rules] == []
    assert loaded.failed_files == ["mixed.yaml (KeyError)"]


# ── Partial LLM runs, citation checks, dedup (DM3-360) ─────────


def _ollama(tmp_path: Path, **kwargs) -> Settings:
    return Settings(engine=Engine.OLLAMA, data_dir=tmp_path / "stackwise", **kwargs)


def _rec(title: str, detail: str = "Why it matters.", category: str = "reliability") -> dict:
    return {"category": category, "title": title, "detail": detail,
            "impact": "high", "effort": "low"}


def _real_prompt_client(responses: dict[str, object]) -> MagicMock:
    """A client that builds real prompts and answers per category.

    A value that is an exception is raised from generate; otherwise it's the list of
    recommendations parse_recommendations returns for that category's prompt.
    """
    client = MagicMock()
    client.is_available.return_value = True
    client.ensure_model.return_value = True
    client.build_category_prompt.side_effect = OllamaClient.build_category_prompt

    def _generate(prompt: str) -> str:
        category = prompt.split(" resources", 1)[0].removeprefix("## ")
        answer = responses.get(category, [])
        if isinstance(answer, Exception):
            raise answer
        return category

    client.generate.side_effect = _generate
    client.parse_recommendations.side_effect = lambda raw: responses.get(raw, [])
    return client


def _two_category_scan(scan_db: ScanDB) -> str:
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute", "data"])
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-0123456789abcdef0", "us-east-1",
        arn="arn:aws:ec2:us-east-1:123:instance/i-0123456789abcdef0",
        metadata={
            "InstanceId": "i-0123456789abcdef0",
            "MetadataOptions": {"HttpTokens": "optional"},
            "SecurityGroups": [{"GroupId": "sg-0aaaabbbbccccdddd"}],
        },
    )
    scan_db.insert_resource(
        scan.id, "s3", "bucket", "my-bucket", "us-east-1",
        arn="arn:aws:s3:::my-bucket", metadata={"Name": "my-bucket"},
    )
    return scan.id


def test_a_failed_chunk_keeps_the_other_categories_and_marks_the_run_partial(
    scan_db: ScanDB, tmp_path: Path
):
    scan_id = _two_category_scan(scan_db)
    client = _real_prompt_client({
        "compute": LLMChunkError("timed out"),
        "data": [_rec("Enable bucket replication")],
    })

    with patch("stackwise.analyzer.engine.OllamaClient", return_value=client):
        result = run_analysis(_ollama(tmp_path), scan_db, scan_id)

    assert result["llm_recommendations"] == 1
    assert [r.title for r in scan_db.get_recommendations(scan_id)] == [
        "Enable bucket replication"
    ]
    status = scan_db.get_analysis_status(scan_id)
    assert status["llm_status"] == "partial"
    assert status["failed_categories"] == ["compute"]
    # Rule findings were committed with the rest.
    assert any(f.rule_id == "CMP-008" for f in scan_db.get_findings(scan_id))


def test_a_run_with_no_failed_chunk_is_complete(scan_db: ScanDB, tmp_path: Path):
    scan_id = _two_category_scan(scan_db)
    client = _real_prompt_client({"data": [_rec("Enable bucket replication")]})
    with patch("stackwise.analyzer.engine.OllamaClient", return_value=client):
        run_analysis(_ollama(tmp_path), scan_db, scan_id)

    status = scan_db.get_analysis_status(scan_id)
    assert status["llm_status"] == "complete"
    assert status["failed_categories"] == []


def test_a_rules_only_run_leaves_the_status_row_alone(scan_db: ScanDB, tmp_path: Path):
    scan_id = _two_category_scan(scan_db)
    client = _real_prompt_client({"compute": LLMChunkError("timed out")})
    with patch("stackwise.analyzer.engine.OllamaClient", return_value=client):
        run_analysis(_ollama(tmp_path), scan_db, scan_id)
    before = scan_db.get_analysis_status(scan_id)

    run_analysis(
        Settings(engine=Engine.RULES_ONLY, data_dir=tmp_path / "stackwise"), scan_db, scan_id
    )

    assert scan_db.get_analysis_status(scan_id) == before


def test_a_rules_only_run_writes_no_status(scan_db: ScanDB, tmp_path: Path):
    scan_id = _two_category_scan(scan_db)
    run_analysis(
        Settings(engine=Engine.RULES_ONLY, data_dir=tmp_path / "stackwise"), scan_db, scan_id
    )
    assert scan_db.get_analysis_status(scan_id) is None


@pytest.mark.parametrize(
    ("title", "detail", "stored"),
    [
        ("Restrict sg-0aaaabbbbccccdddd", "Open to the world.", True),
        ("Harden instance", "arn:aws:ec2:us-east-1:123:instance/i-0123456789abcdef0.", True),
        ("Use spot capacity", "Saves money.", True),
        ("Stop i-0fffffffffffffff0", "It is idle.", False),
        ("Harden instance", "See arn:aws:ec2:us-east-1:123:instance/i-0fffffffffffffff0", False),
        # In the scan, but in another category's chunk.
        ("Encrypt bucket", "arn:aws:s3:::my-bucket is unencrypted.", False),
        # An AWS-managed policy isn't a resource in the scan, so naming it is fine.
        ("Use a managed policy", "Attach arn:aws:iam::aws:policy/ReadOnlyAccess.", True),
    ],
    ids=["id-in-metadata", "arn-in-chunk", "no-ids", "unknown-id", "unknown-arn",
         "other-chunk", "aws-managed-arn"],
)
def test_a_recommendation_citing_a_resource_outside_its_chunk_is_dropped(
    scan_db: ScanDB, tmp_path: Path, title: str, detail: str, stored: bool
):
    scan_id = _two_category_scan(scan_db)
    client = _real_prompt_client({"compute": [_rec(title, detail)]})

    result = _run_llm_analysis(client, scan_db, scan_id, _ollama(tmp_path))

    titles = [r.title for r in scan_db.get_recommendations(scan_id)]
    assert (titles == [title]) is stored
    assert result.count == int(stored)


def test_llm_titles_matching_a_rule_finding_or_another_category_are_stored_once(
    scan_db: ScanDB, tmp_path: Path
):
    scan_id = _two_category_scan(scan_db)
    scan_db.insert_finding(
        scan_id=scan_id, severity="MEDIUM", title="Instance allows IMDSv1", rule_id="CMP-008"
    )
    client = _real_prompt_client({
        "compute": [_rec("instance  ALLOWS imdsv1!"), _rec("Add a backup plan.")],
        "data": [_rec("add a backup plan", category="cost")],
    })

    result = _run_llm_analysis(client, scan_db, scan_id, _ollama(tmp_path))

    assert [r.title for r in scan_db.get_recommendations(scan_id)] == ["Add a backup plan."]
    assert result.count == 1


def test_normalize_title():
    assert _normalize_title("  Enable  MFA, now!  ") == "enable mfa now"


def test_the_validation_set_is_exactly_the_resources_in_the_prompt(
    scan_db: ScanDB, tmp_path: Path
):
    """Resources dropped to fit the prompt can't be cited either."""
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    ids = [f"i-{n:017x}" for n in range(40)]
    for rid in ids:
        scan_db.insert_resource(
            scan.id, "ec2", "instance", rid, "us-east-1",
            metadata={"InstanceId": rid, "padding": "x" * 1000},
        )
    prompts: list[str] = []
    client = _real_prompt_client({})

    def _generate(prompt: str) -> str:
        prompts.append(prompt)
        return "compute"

    client.generate.side_effect = _generate
    client.parse_recommendations.side_effect = lambda raw: [
        _rec(f"Stop {rid}") for rid in ids
    ]

    _run_llm_analysis(client, scan_db, scan.id, _ollama(tmp_path, llm_chunk_size=50))

    [prompt] = prompts
    shown = json.loads(prompt.split("### Resources\n", 1)[1].split("\n", 1)[0])
    shown_ids = [r["InstanceId"] for r in shown]
    assert 0 < len(shown_ids) < len(ids)
    assert f"{len(ids) - len(shown_ids)} resources" in prompt
    stored = sorted(r.title for r in scan_db.get_recommendations(scan.id))
    assert stored == sorted(f"Stop {rid}" for rid in shown_ids)
