"""End-to-end tests driving the actual Typer commands (not just their helper
functions), against a moto-mocked AWS account. Catches wiring bugs — argument
passing, exit codes, profile/account resolution — that unit tests on
individual functions can't see."""

from __future__ import annotations

import json
from pathlib import Path

import boto3
from moto import mock_aws
from typer.testing import CliRunner

from stackwise.cli import app

runner = CliRunner()


@mock_aws
def test_scan_analyze_report_end_to_end(tmp_path: Path, monkeypatch):
    """scan -> analyze -> report through the real CLI commands, rules-only
    (no Ollama dependency), against a single mocked EC2 instance."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.run_instances(ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1)

    scan_result = runner.invoke(
        app, ["scan", "--regions", "us-east-1", "--modules", "compute"]
    )
    assert scan_result.exit_code == 0, scan_result.output

    analyze_result = runner.invoke(app, ["analyze", "--engine", "rules-only"])
    assert analyze_result.exit_code == 0, analyze_result.output

    output_dir = tmp_path / "reports"
    report_result = runner.invoke(
        app,
        [
            "report", "--type", "engineering", "--format", "json",
            "--output-dir", str(output_dir),
        ],
    )
    assert report_result.exit_code == 0, report_result.output

    json_files = list(output_dir.glob("*.json"))
    assert len(json_files) == 1
    payload = json.loads(json_files[0].read_text())
    assert payload["summary"]["resources"] >= 1
    # CMP-001 fires because the instance has no PublicIpAddress metadata? No —
    # it should NOT fire here since the instance has no public IP by default.
    assert "findings" in payload


@mock_aws
def test_scan_skip_cost_explorer_flag(tmp_path: Path, monkeypatch):
    """--skip-cost-explorer through the real scan command must skip the
    billable ce.get_cost_and_usage call while still scanning the rest of
    the cost module (tagged resources, Compute Optimizer)."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="my-tagged-bucket")
    s3.put_bucket_tagging(
        Bucket="my-tagged-bucket", Tagging={"TagSet": [{"Key": "Env", "Value": "prod"}]}
    )

    result = runner.invoke(
        app,
        ["scan", "--regions", "us-east-1", "--modules", "cost", "--skip-cost-explorer"],
    )
    assert result.exit_code == 0, result.output

    db_files = list((tmp_path / "data" / "scans").glob("*/*.db"))
    assert len(db_files) == 1
    from stackwise.store.db import ScanDB

    db = ScanDB(db_files[0])
    scan = db.latest_scan()
    resources = db.get_resources(scan.id)
    db.close()

    assert not any(r.service == "ce" and r.resource_type == "cost_summary" for r in resources)
    assert any(r.resource_type == "tagged_resource" for r in resources)


@mock_aws
def test_scan_rejects_unknown_module(tmp_path: Path, monkeypatch):
    """A typo'd --modules value must fail loudly, not scan zero resources
    and report success (this is the config.py validation exercised through
    the actual scan command, not just resolve_settings() directly)."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    result = runner.invoke(app, ["scan", "--modules", "compute-typo"])
    assert result.exit_code == 1
    assert "compute-typo" in result.output


@mock_aws
def test_analyze_without_prior_scan_fails_cleanly(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    result = runner.invoke(app, ["analyze", "--engine", "rules-only"])
    assert result.exit_code == 1
    assert "No scan found" in result.output


@mock_aws
def test_switching_profile_does_not_analyze_stale_account(tmp_path: Path, monkeypatch):
    """Scan under one profile, then analyze under a different profile without
    --account: must not silently resolve to the first profile's scan data."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    # boto3 profile resolution reads real credentials files, not env vars —
    # moto only mocks the AWS API calls, not this. Point boto3 at a throwaway
    # credentials file with a 'dev' and a 'prod' profile (both same fake creds;
    # moto doesn't care which account they resolve to).
    creds_file = tmp_path / "credentials"
    creds_file.write_text(
        "[dev]\naws_access_key_id = testing\naws_secret_access_key = testing\n\n"
        "[prod]\naws_access_key_id = testing\naws_secret_access_key = testing\n"
    )
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))

    scan_result = runner.invoke(
        app, ["scan", "--profile", "dev", "--regions", "us-east-1", "--modules", "compute"]
    )
    assert scan_result.exit_code == 0, scan_result.output

    analyze_result = runner.invoke(app, ["analyze", "--profile", "prod", "--engine", "rules-only"])
    assert analyze_result.exit_code == 1
    assert "No scan found" in analyze_result.output

    # But re-checking under the original profile still resolves correctly.
    same_profile_result = runner.invoke(
        app, ["analyze", "--profile", "dev", "--engine", "rules-only"]
    )
    assert same_profile_result.exit_code == 0, same_profile_result.output


@mock_aws
def test_report_all_types_exits_nonzero_if_any_fail(tmp_path: Path, monkeypatch):
    """report --type all must exit 1 if any individual report type fails,
    not silently succeed with a red X printed and exit code 0."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    scan_result = runner.invoke(
        app, ["scan", "--regions", "us-east-1", "--modules", "compute"]
    )
    assert scan_result.exit_code == 0, scan_result.output

    bad_dir = tmp_path / "not-writable-reports"
    bad_dir.mkdir()
    bad_dir.chmod(0o400)  # read-only: report generation should fail to write files
    try:
        result = runner.invoke(
            app,
            ["report", "--type", "all", "--format", "html", "--output-dir", str(bad_dir)],
        )
        assert result.exit_code == 1, result.output
    finally:
        bad_dir.chmod(0o700)
