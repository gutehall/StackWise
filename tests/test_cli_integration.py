"""End-to-end tests driving the actual Typer commands (not just their helper
functions), against a moto-mocked AWS account. Catches wiring bugs — argument
passing, exit codes, profile/account resolution — that unit tests on
individual functions can't see."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from botocore.client import BaseClient
from botocore.exceptions import ClientError
from moto import mock_aws
from typer.testing import CliRunner

from stackwise import __version__
from stackwise.cli import app
from stackwise.scanner.compute import EC2Scanner
from stackwise.store.db import ScanDB

runner = CliRunner()

_real_make_api_call = BaseClient._make_api_call


@pytest.fixture
def _compute_optimizer_empty():
    """moto doesn't implement compute-optimizer (every call is a 404 "Not yet
    implemented"), and a failed list call now fails the scan. Answer those calls
    with an empty result so tests of the cost module can reach a clean exit."""

    def _make_api_call(self, operation_name, api_params):
        if self.meta.service_model.service_name == "compute-optimizer":
            return {}
        return _real_make_api_call(self, operation_name, api_params)

    with patch.object(BaseClient, "_make_api_call", _make_api_call):
        yield


def _invoke_scans_with_distinct_timestamps(*arg_lists):
    """Invoke the CLI once per arg_list, forcing each scan() call to get a
    later timestamp, so the order of the db filenames is deterministic."""
    base = datetime(2024, 1, 1, tzinfo=UTC)
    results = []
    for i, args in enumerate(arg_lists):
        with patch("stackwise.cli.datetime") as mock_dt:
            mock_dt.now.return_value = base + timedelta(seconds=i)
            results.append(runner.invoke(app, args))
    return results


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


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
def test_scan_skip_cost_explorer_flag(tmp_path: Path, monkeypatch, _compute_optimizer_empty):
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


@mock_aws
def test_scan_get_account_id_failure_exits_cleanly(tmp_path: Path, monkeypatch):
    """sts:GetCallerIdentity failing (bad/expired credentials) must print a
    clear error and exit 1, not crash with a raw traceback."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    with patch("stackwise.utils.aws.get_account_id", side_effect=RuntimeError("boom")):
        result = runner.invoke(app, ["scan", "--regions", "us-east-1", "--modules", "compute"])

    assert result.exit_code == 1
    assert "Failed to get AWS account ID" in result.output


@mock_aws
def test_scan_wires_every_scanner_module(
    tmp_path: Path, monkeypatch, _compute_optimizer_empty
):
    """--modules with every module name must actually import and run each
    scanner, not just the ones already covered by other integration tests."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    result = runner.invoke(
        app,
        [
            "scan", "--regions", "us-east-1",
            "--modules", "compute,data,network,security,observability,cost,discovery",
            "--skip-cost-explorer",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "compute" in result.output


@mock_aws
def test_report_without_prior_scan_fails_cleanly(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    result = runner.invoke(app, ["report"])
    assert result.exit_code == 1
    assert "No scan found" in result.output


@mock_aws
def test_run_command_full_pipeline(tmp_path: Path, monkeypatch):
    """The `run` convenience command must actually drive scan -> analyze ->
    report end to end, not just each command in isolation."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.run_instances(ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1)

    output_dir = tmp_path / "reports"
    result = runner.invoke(
        app,
        [
            "run", "--regions", "us-east-1", "--modules", "compute",
            "--engine", "rules-only", "--format", "json",
            "--output-dir", str(output_dir),
        ],
    )
    assert result.exit_code == 0, result.output
    assert list(output_dir.glob("*.json"))


@mock_aws
def test_diff_no_previous_scan_fails_cleanly(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    runner.invoke(app, ["scan", "--regions", "us-east-1", "--modules", "compute"])

    result = runner.invoke(app, ["diff"])
    assert result.exit_code == 1
    assert "No previous scan" in result.output


@mock_aws
def test_diff_no_latest_scan_at_all_fails_cleanly(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(app, ["diff"])
    assert result.exit_code == 1
    assert "No latest scan" in result.output


@mock_aws
def test_diff_compare_path_not_found(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(app, ["diff", "--compare", str(tmp_path / "nope.db")])
    assert result.exit_code == 1
    assert "Compare path not found" in result.output


@mock_aws
def test_diff_base_path_not_found(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    runner.invoke(app, ["scan", "--regions", "us-east-1", "--modules", "compute"])

    result = runner.invoke(app, ["diff", "--base", str(tmp_path / "nope.db")])
    assert result.exit_code == 1
    assert "Base path not found" in result.output


def test_diff_scans_value_error_is_reported_cleanly(tmp_path: Path, monkeypatch):
    """A base/compare DB that exists on disk but was never populated with a
    scan record must surface diff_scans()'s ValueError as a clean CLI error,
    not a raw traceback."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    from stackwise.store.db import ScanDB

    empty_base = tmp_path / "empty_base.db"
    empty_compare = tmp_path / "empty_compare.db"
    ScanDB(empty_base).close()
    ScanDB(empty_compare).close()

    result = runner.invoke(
        app, ["diff", "--base", str(empty_base), "--compare", str(empty_compare)]
    )
    assert result.exit_code == 1
    assert "no scan record" in result.output


@mock_aws
def test_diff_text_output_shows_added_and_removed(tmp_path: Path, monkeypatch):
    """Two scans of a changing account should report the right adds/removes
    in the default text output."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.run_instances(ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1)
    scan_args = ["scan", "--regions", "us-east-1", "--modules", "compute"]
    _invoke_scans_with_distinct_timestamps(scan_args, scan_args)

    result = runner.invoke(app, ["diff"])
    assert result.exit_code == 0, result.output
    assert "Resources" in result.output
    assert "Findings" in result.output


@mock_aws
def test_diff_json_output(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.run_instances(ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1)
    scan_args = ["scan", "--regions", "us-east-1", "--modules", "compute"]
    _invoke_scans_with_distinct_timestamps(scan_args, scan_args)

    result = runner.invoke(app, ["diff", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "resources_added" in payload
    assert "findings_unchanged" in payload


@mock_aws
def test_diff_truncates_long_lists(tmp_path: Path, monkeypatch):
    """More than 10 added resources / 5 added findings must be truncated with
    a '... and N more' summary line, not dumped in full."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    ec2 = boto3.client("ec2", region_name="us-east-1")
    scan_args = ["scan", "--regions", "us-east-1", "--modules", "compute"]

    first = _invoke_scans_with_distinct_timestamps(scan_args)[0]
    assert first.exit_code == 0, first.output

    # 15 new public-IP instances → 15 added resources, 15 added CMP-001 findings
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    ec2.run_instances(
        ImageId="ami-12345678", InstanceType="t3.micro", MinCount=15, MaxCount=15,
        NetworkInterfaces=[
            {"DeviceIndex": 0, "AssociatePublicIpAddress": True, "SubnetId": subnet_id}
        ],
    )
    with patch("stackwise.cli.datetime") as mock_dt:
        mock_dt.now.return_value = datetime(2024, 1, 1, tzinfo=UTC) + timedelta(seconds=1)
        second = runner.invoke(app, scan_args)
    assert second.exit_code == 0, second.output
    runner.invoke(app, ["analyze", "--engine", "rules-only"])

    result = runner.invoke(app, ["diff"])
    assert result.exit_code == 0, result.output
    assert "more" in result.output


@mock_aws
def test_diff_truncates_removed_lists(tmp_path: Path, monkeypatch):
    """More than 10 removed resources / 5 resolved findings must also be
    truncated with a '... and N more' line, symmetric with the added case."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg_ids = []
    for i in range(12):
        sg_id = ec2.create_security_group(
            GroupName=f"sg-{i}", Description="d", VpcId=vpc_id
        )["GroupId"]
        sg_ids.append(sg_id)
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

    scan_args = ["scan", "--regions", "us-east-1", "--modules", "network"]
    first = _invoke_scans_with_distinct_timestamps(scan_args)[0]
    assert first.exit_code == 0, first.output
    analyze_result = runner.invoke(app, ["analyze", "--engine", "rules-only"])
    assert analyze_result.exit_code == 0, analyze_result.output

    for sg_id in sg_ids:
        ec2.delete_security_group(GroupId=sg_id)

    with patch("stackwise.cli.datetime") as mock_dt:
        mock_dt.now.return_value = datetime(2024, 1, 1, tzinfo=UTC) + timedelta(seconds=1)
        second = runner.invoke(app, scan_args)
    assert second.exit_code == 0, second.output

    result = runner.invoke(app, ["diff"])
    assert result.exit_code == 0, result.output
    assert "more" in result.output
    assert "resolved" in result.output


@mock_aws
def test_list_scans_reports_none_found(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(app, ["list-scans"])
    assert result.exit_code == 0
    assert "No scans found" in result.output


@mock_aws
def test_list_scans_shows_scanned_account(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    runner.invoke(app, ["scan", "--regions", "us-east-1", "--modules", "compute"])

    # A stray non-directory entry directly under scans/ (e.g. leftover file)
    # must be skipped, not crash iteration.
    (tmp_path / "data" / "scans" / "README.txt").write_text("not an account dir")

    result = runner.invoke(app, ["list-scans"])
    assert result.exit_code == 0
    assert "123456789012" in result.output


@mock_aws
def test_list_scans_with_profile_filter(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    # boto3 profile resolution reads real credentials files, not env vars —
    # a --profile with no matching entry there raises ProfileNotFound before
    # the scan even reaches moto.
    creds_file = tmp_path / "credentials"
    creds_file.write_text(
        "[dev]\naws_access_key_id = testing\naws_secret_access_key = testing\n"
    )
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))

    scan_result = runner.invoke(
        app, ["scan", "--profile", "dev", "--regions", "us-east-1", "--modules", "compute"]
    )
    assert scan_result.exit_code == 0, scan_result.output

    # A second account dir that does NOT match the profile's recorded account
    # must be filtered out, not listed alongside it.
    other_account_dir = tmp_path / "data" / "scans" / "999999999999"
    other_account_dir.mkdir(parents=True)
    (other_account_dir / "20240101T000000.db").write_text("")

    result = runner.invoke(app, ["list-scans", "--profile", "dev"])
    assert result.exit_code == 0
    assert "123456789012" in result.output
    assert "999999999999" not in result.output


@mock_aws
def test_list_scans_with_profile_filter_no_recorded_scan(tmp_path: Path, monkeypatch):
    """A --profile that was never used for a scan must show a warning and
    fall back to listing all accounts, not silently show nothing."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    runner.invoke(app, ["scan", "--regions", "us-east-1", "--modules", "compute"])

    result = runner.invoke(app, ["list-scans", "--profile", "never-used"])
    assert result.exit_code == 0
    assert "No recorded scan for profile" in result.output


_SCAN_ARGS = ["scan", "--regions", "us-east-1", "--modules", "compute"]


def _account_dir(tmp_path: Path) -> Path:
    return tmp_path / "data" / "scans" / "123456789012"


@mock_aws
def test_scan_region_exception_exits_1_and_keeps_previous_latest(tmp_path: Path, monkeypatch):
    """A region failure must exit 1, record a scan_errors row, and leave .latest
    pointing at the last good scan so analyze/report can't pick up partial data."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    good = _invoke_scans_with_distinct_timestamps(_SCAN_ARGS)[0]
    assert good.exit_code == 0, good.output
    latest = _account_dir(tmp_path) / ".latest"
    latest_before = latest.read_text()
    good_db = Path(latest_before.splitlines()[0])

    # The brackets would be a MarkupError if the summary didn't escape AWS text.
    with (
        patch.object(EC2Scanner, "_scan_region", side_effect=RuntimeError("denied [/red] [x]")),
        patch("stackwise.cli.datetime") as mock_dt,
    ):
        mock_dt.now.return_value = datetime(2024, 1, 2, tzinfo=UTC)
        result = runner.invoke(app, _SCAN_ARGS)

    assert result.exit_code == 1, result.output
    assert "Scan complete" not in result.output
    assert "Scan failed" in result.output
    assert "ec2 us-east-1 _scan_region: denied [/red] [x]" in result.output
    assert latest.read_text() == latest_before

    failed_db = next(p for p in _account_dir(tmp_path).glob("*.db") if p != good_db)
    assert str(failed_db) in result.output.replace("\n", "")
    db = ScanDB(failed_db)
    try:
        errors = db.get_scan_errors(db.latest_scan().id)
    finally:
        db.close()
    assert [(e.scanner, e.region, e.operation) for e in errors] == [
        ("ec2", "us-east-1", "_scan_region")
    ]


@mock_aws
def test_scan_list_failure_exits_1(tmp_path: Path, monkeypatch):
    """A list call a scanner swallows internally must fail the scan too, not
    just an exception that reaches the region driver."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    def _make_api_call(self, operation_name, api_params):
        if operation_name == "ListBuckets":
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, operation_name)
        return _real_make_api_call(self, operation_name, api_params)

    with patch.object(BaseClient, "_make_api_call", _make_api_call):
        result = runner.invoke(app, ["scan", "--regions", "us-east-1", "--modules", "data"])

    assert result.exit_code == 1, result.output
    assert "s3 us-east-1 list_buckets" in result.output
    assert not (_account_dir(tmp_path) / ".latest").exists()


@mock_aws
def test_scan_with_only_enrichment_failures_exits_0(tmp_path: Path, monkeypatch):
    """A per-resource lookup failing is not a scan failure: exit 0, .latest
    written, no scan_errors rows."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="locked-bucket")

    def _make_api_call(self, operation_name, api_params):
        if operation_name in {"GetBucketLocation", "GetBucketVersioning"}:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, operation_name)
        return _real_make_api_call(self, operation_name, api_params)

    with patch.object(BaseClient, "_make_api_call", _make_api_call):
        result = runner.invoke(app, ["scan", "--regions", "us-east-1", "--modules", "data"])

    assert result.exit_code == 0, result.output
    assert "Scan complete" in result.output
    db_path, scan_id = (_account_dir(tmp_path) / ".latest").read_text().splitlines()
    db = ScanDB(Path(db_path))
    try:
        assert db.get_scan_errors(scan_id) == []
        bucket = next(r for r in db.get_resources(scan_id) if r.resource_id == "locked-bucket")
    finally:
        db.close()
    assert bucket.metadata["VersioningCheckFailed"] is True


@mock_aws
def test_scan_error_write_failure_still_fails_the_scan(tmp_path: Path, monkeypatch):
    """If the scan_errors row itself can't be written, the scan must still fail
    without moving .latest, and the db must still be closed."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    with (
        patch.object(EC2Scanner, "_scan_region", side_effect=RuntimeError("boom")),
        patch.object(
            ScanDB, "insert_scan_error",
            side_effect=sqlite3.OperationalError("database is locked"),
        ),
        patch.object(ScanDB, "close", autospec=True, side_effect=ScanDB.close) as close,
    ):
        result = runner.invoke(app, _SCAN_ARGS)

    assert result.exit_code == 1
    assert "database is locked" in result.output
    assert "Scan complete" not in result.output
    assert not (_account_dir(tmp_path) / ".latest").exists()
    close.assert_called_once()


@mock_aws
def test_run_stops_after_failed_scan(tmp_path: Path, monkeypatch):
    """`run` must not analyze or report after a failed scan. A previous good scan
    exists, so without the stop they would silently run against stale data."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    good = _invoke_scans_with_distinct_timestamps(_SCAN_ARGS)[0]
    assert good.exit_code == 0, good.output

    output_dir = tmp_path / "reports"
    with (
        patch.object(EC2Scanner, "_scan_region", side_effect=RuntimeError("boom")),
        patch("stackwise.cli.datetime") as mock_dt,
        patch("stackwise.analyzer.engine.run_analysis") as run_analysis,
        patch("stackwise.report.generator.generate_report") as generate_report,
    ):
        mock_dt.now.return_value = datetime(2024, 1, 2, tzinfo=UTC)
        result = runner.invoke(
            app,
            [
                "run", "--regions", "us-east-1", "--modules", "compute",
                "--engine", "rules-only", "--format", "json",
                "--output-dir", str(output_dir),
            ],
        )

    assert result.exit_code == 1, result.output
    run_analysis.assert_not_called()
    generate_report.assert_not_called()
    assert not list(output_dir.glob("*"))


_READ_COMMANDS = [["analyze", "--engine", "rules-only"], ["report"], ["diff"]]


def _point_latest_at(db_path: Path, scan_id: str, monkeypatch, tmp_path: Path) -> None:
    from stackwise.cli import _write_latest_scan
    from stackwise.config import resolve_settings

    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    _write_latest_scan(resolve_settings(), "123456789012", scan_id, db_path)


@pytest.mark.parametrize("command", _READ_COMMANDS, ids=lambda c: c[0])
def test_pointer_to_deleted_database_exits_1_without_creating_it(
    tmp_path: Path, monkeypatch, command: list[str]
):
    db_path = tmp_path / "deleted.db"
    _point_latest_at(db_path, "gone", monkeypatch, tmp_path)

    result = runner.invoke(app, command)

    assert result.exit_code == 1
    assert "Scan database not found" in result.output
    assert "complete" not in result.output
    assert not db_path.exists()


@pytest.mark.parametrize("command", _READ_COMMANDS, ids=lambda c: c[0])
def test_pointer_whose_scan_id_is_absent_exits_1(
    tmp_path: Path, monkeypatch, command: list[str]
):
    db_path = tmp_path / "other.db"
    db = ScanDB(db_path)
    db.create_scan("123456789012", ["us-east-1"], ["compute"])
    db.close()
    _point_latest_at(db_path, "not-this-scan", monkeypatch, tmp_path)

    result = runner.invoke(app, command)

    assert result.exit_code == 1
    assert "not-this-scan not found" in result.output


@pytest.mark.parametrize("command", _READ_COMMANDS, ids=lambda c: c[0])
def test_pointer_to_empty_file_exits_1_and_leaves_it_empty(
    tmp_path: Path, monkeypatch, command: list[str]
):
    """An empty file left by an earlier run must not be given a schema."""
    db_path = tmp_path / "empty.db"
    db_path.touch()
    _point_latest_at(db_path, "gone", monkeypatch, tmp_path)

    result = runner.invoke(app, command)

    assert result.exit_code == 1
    assert "gone not found" in result.output
    assert db_path.stat().st_size == 0


def test_report_does_not_change_the_scan_file(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "scan.db"
    db = ScanDB(db_path)
    scan = db.create_scan("123456789012", ["us-east-1"], ["compute"])
    db.close()
    os.utime(db_path, (1_000_000, 1_000_000))
    _point_latest_at(db_path, scan.id, monkeypatch, tmp_path)

    result = runner.invoke(app, ["report", "--output-dir", str(tmp_path / "out")])

    assert result.exit_code == 0, result.output
    assert db_path.stat().st_mtime == 1_000_000


def test_analyze_can_still_write_findings(tmp_path: Path, monkeypatch):
    """Analyze verifies read-only, then needs a writable connection for its results."""
    db_path = tmp_path / "scan.db"
    db = ScanDB(db_path)
    scan = db.create_scan("123456789012", ["us-east-1"], ["compute"])
    db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1",
        metadata={"PublicIpAddress": "1.2.3.4"},
    )
    db.close()
    _point_latest_at(db_path, scan.id, monkeypatch, tmp_path)

    result = runner.invoke(app, ["analyze", "--engine", "rules-only"])

    assert result.exit_code == 0, result.output
    assert "Analysis complete" in result.output
    db = ScanDB(db_path, mode="ro")
    try:
        assert db.get_findings(scan.id)
    finally:
        db.close()


def _scan_at(seconds: int, args: list[str] | None = None) -> None:
    with patch("stackwise.cli.datetime") as mock_dt:
        mock_dt.now.return_value = datetime(2024, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
        runner.invoke(app, args or _SCAN_ARGS)


def _scan_files(tmp_path: Path) -> list[Path]:
    return sorted(_account_dir(tmp_path).glob("*.db"))


@mock_aws
def test_diff_baseline_ignores_older_file_that_was_read_and_touched(tmp_path: Path, monkeypatch):
    """`diff --base old.db` must not make old.db the next plain diff's baseline,
    even if something else gives that file the newest mtime."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    for seconds in range(3):
        _scan_at(seconds)
    oldest, middle, newest = _scan_files(tmp_path)

    assert runner.invoke(app, ["diff", "--base", str(oldest)]).exit_code == 0
    os.utime(oldest, (newest.stat().st_mtime + 100, newest.stat().st_mtime + 100))

    result = runner.invoke(app, ["diff"])

    assert result.exit_code == 0, result.output
    assert f"Base:    {middle.name}" in result.output


@mock_aws
def test_diff_baseline_skips_scan_with_scan_errors(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    _scan_at(0)
    with patch.object(EC2Scanner, "_scan_region", side_effect=RuntimeError("boom")):
        _scan_at(1)
    _scan_at(2)
    good, failed, latest = _scan_files(tmp_path)

    result = runner.invoke(app, ["diff"])

    assert result.exit_code == 0, result.output
    assert f"Base:    {good.name}" in result.output
    assert f"Compare: {latest.name}" in result.output
    assert failed.name not in result.output


@mock_aws
def test_diff_baseline_skips_scan_that_crashed_before_publishing(tmp_path: Path, monkeypatch):
    """A crash leaves a partial file with no scan_errors row, usually the newest."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    _scan_at(0)
    with patch.object(EC2Scanner, "scan", side_effect=RuntimeError("crash")):
        _scan_at(1)
    _scan_at(2)
    good, crashed, _latest = _scan_files(tmp_path)

    result = runner.invoke(app, ["diff"])

    assert result.exit_code == 0, result.output
    assert f"Base:    {good.name}" in result.output
    assert crashed.name not in result.output


@mock_aws
def test_diff_with_only_failed_earlier_scans_fails_cleanly(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    with patch.object(EC2Scanner, "_scan_region", side_effect=RuntimeError("boom")):
        _scan_at(0)
    _scan_at(1)

    result = runner.invoke(app, ["diff"])

    assert result.exit_code == 1
    assert "No previous scan" in result.output


@mock_aws
@pytest.mark.parametrize(
    ("narrower", "expected"),
    [
        (
            ["scan", "--regions", "us-east-1", "--modules", "compute"],
            ["Base: modules compute,network; regions us-east-1",
             "Compare: modules compute; regions us-east-1"],
        ),
        (
            ["scan", "--regions", "eu-west-1", "--modules", "compute,network"],
            ["Base: modules compute,network; regions us-east-1",
             "Compare: modules compute,network; regions us-east-1,eu-west-1"],
        ),
    ],
    ids=["modules", "regions"],
)
def test_diff_warns_when_scopes_differ_before_the_lists(
    tmp_path: Path, monkeypatch, narrower: list[str], expected: list[str]
):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    _scan_at(0, ["scan", "--regions", "us-east-1", "--modules", "compute,network"])
    _scan_at(1, narrower)

    result = runner.invoke(app, ["diff"])

    assert result.exit_code == 0, result.output
    assert "different scopes" in result.output
    for line in expected:
        assert line in result.output
    assert result.output.index("different scopes") < result.output.index("Resources")


@mock_aws
def test_diff_scope_warning_does_not_corrupt_json(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    _scan_at(0, ["scan", "--regions", "us-east-1", "--modules", "compute,network"])
    _scan_at(1, ["scan", "--regions", "us-east-1", "--modules", "compute"])

    result = runner.invoke(app, ["diff", "--format", "json"])

    assert result.exit_code == 0, result.output
    assert "different scopes" in result.stderr
    assert "resources_added" in json.loads(result.stdout)


@mock_aws
def test_diff_same_scope_has_no_warning(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    _scan_at(0)
    _scan_at(1)

    result = runner.invoke(app, ["diff"])

    assert result.exit_code == 0, result.output
    assert "different scopes" not in result.output


@mock_aws
def test_two_scans_in_the_same_instant_get_their_own_files(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))

    _scan_at(0)
    _scan_at(0)

    files = _scan_files(tmp_path)
    assert len(files) == 2
    for path in files:
        db = ScanDB(path, mode="ro")
        try:
            assert db.conn.execute("SELECT count(*) FROM scans").fetchone()[0] == 1
        finally:
            db.close()
    assert sorted(p.name for p in _account_dir(tmp_path).iterdir() if ".db-" in p.name) == []


def _scanner_blocked_by_another_connection(*, swallow: bool):
    """A _scan_region whose writes hit "database is locked", held by a second
    connection the way an overlapping process would. Returns it and the holders."""
    holders: list[sqlite3.Connection] = []

    def _scan_region(self, session, db, scan_id, region):
        holder = sqlite3.connect(db.db_path, check_same_thread=False)
        holder.execute("BEGIN IMMEDIATE")
        holders.append(holder)
        try:
            db.insert_resource(scan_id, "ec2", "instance", "i-1", region, metadata={})
        except sqlite3.OperationalError:
            # What the scanners' per-resource `except Exception` blocks do.
            if not swallow:
                raise
        return 0

    return _scan_region, holders


@mock_aws
@pytest.mark.parametrize("swallow", [True, False], ids=["swallowed", "raised"])
def test_locked_database_fails_the_scan_and_is_not_published(
    tmp_path: Path, monkeypatch, swallow: bool
):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    _scan_at(0)
    latest = _account_dir(tmp_path) / ".latest"
    before = latest.read_text()

    _scan_region, holders = _scanner_blocked_by_another_connection(swallow=swallow)
    with (
        patch("stackwise.store.db._BUSY_TIMEOUT_SECONDS", 0.01),
        patch.object(EC2Scanner, "_scan_region", _scan_region),
    ):
        with patch("stackwise.cli.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2024, 1, 2, tzinfo=UTC)
            result = runner.invoke(app, _SCAN_ARGS)
    for holder in holders:
        holder.close()

    assert result.exit_code == 1
    assert "database is locked" in result.output
    assert "Scan complete" not in result.output
    assert latest.read_text() == before

    # It also can't become the baseline of a later diff.
    good, locked = _scan_files(tmp_path)
    _scan_at(86_400 * 2)
    diff = runner.invoke(app, ["diff"])
    assert diff.exit_code == 0, diff.output
    assert f"Base:    {good.name}" in diff.output
    assert locked.name not in diff.output


@mock_aws
def test_reading_a_finished_scan_leaves_no_sidecar_files(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    _scan_at(0)
    _scan_at(1)

    assert runner.invoke(app, ["diff"]).exit_code == 0
    assert runner.invoke(app, ["report", "--output-dir", str(tmp_path / "out")]).exit_code == 0

    assert [p for p in _account_dir(tmp_path).iterdir() if ".db-" in p.name] == []


@pytest.mark.parametrize("output_format", ["html", "md", "json"])
def test_reports_render_a_bucket_whose_region_is_unknown(
    tmp_path: Path, monkeypatch, output_format: str
):
    db_path = tmp_path / "scan.db"
    db = ScanDB(db_path)
    scan = db.create_scan("123456789012", ["us-east-1"], ["data"])
    db.insert_resource(
        scan.id, "s3", "bucket", "b", "unknown", metadata={"LocationCheckFailed": True}
    )
    db.close()
    _point_latest_at(db_path, scan.id, monkeypatch, tmp_path)

    result = runner.invoke(
        app,
        ["report", "--type", "all", "--format", output_format,
         "--output-dir", str(tmp_path / "out")],
    )

    assert result.exit_code == 0, result.output


@mock_aws
def test_region_with_no_config_recorder_gets_one_finding(tmp_path: Path, monkeypatch):
    """moto starts with no recorder, so this goes through the real scan and rules."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    args = ["scan", "--regions", "us-east-1", "--modules", "discovery"]
    assert runner.invoke(app, args).exit_code == 0

    result = runner.invoke(app, ["analyze", "--engine", "rules-only"])
    assert result.exit_code == 0, result.output

    db = ScanDB(_scan_files(tmp_path)[0], mode="ro")
    try:
        findings = db.get_findings(db.latest_scan().id)
    finally:
        db.close()
    assert len([f for f in findings if f.rule_id == "DSC-001"]) == 1


@mock_aws
def test_failed_ecs_and_eks_describes_do_not_show_as_drift(tmp_path: Path, monkeypatch):
    """A healthy scan, then one where every per-resource describe fails. The second
    must pass and diff must show no change, which only holds if a flagged row keeps
    the id a successful scan stores."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    iam = boto3.client("iam", region_name="us-east-1")
    role_arn = iam.create_role(RoleName="r", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnets = [
        ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=f"us-east-1{az}"
        )["Subnet"]["SubnetId"]
        for i, az in enumerate(("a", "b"), start=1)
    ]
    eks = boto3.client("eks", region_name="us-east-1")
    eks.create_cluster(name="c1", roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnets})
    eks.create_nodegroup(clusterName="c1", nodegroupName="ng1", subnets=subnets, nodeRole=role_arn)
    ecs = boto3.client("ecs", region_name="us-east-1")
    ecs.create_cluster(clusterName="ecs1")
    ecs.register_task_definition(
        family="fam", containerDefinitions=[{"name": "c", "image": "nginx", "memory": 128}]
    )
    ecs.create_service(cluster="ecs1", serviceName="svc", taskDefinition="fam", desiredCount=1)

    args = ["scan", "--regions", "us-east-1", "--modules", "compute"]
    _scan_at(0, args)

    failing = {"DescribeServices", "DescribeTaskDefinition", "DescribeCluster", "DescribeNodegroup"}

    def _make_api_call(self, operation_name, api_params):
        if operation_name in failing:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, operation_name)
        return _real_make_api_call(self, operation_name, api_params)

    with patch.object(BaseClient, "_make_api_call", _make_api_call):
        _scan_at(1, args)

    result = runner.invoke(app, ["diff", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["resources_added"] == []
    assert payload["resources_removed"] == []

    healthy, flagged = _scan_files(tmp_path)
    db = ScanDB(flagged, mode="ro")
    try:
        rows = db.get_resources(db.latest_scan().id)
    finally:
        db.close()
    assert {r.resource_id for r in rows if r.service == "eks"} == {"c1", "c1/ng1"}
    assert {r.resource_id for r in rows if r.service == "ecs"} == {"ecs1/svc", "fam:1"}
    assert all(
        any(k.endswith("CheckFailed") and v for k, v in r.metadata.items())
        for r in rows if r.service in ("eks", "ecs")
    )


@mock_aws
def test_scan_count_matches_rows_with_overlapping_modules(
    tmp_path: Path, monkeypatch, _compute_optimizer_empty
):
    """cost and discovery both list tagged resources. The total must count rows once."""
    monkeypatch.setenv("STACKWISE_DATA_DIR", str(tmp_path / "data"))
    s3 = boto3.client("s3", region_name="us-east-1")
    for name in ("api", "orders"):
        s3.create_bucket(Bucket=name)
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "Env", "Value": "p"}]})

    result = runner.invoke(
        app,
        ["scan", "--regions", "us-east-1", "--modules", "cost,discovery", "--skip-cost-explorer"],
    )
    assert result.exit_code == 0, result.output

    db = ScanDB(_scan_files(tmp_path)[0], mode="ro")
    try:
        rows = db.get_resources(db.latest_scan().id)
    finally:
        db.close()
    assert f"{len(rows)} resources collected" in result.output
    tagged = [r for r in rows if r.resource_type == "tagged_resource"]
    assert sorted(r.resource_id for r in tagged) == ["arn:aws:s3:::api", "arn:aws:s3:::orders"]


def _scan_with_imds_findings(tmp_path: Path, monkeypatch) -> tuple[Path, str]:
    db_path = tmp_path / "scan.db"
    db = ScanDB(db_path)
    scan = db.create_scan("123456789012", ["us-east-1"], ["compute"])
    for i in range(3):
        db.insert_resource(
            scan.id, "ec2", "instance", f"i-{i}", "us-east-1",
            metadata={"MetadataOptions": {"HttpTokens": "optional"}},
        )
    db.close()
    _point_latest_at(db_path, scan.id, monkeypatch, tmp_path)
    return db_path, scan.id


def _finding_ids(db_path: Path, scan_id: str) -> list[str]:
    db = ScanDB(db_path, mode="ro")
    try:
        return sorted(f.id for f in db.get_findings(scan_id))
    finally:
        db.close()


def test_analyze_twice_keeps_one_set_of_findings(tmp_path: Path, monkeypatch):
    db_path, scan_id = _scan_with_imds_findings(tmp_path, monkeypatch)
    args = ["analyze", "--engine", "rules-only"]

    assert runner.invoke(app, args).exit_code == 0
    first = _finding_ids(db_path, scan_id)
    assert runner.invoke(app, args).exit_code == 0

    assert len(_finding_ids(db_path, scan_id)) == len(first) > 0


def test_analyze_that_rolls_back_exits_1_and_keeps_previous_findings(
    tmp_path: Path, monkeypatch
):
    db_path, scan_id = _scan_with_imds_findings(tmp_path, monkeypatch)
    args = ["analyze", "--engine", "rules-only"]
    assert runner.invoke(app, args).exit_code == 0
    before = _finding_ids(db_path, scan_id)

    with patch.object(ScanDB, "insert_finding", side_effect=sqlite3.OperationalError("full")):
        result = runner.invoke(app, args)

    assert result.exit_code == 1
    assert "Analysis failed" in result.output
    assert "previous findings are unchanged" in result.output
    assert "Analysis complete" not in result.output
    assert _finding_ids(db_path, scan_id) == before
