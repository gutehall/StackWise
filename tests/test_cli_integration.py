"""End-to-end tests driving the actual Typer commands (not just their helper
functions), against a moto-mocked AWS account. Catches wiring bugs — argument
passing, exit codes, profile/account resolution — that unit tests on
individual functions can't see."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import boto3
from moto import mock_aws
from typer.testing import CliRunner

from stackwise import __version__
from stackwise.cli import app

runner = CliRunner()


def _invoke_scans_with_distinct_timestamps(*arg_lists):
    """Invoke the CLI once per arg_list, forcing each scan() call to get a
    distinct timestamp. scan() derives its db filename from
    datetime.now(UTC) at 1-second resolution, so two scans issued back to
    back in a test can land in the same wall-clock second and silently
    overwrite each other's db file."""
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
def test_scan_wires_every_scanner_module(tmp_path: Path, monkeypatch):
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
