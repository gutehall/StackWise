"""Tests for AWS session/client helpers not already exercised via scanner tests."""

from __future__ import annotations

from pathlib import Path

import boto3
import pytest

from stackwise.config import Settings
from stackwise.utils.aws import iter_regions, worker_session_factory


@pytest.fixture
def aws_config(tmp_path: Path, monkeypatch) -> Path:
    """Point boto3 at an empty config file so the developer's profiles can't leak in."""
    config = tmp_path / "config"
    config.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    return config


def test_worker_sessions_are_independent_but_share_credentials(aws_config: Path):
    """Workers must not share a session, but must not re-resolve credentials either:
    that would repeat a role assumption or MFA prompt per worker."""
    source = boto3.Session()
    build = worker_session_factory(source)

    first, second = build(), build()

    assert first is not second
    assert first is not source
    assert first.get_credentials() is source.get_credentials()
    assert second.get_credentials() is source.get_credentials()


def test_worker_session_without_any_profile_uses_env_credentials(aws_config: Path):
    """profile_name reports "default" even with no such profile. Passing that on
    would raise ProfileNotFound for anyone using environment credentials."""
    source = boto3.Session()
    assert source.profile_name == "default"
    assert source.available_profiles == []

    worker = worker_session_factory(source)()

    assert worker.client("sts", region_name="us-east-1").meta.region_name == "us-east-1"


def test_worker_session_keeps_named_profile_and_region(aws_config: Path, monkeypatch):
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    aws_config.write_text("[profile acme]\nregion = eu-north-1\n")
    source = boto3.Session(profile_name="acme")
    assert source.region_name == "eu-north-1"

    worker = worker_session_factory(source)()

    assert worker.profile_name == "acme"
    assert worker.region_name == "eu-north-1"


def test_iter_regions_yields_settings_regions():
    """iter_regions should yield exactly the configured regions, in order."""
    settings = Settings(regions=["us-east-1", "eu-west-1", "ap-south-1"])
    session = object()  # unused by iter_regions, but keeps the signature honest

    assert list(iter_regions(session, settings)) == ["us-east-1", "eu-west-1", "ap-south-1"]
