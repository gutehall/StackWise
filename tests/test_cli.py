"""Tests for CLI helper functions (profile-scoped scan resolution)."""

from __future__ import annotations

from pathlib import Path

from stackwise.cli import _last_account_file, _read_latest_scan, _write_latest_scan
from stackwise.config import Settings


def _settings(tmp_path: Path, profile: str | None) -> Settings:
    return Settings(data_dir=tmp_path / "stackwise", profile=profile)


def test_last_account_file_is_scoped_per_profile(tmp_path: Path):
    dev = _settings(tmp_path, "dev")
    prod = _settings(tmp_path, "prod")
    assert _last_account_file(dev) != _last_account_file(prod)


def test_switching_profile_does_not_read_stale_account(tmp_path: Path):
    """Scanning under one profile then analyzing under another (without
    --account) must not resolve to the first profile's account."""
    dev = _settings(tmp_path, "dev")
    prod = _settings(tmp_path, "prod")

    _write_latest_scan(dev, "111111111111", "scan-1", tmp_path / "dev.db")

    dev_path, dev_scan = _read_latest_scan(dev)
    assert dev_scan == "scan-1"

    prod_path, prod_scan = _read_latest_scan(prod)
    assert prod_path is None
    assert prod_scan is None


def test_same_profile_resolves_its_own_last_scan(tmp_path: Path):
    dev = _settings(tmp_path, "dev")
    _write_latest_scan(dev, "111111111111", "scan-1", tmp_path / "dev.db")

    db_path, scan_id = _read_latest_scan(dev)
    assert scan_id == "scan-1"
    assert db_path == tmp_path / "dev.db"
