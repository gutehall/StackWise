"""Tests for CLI helper functions (profile-scoped scan resolution)."""

from __future__ import annotations

from pathlib import Path

from stackwise.cli import (
    _last_account_file,
    _latest_scan_file,
    _read_latest_scan,
    _write_latest_scan,
)
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


def test_read_latest_scan_returns_none_when_no_last_account_recorded(tmp_path: Path):
    """No .last_account.<profile> file and no legacy .latest_scan file at all:
    a fresh data_dir with nothing scanned yet."""
    settings = _settings(tmp_path, "dev")
    assert _read_latest_scan(settings) == (None, None)


def test_read_latest_scan_falls_back_to_legacy_latest_scan_file(tmp_path: Path):
    """Before per-profile scoping existed, the latest scan was recorded in a
    single '.latest_scan' file at the data_dir root — must still resolve."""
    settings = _settings(tmp_path, "dev")
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    legacy = settings.data_dir / ".latest_scan"
    legacy.write_text("/some/path/scan.db\nscan-legacy\n")

    db_path, scan_id = _read_latest_scan(settings)
    assert scan_id == "scan-legacy"
    assert db_path == Path("/some/path/scan.db")


def test_read_latest_scan_missing_marker_file_for_known_account(tmp_path: Path):
    """account_id is given (or resolved) but its .latest marker file was
    never written — must return (None, None), not raise."""
    settings = _settings(tmp_path, "dev")
    assert _read_latest_scan(settings, account_id="123456789012") == (None, None)


def test_read_latest_scan_malformed_marker_file(tmp_path: Path):
    """A .latest file with fewer than 2 lines (corrupted/truncated write)
    must be treated as unreadable, not crash on index access."""
    settings = _settings(tmp_path, "dev")
    marker = _latest_scan_file(settings, "123456789012")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("only-one-line")

    assert _read_latest_scan(settings, account_id="123456789012") == (None, None)
