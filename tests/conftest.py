"""Shared test fixtures for StackWise."""

from __future__ import annotations

from pathlib import Path

import pytest

from stackwise.config import Engine, Settings
from stackwise.store.db import ScanDB


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    """Ensure no real AWS credentials leak into tests."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Return Settings with temp dirs for testing."""
    return Settings(
        regions=["us-east-1"],
        modules=["compute"],
        engine=Engine.RULES_ONLY,
        data_dir=tmp_path / "stackwise",
        output_dir=tmp_path / "reports",
    )


@pytest.fixture
def scan_db(tmp_path: Path):
    """Yield a fresh ScanDB, closing it after the test regardless of outcome."""
    db_path = tmp_path / "test.db"
    db = ScanDB(db_path)
    try:
        yield db
    finally:
        db.close()
