"""Tests for settings resolution."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from stackwise.config import Engine, auto_select_engine, detect_platform, resolve_settings


def test_resolve_settings_accepts_known_modules():
    settings = resolve_settings(modules="compute,data")
    assert settings.modules == ["compute", "data"]


def test_resolve_settings_rejects_unknown_module():
    """A typo in --modules must fail loudly, not silently scan nothing."""
    with pytest.raises(ValueError, match="compute-typo"):
        resolve_settings(modules="compute-typo")


def test_skip_cost_explorer_defaults_false():
    assert resolve_settings().skip_cost_explorer is False


def test_skip_cost_explorer_flag():
    assert resolve_settings(skip_cost_explorer=True).skip_cost_explorer is True


def test_skip_cost_explorer_env_var(monkeypatch):
    monkeypatch.setenv("STACKWISE_SKIP_COST_EXPLORER", "true")
    assert resolve_settings().skip_cost_explorer is True


def test_settings_scans_dir_creates_and_returns_path(tmp_path):
    from stackwise.config import Settings

    settings = Settings(data_dir=tmp_path)
    path = settings.scans_dir("123456789012")

    assert path == tmp_path / "scans" / "123456789012"
    assert path.is_dir()


def test_resolve_settings_explicit_engine_overrides_auto_detect():
    settings = resolve_settings(engine="rules-only")
    assert settings.engine == Engine.RULES_ONLY


def test_resolve_settings_explicit_output_dir():
    settings = resolve_settings(output_dir="/tmp/my-reports")
    assert str(settings.output_dir) == "/tmp/my-reports"


def test_resolve_settings_regions_env_var(monkeypatch):
    monkeypatch.setenv("STACKWISE_REGIONS", "eu-west-1,ap-south-1")
    settings = resolve_settings()
    assert "eu-west-1" in settings.regions
    assert "ap-south-1" in settings.regions


def test_resolve_settings_prepends_us_east_1_when_missing():
    """us-east-1 hosts IAM/GuardDuty/etc. and must always be scanned, even if
    the user only asked for other regions."""
    settings = resolve_settings(regions="eu-west-1")
    assert settings.regions == ["us-east-1", "eu-west-1"]


def test_resolve_settings_does_not_duplicate_us_east_1():
    settings = resolve_settings(regions="us-east-1,eu-west-1")
    assert settings.regions == ["us-east-1", "eu-west-1"]


def test_resolve_settings_suppressed_rules_arg():
    settings = resolve_settings(suppressed_rules="CMP-001,DAT-002")
    assert settings.suppressed_rules == ["CMP-001", "DAT-002"]


def test_resolve_settings_suppressed_rules_env_var(monkeypatch):
    monkeypatch.setenv("STACKWISE_SUPPRESSED_RULES", "SEC-001")
    settings = resolve_settings()
    assert settings.suppressed_rules == ["SEC-001"]


def test_resolve_settings_scan_max_workers_env_var(monkeypatch):
    monkeypatch.setenv("STACKWISE_SCAN_MAX_WORKERS", "8")
    assert resolve_settings().scan_max_workers == 8


def test_resolve_settings_scan_max_workers_env_var_invalid_is_ignored(monkeypatch):
    """A non-numeric value must not crash settings resolution — just keep the
    default."""
    monkeypatch.setenv("STACKWISE_SCAN_MAX_WORKERS", "not-a-number")
    assert resolve_settings().scan_max_workers == 4


def test_resolve_settings_llm_max_workers_env_var(monkeypatch):
    monkeypatch.setenv("STACKWISE_LLM_MAX_WORKERS", "6")
    assert resolve_settings().llm_max_workers == 6


def test_resolve_settings_llm_max_workers_env_var_invalid_is_ignored(monkeypatch):
    monkeypatch.setenv("STACKWISE_LLM_MAX_WORKERS", "not-a-number")
    assert resolve_settings().llm_max_workers == 3


def test_detect_platform_linux_with_nvidia(monkeypatch):
    monkeypatch.setattr("stackwise.config.platform.system", lambda: "Linux")
    monkeypatch.setattr("stackwise.config.platform.machine", lambda: "x86_64")
    monkeypatch.setattr("stackwise.config.shutil.which", lambda name: "/usr/bin/nvidia-smi")

    info = detect_platform()
    assert info["os"] == "linux"
    assert info["has_nvidia"] is True
    assert info["has_metal"] is False


def test_detect_platform_linux_without_nvidia(monkeypatch):
    monkeypatch.setattr("stackwise.config.platform.system", lambda: "Linux")
    monkeypatch.setattr("stackwise.config.platform.machine", lambda: "x86_64")
    monkeypatch.setattr("stackwise.config.shutil.which", lambda name: None)

    info = detect_platform()
    assert info["has_nvidia"] is False


def test_auto_select_engine_prefers_mlx_on_apple_silicon(monkeypatch):
    monkeypatch.setattr("stackwise.config.platform.system", lambda: "Darwin")
    monkeypatch.setattr("stackwise.config.platform.machine", lambda: "arm64")
    fake_mlx_lm = MagicMock()
    with patch.dict(sys.modules, {"mlx_lm": fake_mlx_lm}):
        assert auto_select_engine() == Engine.MLX


def test_auto_select_engine_falls_back_to_ollama_without_mlx(monkeypatch):
    monkeypatch.setattr("stackwise.config.platform.system", lambda: "Darwin")
    monkeypatch.setattr("stackwise.config.platform.machine", lambda: "arm64")
    monkeypatch.setattr("stackwise.config.shutil.which", lambda name: "/usr/local/bin/ollama")
    with patch.dict(sys.modules, {"mlx_lm": None}):
        assert auto_select_engine() == Engine.OLLAMA


def test_auto_select_engine_falls_back_to_rules_only_without_ollama(monkeypatch):
    monkeypatch.setattr("stackwise.config.platform.system", lambda: "Linux")
    monkeypatch.setattr("stackwise.config.platform.machine", lambda: "x86_64")
    monkeypatch.setattr("stackwise.config.shutil.which", lambda name: None)
    assert auto_select_engine() == Engine.RULES_ONLY


def test_auto_select_engine_uses_ollama_on_linux_when_available(monkeypatch):
    monkeypatch.setattr("stackwise.config.platform.system", lambda: "Linux")
    monkeypatch.setattr("stackwise.config.platform.machine", lambda: "x86_64")
    monkeypatch.setattr("stackwise.config.shutil.which", lambda name: "/usr/local/bin/ollama")
    assert auto_select_engine() == Engine.OLLAMA
