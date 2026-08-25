"""Tests for settings resolution."""

from __future__ import annotations

import pytest

from stackwise.config import resolve_settings


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
