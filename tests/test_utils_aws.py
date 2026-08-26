"""Tests for AWS session/client helpers not already exercised via scanner tests."""

from __future__ import annotations

from stackwise.config import Settings
from stackwise.utils.aws import iter_regions


def test_iter_regions_yields_settings_regions():
    """iter_regions should yield exactly the configured regions, in order."""
    settings = Settings(regions=["us-east-1", "eu-west-1", "ap-south-1"])
    session = object()  # unused by iter_regions, but keeps the signature honest

    assert list(iter_regions(session, settings)) == ["us-east-1", "eu-west-1", "ap-south-1"]
