"""Tests for report chart generation."""

from __future__ import annotations

import base64

from stackwise.report.charts import (
    cost_pie_chart,
    resource_distribution_chart,
    severity_bar_chart,
)


def test_severity_bar_chart_returns_base64():
    """severity_bar_chart should return base64 PNG string."""
    data = severity_bar_chart({"CRITICAL": 2, "HIGH": 5, "MEDIUM": 10})
    assert isinstance(data, str)
    assert len(data) > 0
    decoded = base64.b64decode(data)
    assert decoded[:8] == b"\x89PNG\r\n\x1a\n"


def test_severity_bar_chart_empty_findings():
    """severity_bar_chart with empty dict should show placeholder."""
    data = severity_bar_chart({})
    assert isinstance(data, str)
    assert len(data) > 0


def test_cost_pie_chart_returns_base64():
    """cost_pie_chart should return base64 PNG when data provided."""
    data = cost_pie_chart({"EC2": 100.5, "S3": 25.0, "Lambda": 10.0})
    assert isinstance(data, str)
    assert len(data) > 0
    decoded = base64.b64decode(data)
    assert decoded[:8] == b"\x89PNG\r\n\x1a\n"


def test_cost_pie_chart_empty_returns_empty():
    """cost_pie_chart with empty dict should return empty string."""
    assert cost_pie_chart({}) == ""


def test_resource_distribution_chart():
    """resource_distribution_chart should return base64 PNG."""
    data = resource_distribution_chart({"ec2": [1, 2, 3], "lambda": [1]})
    assert isinstance(data, str)
    assert len(data) > 0
    decoded = base64.b64decode(data)
    assert decoded[:8] == b"\x89PNG\r\n\x1a\n"


def test_resource_distribution_chart_empty():
    """resource_distribution_chart with empty dict should return empty string."""
    assert resource_distribution_chart({}) == ""
