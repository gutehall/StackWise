"""Chart builders for report generation — matplotlib to base64 PNG."""

from __future__ import annotations

import base64
import io

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def _to_base64(fig: plt.Figure) -> str:
    """Render figure to base64 PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=100, bbox_inches="tight")
    buf.seek(0)
    data = base64.b64encode(buf.read()).decode("ascii")
    plt.close(fig)
    return data


def severity_bar_chart(findings_by_severity: dict[str, int]) -> str:
    """Generate a severity distribution bar chart as a base64 PNG."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    labels = [s for s in order if findings_by_severity.get(s, 0) > 0]
    values = [findings_by_severity.get(s, 0) for s in labels]
    colors = ["#dc2626", "#ea580c", "#ca8a04", "#2563eb", "#6b7280"]

    if not labels:
        labels = ["No findings"]
        values = [1]
        colors = ["#e5e7eb"]

    fig, ax = plt.subplots(figsize=(5, 3))
    bars = ax.bar(labels, values, color=colors[: len(labels)])
    ax.set_ylabel("Count")
    ax.set_title("Findings by Severity")
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            ax.annotate(
                str(int(height)),
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 4),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=9,
            )
    plt.tight_layout()
    return _to_base64(fig)


def cost_pie_chart(cost_by_service: dict[str, float]) -> str:
    """Generate a cost-by-service pie chart as a base64 PNG.

    If cost_by_service is empty, returns empty string (no chart).
    """
    if not cost_by_service:
        return ""

    # Filter zero values and sort by value descending
    data = {k: v for k, v in cost_by_service.items() if v > 0}
    if not data:
        return ""

    labels = list(data.keys())
    sizes = list(data.values())
    colors = plt.cm.Set3.colors[: len(labels)]

    fig, ax = plt.subplots(figsize=(5, 4))
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        autopct="%1.1f%%",
        colors=colors,
        startangle=90,
    )
    for t in texts:
        t.set_fontsize(9)
    for t in autotexts:
        t.set_fontsize(8)
    ax.set_title("Cost by Service")
    plt.tight_layout()
    return _to_base64(fig)


def resource_distribution_chart(resources_by_service: dict[str, list]) -> str:
    """Generate a resource-count-by-service bar chart as base64 PNG.

    Used when cost data is not available (e.g. cost scanner not run).
    """
    if not resources_by_service:
        return ""

    labels = list(resources_by_service.keys())
    values = [len(v) for v in resources_by_service.values()]
    colors = plt.cm.Set3.colors[: len(labels)]

    fig, ax = plt.subplots(figsize=(6, 3.5))
    bars = ax.bar(labels, values, color=colors)
    ax.set_ylabel("Resource Count")
    ax.set_title("Resources by Service")
    plt.xticks(rotation=45, ha="right")
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            ax.annotate(
                str(int(height)),
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 4),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8,
            )
    plt.tight_layout()
    return _to_base64(fig)
