"""Local LLM client — talks to Ollama (or MLX in the future)."""

from __future__ import annotations

import json
import logging
import re
import time

import httpx

from stackwise.config import Settings

logger = logging.getLogger(__name__)


def _log_parse_failure(raw: str) -> None:
    """Log a truncated sample when LLM response fails to parse as JSON."""
    sample = raw.strip()[:300] + ("..." if len(raw) > 300 else "")
    logger.warning(
        "Failed to parse LLM response as JSON. Sample: %r",
        sample,
    )


_SYSTEM_PROMPT = """\
You are a senior AWS Solutions Architect reviewing an AWS account scan.
Analyze the provided infrastructure data and produce actionable recommendations.

Respond ONLY with a JSON array of objects. No markdown, no explanation, no text outside the array.
Each object MUST have these keys:
- "category": one of "security", "cost", "reliability", "performance", "operational_excellence"
- "title": short summary (one sentence)
- "detail": explanation of the issue and why it matters
- "impact": "high", "medium", or "low"
- "effort": "low", "medium", or "high"

Example: [{"category": "security", "title": "Enable MFA", "detail": "...",
"impact": "high", "effort": "low"}]

Do NOT duplicate recommendations that match the existing rule-based findings.
Focus on cross-cutting patterns and issues the deterministic rules might miss.
"""

_CATEGORY_CONTEXT = {
    "compute": (
        "For compute: scaling, HA, security (IMDS, networking), cost, modernization."
    ),
    "data": (
        "For data: encryption at rest, backup/recovery, retention, access, cost."
    ),
    "network": (
        "For network: security (ports, WAF), encryption, logging, connectivity."
    ),
    "security": (
        "For security: least privilege, rotation, MFA, audit, key management."
    ),
    "observability": (
        "For observability: alerting, retention, encryption, cost of logs."
    ),
    "cost": (
        "For cost: tagging, rightsizing, reserved capacity, unused resources."
    ),
    "discovery": "For discovery: tagging, compliance, resource inventory.",
    "other": "Identify cross-cutting improvements across the infrastructure.",
}

_CATEGORY_PROMPT = """\
## {category} resources ({count} total){chunk_context}

Below is a JSON summary of the scanned {category} resources and any rule-based
findings already detected. Identify additional cross-cutting recommendations
that the deterministic rules might miss.

{category_focus}

### Resources
{resources_json}

### Existing findings
{findings_json}
"""


class OllamaClient:
    """HTTP client for the Ollama REST API."""

    def __init__(self, settings: Settings) -> None:
        self.base_url = settings.ollama_url.rstrip("/")
        self.model = settings.model
        self.timeout = httpx.Timeout(300.0, connect=10.0)

    # ── Health ─────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if the Ollama server is reachable."""
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=5.0)
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def ensure_model(self) -> bool:
        """Check if the configured model is pulled locally."""
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=10.0)
            if r.status_code != 200:
                return False
            models = [m["name"] for m in r.json().get("models", [])]
            # Ollama tags may include :latest suffix
            return any(
                self.model == m or self.model == m.split(":")[0]
                for m in models
            )
        except httpx.HTTPError:
            return False

    # ── Generation ─────────────────────────────────────────

    def generate(self, prompt: str, *, max_retries: int = 3) -> str:
        """Send a prompt to Ollama and return the full response text."""
        payload = {
            "model": self.model,
            "system": _SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 4096,
            },
        }

        for attempt in range(max_retries):
            try:
                r = httpx.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=self.timeout,
                )
                r.raise_for_status()
                return r.json().get("response", "")
            except httpx.HTTPError as e:
                logger.warning("Ollama request failed (attempt %d): %s", attempt + 1, e)
                if attempt < max_retries - 1:
                    time.sleep(2**attempt)

        logger.error("Ollama unreachable after %d attempts", max_retries)
        return ""

    # ── Prompt builders ────────────────────────────────────

    @staticmethod
    def build_category_prompt(
        category: str,
        resources: list[dict],
        findings: list[dict],
        *,
        chunk_index: int | None = None,
        total_chunks: int | None = None,
    ) -> str:
        """Build a prompt for a single resource category (or chunk)."""
        # Truncate to keep within context window (~6K tokens ≈ 24KB of JSON)
        resources_json = json.dumps(resources, indent=None, default=str)
        if len(resources_json) > 24_000:
            resources_json = resources_json[:24_000] + "\n... (truncated)"

        findings_json = json.dumps(findings[:30], indent=None, default=str)

        chunk_context = ""
        if chunk_index is not None and total_chunks is not None and total_chunks > 1:
            chunk_context = f" (chunk {chunk_index + 1}/{total_chunks})"

        category_focus = _CATEGORY_CONTEXT.get(
            category, _CATEGORY_CONTEXT["other"]
        )
        category_focus = f"Focus: {category_focus}"

        return _CATEGORY_PROMPT.format(
            category=category,
            count=len(resources),
            chunk_context=chunk_context,
            category_focus=category_focus,
            resources_json=resources_json,
            findings_json=findings_json,
        )

    @staticmethod
    def parse_recommendations(raw: str) -> list[dict]:
        """Extract and validate the JSON array from the LLM response text."""
        text = raw.strip()
        if not text:
            return []

        # Extract from ```json ... ``` or ``` ... ``` block
        code_block = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if code_block:
            text = code_block.group(1).strip()

        # Try direct parse first
        try:
            data = json.loads(text)
            if not isinstance(data, list):
                return []
        except json.JSONDecodeError:
            # Try to find a JSON array in the response (handles leading/trailing prose)
            start = text.find("[")
            end = text.rfind("]")
            if start != -1 and end != -1 and end >= start:
                try:
                    data = json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    _log_parse_failure(raw)
                    return []
            else:
                _log_parse_failure(raw)
                return []

        # Validate schema: category, title, detail, impact, effort
        valid_categories = {
            "security", "cost", "reliability", "performance", "operational_excellence"
        }
        result = []
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                logger.debug("Skipping non-dict item at index %d", i)
                continue
            category = item.get("category")
            title = item.get("title")
            if not title or not isinstance(title, str):
                logger.debug("Skipping item without valid title at index %d", i)
                continue
            if category and category not in valid_categories:
                category = "operational_excellence"
            valid_levels = ("high", "medium", "low")
            result.append({
                "category": category or "operational_excellence",
                "title": str(title).strip(),
                "detail": item.get("detail") if isinstance(item.get("detail"), str) else None,
                "impact": item.get("impact") if item.get("impact") in valid_levels else None,
                "effort": item.get("effort") if item.get("effort") in valid_levels else None,
            })
        return result
