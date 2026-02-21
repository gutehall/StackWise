"""Load and evaluate YAML-based rules against scanned resources."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

from stackwise.store.db import ScanDB

logger = logging.getLogger(__name__)

# Safe builtins for rule condition evaluation (blocks open, exec, eval, __import__, etc.)
_SAFE_BUILTINS = {
    "len": len,
    "any": any,
    "all": all,
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "None": None,
    "True": True,
    "False": False,
    "list": list,
    "dict": dict,
    "tuple": tuple,
    "set": set,
    "min": min,
    "max": max,
    "sum": sum,
    "sorted": sorted,
    "isinstance": isinstance,
    "hasattr": hasattr,
    "getattr": getattr,
}

def _default_rules_dir() -> Path:
    """Resolve rules directory (project root or /app/rules in Docker)."""
    base = Path(__file__).resolve().parent.parent.parent.parent / "rules"
    if base.is_dir():
        return base
    # Docker: rules copied to /app/rules
    fallback = Path("/app/rules")
    return fallback if fallback.is_dir() else base


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    resource_type: str
    service: str
    condition: str
    remediation: str
    priority: int = 999  # 1=highest; used for ordering when severity is equal


def load_rules(rules_dir: Path | None = None) -> list[Rule]:
    """Load all YAML rule files from the rules directory."""
    import os
    env_dir = os.environ.get("STACKWISE_RULES_DIR")
    base = rules_dir or (Path(env_dir) if env_dir else _default_rules_dir())
    rules: list[Rule] = []
    if not base.is_dir():
        logger.warning("Rules directory not found: %s", base)
        return rules

    for path in sorted(base.glob("*.yaml")):
        try:
            with open(path) as f:
                entries = yaml.safe_load(f) or []
            for entry in entries:
                rules.append(
                    Rule(
                        id=entry["id"],
                        title=entry["title"],
                        severity=entry["severity"],
                        resource_type=entry["resource_type"],
                        service=entry.get("service", ""),
                        condition=entry["condition"].strip(),
                        remediation=entry.get("remediation", ""),
                        priority=entry.get("priority", 999),
                    )
                )
        except Exception:
            logger.exception("Failed to load rules from %s", path)

    logger.info("Loaded %d rules from %s", len(rules), base)
    return rules


def evaluate_rules(
    rules: list[Rule],
    db: ScanDB,
    scan_id: str,
    *,
    suppressed_rules: list[str] | None = None,
) -> int:
    """Evaluate all rules against resources in the scan and insert findings.

    Returns:
        Number of findings created.
    """
    suppressed = set(suppressed_rules or [])
    resources = db.get_resources(scan_id)
    findings_count = 0

    for rule in rules:
        if rule.id in suppressed:
            continue
        matching = [
            r for r in resources
            if r.resource_type == rule.resource_type
            and (not rule.service or r.service == rule.service)
        ]

        for res in matching:
            try:
                # Evaluate condition with `resource` in scope
                result = eval(
                    rule.condition,
                    {"__builtins__": _SAFE_BUILTINS},
                    {"resource": res.metadata},
                )
                if result:
                    db.insert_finding(
                        scan_id=scan_id,
                        severity=rule.severity,
                        title=rule.title,
                        resource_id=res.id,
                        rule_id=rule.id,
                        detail=f"Resource {res.resource_id} in {res.region}",
                        remediation=rule.remediation,
                    )
                    findings_count += 1
            except Exception:
                logger.debug(
                    "Rule %s failed on resource %s: %s",
                    rule.id, res.resource_id, rule.condition,
                    exc_info=True,
                )

    logger.info("Rule evaluation produced %d findings", findings_count)
    return findings_count
