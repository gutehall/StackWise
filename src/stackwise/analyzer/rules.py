"""Load and evaluate YAML-based rules against scanned resources."""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from types import CodeType

import yaml

from stackwise.store.db import ScanDB

logger = logging.getLogger(__name__)

# Safe builtins for rule condition evaluation (blocks open, exec, eval, __import__, etc.).
# Deliberately excludes getattr/hasattr: those allow dynamic attribute lookup by string
# (e.g. getattr(x, '__class__')), which would bypass the static attribute-name allowlist
# in _validate_condition_ast below and reopen the sandbox-escape path it closes.
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
}

# Restricting __builtins__ alone does not make eval() safe: attribute access
# (`().__class__.__bases__`) is a bytecode operation, not a builtin call, so it bypasses
# any builtins allowlist entirely. Every condition is therefore parsed and validated against
# this explicit AST allowlist before being compiled — only these node types, attribute names,
# and identifiers may appear in a rule's `condition` string.
_ALLOWED_NODE_TYPES = (
    ast.Expression,
    ast.BoolOp, ast.And, ast.Or,
    ast.UnaryOp, ast.Not, ast.USub, ast.UAdd,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod,
    ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.In, ast.NotIn, ast.Is, ast.IsNot,
    ast.Call, ast.Attribute, ast.Subscript, ast.Slice,
    ast.Name, ast.Load, ast.Store, ast.Constant,
    ast.List, ast.Tuple, ast.Dict, ast.Set,
    ast.comprehension, ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp,
    ast.IfExp,
)

# Only inert, no-escape methods on dict/list/str values — resource metadata is always
# plain JSON-decoded data, so this covers every real use case without exposing dunders.
_ALLOWED_METHOD_NAMES = {
    "get", "keys", "values", "items",
    "startswith", "endswith", "split", "rsplit", "strip", "lower", "upper",
}


class RuleConditionError(ValueError):
    """A rule's `condition` failed AST validation or failed to compile."""


def _comprehension_bound_names(tree: ast.AST) -> set[str]:
    """Names bound by `for x in ...` inside the condition (e.g. generator expressions)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.comprehension):
            names |= _target_names(node.target)
    return names


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for elt in target.elts:
            names |= _target_names(elt)
        return names
    return set()


def _compile_condition(condition: str, rule_id: str) -> CodeType:
    """Validate *condition* against the AST allowlist and compile it.

    Raises RuleConditionError if the condition uses any syntax, name, or
    attribute outside the allowlist.
    """
    try:
        tree = ast.parse(condition, mode="eval")
    except SyntaxError as e:
        raise RuleConditionError(f"{rule_id}: syntax error in condition: {e}") from e

    allowed_names = {"resource"} | set(_SAFE_BUILTINS) | _comprehension_bound_names(tree)

    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODE_TYPES):
            raise RuleConditionError(
                f"{rule_id}: disallowed syntax in condition: {type(node).__name__}"
            )
        if isinstance(node, ast.Attribute) and node.attr not in _ALLOWED_METHOD_NAMES:
            raise RuleConditionError(
                f"{rule_id}: disallowed attribute access '.{node.attr}' in condition"
            )
        if isinstance(node, ast.Name) and node.id not in allowed_names:
            raise RuleConditionError(
                f"{rule_id}: disallowed name '{node.id}' in condition"
            )
        if isinstance(node, ast.Call) and (
            node.keywords or any(isinstance(a, ast.Starred) for a in node.args)
        ):
            raise RuleConditionError(
                f"{rule_id}: keyword/starred call arguments are not allowed in condition"
            )

    return compile(tree, filename=f"<rule:{rule_id}>", mode="eval")

def _default_rules_dir() -> Path:
    """Resolve the bundled rules directory.

    rules/ lives inside the stackwise package (src/stackwise/rules) so it is
    included in built wheels/sdists and resolves the same way whether
    installed editable, installed from a wheel, or run from Docker — no
    special-casing needed. The /app/rules fallback is kept only for older
    deployments that still COPY rules to that path explicitly.
    """
    packaged = Path(__file__).resolve().parent.parent / "rules"
    if packaged.is_dir():
        return packaged
    fallback = Path("/app/rules")
    return fallback if fallback.is_dir() else packaged


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
    compiled_condition: CodeType | None = field(default=None, repr=False, compare=False)


def load_rules(rules_dir: Path | None = None) -> list[Rule]:
    """Load all YAML rule files from the rules directory.

    Each condition is validated and compiled once here (not per-resource in
    evaluate_rules) — a rule whose condition fails validation is logged and
    skipped rather than aborting the whole load.
    """
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
                rule_id = entry["id"]
                condition = entry["condition"].strip()
                try:
                    compiled = _compile_condition(condition, rule_id)
                except RuleConditionError:
                    logger.exception("Rejecting rule %s from %s", rule_id, path)
                    continue
                rules.append(
                    Rule(
                        id=rule_id,
                        title=entry["title"],
                        severity=entry["severity"],
                        resource_type=entry["resource_type"],
                        service=entry.get("service", ""),
                        condition=condition,
                        remediation=entry.get("remediation", ""),
                        priority=entry.get("priority", 999),
                        compiled_condition=compiled,
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
                # Evaluate the pre-validated, pre-compiled condition with
                # `resource` in scope — see _compile_condition for what's allowed.
                result = eval(
                    rule.compiled_condition,
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
                logger.warning(
                    "Rule %s failed on resource %s: %s",
                    rule.id, res.resource_id, rule.condition,
                    exc_info=True,
                )

    logger.info("Rule evaluation produced %d findings", findings_count)
    return findings_count
