"""Scan diff / drift detection — compare two scans."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from stackwise.store.db import ScanDB


def _resource_key(r) -> tuple[str, str, str, str]:
    """Unique key for a resource: (service, resource_type, resource_id, region)."""
    return (r.service, r.resource_type, r.resource_id, r.region)


def _finding_key(f, resource_key: tuple | None) -> tuple:
    """Key for finding: (rule_id, resource_key). Same rule on same resource."""
    return (f.rule_id or "", resource_key)


@dataclass
class DiffResult:
    """Result of comparing two scans."""

    base_scan_id: str
    compare_scan_id: str
    resources_added: list = field(default_factory=list)
    resources_removed: list = field(default_factory=list)
    findings_added: list = field(default_factory=list)
    findings_removed: list = field(default_factory=list)
    findings_unchanged: int = 0


def diff_scans(
    base_db_path: Path,
    compare_db_path: Path,
) -> DiffResult:
    """Compare two scans and return added/removed resources and findings."""
    base_db = ScanDB(base_db_path)
    compare_db = ScanDB(compare_db_path)

    base_scan = base_db.latest_scan()
    compare_scan = compare_db.latest_scan()
    if not base_scan or not compare_scan:
        base_db.close()
        compare_db.close()
        raise ValueError("One or both scans have no scan record")

    base_resources = base_db.get_resources(base_scan.id)
    compare_resources = compare_db.get_resources(compare_scan.id)
    base_res_map = {_resource_key(r): r for r in base_resources}
    compare_res_map = {_resource_key(r): r for r in compare_resources}

    resources_added = [
        r for k, r in compare_res_map.items() if k not in base_res_map
    ]
    resources_removed = [
        r for k, r in base_res_map.items() if k not in compare_res_map
    ]

    base_findings = base_db.get_findings(base_scan.id)
    compare_findings = compare_db.get_findings(compare_scan.id)
    base_res_by_id = {r.id: r for r in base_resources}
    compare_res_by_id = {r.id: r for r in compare_resources}

    def finding_keys(findings, res_by_id):
        keys = set()
        for f in findings:
            res = res_by_id.get(f.resource_id) if f.resource_id else None
            rk = _resource_key(res) if res else None
            keys.add(_finding_key(f, rk))
        return keys

    base_f_keys = finding_keys(base_findings, base_res_by_id)
    compare_f_keys = finding_keys(compare_findings, compare_res_by_id)

    def get_res_key(f, res_by_id):
        res = res_by_id.get(f.resource_id) if f.resource_id else None
        return _resource_key(res) if res else None

    findings_added = [
        f for f in compare_findings
        if _finding_key(f, get_res_key(f, compare_res_by_id)) not in base_f_keys
    ]
    findings_removed = [
        f for f in base_findings
        if _finding_key(f, get_res_key(f, base_res_by_id)) not in compare_f_keys
    ]
    findings_unchanged = len(base_f_keys & compare_f_keys)

    base_db.close()
    compare_db.close()

    return DiffResult(
        base_scan_id=base_scan.id,
        compare_scan_id=compare_scan.id,
        resources_added=resources_added,
        resources_removed=resources_removed,
        findings_added=findings_added,
        findings_removed=findings_removed,
        findings_unchanged=findings_unchanged,
    )
