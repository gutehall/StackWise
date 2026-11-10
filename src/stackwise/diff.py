"""Scan diff / drift detection — compare two scans."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from stackwise.store.db import ScanDB


def _resource_key(r) -> tuple[str, str, str, str]:
    """Unique key for a resource: (service, resource_type, resource_id, region).

    S3 bucket names are globally unique and a bucket can't change region, so a bucket's
    stored region is left out. It can differ between scans without the bucket changing:
    a failed location lookup stores "unknown", and older scans stored a guessed
    "us-east-1" or a raw "EU".
    """
    if r.service == "s3" and r.resource_type == "bucket":
        return (r.service, r.resource_type, r.resource_id, "")
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
    base_regions: list[str] = field(default_factory=list)
    base_modules: list[str] = field(default_factory=list)
    compare_regions: list[str] = field(default_factory=list)
    compare_modules: list[str] = field(default_factory=list)

    @property
    def scope_differs(self) -> bool:
        """True if the scans covered different regions or modules, in which case
        anything outside the overlap shows up as added or removed."""
        return (
            set(self.base_regions) != set(self.compare_regions)
            or set(self.base_modules) != set(self.compare_modules)
        )


def is_completed_scan(db_path: Path) -> bool:
    """True if the file holds a scan that finished without scan errors.

    False also for a file that can't be read as a scan. A file older than the
    completeness tables counts as complete.
    """
    try:
        db = ScanDB(db_path, mode="ro")
    except (FileNotFoundError, sqlite3.DatabaseError):
        return False
    try:
        return db.latest_scan() is not None and db.is_complete()
    except sqlite3.DatabaseError:  # empty file, or not a scan database at all
        return False
    finally:
        db.close()


def previous_completed_scan(compare_db_path: Path) -> Path | None:
    """Return the newest completed scan older than *compare_db_path*, or None.

    Scan filenames sort in scan order, unlike mtime. A scan that failed or never
    finished is skipped: everything it missed would look removed.
    """
    earlier = [p for p in compare_db_path.parent.glob("*.db") if p.stem < compare_db_path.stem]
    for path in sorted(earlier, key=lambda p: p.stem, reverse=True):
        if is_completed_scan(path):
            return path
    return None


def diff_scans(
    base_db_path: Path,
    compare_db_path: Path,
) -> DiffResult:
    """Compare two scans and return added/removed resources and findings."""
    base_db = ScanDB(base_db_path, mode="ro")
    try:
        compare_db = ScanDB(compare_db_path, mode="ro")
    except Exception:
        base_db.close()
        raise

    try:
        try:
            base_scan = base_db.latest_scan()
            compare_scan = compare_db.latest_scan()
        except sqlite3.DatabaseError:  # empty file, or not a scan database at all
            base_scan = compare_scan = None
        if not base_scan or not compare_scan:
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
    finally:
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
        base_regions=base_scan.regions,
        base_modules=base_scan.modules,
        compare_regions=compare_scan.regions,
        compare_modules=compare_scan.modules,
    )
