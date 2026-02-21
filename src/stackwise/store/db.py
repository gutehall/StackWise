"""SQLite data store for scan results, findings, and recommendations."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    account_id  TEXT NOT NULL,
    regions     TEXT NOT NULL,   -- JSON array
    modules     TEXT NOT NULL    -- JSON array
);

CREATE TABLE IF NOT EXISTS resources (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    service         TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    region          TEXT NOT NULL,
    arn             TEXT,
    metadata_json   TEXT NOT NULL  -- full API response as JSON
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id),
    resource_id TEXT REFERENCES resources(id),
    rule_id     TEXT,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT,
    remediation TEXT
);

CREATE TABLE IF NOT EXISTS recommendations (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id),
    source      TEXT NOT NULL,  -- 'rule' or 'llm'
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT,
    impact      TEXT,
    effort      TEXT
);

CREATE INDEX IF NOT EXISTS idx_resources_scan ON resources(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_recommendations_scan ON recommendations(scan_id);
"""


def _uid() -> str:
    return uuid.uuid4().hex[:12]


@dataclass
class ScanRecord:
    id: str
    timestamp: str
    account_id: str
    regions: list[str]
    modules: list[str]


@dataclass
class ResourceRecord:
    id: str
    scan_id: str
    service: str
    resource_type: str
    resource_id: str
    region: str
    arn: str | None
    metadata: dict = field(default_factory=dict)


@dataclass
class FindingRecord:
    id: str
    scan_id: str
    resource_id: str | None
    rule_id: str | None
    severity: str
    title: str
    detail: str | None = None
    remediation: str | None = None


@dataclass
class RecommendationRecord:
    id: str
    scan_id: str
    source: str
    category: str
    title: str
    detail: str | None = None
    impact: str | None = None
    effort: str | None = None


class ScanDB:
    """Thin wrapper around a per-scan SQLite database."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)

    # ── Scans ──────────────────────────────────────────────

    def create_scan(self, account_id: str, regions: list[str], modules: list[str]) -> ScanRecord:
        scan = ScanRecord(
            id=_uid(),
            timestamp=datetime.now(UTC).isoformat(),
            account_id=account_id,
            regions=regions,
            modules=modules,
        )
        self.conn.execute(
            "INSERT INTO scans (id, timestamp, account_id, regions, modules) VALUES (?,?,?,?,?)",
            (scan.id, scan.timestamp, scan.account_id,
             json.dumps(scan.regions), json.dumps(scan.modules)),
        )
        self.conn.commit()
        return scan

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        row = self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return ScanRecord(
            id=row["id"],
            timestamp=row["timestamp"],
            account_id=row["account_id"],
            regions=json.loads(row["regions"]),
            modules=json.loads(row["modules"]),
        )

    def latest_scan(self) -> ScanRecord | None:
        row = self.conn.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 1").fetchone()
        if not row:
            return None
        return ScanRecord(
            id=row["id"],
            timestamp=row["timestamp"],
            account_id=row["account_id"],
            regions=json.loads(row["regions"]),
            modules=json.loads(row["modules"]),
        )

    # ── Resources ──────────────────────────────────────────

    def insert_resource(
        self,
        scan_id: str,
        service: str,
        resource_type: str,
        resource_id: str,
        region: str,
        arn: str | None = None,
        metadata: dict | None = None,
    ) -> ResourceRecord:
        with self._lock:
            return self._insert_resource_unsafe(
                scan_id, service, resource_type, resource_id, region, arn, metadata
            )

    def _insert_resource_unsafe(
        self,
        scan_id: str,
        service: str,
        resource_type: str,
        resource_id: str,
        region: str,
        arn: str | None = None,
        metadata: dict | None = None,
    ) -> ResourceRecord:
        rec = ResourceRecord(
            id=_uid(),
            scan_id=scan_id,
            service=service,
            resource_type=resource_type,
            resource_id=resource_id,
            region=region,
            arn=arn,
            metadata=metadata or {},
        )
        self.conn.execute(
            "INSERT INTO resources "
            "(id, scan_id, service, resource_type, resource_id, "
            "region, arn, metadata_json) VALUES (?,?,?,?,?,?,?,?)",
            (rec.id, rec.scan_id, rec.service, rec.resource_type,
             rec.resource_id, rec.region, rec.arn,
             json.dumps(rec.metadata, default=str)),
        )
        self.conn.commit()
        return rec

    def get_resources(self, scan_id: str, service: str | None = None) -> list[ResourceRecord]:
        query = "SELECT * FROM resources WHERE scan_id = ?"
        params: list[Any] = [scan_id]
        if service:
            query += " AND service = ?"
            params.append(service)
        rows = self.conn.execute(query, params).fetchall()
        return [
            ResourceRecord(
                id=r["id"], scan_id=r["scan_id"], service=r["service"],
                resource_type=r["resource_type"], resource_id=r["resource_id"],
                region=r["region"], arn=r["arn"], metadata=json.loads(r["metadata_json"]),
            )
            for r in rows
        ]

    # ── Findings ───────────────────────────────────────────

    def insert_finding(
        self,
        scan_id: str,
        severity: str,
        title: str,
        *,
        resource_id: str | None = None,
        rule_id: str | None = None,
        detail: str | None = None,
        remediation: str | None = None,
    ) -> FindingRecord:
        rec = FindingRecord(
            id=_uid(), scan_id=scan_id, resource_id=resource_id,
            rule_id=rule_id, severity=severity, title=title,
            detail=detail, remediation=remediation,
        )
        self.conn.execute(
            "INSERT INTO findings "
            "(id, scan_id, resource_id, rule_id, severity, "
            "title, detail, remediation) VALUES (?,?,?,?,?,?,?,?)",
            (rec.id, rec.scan_id, rec.resource_id, rec.rule_id,
             rec.severity, rec.title, rec.detail, rec.remediation),
        )
        self.conn.commit()
        return rec

    def get_findings(self, scan_id: str, severity: str | None = None) -> list[FindingRecord]:
        query = "SELECT * FROM findings WHERE scan_id = ?"
        params: list[Any] = [scan_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += (
            " ORDER BY CASE severity"
            " WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1"
            " WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3"
            " ELSE 4 END"
        )
        rows = self.conn.execute(query, params).fetchall()
        return [
            FindingRecord(
                id=r["id"], scan_id=r["scan_id"], resource_id=r["resource_id"],
                rule_id=r["rule_id"], severity=r["severity"], title=r["title"],
                detail=r["detail"], remediation=r["remediation"],
            )
            for r in rows
        ]

    # ── Recommendations ────────────────────────────────────

    def insert_recommendation(
        self,
        scan_id: str,
        source: str,
        category: str,
        title: str,
        *,
        detail: str | None = None,
        impact: str | None = None,
        effort: str | None = None,
    ) -> RecommendationRecord:
        rec = RecommendationRecord(
            id=_uid(), scan_id=scan_id, source=source, category=category,
            title=title, detail=detail, impact=impact, effort=effort,
        )
        self.conn.execute(
            "INSERT INTO recommendations "
            "(id, scan_id, source, category, title, detail, "
            "impact, effort) VALUES (?,?,?,?,?,?,?,?)",
            (rec.id, rec.scan_id, rec.source, rec.category,
             rec.title, rec.detail, rec.impact, rec.effort),
        )
        self.conn.commit()
        return rec

    def get_recommendations(self, scan_id: str) -> list[RecommendationRecord]:
        rows = self.conn.execute(
            "SELECT * FROM recommendations WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [
            RecommendationRecord(
                id=r["id"], scan_id=r["scan_id"], source=r["source"],
                category=r["category"], title=r["title"], detail=r["detail"],
                impact=r["impact"], effort=r["effort"],
            )
            for r in rows
        ]

    # ── Utilities ──────────────────────────────────────────

    def summary(self, scan_id: str) -> dict:
        """Return a quick summary of a scan's contents."""
        resource_count = self.conn.execute(
            "SELECT COUNT(*) FROM resources WHERE scan_id = ?", (scan_id,)
        ).fetchone()[0]
        findings_by_sev = {}
        for row in self.conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings WHERE scan_id = ? GROUP BY severity",
            (scan_id,),
        ):
            findings_by_sev[row["severity"]] = row["cnt"]
        rec_count = self.conn.execute(
            "SELECT COUNT(*) FROM recommendations WHERE scan_id = ?", (scan_id,)
        ).fetchone()[0]
        return {
            "resources": resource_count,
            "findings": findings_by_sev,
            "recommendations": rec_count,
        }

    def close(self) -> None:
        self.conn.close()
