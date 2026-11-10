"""SQLite data store for scan results, findings, and recommendations."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)

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

CREATE TABLE IF NOT EXISTS scan_errors (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id),
    scanner     TEXT NOT NULL,
    region      TEXT NOT NULL,
    operation   TEXT NOT NULL,
    message     TEXT NOT NULL
);

-- Written when a scan starts and removed when it succeeds, so a crashed scan keeps
-- its row. Inverted on purpose: files older than this table have no row and count
-- as complete.
CREATE TABLE IF NOT EXISTS incomplete_scans (
    scan_id     TEXT PRIMARY KEY REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_resources_scan ON resources(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_recommendations_scan ON recommendations(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_errors_scan ON scan_errors(scan_id);
"""

# How long a write waits for another connection to release the database. A longer
# wait multiplies: each row of a scan would wait this long in turn.
_BUSY_TIMEOUT_SECONDS = 10

# A row in any of these means the file holds a scan that must not be a diff baseline.
_INCOMPLETE_SCAN_CHECKS = {
    "scan_errors": "SELECT 1 FROM scan_errors LIMIT 1",
    "incomplete_scans": "SELECT 1 FROM incomplete_scans LIMIT 1",
}

# Enforces one row per (scan_id, service, resource_type, resource_id, region) so a
# resource discovered by two scanner modules in the same scan (e.g. cost + discovery
# both walking resourcegroupstaggingapi) is stored once. Created separately from
# _SCHEMA and best-effort: a pre-existing scan DB written before this constraint
# existed may already contain duplicate rows, which would make index creation fail.
_UNIQUE_RESOURCE_INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_resources_identity "
    "ON resources(scan_id, service, resource_type, resource_id, region)"
)


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


@dataclass
class ScanErrorRecord:
    id: str
    scan_id: str
    scanner: str
    region: str
    operation: str
    message: str


class ScanDB:
    """Thin wrapper around a per-scan SQLite database.

    ``mode`` is ``"create"`` for a new scan, ``"rw"`` to write to an existing file,
    or ``"ro"`` to read one without changing it, including its mtime. ``"rw"`` and
    ``"ro"`` raise FileNotFoundError for a missing file instead of creating it.
    ``"ro"`` skips the schema, so a table newer than the file can be absent.

    ``"create"`` uses WAL while the scan writes and returns to a single file on
    close. A read-only open of a WAL file would otherwise leave -shm and -wal
    files beside it.
    """

    def __init__(self, db_path: Path, mode: Literal["create", "rw", "ro"] = "create") -> None:
        self.db_path = db_path
        self._mode = mode
        self._lock = threading.Lock()
        # Scanners catch broad exceptions around per-resource work, which can swallow
        # a failed write. This keeps it visible, so the scan can still fail.
        self.write_failures: set[str] = set()
        if mode == "create":
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(
                str(db_path), timeout=_BUSY_TIMEOUT_SECONDS, check_same_thread=False
            )
            self.conn.execute("PRAGMA journal_mode=WAL")
        else:
            if not db_path.exists():
                raise FileNotFoundError(f"Scan database not found: {db_path}")
            self.conn = sqlite3.connect(
                f"{db_path.resolve().as_uri()}?mode={mode}",
                uri=True,
                timeout=_BUSY_TIMEOUT_SECONDS,
                check_same_thread=False,
            )
        self.conn.row_factory = sqlite3.Row
        if mode == "ro":
            return
        self.conn.executescript(_SCHEMA)
        try:
            self.conn.execute(_UNIQUE_RESOURCE_INDEX)
            self.conn.commit()
        except sqlite3.IntegrityError:
            logger.warning(
                "Could not enforce unique resource identity on %s — "
                "existing scan data has duplicate rows from before this constraint.",
                db_path,
            )

    # ── Scans ──────────────────────────────────────────────

    def create_scan(
        self,
        account_id: str,
        regions: list[str],
        modules: list[str],
        in_progress: bool = False,
    ) -> ScanRecord:
        """Insert a scan. With *in_progress*, it counts as incomplete until
        ``mark_scan_complete``, including if the process dies first."""
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
        if in_progress:
            self.conn.execute("INSERT INTO incomplete_scans (scan_id) VALUES (?)", (scan.id,))
        self.conn.commit()
        return scan

    def mark_scan_complete(self, scan_id: str) -> None:
        self.conn.execute("DELETE FROM incomplete_scans WHERE scan_id = ?", (scan_id,))
        self.conn.commit()

    def is_complete(self) -> bool:
        """False if a scan in this file failed or never finished.

        Read-only connections skip the schema, so a table newer than the file can
        be absent. That file predates the check and counts as complete.
        """
        tables = {
            row["name"]
            for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        return not any(
            self.conn.execute(query).fetchone()
            for table, query in _INCOMPLETE_SCAN_CHECKS.items()
            if table in tables
        )

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
        return self._insert_resource(
            scan_id, service, resource_type, resource_id, region, arn, metadata
        )[0]

    def insert_resource_if_new(
        self,
        scan_id: str,
        service: str,
        resource_type: str,
        resource_id: str,
        region: str,
        arn: str | None = None,
        metadata: dict | None = None,
    ) -> bool:
        """Insert a resource, and return True only if that created a row.

        Lets a scanner count what it stored, not what it saw: two modules can observe
        the same resource in one scan.
        """
        return self._insert_resource(
            scan_id, service, resource_type, resource_id, region, arn, metadata
        )[1]

    def _insert_resource(self, *args) -> tuple[ResourceRecord, bool]:
        with self._lock:
            try:
                return self._insert_resource_unsafe(*args)
            except sqlite3.Error as e:
                self.write_failures.add(str(e))
                raise

    def _insert_resource_unsafe(
        self,
        scan_id: str,
        service: str,
        resource_type: str,
        resource_id: str,
        region: str,
        arn: str | None = None,
        metadata: dict | None = None,
    ) -> tuple[ResourceRecord, bool]:
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
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO resources "
            "(id, scan_id, service, resource_type, resource_id, "
            "region, arn, metadata_json) VALUES (?,?,?,?,?,?,?,?)",
            (rec.id, rec.scan_id, rec.service, rec.resource_type,
             rec.resource_id, rec.region, rec.arn,
             json.dumps(rec.metadata, default=str)),
        )
        self.conn.commit()
        if cur.rowcount == 0:
            # Same (scan_id, service, resource_type, resource_id, region) already
            # stored by another scanner module in this scan — return that row.
            existing = self.conn.execute(
                "SELECT * FROM resources WHERE scan_id=? AND service=? AND "
                "resource_type=? AND resource_id=? AND region=?",
                (scan_id, service, resource_type, resource_id, region),
            ).fetchone()
            if existing:
                return ResourceRecord(
                    id=existing["id"], scan_id=existing["scan_id"],
                    service=existing["service"], resource_type=existing["resource_type"],
                    resource_id=existing["resource_id"], region=existing["region"],
                    arn=existing["arn"], metadata=json.loads(existing["metadata_json"]),
                ), False
        return rec, cur.rowcount > 0

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

    # ── Scan errors ────────────────────────────────────────

    def insert_scan_error(
        self,
        scan_id: str,
        scanner: str,
        region: str,
        operation: str,
        message: str,
    ) -> ScanErrorRecord:
        rec = ScanErrorRecord(
            id=_uid(), scan_id=scan_id, scanner=scanner, region=region,
            operation=operation, message=message,
        )
        # Called from scanner worker threads sharing this connection.
        with self._lock:
            self.conn.execute(
                "INSERT INTO scan_errors "
                "(id, scan_id, scanner, region, operation, message) VALUES (?,?,?,?,?,?)",
                (rec.id, rec.scan_id, rec.scanner, rec.region, rec.operation, rec.message),
            )
            self.conn.commit()
        return rec

    def get_scan_errors(self, scan_id: str) -> list[ScanErrorRecord]:
        rows = self.conn.execute(
            "SELECT * FROM scan_errors WHERE scan_id = ? ORDER BY rowid", (scan_id,)
        ).fetchall()
        return [
            ScanErrorRecord(
                id=r["id"], scan_id=r["scan_id"], scanner=r["scanner"], region=r["region"],
                operation=r["operation"], message=r["message"],
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
        if self._mode == "create":
            try:
                self.conn.execute("PRAGMA journal_mode=DELETE")
            except sqlite3.Error:
                # Another connection still has it open. A WAL file still reads fine.
                logger.debug("Could not leave WAL mode on %s", self.db_path, exc_info=True)
        self.conn.close()
