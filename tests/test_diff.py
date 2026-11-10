"""Tests for scan diff / drift detection."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from stackwise.diff import DiffResult, diff_scans, previous_completed_scan
from stackwise.store.db import ScanDB


def test_diff_scans_resources_added_removed(tmp_path: Path):
    """Diff should detect added and removed resources."""
    db1 = ScanDB(tmp_path / "scan1.db")
    db2 = ScanDB(tmp_path / "scan2.db")

    s1 = db1.create_scan("123", ["us-east-1"], ["compute"])
    s2 = db2.create_scan("123", ["us-east-1"], ["compute"])

    db1.insert_resource(s1.id, "ec2", "instance", "i-1", "us-east-1", metadata={})
    db1.insert_resource(s1.id, "ec2", "instance", "i-2", "us-east-1", metadata={})

    db2.insert_resource(s2.id, "ec2", "instance", "i-2", "us-east-1", metadata={})
    db2.insert_resource(s2.id, "ec2", "instance", "i-3", "us-east-1", metadata={})

    result = diff_scans(tmp_path / "scan1.db", tmp_path / "scan2.db")

    assert len(result.resources_added) == 1
    assert result.resources_added[0].resource_id == "i-3"
    assert len(result.resources_removed) == 1
    assert result.resources_removed[0].resource_id == "i-1"

    db1.close()
    db2.close()


def test_diff_scans_findings(tmp_path: Path):
    """Diff should detect added and removed findings."""
    db1 = ScanDB(tmp_path / "scan1.db")
    db2 = ScanDB(tmp_path / "scan2.db")

    s1 = db1.create_scan("123", ["us-east-1"], ["compute"])
    s2 = db2.create_scan("123", ["us-east-1"], ["compute"])

    r1 = db1.insert_resource(s1.id, "ec2", "instance", "i-1", "us-east-1", metadata={})
    r2 = db2.insert_resource(s2.id, "ec2", "instance", "i-1", "us-east-1", metadata={})

    db1.insert_finding(s1.id, "HIGH", "Old finding", resource_id=r1.id, rule_id="R1")
    db2.insert_finding(s2.id, "HIGH", "New finding", resource_id=r2.id, rule_id="R2")

    result = diff_scans(tmp_path / "scan1.db", tmp_path / "scan2.db")

    assert len(result.findings_added) == 1
    assert result.findings_added[0].rule_id == "R2"
    assert len(result.findings_removed) == 1
    assert result.findings_removed[0].rule_id == "R1"

    db1.close()
    db2.close()


def test_diff_scans_closes_connections_even_on_failure(tmp_path: Path):
    """An exception mid-comparison must still close both scan DB connections."""
    db1 = ScanDB(tmp_path / "scan1.db")
    db2 = ScanDB(tmp_path / "scan2.db")
    db1.create_scan("123", ["us-east-1"], ["compute"])
    db2.create_scan("123", ["us-east-1"], ["compute"])
    db1.close()
    db2.close()

    # Wrap the real close() (rather than replacing it) so this test doesn't
    # itself leak the sqlite3 connections diff_scans() opens internally.
    close_calls: list[ScanDB] = []
    real_close = ScanDB.close

    def counting_close(self: ScanDB) -> None:
        close_calls.append(self)
        real_close(self)

    with patch.object(ScanDB, "get_resources", side_effect=RuntimeError("boom")), patch.object(
        ScanDB, "close", counting_close
    ):
        with pytest.raises(RuntimeError):
            diff_scans(tmp_path / "scan1.db", tmp_path / "scan2.db")

    assert len(close_calls) == 2


def test_diff_scans_raises_when_a_scan_has_no_record(tmp_path: Path):
    """A DB file with no scan row (e.g. created but never populated) must raise
    a clear ValueError rather than diffing against a None scan."""
    db1 = ScanDB(tmp_path / "empty1.db")
    db2 = ScanDB(tmp_path / "scan2.db")
    db2.create_scan("123", ["us-east-1"], ["compute"])
    db1.close()
    db2.close()

    with pytest.raises(ValueError, match="no scan record"):
        diff_scans(tmp_path / "empty1.db", tmp_path / "scan2.db")


def test_diff_scans_does_not_change_either_file(tmp_path: Path):
    """Reading an old scan must not make it look like the newest one."""
    paths = [tmp_path / "scan1.db", tmp_path / "scan2.db"]
    for path in paths:
        db = ScanDB(path)
        db.create_scan("123", ["us-east-1"], ["compute"])
        db.close()
        os.utime(path, (1_000_000, 1_000_000))

    diff_scans(*paths)

    assert [p.stat().st_mtime for p in paths] == [1_000_000, 1_000_000]


def test_diff_scans_missing_compare_raises_and_creates_nothing(tmp_path: Path):
    base = tmp_path / "base.db"
    db = ScanDB(base)
    db.create_scan("123", ["us-east-1"], ["compute"])
    db.close()
    missing = tmp_path / "missing.db"

    with pytest.raises(FileNotFoundError):
        diff_scans(base, missing)

    assert not missing.exists()


def test_diff_scans_empty_file_has_no_scan_record(tmp_path: Path):
    base = tmp_path / "base.db"
    db = ScanDB(base)
    db.create_scan("123", ["us-east-1"], ["compute"])
    db.close()
    empty = tmp_path / "empty.db"
    empty.touch()

    with pytest.raises(ValueError, match="no scan record"):
        diff_scans(base, empty)

    assert empty.stat().st_size == 0


def _make_scan(path: Path, *, in_progress: bool = False, error: bool = False) -> Path:
    db = ScanDB(path)
    scan = db.create_scan("123", ["us-east-1"], ["compute"], in_progress=in_progress)
    if error:
        db.insert_scan_error(scan.id, "ec2", "us-east-1", "describe_instances", "boom")
    db.close()
    return path


def test_previous_completed_scan_goes_by_filename_not_mtime(tmp_path: Path):
    old = _make_scan(tmp_path / "20240101T000000.db")
    middle = _make_scan(tmp_path / "20240101T000001.db")
    latest = _make_scan(tmp_path / "20240101T000002.db")
    os.utime(old, (9_000_000_000, 9_000_000_000))

    assert previous_completed_scan(latest) == middle


def test_previous_completed_scan_is_older_than_compare(tmp_path: Path):
    """--compare on an old scan must not pick a baseline from its future."""
    old = _make_scan(tmp_path / "20240101T000000.db")
    middle = _make_scan(tmp_path / "20240101T000001.db")
    _make_scan(tmp_path / "20240101T000002.db")

    assert previous_completed_scan(middle) == old
    assert previous_completed_scan(old) is None


def test_previous_completed_scan_skips_unusable_files(tmp_path: Path):
    good = _make_scan(tmp_path / "20240101T000000.db")
    _make_scan(tmp_path / "20240101T000001.db", error=True)
    _make_scan(tmp_path / "20240101T000002.db", in_progress=True)
    (tmp_path / "20240101T000003.db").touch()
    (tmp_path / "20240101T000004.db").write_text("not a database, not even close " * 50)
    ScanDB(tmp_path / "20240101T000005.db").close()  # schema, but no scan record
    latest = _make_scan(tmp_path / "20240101T000006.db")

    assert previous_completed_scan(latest) == good


def test_previous_completed_scan_tolerates_file_vanishing(tmp_path: Path):
    good = _make_scan(tmp_path / "20240101T000000.db")
    latest = _make_scan(tmp_path / "20240101T000001.db")

    with patch("stackwise.diff.ScanDB", side_effect=FileNotFoundError("gone")):
        assert previous_completed_scan(latest) is None
    assert previous_completed_scan(latest) == good


def test_diff_result_scope_ignores_order():
    same = DiffResult(
        "a", "b",
        base_regions=["us-east-1", "eu-west-1"],
        compare_regions=["eu-west-1", "us-east-1"],
    )
    assert same.scope_differs is False

    assert DiffResult("a", "b", base_modules=["compute"]).scope_differs is True
    assert DiffResult("a", "b", compare_regions=["us-east-1"]).scope_differs is True


def test_filename_order_holds_across_the_old_and_new_naming(tmp_path: Path):
    """Scans from before the microsecond and suffix names must sort correctly
    against new ones, including within the same second."""
    old = _make_scan(tmp_path / "20240101T000000.db")
    same_second = _make_scan(tmp_path / "20240101T000000.000001-aaaaaa.db")
    later = _make_scan(tmp_path / "20240101T000000.500000-000000.db")
    next_old = _make_scan(tmp_path / "20240101T000001.db")

    assert previous_completed_scan(same_second) == old
    assert previous_completed_scan(later) == same_second
    assert previous_completed_scan(next_old) == later


def _scan_with_bucket(path: Path, name: str, region: str, *, finding: bool = True) -> Path:
    db = ScanDB(path)
    scan = db.create_scan("123", ["us-east-1"], ["data"])
    bucket = db.insert_resource(scan.id, "s3", "bucket", name, region, metadata={})
    if finding:
        db.insert_finding(
            scan.id, "HIGH", "No versioning", resource_id=bucket.id, rule_id="DAT-001"
        )
    db.close()
    return path


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("unknown", "eu-west-1"),  # a failed location lookup, then a healthy scan
        ("eu-west-1", "unknown"),  # and the other way around
        ("us-east-1", "eu-west-1"),  # an older scan that guessed us-east-1
        ("EU", "eu-west-1"),  # an older scan that stored the raw constraint
    ],
)
def test_bucket_with_a_different_stored_region_is_not_drift(
    tmp_path: Path, before: str, after: str
):
    base = _scan_with_bucket(tmp_path / "a.db", "my-bucket", before)
    compare = _scan_with_bucket(tmp_path / "b.db", "my-bucket", after)

    result = diff_scans(base, compare)

    assert result.resources_added == []
    assert result.resources_removed == []
    assert result.findings_added == []
    assert result.findings_removed == []
    assert result.findings_unchanged == 1


def test_a_really_different_bucket_is_still_drift(tmp_path: Path):
    base = _scan_with_bucket(tmp_path / "a.db", "old-bucket", "eu-west-1", finding=False)
    compare = _scan_with_bucket(tmp_path / "b.db", "new-bucket", "eu-west-1", finding=False)

    result = diff_scans(base, compare)

    assert [r.resource_id for r in result.resources_added] == ["new-bucket"]
    assert [r.resource_id for r in result.resources_removed] == ["old-bucket"]


def test_region_still_matters_for_other_resources(tmp_path: Path):
    """Most ids are only unique within a region, so region stays in their key."""
    paths = []
    for name, region in (("a.db", "us-east-1"), ("b.db", "eu-west-1")):
        db = ScanDB(tmp_path / name)
        scan = db.create_scan("123", ["us-east-1"], ["data"])
        db.insert_resource(scan.id, "dynamodb", "table", "orders", region, metadata={})
        db.close()
        paths.append(tmp_path / name)

    result = diff_scans(*paths)

    assert [r.region for r in result.resources_added] == ["eu-west-1"]
    assert [r.region for r in result.resources_removed] == ["us-east-1"]
