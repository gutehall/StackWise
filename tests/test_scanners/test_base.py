"""Tests for BaseScanner's region fan-out, error handling, and progress reporting."""

from __future__ import annotations

import sqlite3
from unittest.mock import MagicMock

import pytest

from stackwise.scanner.base import BaseScanner
from stackwise.store.db import ScanDB


class _CountingScanner(BaseScanner):
    """Returns a fixed count per region, or raises for regions in `fail_regions`."""

    name = "counting"

    def __init__(self, count_per_region: int = 1, fail_regions: set[str] | None = None):
        self.count_per_region = count_per_region
        self.fail_regions = fail_regions or set()
        self.scanned_regions: list[str] = []

    def _scan_region(self, session, db, scan_id, region) -> int:
        self.scanned_regions.append(region)
        if region in self.fail_regions:
            raise RuntimeError(f"boom in {region}")
        return self.count_per_region


def test_scan_sequential_sums_counts_across_regions():
    """With max_workers<=1, scan() should sum each region's count sequentially."""
    scanner = _CountingScanner(count_per_region=3)
    total = scanner.scan(MagicMock(), MagicMock(), "scan-1", ["us-east-1", "eu-west-1"])

    assert total == 6
    assert scanner.scanned_regions == ["us-east-1", "eu-west-1"]


def test_scan_region_failure_is_recorded_and_other_regions_still_counted(scan_db: ScanDB):
    """A region whose _scan_region raises must not abort the other regions, and
    must be recorded in scan_errors so the scan can't pass as a success."""
    scanner = _CountingScanner(count_per_region=5, fail_regions={"eu-west-1"})
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    total = scanner.scan(
        MagicMock(), scan_db, scan.id, ["us-east-1", "eu-west-1", "ap-south-1"]
    )

    assert total == 10  # us-east-1 (5) + ap-south-1 (5); eu-west-1 failed
    assert scanner.scanned_regions == ["us-east-1", "eu-west-1", "ap-south-1"]
    errors = scan_db.get_scan_errors(scan.id)
    assert [(e.scanner, e.region, e.operation, e.message) for e in errors] == [
        ("counting", "eu-west-1", "_scan_region", "boom in eu-west-1")
    ]


def test_scan_parallel_regions_sums_counts():
    """With max_workers>1, scan() should fan out across a ThreadPoolExecutor
    and still sum every region's count correctly."""
    scanner = _CountingScanner(count_per_region=2)
    regions = ["us-east-1", "eu-west-1", "ap-south-1"]
    total = scanner.scan(MagicMock(), MagicMock(), "scan-1", regions, max_workers=3)

    assert total == 6
    assert set(scanner.scanned_regions) == set(regions)


def test_scan_parallel_region_failure_is_recorded(scan_db: ScanDB):
    """A region failure under parallel execution must be recorded in scan_errors
    without corrupting the total for the other regions."""
    scanner = _CountingScanner(count_per_region=4, fail_regions={"us-east-1"})
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    total = scanner.scan(
        MagicMock(), scan_db, scan.id, ["us-east-1", "eu-west-1"], max_workers=2
    )

    assert total == 4  # only eu-west-1 succeeded
    errors = scan_db.get_scan_errors(scan.id)
    assert [(e.scanner, e.region, e.operation) for e in errors] == [
        ("counting", "us-east-1", "_scan_region")
    ]


@pytest.mark.parametrize("max_workers", [1, 2])
def test_scan_error_write_failure_propagates(max_workers: int):
    """If the scan_errors row can't be written (e.g. "database is locked"), the
    failure must escape scan() rather than vanish and look like a clean scan."""
    db = MagicMock()
    db.insert_scan_error.side_effect = sqlite3.OperationalError("database is locked")
    scanner = _CountingScanner(fail_regions={"us-east-1"})

    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        scanner.scan(
            MagicMock(), db, "scan-1", ["us-east-1", "eu-west-1"], max_workers=max_workers
        )


def test_record_list_failure_falls_back_to_repr_for_empty_message(scan_db: ScanDB):
    """An exception with no message must still leave something readable."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    _CountingScanner()._record_list_failure(
        scan_db, scan.id, "us-east-1", "list_things", TimeoutError()
    )

    assert scan_db.get_scan_errors(scan.id)[0].message == "TimeoutError()"


def test_scan_reports_progress_advance_per_region():
    """When a progress reporter is passed, scan() must add a task and advance
    it once per region scanned."""
    scanner = _CountingScanner(count_per_region=1)
    progress = MagicMock()
    progress.add_task.return_value = "task-id"

    scanner.scan(MagicMock(), MagicMock(), "scan-1", ["us-east-1", "eu-west-1"], progress=progress)

    progress.add_task.assert_called_once_with("[cyan]counting", total=2)
    assert progress.advance.call_count == 2
    progress.advance.assert_called_with("task-id")


def test_scan_reports_progress_advance_in_parallel_mode():
    """Progress reporting must also work under the ThreadPoolExecutor path."""
    scanner = _CountingScanner(count_per_region=1)
    progress = MagicMock()
    progress.add_task.return_value = "task-id"

    scanner.scan(
        MagicMock(), MagicMock(), "scan-1", ["us-east-1", "eu-west-1"],
        progress=progress, max_workers=2,
    )

    assert progress.advance.call_count == 2
