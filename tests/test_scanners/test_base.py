"""Tests for BaseScanner's region fan-out, error handling, and progress reporting."""

from __future__ import annotations

from unittest.mock import MagicMock

from stackwise.scanner.base import BaseScanner


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


def test_scan_region_failure_is_caught_and_counts_as_zero():
    """A region whose _scan_region raises must not abort the other regions —
    it contributes 0 to the total and the exception never escapes scan()."""
    scanner = _CountingScanner(count_per_region=5, fail_regions={"eu-west-1"})
    total = scanner.scan(
        MagicMock(), MagicMock(), "scan-1", ["us-east-1", "eu-west-1", "ap-south-1"]
    )

    assert total == 10  # us-east-1 (5) + eu-west-1 (0, failed) + ap-south-1 (5)


def test_scan_parallel_regions_sums_counts():
    """With max_workers>1, scan() should fan out across a ThreadPoolExecutor
    and still sum every region's count correctly."""
    scanner = _CountingScanner(count_per_region=2)
    regions = ["us-east-1", "eu-west-1", "ap-south-1"]
    total = scanner.scan(MagicMock(), MagicMock(), "scan-1", regions, max_workers=3)

    assert total == 6
    assert set(scanner.scanned_regions) == set(regions)


def test_scan_parallel_region_failure_is_caught():
    """A region failure under parallel execution must not raise out of scan()
    or corrupt the total for the other regions."""
    scanner = _CountingScanner(count_per_region=4, fail_regions={"us-east-1"})
    total = scanner.scan(
        MagicMock(), MagicMock(), "scan-1", ["us-east-1", "eu-west-1"], max_workers=2
    )

    assert total == 4  # only eu-west-1 succeeded


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
