"""Abstract base class for all AWS service scanners."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from rich.progress import Progress, TaskID

from stackwise.store.db import ScanDB

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Base class that every scanner module must extend.

    Subclasses implement ``_scan_region`` to collect resources from a single
    AWS region.  The ``scan`` driver method iterates all requested regions,
    handles errors, and reports progress.
    """

    name: str = "base"  # override in subclasses

    def scan(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        regions: list[str],
        progress: Progress | None = None,
        max_workers: int = 1,
    ) -> int:
        """Run the scanner across all *regions* and persist results.

        Args:
            max_workers: If > 1, scan regions in parallel via ThreadPoolExecutor.

        Returns:
            Total number of resources collected.
        """
        total = 0
        task: TaskID | None = None
        if progress is not None:
            task = progress.add_task(f"[cyan]{self.name}", total=len(regions))

        def do_region(region: str) -> int:
            try:
                count = self._scan_region(session, db, scan_id, region)
                logger.info("%s: %s → %d resources", self.name, region, count)
                return count
            except Exception:
                logger.exception("%s: failed in %s", self.name, region)
                return 0

        if max_workers <= 1:
            for region in regions:
                total += do_region(region)
                if progress is not None and task is not None:
                    progress.advance(task)
        else:
            workers = min(max_workers, len(regions))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(do_region, r): r for r in regions}
                for future in as_completed(futures):
                    total += future.result()
                    if progress is not None and task is not None:
                        progress.advance(task)

        return total

    @abstractmethod
    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        """Scan a single region and insert resources into *db*.

        Returns:
            Number of resources collected in this region.
        """
        ...
