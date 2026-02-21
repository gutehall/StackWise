"""Structured logging configuration for StackWise."""

from __future__ import annotations

import logging
import sys


def setup_logging(*, verbose: bool = False) -> None:
    """Configure root logger with structured console output."""
    level = logging.DEBUG if verbose else logging.INFO

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )

    root = logging.getLogger("stackwise")
    root.setLevel(level)
    root.addHandler(handler)

    # Quiet noisy libraries
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
