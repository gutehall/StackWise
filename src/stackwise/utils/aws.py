"""AWS session management, region iteration, and rate-limit helpers."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from stackwise.config import Settings

logger = logging.getLogger(__name__)

# boto3 retry config with adaptive mode
_BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
    max_pool_connections=20,
)


def create_session(settings: Settings) -> boto3.Session:
    """Create a boto3 session using the configured AWS profile."""
    kwargs: dict[str, Any] = {}
    if settings.profile:
        kwargs["profile_name"] = settings.profile
    return boto3.Session(**kwargs)


def get_account_id(session: boto3.Session) -> str:
    """Return the AWS account ID for the current session."""
    sts = session.client("sts", config=_BOTO_CONFIG)
    return sts.get_caller_identity()["Account"]


def regional_client(session: boto3.Session, service: str, region: str):
    """Create a boto3 client for a specific service and region."""
    return session.client(service, region_name=region, config=_BOTO_CONFIG)


def iter_regions(session: boto3.Session, settings: Settings) -> Iterator[str]:
    """Yield each configured region."""
    yield from settings.regions


def paginate(client, method: str, key: str, **kwargs) -> list[dict]:
    """Auto-paginate a boto3 API call and return the concatenated result list.

    Args:
        client: boto3 client instance.
        method: The API method name (e.g. 'describe_instances').
        key: The response key containing the list of results.
        **kwargs: Extra arguments forwarded to the paginator.

    Returns:
        Concatenated list of result dicts across all pages.
    """
    results: list[dict] = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(key, []))
    return results


def retry_on_throttle(func, *args, max_retries: int = 5, **kwargs):
    """Call *func* with exponential backoff on throttling errors."""
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("Throttling", "TooManyRequestsException", "RequestLimitExceeded"):
                wait = 2**attempt
                logger.warning(
                    "Throttled (%s), retrying in %ds (attempt %d)",
                    code, wait, attempt + 1,
                )
                time.sleep(wait)
            else:
                raise
    return func(*args, **kwargs)  # final attempt, let it raise
