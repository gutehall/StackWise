"""AWS session management, region iteration, and rate-limit helpers."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from typing import Any

import boto3
import botocore.session
from botocore.config import Config
from botocore.credentials import CredentialProvider, CredentialResolver

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


class _SharedCredentialProvider(CredentialProvider):
    """Hands a worker session credentials that were already resolved."""

    METHOD = "stackwise-shared"
    CANONICAL_NAME = None

    def __init__(self, credentials: Any) -> None:
        super().__init__()
        self._credentials = credentials

    def load(self) -> Any:
        return self._credentials


def worker_session_factory(session: boto3.Session) -> Callable[[], boto3.Session]:
    """Return a builder of independent sessions for scanner worker threads.

    ``Session.client()`` is not thread-safe, so each worker needs its own session.
    Call this on the main thread, then call the builder once per worker.

    Workers share *session*'s resolved credentials, which refresh safely across
    threads, so a role assumption or MFA prompt doesn't repeat for every worker.
    """
    # profile_name reports "default" even when no such profile exists, and naming
    # a missing profile raises ProfileNotFound (e.g. credentials from env vars only).
    profile = session.profile_name if session.profile_name in session.available_profiles else None
    region = session.region_name
    credentials = session.get_credentials()

    def build() -> boto3.Session:
        core = botocore.session.Session(profile=profile)
        core.register_component(
            "credential_provider",
            CredentialResolver([_SharedCredentialProvider(credentials)]),
        )
        return boto3.Session(botocore_session=core, region_name=region)

    return build


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
