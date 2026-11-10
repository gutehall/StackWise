"""Tests for storing tagged resources from the Resource Groups Tagging API."""

from __future__ import annotations

from stackwise.scanner.tagging import store_tagged_resources
from stackwise.store.db import ScanDB


def _mapping(arn: str, env: str = "prod") -> dict:
    return {"ResourceARN": arn, "Tags": [{"Key": "Env", "Value": env}]}


def test_resources_whose_arn_tails_match_are_both_stored(scan_db: ScanDB):
    """These pairs share the last ARN segment that used to be the id."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["discovery"])
    arns = [
        "arn:aws:ecs:us-east-1:1:service/cluster-a/api",
        "arn:aws:ecs:us-east-1:1:service/cluster-b/api",
        "arn:aws:sns:us-east-1:1:orders",
        "arn:aws:sqs:us-east-1:1:orders",
        "arn:aws:iam::1:role/deploy",
        "arn:aws:iam::1:policy/deploy",
        "arn:aws:lambda:us-east-1:1:function:checkout:live",
        "arn:aws:lambda:us-east-1:1:function:search:live",
    ]

    count = store_tagged_resources(scan_db, scan.id, "us-east-1", [_mapping(a) for a in arns])

    assert count == len(arns)
    stored = scan_db.get_resources(scan.id, service="resourcegroupstaggingapi")
    assert sorted(r.resource_id for r in stored) == sorted(arns)
    assert all(r.arn == r.resource_id for r in stored)


def test_count_is_only_new_rows(scan_db: ScanDB):
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost", "discovery"])
    mappings = [_mapping("arn:aws:s3:::a"), _mapping("arn:aws:s3:::b")]

    first = store_tagged_resources(scan_db, scan.id, "us-east-1", mappings)
    second = store_tagged_resources(scan_db, scan.id, "us-east-1", mappings)

    assert (first, second) == (2, 0)
    assert len(scan_db.get_resources(scan.id)) == 2


def test_mappings_without_an_arn_are_skipped(scan_db: ScanDB):
    """Every blank ARN would otherwise share one empty id and collapse into one row."""
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["discovery"])
    mappings = [{"ResourceARN": "", "Tags": []}, {"Tags": []}, _mapping("arn:aws:s3:::a")]

    count = store_tagged_resources(scan_db, scan.id, "us-east-1", mappings)

    assert count == 1
    assert [r.resource_id for r in scan_db.get_resources(scan.id)] == ["arn:aws:s3:::a"]
