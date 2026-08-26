"""Tests for cost scanners (tagging dedup, Cost Explorer, Compute Optimizer paging)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

from stackwise.scanner.cost import CostScanner
from stackwise.scanner.discovery import DiscoveryScanner
from stackwise.store.db import ScanDB


@mock_aws
def test_cost_and_discovery_scanners_dedup_tagged_resources(scan_db: ScanDB):
    """Running both cost and discovery in one scan should not double-store or
    double-count the same tagged resource."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="my-tagged-bucket")
    s3.put_bucket_tagging(
        Bucket="my-tagged-bucket", Tagging={"TagSet": [{"Key": "Env", "Value": "prod"}]}
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost", "discovery"])
    CostScanner()._scan_region(session, scan_db, scan.id, "us-east-1")
    DiscoveryScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    tagged = [
        r
        for r in scan_db.get_resources(scan.id, service="resourcegroupstaggingapi")
        if r.resource_type == "tagged_resource"
    ]
    assert len(tagged) == 1


@mock_aws
def test_cost_explorer_scan_inserts_cost_summary(scan_db: ScanDB):
    """CostScanner should populate a ce/cost_summary resource for the report chart."""
    session = boto3.Session(region_name="us-east-1")
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost"])

    CostScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    summaries = [
        r
        for r in scan_db.get_resources(scan.id, service="ce")
        if r.resource_type == "cost_summary"
    ]
    assert len(summaries) == 1
    assert "Groups" in summaries[0].metadata


@mock_aws
def test_skip_cost_explorer_makes_no_billable_call(scan_db: ScanDB):
    """--skip-cost-explorer must actually skip the $0.01/request API call,
    not just hide its result."""
    session = boto3.Session(region_name="us-east-1")
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost"])

    with patch.object(CostScanner, "_scan_cost_explorer") as mock_scan_ce:
        CostScanner(skip_cost_explorer=True)._scan_region(
            session, scan_db, scan.id, "us-east-1"
        )

    mock_scan_ce.assert_not_called()
    summaries = [
        r
        for r in scan_db.get_resources(scan.id, service="ce")
        if r.resource_type == "cost_summary"
    ]
    assert len(summaries) == 0


@mock_aws
def test_skip_cost_explorer_false_still_scans_it(scan_db: ScanDB):
    """Sanity check the flag's default (False) preserves current behavior."""
    session = boto3.Session(region_name="us-east-1")
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost"])

    with patch.object(CostScanner, "_scan_cost_explorer") as mock_scan_ce:
        mock_scan_ce.return_value = 0
        CostScanner(skip_cost_explorer=False)._scan_region(
            session, scan_db, scan.id, "us-east-1"
        )

    mock_scan_ce.assert_called_once()


def test_compute_optimizer_ec2_recommendations_paginate(scan_db: ScanDB):
    """EC2 Compute Optimizer recommendations spanning multiple pages should all
    be collected via manual nextToken paging."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost"])

    page_1 = {
        "instanceRecommendations": [{"instanceArn": "arn:aws:ec2:us-east-1:1:instance/i-1"}],
        "nextToken": "token-2",
    }
    page_2 = {
        "instanceRecommendations": [{"instanceArn": "arn:aws:ec2:us-east-1:1:instance/i-2"}],
    }
    mock_client = MagicMock()
    mock_client.get_ec2_instance_recommendations.side_effect = [page_1, page_2]

    with patch("stackwise.scanner.cost.regional_client", return_value=mock_client), patch(
        "stackwise.scanner.cost.paginate", return_value=[]
    ):
        CostScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    recs = [
        r
        for r in scan_db.get_resources(scan.id, service="compute-optimizer")
        if r.resource_type == "ec2_recommendation"
    ]
    assert {r.resource_id for r in recs} == {"i-1", "i-2"}
    assert mock_client.get_ec2_instance_recommendations.call_count == 2


def test_compute_optimizer_lambda_recommendations_are_scanned(scan_db: ScanDB):
    """Lambda Compute Optimizer recommendations should be stored with their
    finding and recommendation options."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost"])

    def _paginate(client, method, key, **kw):
        if method == "get_lambda_function_recommendations":
            return [
                {
                    "functionArn": "arn:aws:lambda:us-east-1:1:function:my-fn",
                    "recommendationSourceType": "LambdaFunction",
                    "finding": "NotOptimized",
                    "recommendationOptions": [{"memorySize": 512}],
                }
            ]
        return []

    # get_ec2_instance_recommendations isn't reached via paginate() — it's a
    # manual nextToken while-loop, so it needs an explicit terminating return
    # value or an unconfigured MagicMock's truthy .get("nextToken") loops forever.
    generic_client = MagicMock()
    generic_client.get_ec2_instance_recommendations.return_value = {
        "instanceRecommendations": []
    }

    with (
        patch("stackwise.scanner.cost.regional_client", return_value=generic_client),
        patch("stackwise.scanner.cost.paginate", side_effect=_paginate),
    ):
        CostScanner(skip_cost_explorer=True)._scan_region(
            session, scan_db, scan.id, "us-east-1"
        )

    recs = [
        r
        for r in scan_db.get_resources(scan.id, service="compute-optimizer")
        if r.resource_type == "lambda_recommendation"
    ]
    assert len(recs) == 1
    assert recs[0].resource_id == "my-fn"
    assert recs[0].metadata["finding"] == "NotOptimized"


def test_tagged_resource_with_malformed_arn_falls_back(scan_db: ScanDB):
    """A malformed/empty ResourceARN (no '/' or ':') must not crash resource_id
    derivation — it falls back to using the raw ARN string."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost"])

    generic_client = MagicMock()
    generic_client.get_ec2_instance_recommendations.return_value = {
        "instanceRecommendations": []
    }

    with (
        patch("stackwise.scanner.cost.regional_client", return_value=generic_client),
        patch(
            "stackwise.scanner.cost.paginate",
            side_effect=lambda client, method, key, **kw: (
                [{"ResourceARN": "", "Tags": []}] if method == "get_resources" else []
            ),
        ),
    ):
        CostScanner(skip_cost_explorer=True)._scan_region(
            session, scan_db, scan.id, "us-east-1"
        )

    tagged = [
        r
        for r in scan_db.get_resources(scan.id, service="resourcegroupstaggingapi")
        if r.resource_type == "tagged_resource"
    ]
    assert len(tagged) == 1
    assert tagged[0].resource_id == ""


def test_tagged_resources_top_level_failure_does_not_raise(scan_db: ScanDB):
    """get_resources failing entirely must not raise out of _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost"])

    generic_client = MagicMock()
    generic_client.get_ec2_instance_recommendations.return_value = {
        "instanceRecommendations": []
    }

    with (
        patch("stackwise.scanner.cost.regional_client", return_value=generic_client),
        patch("stackwise.scanner.cost.paginate", side_effect=RuntimeError("boom")),
    ):
        count = CostScanner(skip_cost_explorer=True)._scan_region(
            session, scan_db, scan.id, "us-east-1"
        )

    assert count == 0


def test_cost_explorer_groups_costs_by_service(scan_db: ScanDB):
    """Cost Explorer results must be grouped and summed by service across all
    time periods, not just stored as an empty summary."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost"])

    ce = MagicMock()
    ce.get_cost_and_usage.return_value = {
        "ResultsByTime": [
            {
                "Groups": [
                    {
                        "Keys": ["Amazon EC2"],
                        "Metrics": {"UnblendedCost": {"Amount": "10.50", "Unit": "USD"}},
                    },
                    {
                        "Keys": ["Amazon S3"],
                        "Metrics": {"UnblendedCost": {"Amount": "2.25", "Unit": "USD"}},
                    },
                ]
            }
        ]
    }

    with patch("stackwise.scanner.cost.regional_client", return_value=ce):
        CostScanner()._scan_cost_explorer(session, scan_db, scan.id, "us-east-1")

    summaries = [
        r for r in scan_db.get_resources(scan.id, service="ce") if r.resource_type == "cost_summary"
    ]
    assert len(summaries) == 1
    groups = {
        g["Keys"][0]: g["Metrics"]["UnblendedCost"]["Amount"]
        for g in summaries[0].metadata["Groups"]
    }
    assert groups == {"Amazon EC2": "10.5", "Amazon S3": "2.25"}


def test_cost_explorer_failure_returns_zero(scan_db: ScanDB):
    """get_cost_and_usage failing must return 0, not raise."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["cost"])

    ce = MagicMock()
    ce.get_cost_and_usage.side_effect = RuntimeError("boom")

    with patch("stackwise.scanner.cost.regional_client", return_value=ce):
        count = CostScanner()._scan_cost_explorer(session, scan_db, scan.id, "us-east-1")

    assert count == 0
