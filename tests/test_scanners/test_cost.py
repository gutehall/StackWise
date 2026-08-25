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
