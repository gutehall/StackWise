"""Tests for network scanners (VPC flow logs) using moto mocking."""

from __future__ import annotations

import boto3
from moto import mock_aws

from stackwise.scanner.network import NetworkScanner
from stackwise.store.db import ScanDB


@mock_aws
def test_flow_logs_detected_for_vpc(scan_db: ScanDB):
    """A VPC with an active flow log should be reported as FlowLogsEnabled."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]

    logs = session.client("logs", region_name="us-east-1")
    logs.create_log_group(logGroupName="/vpc/flowlogs")
    ec2.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType="VPC",
        TrafficType="ALL",
        LogGroupName="/vpc/flowlogs",
        DeliverLogsPermissionArn="arn:aws:iam::123456789012:role/flow-logs-role",
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    scanner = NetworkScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="ec2")
    vpcs = [r for r in resources if r.resource_type == "vpc" and r.resource_id == vpc_id]
    assert len(vpcs) == 1
    assert vpcs[0].metadata["FlowLogsEnabled"] is True


@mock_aws
def test_vpc_without_flow_logs(scan_db: ScanDB):
    """A VPC with no flow logs should be reported as FlowLogsEnabled=False."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    scanner = NetworkScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="ec2")
    vpcs = [r for r in resources if r.resource_type == "vpc" and r.resource_id == vpc_id]
    assert len(vpcs) == 1
    assert vpcs[0].metadata["FlowLogsEnabled"] is False
