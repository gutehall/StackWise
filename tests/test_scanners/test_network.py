"""Tests for network scanners (VPC flow logs) using moto mocking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

from stackwise.scanner.network import NetworkScanner
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate as real_paginate


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


@mock_aws
def test_load_balancer_listener_protocols_are_collected(scan_db: ScanDB):
    """Listener protocols must be stored so NET-007 can tell HTTP-only LBs from
    HTTPS ones — 'Scheme' (internet-facing/internal) never carries this."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_ids = [
        ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=f"us-east-1{az}"
        )["Subnet"]["SubnetId"]
        for i, az in enumerate(("a", "b"), start=1)
    ]

    elbv2 = session.client("elbv2", region_name="us-east-1")
    lb_arn = elbv2.create_load_balancer(Name="test-lb", Subnets=subnet_ids)["LoadBalancers"][0][
        "LoadBalancerArn"
    ]
    tg_arn = elbv2.create_target_group(
        Name="tg1", Protocol="HTTP", Port=80, VpcId=vpc_id
    )["TargetGroups"][0]["TargetGroupArn"]
    elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    scanner = NetworkScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    lbs = [
        r
        for r in scan_db.get_resources(scan.id, service="elbv2")
        if r.resource_type == "load_balancer"
    ]
    assert len(lbs) == 1
    listeners = lbs[0].metadata["Listeners"]
    assert listeners == [{"Protocol": "HTTP", "Port": 80}]


@mock_aws
def test_api_gateway_throttle_settings_are_fetched(scan_db: ScanDB):
    """Throttle must come from the stage's method settings, not a hardcoded {} —
    NET-010 depends on this to avoid flagging every REST API unconditionally."""
    session = boto3.Session(region_name="us-east-1")
    apigw = session.client("apigateway", region_name="us-east-1")

    api_id = apigw.create_rest_api(name="test-api")["id"]
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK")
    apigw.create_deployment(restApiId=api_id, stageName="prod")
    apigw.update_stage(
        restApiId=api_id,
        stageName="prod",
        patchOperations=[
            {"op": "replace", "path": "/*/*/throttling/rateLimit", "value": "100"},
            {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "50"},
        ],
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    scanner = NetworkScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    apis = [
        r
        for r in scan_db.get_resources(scan.id, service="apigateway")
        if r.resource_type == "rest_api"
    ]
    assert len(apis) == 1
    assert apis[0].metadata["Throttle"] == {"rateLimit": 100.0, "burstLimit": 50}


@mock_aws
def test_api_gateway_without_throttle_configured(scan_db: ScanDB):
    """A REST API with no stage-level throttling should report an empty Throttle,
    which is what NET-010 keys off to flag it — a real 'not configured' case."""
    session = boto3.Session(region_name="us-east-1")
    apigw = session.client("apigateway", region_name="us-east-1")
    apigw.create_rest_api(name="unthrottled-api")

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    scanner = NetworkScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    apis = [
        r
        for r in scan_db.get_resources(scan.id, service="apigateway")
        if r.resource_type == "rest_api"
    ]
    assert len(apis) == 1
    assert apis[0].metadata["Throttle"] == {}


@mock_aws
def test_security_group_and_nat_gateway_scanned(scan_db: ScanDB):
    """Security groups and NAT gateways should be collected with their raw
    ingress/egress rules and state."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a"
    )["Subnet"]["SubnetId"]

    sg_id = ec2.create_security_group(
        GroupName="test-sg", Description="test", VpcId=vpc_id
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    alloc_id = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat_id = ec2.create_nat_gateway(SubnetId=subnet_id, AllocationId=alloc_id)["NatGateway"][
        "NatGatewayId"
    ]

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    scanner = NetworkScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="ec2")
    sgs = [r for r in resources if r.resource_type == "security_group" and r.resource_id == sg_id]
    assert len(sgs) == 1
    assert sgs[0].metadata["IpPermissions"][0]["FromPort"] == 22

    nats = [r for r in resources if r.resource_type == "nat_gateway" and r.resource_id == nat_id]
    assert len(nats) == 1
    assert nats[0].metadata["SubnetId"] == subnet_id


@mock_aws
def test_deleted_nat_gateway_is_skipped(scan_db: ScanDB):
    """A NAT gateway that's been deleted (State='deleted') should not be stored —
    it's a stale/terminal record, not a live resource to flag or diff on."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a"
    )["Subnet"]["SubnetId"]
    alloc_id = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat_id = ec2.create_nat_gateway(SubnetId=subnet_id, AllocationId=alloc_id)["NatGateway"][
        "NatGatewayId"
    ]
    ec2.delete_nat_gateway(NatGatewayId=nat_id)

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    scanner = NetworkScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    nats = [
        r
        for r in scan_db.get_resources(scan.id, service="ec2")
        if r.resource_type == "nat_gateway"
    ]
    assert nats == []


@mock_aws
def test_flow_logs_lookup_failure_still_stores_vpc(scan_db: ScanDB):
    """A describe_flow_logs failure is narrower than the outer VPC try/except —
    the VPC itself must still be stored (as FlowLogsEnabled=False), not dropped."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

    def _paginate(client, method, key, **kw):
        if method == "describe_flow_logs":
            raise RuntimeError("boom")
        return real_paginate(client, method, key, **kw)

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    with patch("stackwise.scanner.network.paginate", side_effect=_paginate):
        NetworkScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    # moto also creates a default VPC per region — filter down to the one we made.
    vpcs = [
        r
        for r in scan_db.get_resources(scan.id, service="ec2")
        if r.resource_type == "vpc" and r.resource_id == vpc_id
    ]
    assert len(vpcs) == 1
    assert vpcs[0].metadata["FlowLogsEnabled"] is False


@mock_aws
def test_lb_attribute_and_listener_failures_still_store_lb(scan_db: ScanDB):
    """describe_load_balancer_attributes and describe_listeners failures are each
    narrower than the outer LB try/except — the LB must still be stored, with
    empty Attributes/Listeners rather than being dropped entirely."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_ids = [
        ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=f"us-east-1{az}"
        )["Subnet"]["SubnetId"]
        for i, az in enumerate(("a", "b"), start=1)
    ]
    elbv2 = session.client("elbv2", region_name="us-east-1")
    elbv2.create_load_balancer(Name="test-lb", Subnets=subnet_ids)
    # The scanner builds its own clients via regional_client(); patch it to hand
    # back this exact elbv2 instance so mutating its method below actually takes
    # effect (a freshly-constructed client wouldn't carry the override).
    elbv2.describe_load_balancer_attributes = MagicMock(side_effect=RuntimeError("boom"))

    def _paginate(client, method, key, **kw):
        if method == "describe_listeners":
            raise RuntimeError("boom")
        return real_paginate(client, method, key, **kw)

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    with (
        patch(
            "stackwise.scanner.network.regional_client",
            side_effect=lambda session, service, region: (
                elbv2 if service == "elbv2" else ec2
            ),
        ),
        patch("stackwise.scanner.network.paginate", side_effect=_paginate),
    ):
        NetworkScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    lbs = [
        r
        for r in scan_db.get_resources(scan.id, service="elbv2")
        if r.resource_type == "load_balancer"
    ]
    assert len(lbs) == 1
    assert lbs[0].metadata["Attributes"] == []
    assert lbs[0].metadata["Listeners"] == []


@mock_aws
def test_get_rest_api_failure_falls_back_to_summary(scan_db: ScanDB):
    """A get_rest_api failure must fall back to the get_rest_apis summary item
    for the name, not drop the API or crash the scan."""
    session = boto3.Session(region_name="us-east-1")
    apigw = session.client("apigateway", region_name="us-east-1")
    apigw.create_rest_api(name="fallback-api")
    apigw.get_rest_api = MagicMock(side_effect=RuntimeError("boom"))

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    with patch("stackwise.scanner.network.regional_client", return_value=apigw):
        NetworkScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    apis = [
        r
        for r in scan_db.get_resources(scan.id, service="apigateway")
        if r.resource_type == "rest_api"
    ]
    assert len(apis) == 1
    assert apis[0].metadata["name"] == "fallback-api"
    assert apis[0].metadata["Throttle"] == {}


@mock_aws
def test_get_stages_failure_leaves_throttle_empty(scan_db: ScanDB):
    """A get_stages failure must not crash the API Gateway scan — the API is
    still stored, just with an empty (unverified) Throttle."""
    session = boto3.Session(region_name="us-east-1")
    apigw = session.client("apigateway", region_name="us-east-1")
    apigw.create_rest_api(name="test-api")
    apigw.get_stages = MagicMock(side_effect=RuntimeError("boom"))

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])
    with patch("stackwise.scanner.network.regional_client", return_value=apigw):
        NetworkScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    apis = [
        r
        for r in scan_db.get_resources(scan.id, service="apigateway")
        if r.resource_type == "rest_api"
    ]
    assert len(apis) == 1
    assert apis[0].metadata["Throttle"] == {}


def test_top_level_api_failures_degrade_gracefully(scan_db: ScanDB):
    """Each section (VPC, security groups, load balancers, NAT gateways, API
    Gateway) is independently wrapped — one section's top-level API failure
    must not take down the others or raise out of _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["network"])

    clients = {"ec2": MagicMock(), "elbv2": MagicMock(), "apigateway": MagicMock()}

    with (
        patch(
            "stackwise.scanner.network.regional_client",
            side_effect=lambda session, service, region: clients[service],
        ),
        patch(
            "stackwise.scanner.network.paginate",
            side_effect=RuntimeError("boom"),
        ),
    ):
        count = NetworkScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0
    assert scan_db.get_resources(scan.id) == []
