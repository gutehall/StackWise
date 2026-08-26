"""Tests for compute scanners (EC2, Lambda) using moto mocking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

from stackwise.scanner.compute import EC2Scanner, ECSScanner, EKSScanner, LambdaScanner
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate as real_paginate


@mock_aws
def test_ec2_scanner_collects_instances(scan_db: ScanDB):
    """EC2Scanner should find running instances."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    # Launch a couple of instances
    ec2.run_instances(
        ImageId="ami-12345678",
        InstanceType="t3.micro",
        MinCount=2,
        MaxCount=2,
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scanner = EC2Scanner()
    count = scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count >= 2  # at least 2 instances
    resources = scan_db.get_resources(scan.id, service="ec2")
    instances = [r for r in resources if r.resource_type == "instance"]
    assert len(instances) == 2
    assert instances[0].metadata["InstanceType"] == "t3.micro"


@mock_aws
def test_ec2_scanner_empty_region(scan_db: ScanDB):
    """EC2Scanner should handle empty regions gracefully."""
    session = boto3.Session(region_name="us-east-1")
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    scanner = EC2Scanner()
    count = scanner._scan_region(session, scan_db, scan.id, "us-east-1")
    assert count == 0


@mock_aws
def test_lambda_scanner_collects_functions(scan_db: ScanDB):
    """LambdaScanner should find Lambda functions."""
    session = boto3.Session(region_name="us-east-1")

    # Create IAM role for Lambda
    iam = session.client("iam", region_name="us-east-1")
    iam.create_role(
        RoleName="lambda-role",
        AssumeRolePolicyDocument="{}",
        Path="/",
    )

    # Create Lambda function
    client = session.client("lambda", region_name="us-east-1")
    client.create_function(
        FunctionName="my-function",
        Runtime="python3.11",
        Role="arn:aws:iam::123456789012:role/lambda-role",
        Handler="handler.main",
        Code={"ZipFile": b"fake-code"},
        MemorySize=256,
        Timeout=30,
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scanner = LambdaScanner()
    count = scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 1
    resources = scan_db.get_resources(scan.id, service="lambda")
    assert len(resources) == 1
    assert resources[0].resource_id == "my-function"
    assert resources[0].metadata["Runtime"] == "python3.11"
    assert resources[0].metadata["MemorySize"] == 256


@mock_aws
def test_ec2_scanner_collects_launch_template_metadata_options(scan_db: ScanDB):
    """EC2Scanner should resolve the default version's LaunchTemplateData so
    CMP-019 (IMDSv1 on launch templates) has something to evaluate."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    ec2.create_launch_template(
        LaunchTemplateName="my-lt",
        LaunchTemplateData={
            "ImageId": "ami-12345678",
            "InstanceType": "t3.micro",
            "MetadataOptions": {"HttpTokens": "required"},
        },
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    EC2Scanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="ec2")
    lts = [r for r in resources if r.resource_type == "launch_template"]
    assert len(lts) == 1
    assert lts[0].metadata["MetadataOptions"] == {"HttpTokens": "required"}


@mock_aws
def test_ecs_scanner_keeps_task_definition_revisions_distinct(scan_db: ScanDB):
    """Each ECS task definition revision is a distinct resource (own ARN);
    diff_scans relies on resource_id being revision-specific."""
    session = boto3.Session(region_name="us-east-1")
    ecs = session.client("ecs", region_name="us-east-1")
    ecs.register_task_definition(
        family="my-task", containerDefinitions=[{"name": "c", "image": "nginx", "memory": 128}]
    )
    ecs.register_task_definition(
        family="my-task", containerDefinitions=[{"name": "c", "image": "nginx:2", "memory": 128}]
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    scanner = ECSScanner()
    scanner._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="ecs")
    task_defs = [r for r in resources if r.resource_type == "task_definition"]
    assert len(task_defs) == 2
    assert {r.resource_id for r in task_defs} == {"my-task:1", "my-task:2"}
    assert {r.metadata["revision"] for r in task_defs} == {1, 2}


@mock_aws
def test_asg_scanner_collects_auto_scaling_groups(scan_db: ScanDB):
    """EC2Scanner should find Auto Scaling Groups with size/health settings."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    ec2.create_launch_template(
        LaunchTemplateName="my-lt",
        LaunchTemplateData={"ImageId": "ami-12345678", "InstanceType": "t3.micro"},
    )
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a"
    )["Subnet"]["SubnetId"]

    asg_client = session.client("autoscaling", region_name="us-east-1")
    asg_client.create_auto_scaling_group(
        AutoScalingGroupName="my-asg",
        LaunchTemplate={"LaunchTemplateName": "my-lt", "Version": "$Latest"},
        MinSize=1,
        MaxSize=3,
        DesiredCapacity=2,
        VPCZoneIdentifier=subnet_id,
        HealthCheckType="EC2",
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    EC2Scanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="ec2")
    asgs = [r for r in resources if r.resource_type == "auto_scaling_group"]
    assert len(asgs) == 1
    assert asgs[0].resource_id == "my-asg"
    assert asgs[0].metadata["MinSize"] == 1
    assert asgs[0].metadata["MaxSize"] == 3
    assert asgs[0].metadata["HealthCheckType"] == "EC2"


@mock_aws
def test_launch_template_version_lookup_failure_still_stores_template(scan_db: ScanDB):
    """A describe_launch_template_versions failure is narrower than the outer
    launch-templates try/except — the template itself must still be stored."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    ec2.create_launch_template(
        LaunchTemplateName="my-lt",
        LaunchTemplateData={"ImageId": "ami-12345678", "InstanceType": "t3.micro"},
    )
    ec2.describe_launch_template_versions = MagicMock(side_effect=RuntimeError("boom"))
    asg_client = session.client("autoscaling", region_name="us-east-1")

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    with patch(
        "stackwise.scanner.compute.regional_client",
        side_effect=lambda session, service, region: (
            ec2 if service == "ec2" else asg_client
        ),
    ):
        EC2Scanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="ec2")
    lts = [r for r in resources if r.resource_type == "launch_template"]
    assert len(lts) == 1
    assert lts[0].metadata["MetadataOptions"] == {}


def test_launch_templates_top_level_failure_does_not_raise(scan_db: ScanDB):
    """describe_launch_templates failing entirely must not abort the whole
    EC2 scan — instances/ASGs found earlier are already inserted by then."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    def _paginate(client, method, key, **kw):
        if method == "describe_launch_templates":
            raise RuntimeError("boom")
        return []

    with (
        patch("stackwise.scanner.compute.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.compute.paginate", side_effect=_paginate),
    ):
        count = EC2Scanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0


@mock_aws
def test_ecs_cluster_and_service_scanned(scan_db: ScanDB):
    """ECSScanner should find services on a cluster with their launch type and
    desired/running counts."""
    session = boto3.Session(region_name="us-east-1")
    ecs = session.client("ecs", region_name="us-east-1")
    ecs.create_cluster(clusterName="my-cluster")
    ecs.register_task_definition(
        family="svc-task", containerDefinitions=[{"name": "c", "image": "nginx", "memory": 128}]
    )
    ecs.create_service(
        cluster="my-cluster",
        serviceName="my-svc",
        taskDefinition="svc-task",
        desiredCount=2,
        launchType="FARGATE",
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    ECSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="ecs")
    services = [r for r in resources if r.resource_type == "service"]
    assert len(services) == 1
    assert services[0].resource_id == "my-cluster/my-svc"
    assert services[0].metadata["launchType"] == "FARGATE"
    assert services[0].metadata["desiredCount"] == 2


@mock_aws
def test_ecs_describe_services_failure_does_not_abort_scan(scan_db: ScanDB):
    """A describe_services failure for one service must not stop task
    definitions from still being scanned."""
    session = boto3.Session(region_name="us-east-1")
    ecs = session.client("ecs", region_name="us-east-1")
    ecs.create_cluster(clusterName="my-cluster")
    ecs.register_task_definition(
        family="svc-task", containerDefinitions=[{"name": "c", "image": "nginx", "memory": 128}]
    )
    ecs.create_service(
        cluster="my-cluster", serviceName="my-svc", taskDefinition="svc-task", desiredCount=1
    )
    ecs.describe_services = MagicMock(side_effect=RuntimeError("boom"))

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    with patch("stackwise.scanner.compute.regional_client", return_value=ecs):
        ECSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="ecs")
    assert [r for r in resources if r.resource_type == "service"] == []
    assert len([r for r in resources if r.resource_type == "task_definition"]) == 1


@mock_aws
def test_ecs_describe_task_definition_failure_does_not_abort_scan(scan_db: ScanDB):
    """A describe_task_definition failure for one task def must not stop other
    task defs (or services already scanned) from being stored."""
    session = boto3.Session(region_name="us-east-1")
    ecs = session.client("ecs", region_name="us-east-1")
    ecs.register_task_definition(
        family="broken-task", containerDefinitions=[{"name": "c", "image": "nginx", "memory": 128}]
    )
    ecs.describe_task_definition = MagicMock(side_effect=RuntimeError("boom"))

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    with patch("stackwise.scanner.compute.regional_client", return_value=ecs):
        count = ECSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0


@mock_aws
def test_ecs_skips_empty_service_arn(scan_db: ScanDB):
    """list_services can return an empty string entry (seen in some paginated
    responses) — that entry must be skipped, not passed to describe_services."""
    session = boto3.Session(region_name="us-east-1")
    ecs = session.client("ecs", region_name="us-east-1")
    ecs.create_cluster(clusterName="my-cluster")

    def _paginate(client, method, key, **kw):
        if method == "list_services":
            return [""]
        return real_paginate(client, method, key, **kw)

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    with patch("stackwise.scanner.compute.paginate", side_effect=_paginate):
        count = ECSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0
    assert scan_db.get_resources(scan.id, service="ecs") == []


def test_ecs_top_level_failure_does_not_raise(scan_db: ScanDB):
    """list_clusters failing entirely must not raise out of _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    with (
        patch("stackwise.scanner.compute.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.compute.paginate", side_effect=RuntimeError("boom")),
    ):
        count = ECSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0


@mock_aws
def test_eks_cluster_and_nodegroup_scanned(scan_db: ScanDB):
    """EKSScanner should find clusters and their node groups with scaling
    config and VPC settings."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam", region_name="us-east-1")
    role_arn = iam.create_role(RoleName="eks-role", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_ids = [
        ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=f"us-east-1{az}"
        )["Subnet"]["SubnetId"]
        for i, az in enumerate(("a", "b"), start=1)
    ]
    eks = session.client("eks", region_name="us-east-1")
    eks.create_cluster(
        name="my-cluster",
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids, "endpointPublicAccess": True},
    )
    eks.create_nodegroup(
        clusterName="my-cluster", nodegroupName="ng1", subnets=subnet_ids, nodeRole=role_arn
    )

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    EKSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="eks")
    clusters = [r for r in resources if r.resource_type == "cluster"]
    assert len(clusters) == 1
    assert clusters[0].metadata["resourcesVpcConfig"]["endpointPublicAccess"] is True

    nodegroups = [r for r in resources if r.resource_type == "nodegroup"]
    assert len(nodegroups) == 1
    assert nodegroups[0].resource_id == "my-cluster/ng1"


@mock_aws
def test_eks_describe_cluster_failure_does_not_abort_scan(scan_db: ScanDB):
    """A describe_cluster failure for one cluster must not stop other clusters
    from being scanned."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam", region_name="us-east-1")
    role_arn = iam.create_role(RoleName="eks-role", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_ids = [
        ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=f"us-east-1{az}"
        )["Subnet"]["SubnetId"]
        for i, az in enumerate(("a", "b"), start=1)
    ]
    eks = session.client("eks", region_name="us-east-1")
    eks.create_cluster(
        name="broken-cluster", roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}
    )
    eks.describe_cluster = MagicMock(side_effect=RuntimeError("boom"))

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    with patch("stackwise.scanner.compute.regional_client", return_value=eks):
        count = EKSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0


@mock_aws
def test_eks_describe_nodegroup_failure_does_not_abort_cluster(scan_db: ScanDB):
    """A describe_nodegroup failure for one node group must not stop the
    cluster itself from being stored."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam", region_name="us-east-1")
    role_arn = iam.create_role(RoleName="eks-role", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
    ec2 = session.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_ids = [
        ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=f"us-east-1{az}"
        )["Subnet"]["SubnetId"]
        for i, az in enumerate(("a", "b"), start=1)
    ]
    eks = session.client("eks", region_name="us-east-1")
    eks.create_cluster(
        name="my-cluster", roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}
    )
    eks.create_nodegroup(
        clusterName="my-cluster", nodegroupName="ng1", subnets=subnet_ids, nodeRole=role_arn
    )
    eks.describe_nodegroup = MagicMock(side_effect=RuntimeError("boom"))

    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])
    with patch("stackwise.scanner.compute.regional_client", return_value=eks):
        EKSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    resources = scan_db.get_resources(scan.id, service="eks")
    clusters = [r for r in resources if r.resource_type == "cluster"]
    assert len(clusters) == 1
    assert [r for r in resources if r.resource_type == "nodegroup"] == []


def test_eks_top_level_failure_does_not_raise(scan_db: ScanDB):
    """list_clusters failing entirely must not raise out of _scan_region."""
    session = MagicMock()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    with (
        patch("stackwise.scanner.compute.regional_client", return_value=MagicMock()),
        patch("stackwise.scanner.compute.paginate", side_effect=RuntimeError("boom")),
    ):
        count = EKSScanner()._scan_region(session, scan_db, scan.id, "us-east-1")

    assert count == 0
