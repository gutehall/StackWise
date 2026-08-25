"""Tests for compute scanners (EC2, Lambda) using moto mocking."""

from __future__ import annotations

import boto3
from moto import mock_aws

from stackwise.scanner.compute import EC2Scanner, ECSScanner, LambdaScanner
from stackwise.store.db import ScanDB


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
