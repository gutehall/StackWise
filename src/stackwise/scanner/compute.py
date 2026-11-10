"""Compute scanners: EC2, Auto Scaling Groups, Launch Templates, Lambda."""

from __future__ import annotations

import logging

import boto3

from stackwise.scanner.base import BaseScanner
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate, regional_client

logger = logging.getLogger(__name__)


def _to_int(value):
    """ECS task def cpu/memory come back as strings (e.g. "256"); coerce or drop."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class EC2Scanner(BaseScanner):
    """Scan EC2 instances, Auto Scaling Groups, and Launch Templates."""

    name = "ec2"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        ec2 = regional_client(session, "ec2", region)
        asg_client = regional_client(session, "autoscaling", region)

        # ── EC2 Instances ──────────────────────────────────
        reservations = paginate(ec2, "describe_instances", "Reservations")
        for res in reservations:
            # OwnerId is on the reservation, not the instance — already free in this
            # response, no separate STS call needed to build a real ARN.
            owner_id = res.get("OwnerId", "")
            for inst in res.get("Instances", []):
                instance_id = inst["InstanceId"]
                db.insert_resource(
                    scan_id=scan_id,
                    service="ec2",
                    resource_type="instance",
                    resource_id=instance_id,
                    region=region,
                    arn=f"arn:aws:ec2:{region}:{owner_id}:instance/{instance_id}",
                    metadata={
                        "InstanceId": instance_id,
                        "InstanceType": inst.get("InstanceType"),
                        "State": inst.get("State", {}).get("Name"),
                        "Platform": inst.get("PlatformDetails"),
                        "PublicIpAddress": inst.get("PublicIpAddress"),
                        "SubnetId": inst.get("SubnetId"),
                        "VpcId": inst.get("VpcId"),
                        "Tags": inst.get("Tags", []),
                        "BlockDeviceMappings": inst.get("BlockDeviceMappings", []),
                        "LaunchTime": inst.get("LaunchTime"),
                        "Architecture": inst.get("Architecture"),
                        "EbsOptimized": inst.get("EbsOptimized"),
                        "Monitoring": inst.get("Monitoring", {}).get("State"),
                        "MetadataOptions": inst.get("MetadataOptions"),
                        "LaunchTemplate": inst.get("LaunchTemplate"),
                    },
                )
                count += 1

        # ── Auto Scaling Groups ────────────────────────────
        asgs = paginate(asg_client, "describe_auto_scaling_groups", "AutoScalingGroups")
        for asg in asgs:
            asg_name = asg["AutoScalingGroupName"]
            db.insert_resource(
                scan_id=scan_id,
                service="ec2",
                resource_type="auto_scaling_group",
                resource_id=asg_name,
                region=region,
                arn=asg.get("AutoScalingGroupARN"),
                metadata={
                    "AutoScalingGroupName": asg_name,
                    "MinSize": asg.get("MinSize"),
                    "MaxSize": asg.get("MaxSize"),
                    "DesiredCapacity": asg.get("DesiredCapacity"),
                    "LaunchTemplate": asg.get("LaunchTemplate"),
                    "LaunchConfigurationName": asg.get("LaunchConfigurationName"),
                    "AvailabilityZones": asg.get("AvailabilityZones", []),
                    "HealthCheckType": asg.get("HealthCheckType"),
                    "Tags": asg.get("Tags", []),
                },
            )
            count += 1

        # ── Launch Templates ───────────────────────────────
        try:
            templates = paginate(ec2, "describe_launch_templates", "LaunchTemplates")
            for lt in templates:
                lt_id = lt["LaunchTemplateId"]
                default_version = lt.get("DefaultVersionNumber")
                launch_template_data: dict = {}
                # Stays set unless the default version is actually read: an empty result
                # tells us nothing about the template's settings either.
                metadata_check_failed = True
                if default_version is not None:
                    try:
                        versions = ec2.describe_launch_template_versions(
                            LaunchTemplateId=lt_id, Versions=[str(default_version)]
                        ).get("LaunchTemplateVersions", [])
                        if versions:
                            launch_template_data = versions[0].get("LaunchTemplateData", {})
                            metadata_check_failed = False
                    except Exception:
                        logger.debug(
                            "describe_launch_template_versions failed for %s", lt_id,
                            exc_info=True,
                        )
                metadata = {
                    "LaunchTemplateId": lt_id,
                    "LaunchTemplateName": lt.get("LaunchTemplateName"),
                    "DefaultVersionNumber": default_version,
                    "LatestVersionNumber": lt.get("LatestVersionNumber"),
                    "EbsOptimized": launch_template_data.get("EbsOptimized"),
                    "MetadataOptionsCheckFailed": metadata_check_failed,
                }
                if not metadata_check_failed:
                    metadata["MetadataOptions"] = launch_template_data.get("MetadataOptions", {})
                db.insert_resource(
                    scan_id=scan_id,
                    service="ec2",
                    resource_type="launch_template",
                    resource_id=lt_id,
                    region=region,
                    metadata=metadata,
                )
                count += 1
        except Exception as e:
            logger.debug("launch_templates: not available in %s", region, exc_info=True)
            self._record_list_failure(db, scan_id, region, "describe_launch_templates", e)

        return count


class LambdaScanner(BaseScanner):
    """Scan Lambda functions."""

    name = "lambda"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        client = regional_client(session, "lambda", region)

        functions = paginate(client, "list_functions", "Functions")
        for fn in functions:
            fn_name = fn["FunctionName"]
            db.insert_resource(
                scan_id=scan_id,
                service="lambda",
                resource_type="function",
                resource_id=fn_name,
                region=region,
                arn=fn.get("FunctionArn"),
                metadata={
                    "FunctionName": fn_name,
                    "Runtime": fn.get("Runtime"),
                    "MemorySize": fn.get("MemorySize"),
                    "Timeout": fn.get("Timeout"),
                    "Handler": fn.get("Handler"),
                    "CodeSize": fn.get("CodeSize"),
                    "LastModified": fn.get("LastModified"),
                    "Architectures": fn.get("Architectures", []),
                    "PackageType": fn.get("PackageType"),
                    "EphemeralStorage": fn.get("EphemeralStorage"),
                    "VpcConfig": fn.get("VpcConfig"),
                    "DeadLetterConfig": fn.get("DeadLetterConfig"),
                    "ReservedConcurrentExecutions": fn.get("ReservedConcurrentExecutions"),
                },
            )
            count += 1

        return count


class ECSScanner(BaseScanner):
    """Scan ECS services and task definitions."""

    name = "ecs"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        ecs = regional_client(session, "ecs", region)

        operation = "list_clusters"
        try:
            cluster_arns = paginate(ecs, "list_clusters", "clusterArns")
            for cluster_arn in cluster_arns:
                cluster_name = cluster_arn.split("/")[-1]
                operation = "list_services"
                svc_arns = paginate(
                    ecs,
                    "list_services",
                    "serviceArns",
                    cluster=cluster_arn,
                )
                for svc_arn in svc_arns:
                    if not svc_arn:
                        continue
                    # The name in the ARN is the name describe_services returns, so a
                    # flagged row keeps the identity a successful scan would store.
                    arn_name = svc_arn.split("/")[-1]
                    try:
                        svcs = ecs.describe_services(
                            cluster=cluster_arn,
                            services=[svc_arn],
                        ).get("services", [])
                    except Exception:
                        logger.debug("describe_services failed for %s", svc_arn, exc_info=True)
                        db.insert_resource(
                            scan_id=scan_id,
                            service="ecs",
                            resource_type="service",
                            resource_id=f"{cluster_name}/{arn_name}",
                            region=region,
                            arn=svc_arn,
                            metadata={
                                "serviceName": arn_name,
                                "clusterArn": cluster_arn,
                                "ServiceCheckFailed": True,
                            },
                        )
                        count += 1
                        continue
                    for svc in svcs:
                        svc_name = svc.get("serviceName", arn_name)
                        db.insert_resource(
                            scan_id=scan_id,
                            service="ecs",
                            resource_type="service",
                            resource_id=f"{cluster_name}/{svc_name}",
                            region=region,
                            arn=svc.get("serviceArn"),
                            metadata={
                                "serviceName": svc_name,
                                "clusterArn": cluster_arn,
                                "launchType": svc.get("launchType"),
                                "desiredCount": svc.get("desiredCount"),
                                "runningCount": svc.get("runningCount"),
                                "ServiceCheckFailed": False,
                            },
                        )
                        count += 1

            operation = "list_task_definitions"
            task_def_arns = paginate(ecs, "list_task_definitions", "taskDefinitionArns")
            for td_arn in task_def_arns:
                try:
                    td = ecs.describe_task_definition(
                        taskDefinition=td_arn,
                    ).get("taskDefinition", {})
                except Exception:
                    logger.debug("describe_task_definition failed for %s", td_arn, exc_info=True)
                    # The ARN ends in family:revision, the id a successful scan stores.
                    db.insert_resource(
                        scan_id=scan_id,
                        service="ecs",
                        resource_type="task_definition",
                        resource_id=td_arn.split("/")[-1],
                        region=region,
                        arn=td_arn,
                        metadata={"TaskDefinitionCheckFailed": True},
                    )
                    count += 1
                    continue
                td_family = td.get("family", td_arn.split("/")[-1].rsplit(":", 1)[0])
                td_revision = td.get("revision")
                # Include the revision in the identity: each revision is a
                # distinct AWS resource (own ARN), and collapsing them onto
                # the shared family name would make diff_scans silently miss
                # added/removed revisions.
                resource_id = (
                    f"{td_family}:{td_revision}" if td_revision is not None else td_family
                )
                db.insert_resource(
                    scan_id=scan_id,
                    service="ecs",
                    resource_type="task_definition",
                    resource_id=resource_id,
                    region=region,
                    arn=td.get("taskDefinitionArn"),
                    metadata={
                        "family": td_family,
                        "revision": td_revision,
                        "cpu": _to_int(td.get("cpu")),
                        "memory": _to_int(td.get("memory")),
                        "status": td.get("status"),
                        "TaskDefinitionCheckFailed": False,
                    },
                )
                count += 1
        except Exception as e:
            logger.debug("ECS scan failed in %s", region, exc_info=True)
            self._record_list_failure(db, scan_id, region, operation, e)

        return count


class EKSScanner(BaseScanner):
    """Scan EKS clusters and node groups."""

    name = "eks"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        try:
            eks = regional_client(session, "eks", region)
            clusters = paginate(eks, "list_clusters", "clusters")
            for cluster_name in clusters:
                metadata = {"name": cluster_name, "ClusterCheckFailed": False}
                arn = None
                try:
                    cluster = eks.describe_cluster(name=cluster_name).get("cluster", {})
                    arn = cluster.get("arn")
                    metadata["version"] = cluster.get("version")
                    metadata["status"] = cluster.get("status")
                    metadata["resourcesVpcConfig"] = cluster.get("resourcesVpcConfig", {})
                except Exception:
                    logger.debug("describe_cluster failed for %s", cluster_name, exc_info=True)
                    metadata["ClusterCheckFailed"] = True
                db.insert_resource(
                    scan_id=scan_id,
                    service="eks",
                    resource_type="cluster",
                    resource_id=cluster_name,
                    region=region,
                    arn=arn,
                    metadata=metadata,
                )
                count += 1

                try:
                    nodegroups = paginate(
                        eks,
                        "list_nodegroups",
                        "nodegroups",
                        clusterName=cluster_name,
                    )
                except Exception as e:
                    # Unlike a describe failure, the ids are unknown here, so no row can
                    # be stored. Only a failed scan keeps diff from reporting the cluster's
                    # node groups as removed.
                    logger.debug("list_nodegroups failed for %s", cluster_name, exc_info=True)
                    self._record_list_failure(db, scan_id, region, "list_nodegroups", e)
                    continue

                for ng_name in nodegroups:
                    metadata = {
                        "nodegroupName": ng_name,
                        "clusterName": cluster_name,
                        "NodegroupCheckFailed": False,
                    }
                    arn = None
                    try:
                        ng = eks.describe_nodegroup(
                            clusterName=cluster_name,
                            nodegroupName=ng_name,
                        ).get("nodegroup", {})
                        arn = ng.get("nodegroupArn")
                        metadata["scalingConfig"] = ng.get("scalingConfig")
                        metadata["status"] = ng.get("status")
                    except Exception:
                        logger.debug(
                            "describe_nodegroup failed for %s/%s",
                            cluster_name,
                            ng_name,
                            exc_info=True,
                        )
                        metadata["NodegroupCheckFailed"] = True
                    db.insert_resource(
                        scan_id=scan_id,
                        service="eks",
                        resource_type="nodegroup",
                        resource_id=f"{cluster_name}/{ng_name}",
                        region=region,
                        arn=arn,
                        metadata=metadata,
                    )
                    count += 1
        except Exception as e:
            logger.debug("EKS scan failed in %s", region, exc_info=True)
            self._record_list_failure(db, scan_id, region, "list_clusters", e)

        return count


# Registry of scanners belonging to the "compute" module
COMPUTE_SCANNERS: list[BaseScanner] = [
    EC2Scanner(),
    LambdaScanner(),
    ECSScanner(),
    EKSScanner(),
]
