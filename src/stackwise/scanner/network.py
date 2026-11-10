"""Network scanners: VPC, Security Groups, ELB, NAT Gateway, API Gateway."""

from __future__ import annotations

import logging

import boto3

from stackwise.scanner.base import BaseScanner
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate, regional_client

logger = logging.getLogger(__name__)


class NetworkScanner(BaseScanner):
    """Scan VPCs, security groups, load balancers, NAT gateways, and API Gateway REST APIs."""

    name = "network"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        ec2 = regional_client(session, "ec2", region)
        elbv2 = regional_client(session, "elbv2", region)

        # ── VPCs ───────────────────────────────────────────
        try:
            vpcs = paginate(ec2, "describe_vpcs", "Vpcs")
            flow_logs_by_vpc: dict[str, list] = {}
            flow_logs_check_failed = False
            try:
                flow_logs = paginate(ec2, "describe_flow_logs", "FlowLogs")
                for fl in flow_logs:
                    rid = fl.get("ResourceId") or ""
                    if rid.startswith("vpc-"):
                        flow_logs_by_vpc.setdefault(rid, []).append(fl)
            except Exception:
                logger.debug("describe_flow_logs failed in %s", region, exc_info=True)
                flow_logs_check_failed = True

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                metadata = {
                    "VpcId": vpc_id,
                    "CidrBlock": vpc.get("CidrBlock"),
                    "IsDefault": vpc.get("IsDefault", False),
                    "FlowLogsCheckFailed": flow_logs_check_failed,
                }
                if not flow_logs_check_failed:
                    fl_list = flow_logs_by_vpc.get(vpc_id, [])
                    metadata["FlowLogsEnabled"] = len(fl_list) > 0
                    metadata["FlowLogs"] = fl_list
                db.insert_resource(
                    scan_id=scan_id,
                    service="ec2",
                    resource_type="vpc",
                    resource_id=vpc_id,
                    region=region,
                    arn=f"arn:aws:ec2:{region}:{vpc.get('OwnerId', '')}:vpc/{vpc_id}",
                    metadata=metadata,
                )
                count += 1
        except Exception as e:
            logger.debug("VPC scan failed in %s", region, exc_info=True)
            self._record_list_failure(db, scan_id, region, "describe_vpcs", e)

        # ── Security Groups ─────────────────────────────────
        try:
            sgs = paginate(ec2, "describe_security_groups", "SecurityGroups")
            for sg in sgs:
                sg_id = sg["GroupId"]
                db.insert_resource(
                    scan_id=scan_id,
                    service="ec2",
                    resource_type="security_group",
                    resource_id=sg_id,
                    region=region,
                    arn=sg.get("GroupArn"),
                    metadata={
                        "GroupId": sg_id,
                        "GroupName": sg.get("GroupName"),
                        "VpcId": sg.get("VpcId"),
                        "IpPermissions": sg.get("IpPermissions", []),
                        "IpPermissionsEgress": sg.get("IpPermissionsEgress", []),
                    },
                )
                count += 1
        except Exception as e:
            logger.debug("Security group scan failed in %s", region, exc_info=True)
            self._record_list_failure(db, scan_id, region, "describe_security_groups", e)

        # ── Load Balancers (ALB/NLB) ─────────────────────────
        try:
            lbs = paginate(elbv2, "describe_load_balancers", "LoadBalancers")
            for lb in lbs:
                lb_arn = lb["LoadBalancerArn"]
                metadata = {
                    "LoadBalancerName": lb.get("LoadBalancerName"),
                    "Scheme": lb.get("Scheme"),
                    "Type": lb.get("Type"),
                    "State": lb.get("State", {}).get("Code"),
                    "AttributesCheckFailed": False,
                    "ListenersCheckFailed": False,
                }
                try:
                    attr_resp = elbv2.describe_load_balancer_attributes(
                        LoadBalancerArn=lb_arn
                    )
                    metadata["Attributes"] = attr_resp.get("Attributes", [])
                except Exception:
                    logger.debug("describe_load_balancer_attributes failed for %s", lb_arn)
                    metadata["AttributesCheckFailed"] = True
                try:
                    listener_resp = paginate(
                        elbv2, "describe_listeners", "Listeners", LoadBalancerArn=lb_arn
                    )
                    metadata["Listeners"] = [
                        {"Protocol": lst.get("Protocol"), "Port": lst.get("Port")}
                        for lst in listener_resp
                    ]
                except Exception:
                    logger.debug("describe_listeners failed for %s", lb_arn)
                    metadata["ListenersCheckFailed"] = True
                db.insert_resource(
                    scan_id=scan_id,
                    service="elbv2",
                    resource_type="load_balancer",
                    resource_id=lb.get("LoadBalancerName", lb_arn),
                    region=region,
                    arn=lb_arn,
                    metadata=metadata,
                )
                count += 1
        except Exception as e:
            logger.debug("Load balancer scan failed in %s", region, exc_info=True)
            self._record_list_failure(db, scan_id, region, "describe_load_balancers", e)

        # ── NAT Gateways ────────────────────────────────────
        try:
            nats = paginate(ec2, "describe_nat_gateways", "NatGateways")
            for nat in nats:
                nat_id = nat["NatGatewayId"]
                if nat.get("State") == "deleted":
                    continue
                db.insert_resource(
                    scan_id=scan_id,
                    service="ec2",
                    resource_type="nat_gateway",
                    resource_id=nat_id,
                    region=region,
                    arn=f"arn:aws:ec2:{region}:{nat.get('OwnerId', '')}:natgateway/{nat_id}",
                    metadata={
                        "NatGatewayId": nat_id,
                        "State": nat.get("State"),
                        "SubnetId": nat.get("SubnetId"),
                        "VpcId": nat.get("VpcId"),
                    },
                )
                count += 1
        except Exception as e:
            logger.debug("NAT gateway scan failed in %s", region, exc_info=True)
            self._record_list_failure(db, scan_id, region, "describe_nat_gateways", e)

        # ── API Gateway REST APIs ───────────────────────────
        try:
            apigw = regional_client(session, "apigateway", region)
            apis = paginate(apigw, "get_rest_apis", "items")
            for api in apis:
                api_id = api["id"]
                try:
                    full = apigw.get_rest_api(restApiId=api_id)
                except Exception:
                    full = api
                # Throttling on a REST API is set per-stage (default method settings
                # under the "*/*" key) — there is no API-level throttle field, so we
                # take the first stage that has one configured. A limit of 0 is configured:
                # it blocks all traffic.
                metadata = {
                    "id": api_id,
                    "name": full.get("name", api.get("name")),
                    "ApiKeySource": full.get("apiKeySource"),
                    "ThrottleCheckFailed": False,
                }
                try:
                    throttle: dict = {}
                    stages = apigw.get_stages(restApiId=api_id).get("item", [])
                    for stage in stages:
                        settings = stage.get("methodSettings", {}).get("*/*", {})
                        rate = settings.get("throttlingRateLimit")
                        burst = settings.get("throttlingBurstLimit")
                        if rate is not None or burst is not None:
                            throttle = {"rateLimit": rate, "burstLimit": burst}
                            break
                    metadata["Throttle"] = throttle
                except Exception:
                    logger.debug("get_stages failed for %s", api_id, exc_info=True)
                    metadata["ThrottleCheckFailed"] = True
                db.insert_resource(
                    scan_id=scan_id,
                    service="apigateway",
                    resource_type="rest_api",
                    resource_id=api_id,
                    region=region,
                    arn=f"arn:aws:apigateway:{region}::/restapis/{api_id}",
                    metadata=metadata,
                )
                count += 1
        except Exception as e:
            logger.debug("API Gateway scan failed in %s", region, exc_info=True)
            self._record_list_failure(db, scan_id, region, "get_rest_apis", e)

        return count


NETWORK_SCANNERS: list[BaseScanner] = [NetworkScanner()]
