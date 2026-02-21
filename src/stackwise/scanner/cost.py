"""Cost scanners: Resource Groups Tagging, Compute Optimizer."""

from __future__ import annotations

import logging

import boto3

from stackwise.scanner.base import BaseScanner
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate, regional_client

logger = logging.getLogger(__name__)


class CostScanner(BaseScanner):
    """Scan tagged resources and Compute Optimizer recommendations."""

    name = "cost"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0

        # ── Tagged resources (Resource Groups Tagging API) ─────
        try:
            tag_client = regional_client(session, "resourcegroupstaggingapi", region)
            resources = paginate(
                tag_client,
                "get_resources",
                "ResourceTagMappingList",
            )
            for res in resources:
                arn = res.get("ResourceARN", "")
                res_id = arn.split("/")[-1] if "/" in arn else arn.split(":")[-1]
                if not res_id:
                    res_id = arn
                db.insert_resource(
                    scan_id=scan_id,
                    service="resourcegroupstaggingapi",
                    resource_type="tagged_resource",
                    resource_id=res_id,
                    region=region,
                    arn=arn,
                    metadata={
                        "ResourceARN": arn,
                        "Tags": res.get("Tags", []),
                    },
                )
                count += 1
        except Exception:
            logger.debug("Tagged resources scan failed in %s", region, exc_info=True)

        # ── Compute Optimizer EC2 recommendations ─────────────
        try:
            opt = regional_client(session, "compute-optimizer", region)
            ec2_recs = opt.get_ec2_instance_recommendations()
            for rec in ec2_recs.get("instanceRecommendations", []):
                inst_arn = rec.get("instanceArn", "")
                rec_id = inst_arn.split("/")[-1] if "/" in inst_arn else inst_arn
                db.insert_resource(
                    scan_id=scan_id,
                    service="compute-optimizer",
                    resource_type="ec2_recommendation",
                    resource_id=rec_id,
                    region=region,
                    arn=inst_arn,
                    metadata={
                        "instanceArn": inst_arn,
                        "RecommendationSourceType": rec.get("recommendationSourceType")
                        or rec.get("RecommendationSourceType"),
                        "finding": rec.get("finding"),
                        "recommendationOptions": rec.get("recommendationOptions", []),
                    },
                )
                count += 1
        except Exception:
            logger.debug(
                "Compute Optimizer EC2 scan failed in %s", region, exc_info=True
            )

        # ── Compute Optimizer Lambda recommendations ──────────
        try:
            opt = regional_client(session, "compute-optimizer", region)
            lambda_recs = opt.get_lambda_function_recommendations()
            for rec in lambda_recs.get("lambdaFunctionRecommendations", []):
                fn_arn = rec.get("functionArn", "")
                fn_name = fn_arn.split(":")[-1] if ":" in fn_arn else fn_arn
                db.insert_resource(
                    scan_id=scan_id,
                    service="compute-optimizer",
                    resource_type="lambda_recommendation",
                    resource_id=fn_name,
                    region=region,
                    arn=fn_arn,
                    metadata={
                        "functionArn": fn_arn,
                        "RecommendationSourceType": rec.get("recommendationSourceType")
                        or rec.get("RecommendationSourceType"),
                        "finding": rec.get("finding"),
                        "recommendationOptions": rec.get("recommendationOptions", []),
                    },
                )
                count += 1
        except Exception:
            logger.debug(
                "Compute Optimizer Lambda scan failed in %s", region, exc_info=True
            )

        return count


COST_SCANNERS: list[BaseScanner] = [CostScanner()]
