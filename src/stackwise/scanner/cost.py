"""Cost scanners: Resource Groups Tagging, Compute Optimizer."""

from __future__ import annotations

import logging
from datetime import date, timedelta

import boto3

from stackwise.scanner.base import BaseScanner
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate, regional_client

logger = logging.getLogger(__name__)


class CostScanner(BaseScanner):
    """Scan tagged resources, Cost Explorer summary, and Compute Optimizer recommendations."""

    name = "cost"

    def __init__(self, skip_cost_explorer: bool = False) -> None:
        # Unlike every other scanner call in this codebase, ce:GetCostAndUsage
        # bills $0.01/request — this lets a caller opt out of that one call.
        self.skip_cost_explorer = skip_cost_explorer

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0

        # ── Cost Explorer (global — only run in us-east-1) ─────
        if region == "us-east-1" and not self.skip_cost_explorer:
            count += self._scan_cost_explorer(session, db, scan_id, region)

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
        # No boto3 paginator exists for this operation — page manually via nextToken.
        try:
            opt = regional_client(session, "compute-optimizer", region)
            next_token = None
            while True:
                kwargs = {"nextToken": next_token} if next_token else {}
                ec2_recs = opt.get_ec2_instance_recommendations(**kwargs)
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
                next_token = ec2_recs.get("nextToken")
                if not next_token:
                    break
        except Exception:
            logger.debug(
                "Compute Optimizer EC2 scan failed in %s", region, exc_info=True
            )

        # ── Compute Optimizer Lambda recommendations ──────────
        try:
            opt = regional_client(session, "compute-optimizer", region)
            lambda_recs_list = paginate(
                opt, "get_lambda_function_recommendations", "lambdaFunctionRecommendations"
            )
            for rec in lambda_recs_list:
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

    def _scan_cost_explorer(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        """Fetch a trailing-30-day cost summary grouped by service.

        Stored as a single 'ce'/'cost_summary' resource that report/generator.py
        reads to build the "Cost by Service" chart.
        """
        try:
            ce = regional_client(session, "ce", region)
            end_date = date.today()
            start_date = end_date - timedelta(days=30)
            resp = ce.get_cost_and_usage(
                TimePeriod={"Start": start_date.isoformat(), "End": end_date.isoformat()},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
            cost_by_service: dict[str, float] = {}
            for period in resp.get("ResultsByTime", []):
                for g in period.get("Groups", []):
                    svc = g.get("Keys", ["Other"])[0] if g.get("Keys") else "Other"
                    amount = float(
                        g.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0) or 0
                    )
                    cost_by_service[svc] = cost_by_service.get(svc, 0.0) + amount

            db.insert_resource(
                scan_id=scan_id,
                service="ce",
                resource_type="cost_summary",
                resource_id=f"cost-summary-{start_date.isoformat()}-{end_date.isoformat()}",
                region=region,
                metadata={
                    "TimePeriod": {"Start": start_date.isoformat(), "End": end_date.isoformat()},
                    "Groups": [
                        {
                            "Keys": [svc],
                            "Metrics": {"UnblendedCost": {"Amount": str(amt), "Unit": "USD"}},
                        }
                        for svc, amt in cost_by_service.items()
                    ],
                },
            )
            return 1
        except Exception:
            logger.debug("Cost Explorer get_cost_and_usage failed in %s", region, exc_info=True)
            return 0


COST_SCANNERS: list[BaseScanner] = [CostScanner()]
