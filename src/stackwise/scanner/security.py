"""Security scanners: IAM, KMS, Secrets Manager, GuardDuty."""

from __future__ import annotations

import logging

import boto3

from stackwise.scanner.base import BaseScanner
from stackwise.store.db import ScanDB
from stackwise.utils.aws import paginate, regional_client

logger = logging.getLogger(__name__)


class SecurityScanner(BaseScanner):
    """Scan IAM roles/users, KMS keys, Secrets Manager, GuardDuty. Most are global (us-east-1)."""

    name = "security"

    def _scan_region(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0

        # ── IAM (global) — only run in us-east-1 ──────────────
        if region == "us-east-1":
            count += self._scan_iam(session, db, scan_id, region)
            count += self._scan_guardduty(session, db, scan_id, region)

        # ── KMS (regional) ────────────────────────────────────
        count += self._scan_kms_regional(session, db, scan_id, region)

        # ── Secrets Manager (regional) ────────────────────────
        count += self._scan_secrets(session, db, scan_id, region)

        return count

    def _scan_iam(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        iam = regional_client(session, "iam", "us-east-1")
        try:
            roles = paginate(iam, "list_roles", "Roles")
            for role in roles:
                role_name = role["RoleName"]
                policy_check_failed = False
                try:
                    detail = iam.get_role(RoleName=role_name)
                    r = detail["Role"]
                    inline = iam.list_role_policies(RoleName=role_name)
                    inline_count = len(inline.get("PolicyNames", []))
                except Exception as e:
                    logger.warning(
                        "Failed to enrich IAM role %s (get_role/list_role_policies): %s",
                        role_name, e,
                    )
                    r = role
                    inline_count = 0
                    policy_check_failed = True
                db.insert_resource(
                    scan_id=scan_id,
                    service="iam",
                    resource_type="role",
                    resource_id=role_name,
                    region=region,
                    arn=r.get("Arn"),
                    metadata={
                        "RoleName": role_name,
                        "Arn": r.get("Arn"),
                        "InlinePoliciesCount": inline_count,
                        "InlinePoliciesCheckFailed": policy_check_failed,
                        "PermissionsBoundary": (
                            r.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
                            if isinstance(r.get("PermissionsBoundary"), dict)
                            else r.get("PermissionsBoundary")
                        ),
                    },
                )
                count += 1

            users = paginate(iam, "list_users", "Users")
            for user in users:
                user_name = user["UserName"]
                mfa_check_failed = False
                policy_check_failed = False
                try:
                    mfa = iam.list_mfa_devices(UserName=user_name)
                    mfa_devices = mfa.get("MFADevices", [])
                except Exception as e:
                    logger.warning(
                        "Failed to check MFA devices for IAM user %s: %s", user_name, e
                    )
                    mfa_devices = []
                    mfa_check_failed = True
                try:
                    inline = iam.list_user_policies(UserName=user_name)
                    inline_count = len(inline.get("PolicyNames", []))
                except Exception as e:
                    logger.warning(
                        "Failed to list inline policies for IAM user %s: %s", user_name, e
                    )
                    inline_count = 0
                    policy_check_failed = True
                db.insert_resource(
                    scan_id=scan_id,
                    service="iam",
                    resource_type="user",
                    resource_id=user_name,
                    region=region,
                    arn=user.get("Arn"),
                    metadata={
                        "UserName": user_name,
                        "Arn": user.get("Arn"),
                        "MFADevices": mfa_devices,
                        "MFACheckFailed": mfa_check_failed,
                        "InlinePoliciesCount": inline_count,
                        "InlinePoliciesCheckFailed": policy_check_failed,
                    },
                )
                count += 1
        except Exception:
            logger.debug("IAM scan failed: %s", exc_info=True)
        return count

    def _scan_kms_regional(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        try:
            kms = regional_client(session, "kms", region)
            keys = paginate(kms, "list_keys", "Keys")
            for key in keys:
                key_id = key["KeyId"]
                try:
                    desc = kms.describe_key(KeyId=key_id)
                    key_meta = desc.get("KeyMetadata", {})
                    rot = kms.get_key_rotation_status(KeyId=key_id)
                except Exception:
                    key_meta = {}
                    rot = {}
                db.insert_resource(
                    scan_id=scan_id,
                    service="kms",
                    resource_type="key",
                    resource_id=key_id,
                    region=region,
                    arn=key_meta.get("Arn"),
                    metadata={
                        "KeyId": key_id,
                        "Arn": key_meta.get("Arn"),
                        "KeyManager": key_meta.get("KeyManager"),
                        "KeyState": key_meta.get("KeyState"),
                        "KeyRotationEnabled": rot.get("KeyRotationEnabled"),
                    },
                )
                count += 1
        except Exception:
            logger.debug("KMS scan failed in %s: %s", region, exc_info=True)
        return count

    def _scan_secrets(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        try:
            sm = regional_client(session, "secretsmanager", region)
            secrets = paginate(sm, "list_secrets", "SecretList")
            for sec in secrets:
                sec_id = sec["ARN"].split(":")[-1]
                db.insert_resource(
                    scan_id=scan_id,
                    service="secretsmanager",
                    resource_type="secret",
                    resource_id=sec_id,
                    region=region,
                    arn=sec.get("ARN"),
                    metadata={
                        "Name": sec.get("Name"),
                        "ARN": sec.get("ARN"),
                        "RotationEnabled": sec.get("RotationEnabled"),
                        "RotationRules": sec.get("RotationRules"),
                    },
                )
                count += 1
        except Exception:
            logger.debug("Secrets Manager scan failed in %s: %s", region, exc_info=True)
        return count

    def _scan_guardduty(
        self,
        session: boto3.Session,
        db: ScanDB,
        scan_id: str,
        region: str,
    ) -> int:
        count = 0
        try:
            gd = regional_client(session, "guardduty", region)
            detectors = paginate(gd, "list_detectors", "DetectorIds")
            for det_id in detectors:
                try:
                    det = gd.get_detector(DetectorId=det_id)
                except Exception:
                    continue
                db.insert_resource(
                    scan_id=scan_id,
                    service="guardduty",
                    resource_type="detector",
                    resource_id=det_id,
                    region=region,
                    arn=(
                        f"arn:aws:guardduty:{region}:"
                        f"{det.get('Service', {}).get('AccountId', '')}:detector/{det_id}"
                    ),
                    metadata={
                        "DetectorId": det_id,
                        "Status": det.get("Status"),
                        "FindingPublishingFrequency": det.get("FindingPublishingFrequency"),
                    },
                )
                count += 1
                count += self._scan_guardduty_findings(gd, db, scan_id, region, det_id)

        except Exception:
            logger.debug("GuardDuty scan failed in %s: %s", region, exc_info=True)
        return count

    def _scan_guardduty_findings(
        self, gd, db: ScanDB, scan_id: str, region: str, detector_id: str
    ) -> int:
        count = 0
        try:
            finding_ids = paginate(gd, "list_findings", "FindingIds", DetectorId=detector_id)
            for i in range(0, len(finding_ids), 50):  # get_findings takes at most 50 IDs
                batch = finding_ids[i : i + 50]
                resp = gd.get_findings(DetectorId=detector_id, FindingIds=batch)
                for f in resp.get("Findings", []):
                    finding_id = f.get("Id", "")
                    db.insert_resource(
                        scan_id=scan_id,
                        service="guardduty",
                        resource_type="finding",
                        resource_id=finding_id,
                        region=region,
                        arn=f.get("Arn"),
                        metadata={
                            "Id": finding_id,
                            "Type": f.get("Type"),
                            "Title": f.get("Title"),
                            "Severity": f.get("Severity"),
                            "CreatedAt": f.get("CreatedAt"),
                        },
                    )
                    count += 1
        except Exception:
            logger.debug(
                "GuardDuty findings scan failed for detector %s in %s", detector_id, region,
                exc_info=True,
            )
        return count


SECURITY_SCANNERS: list[BaseScanner] = [SecurityScanner()]
