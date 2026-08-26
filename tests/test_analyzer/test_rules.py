"""Tests for YAML rule loading and evaluation."""

from __future__ import annotations

import glob
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from stackwise.analyzer.rules import (
    Rule,
    RuleConditionError,
    _compile_condition,
    _default_rules_dir,
    evaluate_rules,
    load_rules,
)
from stackwise.store.db import ScanDB


def test_load_rules_includes_priority():
    """Rules should load optional priority from YAML."""
    rules = load_rules()
    cmp001 = next(r for r in rules if r.id == "CMP-001")
    assert cmp001.priority == 1
    # Rules without priority get default 999
    cmp002 = next(r for r in rules if r.id == "CMP-002")
    assert cmp002.priority == 999


def test_safe_builtins_allow_len_and_any(scan_db: ScanDB):
    """Rule conditions can use len() and any() from safe builtins."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    # NET-005 uses any() - need security_group with 0.0.0.0/0
    scan_db.insert_resource(
        scan.id, "ec2", "security_group", "sg-123", "us-east-1",
        metadata={
            "IpPermissions": [
                {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 80, "ToPort": 80}
            ]
        },
    )
    evaluate_rules(rules, scan_db, scan.id)
    net005 = [f for f in scan_db.get_findings(scan.id) if f.rule_id == "NET-005"]
    assert len(net005) >= 1


def test_load_rules_from_default_dir():
    """Should load rules from the rules/ directory."""
    rules = load_rules()
    assert len(rules) > 0
    # compute.yaml should have CMP-001
    ids = [r.id for r in rules]
    assert "CMP-001" in ids


def test_all_bundled_rules_pass_condition_validation():
    """Every shipped rule's condition must survive AST validation — a false
    positive in the validator would silently drop a real rule with no test
    failure elsewhere, since load_rules() just skips and logs."""
    from stackwise.analyzer.rules import _default_rules_dir

    total_entries = 0
    for path in sorted(glob.glob(str(_default_rules_dir() / "*.yaml"))):
        with open(path) as f:
            entries = yaml.safe_load(f) or []
        total_entries += len(entries)

    rules = load_rules()
    assert len(rules) == total_entries


@pytest.mark.parametrize(
    "malicious_condition",
    [
        "().__class__.__bases__[0].__subclasses__()",
        "resource.__class__",
        "resource.__init__.__globals__",
        "().__class__",
        "[].__class__.__base__.__subclasses__()",
    ],
)
def test_dunder_attribute_access_is_rejected(malicious_condition):
    """Attribute access to dunders is the classic eval() sandbox escape —
    restricting __builtins__ alone does not block it, since attribute access
    is a bytecode op, not a builtin call. The AST validator must reject it."""
    with pytest.raises(RuleConditionError):
        _compile_condition(malicious_condition, "TEST-EVIL")


@pytest.mark.parametrize(
    "malicious_condition",
    [
        "__import__('os').system('id')",
        "exec('1')",
        "eval('1')",
        "open('/etc/passwd')",
    ],
)
def test_disallowed_names_are_rejected(malicious_condition):
    """Names outside {'resource'} | safe builtins | comprehension targets
    must be rejected, even though __builtins__ restriction already blocks
    these at eval() time — the AST check should catch them at load time too."""
    with pytest.raises(RuleConditionError):
        _compile_condition(malicious_condition, "TEST-EVIL")


def test_getattr_based_dunder_bypass_is_rejected():
    """getattr/hasattr must not be available — they'd let a condition reach
    dunders by string name, bypassing the static attribute-name allowlist."""
    with pytest.raises(RuleConditionError):
        _compile_condition("getattr(resource, '__class__', None)", "TEST-EVIL")


def test_obs002_fires_when_alarm_has_no_actions(scan_db: ScanDB):
    """OBS-002's condition used to be a bare multi-line expression with no
    enclosing bracket — a SyntaxError on every eval(), silently swallowed
    per-resource. Confirm it now actually compiles and fires."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["observability"])
    scan_db.insert_resource(
        scan.id, "cloudwatch", "alarm", "alarm-no-actions", "us-east-1",
        metadata={"AlarmActions": [], "OKActions": []},
    )
    scan_db.insert_resource(
        scan.id, "cloudwatch", "alarm", "alarm-with-actions", "us-east-1",
        metadata={"AlarmActions": ["arn:aws:sns:us-east-1:1:topic"], "OKActions": []},
    )
    evaluate_rules(rules, scan_db, scan.id)
    findings = [f for f in scan_db.get_findings(scan.id) if f.rule_id == "OBS-002"]
    assert len(findings) == 1
    assert "alarm-no-actions" in findings[0].detail


def test_legitimate_comprehension_condition_compiles():
    """Conditions with comprehension-bound loop variables (perm, ipr, etc.)
    must still validate — those names aren't 'resource' or a safe builtin."""
    condition = (
        "any(ipr.get('CidrIp') == '0.0.0.0/0' "
        "for perm in (resource.get('IpPermissions') or []) "
        "for ipr in (perm.get('IpRanges') or []))"
    )
    code = _compile_condition(condition, "TEST-OK")
    assert code is not None


def test_evaluate_public_ip_rule(scan_db: ScanDB):
    """CMP-001 should fire when an instance has a public IP."""
    rules = load_rules()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    # Instance WITH public IP → should trigger
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-public", "us-east-1",
        metadata={"PublicIpAddress": "1.2.3.4", "EbsOptimized": True, "Monitoring": "enabled"},
    )
    # Instance WITHOUT public IP → should not trigger
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-private", "us-east-1",
        metadata={"PublicIpAddress": None, "EbsOptimized": True, "Monitoring": "enabled"},
    )

    evaluate_rules(rules, scan_db, scan.id)
    findings = scan_db.get_findings(scan.id)

    # CMP-001 should fire for i-public
    cmp001 = [f for f in findings if f.rule_id == "CMP-001"]
    assert len(cmp001) == 1
    assert "i-public" in cmp001[0].detail


def test_evaluate_deprecated_runtime_rule(scan_db: ScanDB):
    """CMP-004 should fire for deprecated Lambda runtimes."""
    rules = load_rules()
    scan = scan_db.create_scan("123456789012", ["us-east-1"], ["compute"])

    scan_db.insert_resource(
        scan.id, "lambda", "function", "old-fn", "us-east-1",
        metadata={"Runtime": "python3.8", "MemorySize": 256, "Timeout": 30},
    )
    scan_db.insert_resource(
        scan.id, "lambda", "function", "new-fn", "us-east-1",
        metadata={"Runtime": "python3.12", "MemorySize": 256, "Timeout": 30},
    )

    evaluate_rules(rules, scan_db, scan.id)
    findings = scan_db.get_findings(scan.id)

    cmp004 = [f for f in findings if f.rule_id == "CMP-004"]
    assert len(cmp004) == 1
    assert "old-fn" in cmp004[0].detail


def test_data_rule_s3_versioning(scan_db: ScanDB):
    """DAT-001 should fire when S3 bucket has versioning disabled."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["data"])
    scan_db.insert_resource(
        scan.id, "s3", "bucket", "my-bucket", "us-east-1",
        metadata={"Name": "my-bucket", "Versioning": {"Status": "Suspended"}},
    )
    scan_db.insert_resource(
        scan.id, "s3", "bucket", "versioned-bucket", "us-east-1",
        metadata={"Name": "versioned-bucket", "Versioning": {"Status": "Enabled"}},
    )
    evaluate_rules(rules, scan_db, scan.id)
    findings = scan_db.get_findings(scan.id)
    dat001 = [f for f in findings if f.rule_id == "DAT-001"]
    assert len(dat001) == 1
    assert "my-bucket" in dat001[0].detail


def test_dat001_does_not_fire_when_versioning_check_failed(scan_db: ScanDB):
    """A bucket whose versioning check failed (permissions/API error) must not
    be reported as 'versioning disabled' — that would be a false positive."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["data"])
    scan_db.insert_resource(
        scan.id, "s3", "bucket", "locked-bucket", "us-east-1",
        metadata={"Versioning": {}, "VersioningCheckFailed": True},
    )
    evaluate_rules(rules, scan_db, scan.id)
    findings = scan_db.get_findings(scan.id)
    assert not any(f.rule_id == "DAT-001" for f in findings)
    assert any(f.rule_id == "DAT-019" for f in findings)


def test_eks_deprecated_version_rule_does_not_flag_current_versions(scan_db: ScanDB):
    """CMP-017 must not flag every 1.2x version — only ones below the threshold."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "eks", "cluster", "old-cluster", "us-east-1",
        metadata={"version": "1.21"},
    )
    scan_db.insert_resource(
        scan.id, "eks", "cluster", "current-cluster", "us-east-1",
        metadata={"version": "1.30"},
    )
    evaluate_rules(rules, scan_db, scan.id)
    findings = [f for f in scan_db.get_findings(scan.id) if f.rule_id == "CMP-017"]
    assert len(findings) == 1
    assert "old-cluster" in findings[0].detail


def test_efs_lifecycle_rule_checks_actual_policies(scan_db: ScanDB):
    """DAT-015 must key off LifecyclePolicies, not filesystem LifeCycleState."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["data"])
    scan_db.insert_resource(
        scan.id, "efs", "file_system", "fs-no-policy", "us-east-1",
        metadata={"LifeCycleState": "available", "LifecyclePolicies": []},
    )
    scan_db.insert_resource(
        scan.id, "efs", "file_system", "fs-with-policy", "us-east-1",
        metadata={
            "LifeCycleState": "available",
            "LifecyclePolicies": [{"TransitionToIA": "AFTER_30_DAYS"}],
        },
    )
    evaluate_rules(rules, scan_db, scan.id)
    findings = [f for f in scan_db.get_findings(scan.id) if f.rule_id == "DAT-015"]
    assert len(findings) == 1
    assert "fs-no-policy" in findings[0].detail


def test_sec002_does_not_fire_when_mfa_check_failed(scan_db: ScanDB):
    """A throttled MFA check must not be reported as 'no MFA'."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["security"])
    scan_db.insert_resource(
        scan.id, "iam", "user", "alice", "us-east-1",
        metadata={"MFADevices": [], "MFACheckFailed": True, "InlinePoliciesCount": 0},
    )
    evaluate_rules(rules, scan_db, scan.id)
    findings = scan_db.get_findings(scan.id)
    assert not any(f.rule_id == "SEC-002" for f in findings)
    assert any(f.rule_id == "SEC-012" for f in findings)


def test_sec010_fires_on_medium_or_higher_guardduty_finding(scan_db: ScanDB):
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["security"])
    scan_db.insert_resource(
        scan.id, "guardduty", "finding", "finding-1", "us-east-1",
        metadata={"Severity": 5.0},
    )
    scan_db.insert_resource(
        scan.id, "guardduty", "finding", "finding-2", "us-east-1",
        metadata={"Severity": 2.0},
    )
    evaluate_rules(rules, scan_db, scan.id)
    findings = [f for f in scan_db.get_findings(scan.id) if f.rule_id == "SEC-010"]
    assert len(findings) == 1
    assert "finding-1" in findings[0].detail


def test_cmp019_fires_when_launch_template_allows_imdsv1(scan_db: ScanDB):
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "ec2", "launch_template", "lt-optional", "us-east-1",
        metadata={"MetadataOptions": {"HttpTokens": "optional"}},
    )
    scan_db.insert_resource(
        scan.id, "ec2", "launch_template", "lt-required", "us-east-1",
        metadata={"MetadataOptions": {"HttpTokens": "required"}},
    )
    evaluate_rules(rules, scan_db, scan.id)
    findings = [f for f in scan_db.get_findings(scan.id) if f.rule_id == "CMP-019"]
    assert len(findings) == 1
    assert "lt-optional" in findings[0].detail


def test_compile_condition_with_non_name_comprehension_target():
    """A comprehension target that's neither a Name nor Tuple/List (e.g. a
    subscript target) binds no names — _target_names must handle it instead
    of crashing, even though it's an unusual thing for a rule to write."""
    code = _compile_condition(
        "any(True for resource['tags'][0] in [1, 2, 3])", "TEST-OK"
    )
    assert code is not None


def test_compile_condition_with_tuple_destructuring_comprehension():
    """A comprehension binding a tuple target ('for k, v in ...') must bind
    both k and v as allowed names, not just the first."""
    code = _compile_condition(
        "any(v == 'x' for k, v in resource.get('Tags', {}).items())", "TEST-OK"
    )
    assert code is not None


def test_compile_condition_syntax_error_is_rejected():
    with pytest.raises(RuleConditionError, match="syntax error"):
        _compile_condition("resource.get('X') ==", "TEST-BAD")


def test_compile_condition_rejects_disallowed_syntax():
    """A lambda is not in the AST allowlist and must be rejected."""
    with pytest.raises(RuleConditionError, match="disallowed syntax"):
        _compile_condition("(lambda: True)()", "TEST-BAD")


def test_compile_condition_rejects_keyword_call_args():
    with pytest.raises(RuleConditionError, match="keyword/starred"):
        _compile_condition("len(resource, x=1)", "TEST-BAD")


def test_compile_condition_rejects_starred_call_args():
    with pytest.raises(RuleConditionError, match="keyword/starred"):
        _compile_condition("len(*[resource])", "TEST-BAD")


def test_default_rules_dir_falls_back_to_app_rules_when_it_exists():
    """If the packaged rules/ dir isn't found but /app/rules exists (the
    Docker image layout), that fallback must be used."""

    def _is_dir(self: Path) -> bool:
        return str(self) == "/app/rules"

    with patch.object(Path, "is_dir", _is_dir):
        assert _default_rules_dir() == Path("/app/rules")


def test_default_rules_dir_returns_packaged_path_when_neither_exists():
    """If neither the packaged dir nor /app/rules exists, fall back to
    returning the (nonexistent) packaged path — load_rules() then logs and
    returns an empty rule set rather than raising."""
    import stackwise.analyzer.rules as rules_module

    expected = Path(rules_module.__file__).resolve().parent.parent / "rules"
    with patch.object(Path, "is_dir", return_value=False):
        assert _default_rules_dir() == expected


def test_load_rules_missing_directory_returns_empty_list(tmp_path: Path):
    result = load_rules(rules_dir=tmp_path / "does-not-exist")
    assert result == []


def test_load_rules_skips_rule_with_invalid_condition(tmp_path: Path):
    """A rule whose condition fails AST validation must be rejected and
    logged, not abort loading the rest of the file."""
    (tmp_path / "bad.yaml").write_text(
        yaml.dump(
            [
                {
                    "id": "BAD-001",
                    "title": "Uses eval",
                    "severity": "LOW",
                    "resource_type": "thing",
                    "condition": "eval('1')",
                },
                {
                    "id": "GOOD-001",
                    "title": "Fine",
                    "severity": "LOW",
                    "resource_type": "thing",
                    "condition": "resource.get('x') is None",
                },
            ]
        )
    )
    rules = load_rules(rules_dir=tmp_path)
    ids = [r.id for r in rules]
    assert "BAD-001" not in ids
    assert "GOOD-001" in ids


def test_load_rules_handles_malformed_yaml_file(tmp_path: Path):
    """A YAML file that fails to parse entirely must not crash load_rules() —
    it's logged and skipped, other files still load."""
    (tmp_path / "broken.yaml").write_text("id: [unterminated")
    (tmp_path / "good.yaml").write_text(
        yaml.dump(
            [
                {
                    "id": "GOOD-002",
                    "title": "Fine",
                    "severity": "LOW",
                    "resource_type": "thing",
                    "condition": "resource.get('x') is None",
                }
            ]
        )
    )
    rules = load_rules(rules_dir=tmp_path)
    assert [r.id for r in rules] == ["GOOD-002"]


def test_evaluate_rules_skips_suppressed_rule_ids(scan_db: ScanDB):
    """A rule ID in suppressed_rules must be skipped entirely, even for a
    resource that would otherwise match."""
    rules = load_rules()
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-public", "us-east-1",
        metadata={"PublicIpAddress": "1.2.3.4"},
    )

    evaluate_rules(rules, scan_db, scan.id, suppressed_rules=["CMP-001"])

    findings = scan_db.get_findings(scan.id)
    assert not any(f.rule_id == "CMP-001" for f in findings)


def test_evaluate_rules_catches_runtime_exception_in_condition(scan_db: ScanDB):
    """A condition that passes AST validation but raises at eval() time
    (e.g. comparing incompatible types) must be logged and skipped, not
    crash the whole rule evaluation pass."""
    scan = scan_db.create_scan("123", ["us-east-1"], ["compute"])
    scan_db.insert_resource(
        scan.id, "ec2", "instance", "i-1", "us-east-1",
        metadata={"Count": "not-a-number"},
    )
    condition = "resource.get('Count') > 5"
    rule = Rule(
        id="RUNTIME-ERR",
        title="Bad rule",
        severity="LOW",
        resource_type="instance",
        service="ec2",
        condition=condition,
        remediation="",
        compiled_condition=_compile_condition(condition, "RUNTIME-ERR"),
    )

    count = evaluate_rules([rule], scan_db, scan.id)

    assert count == 0
    assert scan_db.get_findings(scan.id) == []
