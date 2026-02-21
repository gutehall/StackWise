# JSON Output Schema

StackWise supports JSON output for CI/CD integration. This document describes the schema for report and diff JSON outputs.

## Report JSON (`stackwise report --format json`)

Output file: `stackwise-{type}-{account_id}-{date}.json`

```json
{
  "scan": {
    "id": "string",
    "account_id": "string",
    "timestamp": "ISO8601",
    "regions": ["string"],
    "modules": ["string"]
  },
  "summary": {
    "resources": { "service": count },
    "findings": { "CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n, "INFO": n },
    "findings_total": number,
    "recommendations": { "rule": n, "llm": n }
  },
  "findings": [
    {
      "id": "string",
      "rule_id": "string",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "title": "string",
      "detail": "string|null",
      "remediation": "string|null",
      "resource_id": "string|null"
    }
  ],
  "recommendations": [
    {
      "id": "string",
      "source": "rule|llm",
      "category": "string",
      "title": "string",
      "detail": "string|null",
      "impact": "high|medium|low|null",
      "effort": "high|medium|low|null"
    }
  ]
}
```

### Example CI usage

```bash
stackwise run --format json -o ./artifacts
# Parse findings_total for pipeline gates
jq '.summary.findings_total' ./artifacts/stackwise-engineering-*.json
# Fail if critical findings exist
jq '.summary.findings.CRITICAL // 0' ./artifacts/stackwise-engineering-*.json
```

## Diff JSON (`stackwise diff --format json`)

Output: written to stdout (pipe to file if needed)

```json
{
  "base_scan_id": "string",
  "compare_scan_id": "string",
  "resources_added": [
    { "service": "string", "resource_type": "string", "resource_id": "string", "region": "string" }
  ],
  "resources_removed": [
    { "service": "string", "resource_type": "string", "resource_id": "string", "region": "string" }
  ],
  "findings_added": [
    { "rule_id": "string", "severity": "string", "title": "string" }
  ],
  "findings_removed": [
    { "rule_id": "string", "severity": "string", "title": "string" }
  ],
  "findings_unchanged": number
}
```

### Example CI usage

```bash
stackwise diff --format json > diff.json
# Fail if new critical findings
jq '[.findings_added[] | select(.severity == "CRITICAL")] | length' diff.json
# Alert on resource drift
jq '.resources_added | length + .resources_removed | length' diff.json
```
