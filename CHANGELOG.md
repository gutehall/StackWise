# Changelog

## v0.2.0 — 2026-11-10

### Breaking Changes
- Scans exit 1 when a region or whole-service list call fails, and a failed scan is never published as `.latest` (PR #4)
- Scan database files are now named `{timestamp}.{microseconds}-{suffix}.db`, and report files include the scan id (PR #4, #8)
- The first `diff` against a scan from an older version shows every tagged resource as removed and re-added, because they are now keyed by full ARN (PR #6)
- `analyze` exits 1 on a broken packaged rules file, or when an explicitly requested engine (`--engine mlx`, or `--engine ollama` with Ollama down) can't run (PR #7, #8)
- `report --format pdf` exits 1 when WeasyPrint can't write a PDF, instead of silently writing HTML (PR #8)
- Rules `CST-001` and `NET-011` are removed; suppressions of them do nothing (PR #8)
- New IAM permissions: `lambda:GetFunctionConcurrency` and `lambda:GetFunctionEventInvokeConfig`; redeploy the role from `docs/` (PR #6, #8)

### Changes
- PR #4: Trust the scan result: fail partial scans and keep them out of diff
- PR #5: Stop false findings from API errors: flag failed checks instead of reporting them
- PR #6: Match rules to live AWS fields: read what the API returns, key tagged resources by ARN
- PR #7: Make analyze safe to re-run: one transaction, and fail on broken packaged rules
- PR #8: Reliability follow-ups: rules match the real case, reports and commands fail honestly
- PR #9: Show a partial LLM run in the HTML reports

### Documentation
- commit: 79a0082 Update CLAUDE.md for the engine selection change in DM3-361
- commit: 93b9f7b Add the MIT license.

### Chores
- commit: 9b41f53 Update CHANGELOG.md for v0.1.1

## v0.1.1 — 2026-08-26

### Bug Fixes
- Fix scanner/rule correctness bugs, remove dead code — NET-007/NET-010 rules that never matched or always fired, a KMS scanner bug that discarded key metadata on rotation-status failure, a DynamoDB PITR field read one level too shallow (fired on every table), a Config recorder IndexError on malformed roleARN, and a PDF report fallback that only caught ImportError
- PR #3: fix: replace direct jinja2.Environment with SandboxedEnvironment to prevent XSS
- PR #1: Add non-root USER to Dockerfile to fix container security finding
- fix: PDF report test assumed WeasyPrint system libs present in CI

### Chores
- Bring test coverage to 100%, fix moto apigateway extra
- ci: pin GitHub Actions to commit SHAs (mitigates supply-chain risk from mutable tag refs)

### Documentation
- Expand README intro to explain what StackWise does
- Document release cadence in CLAUDE.md
- Add CHANGELOG.md for v0.1.0

## v0.1.0 — 2026-08-25

First release.

### Features
- commit 0e1dfdf: Added tabs to report
- commit e953ab1: Add self-contained single-EC2 CFN template

### Bug Fixes
- commit d5674f4: Fix scanner correctness bugs, harden rule eval, add cost opt-out
- commit d0a82a7: Fix CMP-015 crash: coerce ECS task def cpu/memory to int
- commit f4050cf: Fix LLM recommendations with no detail/impact/effort
- commit c6df117, cfca4e2, adcc380, 0466f98: Bug fixes

### Performance
- commit 3d9308c: Speed up LLM analysis: skip low-value category, bigger chunks, parallel calls

### Documentation
- commit e8b2ff2: Add CLAUDE.md project guide
- commit a83bafb: Update README
- commit b58fe28: Document the one-shot EC2 CFN deploy in README
- commit 4339a9c: Fix repository name case in README setup instructions

### Chores
- commit 2884930: Ignore .remember/ (local session memory)
- commit 34124e2: Untrack __pycache__ (already gitignored, tracked from before)
- commit 6ce2b8d: Delete stray report file from repo

### Changes
- commit 52a3f30: Default to qwen3:14b for local LLM analysis
