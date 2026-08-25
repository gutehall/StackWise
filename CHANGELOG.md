# Changelog

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
