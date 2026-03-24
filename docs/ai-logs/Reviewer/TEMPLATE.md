---
reviewer: Reviewer
timestamp: YYYY-MM-DD HH:MM UTC+8
repo: myOS
branch: <branch-name>
commit_range: <start-commit>..<end-commit>
pr_or_task: <PR# or task id>
scope: Rust-only (including arceos/)
decision: APPROVE # APPROVE | REQUEST_CHANGES
critical_count: 0
major_count: 0
minor_count: 0
arceos_reuse_violations: false
checklist_reuse_gate: pass # pass | fail
checklist_correctness: pass # pass | fail
checklist_concurrency_safety: pass # pass | fail | n/a
checklist_security_robustness: pass # pass | fail
checklist_performance: pass # pass | fail
checklist_api_compatibility: pass # pass | fail
checklist_tests_regression: pass # pass | fail
confidence_high_count: 0
confidence_medium_count: 0
confidence_low_count: 0
---

# Reviewer Log

## 1) Task Summary
- Review target: <PR/task/diff>
- Goal: Enforce ArceOS-first reuse; block custom Rust reimplementation when equivalent exists.
- Input provided: <changed files/commit range/extra context>

## 2) Reviewed Changes
- Changed Rust files:
  - <path>
- Non-Rust changes checked for Rust-interface impact:
  - <none or path>

## 3) ArceOS Discovery Evidence
- Searched locations:
  - arceos/modules/
  - arceos/api/
  - arceos/ulib/
  - arceos/examples/
- Candidate symbols/modules found:
  - <path>:<line> (<symbol>)
- Why relevant:
  - <capability mapping summary>

## 4) Findings (Severity Ordered)

### Critical
1. [<reviewed-file>:<line>]
- Issue: <duplication or reimplementation description>
- ArceOS candidate: [<arceos-file>:<line>] (`<symbol>`)
- Match rationale: <behavior/constraints/error model/call context>
- Required migration: <what to replace with>
- Impact: <user/business/runtime impact>
- Confidence: High
- Evidence path: <symbol/file/behavior>

### Major
1. [<reviewed-file>:<line>]
- Issue: <partial duplication or abstraction bypass>
- ArceOS candidate: [<arceos-file>:<line>] (`<symbol>`)
- Match rationale: <near-equivalent rationale>
- Recommended migration: <adapter/composition guidance>
- Impact: <scope and potential breakage>
- Confidence: Medium
- Evidence path: <symbol/file/behavior>

### Minor
1. [<reviewed-file>:<line>]
- Issue: <clarity/style/docs>
- Suggestion: <improvement>

## 5) Approval Decision
- Final: APPROVE
- Gate reason:
  - <why approve/request changes>

## 6) Recommended Change List (No Direct Edits)
1. <change 1>
2. <change 2>
3. <change 3>

## 7) Validation & Test Gaps
- Performed checks:
  - compile check context: <pass/fail + note>
  - lint/error context: <pass/fail + note>
- Missing tests:
  - <test gap 1>
  - <test gap 2>

## 8) Open Questions / Assumptions
- Q1: <question>
- Assumption: <assumption>

## 9) Checklist Result
- Reuse gate (ArceOS-first): pass
- Correctness/edge cases: pass
- Concurrency/safety: pass
- Security/robustness: pass
- Performance hotspots: pass
- API compatibility: pass
- Tests coverage and regression risk: pass

## 10) Confidence Summary
- High: 0
- Medium: 0
- Low: 0

## 11) Top 3 Risks
- <risk 1>
- <risk 2>
- <risk 3>

## 12) Residual Risks
- <risk 1>
- <risk 2>
