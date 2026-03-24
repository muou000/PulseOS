---
reviewer: Reviewer
timestamp: YYYY-MM-DD HH:MM UTC+8
branch: <branch-name>
commit_range: <start-commit>..<end-commit>
pr_or_task: <PR# or task id>
decision: APPROVE # APPROVE | REQUEST_CHANGES
---

# Reviewer Log

## 1) Scope
- Reviewed Rust files:
  - <path>
- Review focus:
  - ArceOS-first reuse
  - correctness/safety/security/performance (as applicable)

## 2) Findings (Severity Ordered)

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

## 3) Decision
- Final: APPROVE
- Reason:
  - <why approve or request changes>

## 4) Required Changes
1. <required change 1>
2. <required change 2>

## 5) Test Gaps
- <missing test 1>
- <missing test 2>

## 6) Residual Risks
- <risk 1>
- <risk 2>
