---
reviewer: Reviewer
timestamp: YYYY-MM-DD
branch: <branch-name>
commit_range: <start-commit>..<end-commit>
pr_or_task: <PR# or task id>
decision: APPROVE # APPROVE | REQUEST_CHANGES
---

# 审查日志 (Reviewer Log)

## 1) 审查范围 (Scope)
- 已审查的 Rust 文件:
  - <path>
- 审查重点:
  - 优先复用 ArceOS (ArceOS-first reuse)
  - 正确性/安全性/性能等 (如适用)

## 2) 发现的问题 (Findings - 按严重程度排序)

### 严重 (Critical)
1. [<reviewed-file>:<line>]
- 问题 (Issue): <描述重复或重新实现的内容>
- ArceOS 替代方案: [<arceos-file>:<line>] (`<symbol>`)
- 匹配理由 (Match rationale): <行为/约束/错误模型/调用上下文>
- 需要的迁移 (Required migration): <替换的具体内容>
- 影响 (Impact): <对用户/业务/运行时的影响>
- 信心指数 (Confidence): 高 (High)
- 证据路径 (Evidence path): <符号/文件/行为>

### 主要 (Major)
1. [<reviewed-file>:<line>]
- 问题 (Issue): <部分重复或未正确使用抽象>
- ArceOS 替代方案: [<arceos-file>:<line>] (`<symbol>`)
- 匹配理由 (Match rationale): <极其相似或等价的理由>
- 建议的迁移 (Recommended migration): <适配器/组合相关的建议>
- 影响 (Impact): <范围与潜在破损>
- 信心指数 (Confidence): 中 (Medium)
- 证据路径 (Evidence path): <符号/文件/行为>

### 次要 (Minor)
1. [<reviewed-file>:<line>]
- 问题 (Issue): <清晰度/代码风格/文档等问题>
- 建议 (Suggestion): <改进方法>

## 3) 结论 (Decision)
- 最终结论 (Final): APPROVE (或者 REQUEST_CHANGES)
- 原因 (Reason):
  - <为什么同意或要求修改的理由>

## 4) 需要的修改 (Required Changes)
1. <需要进行的修改 1>
2. <需要进行的修改 2>

## 5) 测试缺失 (Test Gaps)
- <缺失的测试 1>
- <缺失的测试 2>

## 6) 遗留风险 (Residual Risks)
- <风险 1>
- <风险 2>
