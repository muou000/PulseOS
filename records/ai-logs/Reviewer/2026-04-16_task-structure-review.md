---
reviewer: Reviewer
timestamp: 2026-04-16
branch: <branch-name>
commit_range: <start-commit>..<end-commit>
pr_or_task: task module structure review
decision: REQUEST_CHANGES
---

# 审查日志 (Reviewer Log)

## 1) 审查范围 (Scope)
- 已审查的 Rust 文件:
  - [pulse_syscalls/src/impls/task/mod.rs](pulse_syscalls/src/impls/task/mod.rs#L1)
  - [pulse_syscalls/src/impls/task/common.rs](pulse_syscalls/src/impls/task/common.rs#L1)
  - [pulse_syscalls/src/impls/task/clone.rs](pulse_syscalls/src/impls/task/clone.rs#L1)
  - [pulse_syscalls/src/impls/task/exec.rs](pulse_syscalls/src/impls/task/exec.rs#L1)
  - [pulse_syscalls/src/impls/task/process.rs](pulse_syscalls/src/impls/task/process.rs#L1)
  - [pulse_syscalls/src/impls/task/exit.rs](pulse_syscalls/src/impls/task/exit.rs#L1)
  - [pulse_syscalls/src/impls/task/wait.rs](pulse_syscalls/src/impls/task/wait.rs#L1)
  - [pulse_syscalls/src/impls/task/user.rs](pulse_syscalls/src/impls/task/user.rs#L1)
- 审查重点:
  - 模块边界是否清晰
  - 是否存在职责混杂/重复抽象
  - 后续扩展时是否容易定位与维护

## 2) 发现的问题 (Findings - 按严重程度排序)

### 主要 (Major)
1. [pulse_syscalls/src/impls/task/mod.rs](pulse_syscalls/src/impls/task/mod.rs#L1)
- 问题 (Issue): `mod.rs` 仍承担门面、导出和部分共享辅助的组织职责，虽然 helper 已下沉到 `common.rs`，但模块边界仍偏“平铺”，不够明确。
- 建议 (Recommended migration): 继续收紧 `mod.rs` 的公开面，只保留 syscall 入口级导出；内部辅助尽量保持模块私有，避免 task 目录继续向“总入口”收敛。
- 影响 (Impact): 未来新增 syscall 时，容易把实现细节继续塞回门面层，长期会削弱目录结构的可读性。
- 信心指数 (Confidence): 中 (Medium)
- 证据路径 (Evidence path): `mod common;`、`pub use clone::*;`、`pub use user::*;`、`pub use exec::*;` 等平铺导出

2. [pulse_syscalls/src/impls/task/common.rs](pulse_syscalls/src/impls/task/common.rs#L1)
- 问题 (Issue): `common.rs` 已成为 task 子系统的共享 helper 汇聚点，后续若继续增加错误映射、参数解析、状态缓存等逻辑，仍有演化成“公共杂物箱”的风险。
- 建议 (Recommended migration): 维持 helper 模块的瘦身策略，优先按职责切分为用户态读写、状态/上下文、参数解析等更小单元，而不是继续向 common.rs 追加新函数。
- 影响 (Impact): 当前可维护性已改善，但如果继续叠加功能，结构问题会重新出现。
- 信心指数 (Confidence): 高 (High)
- 证据路径 (Evidence path): `read_user_bytes`、`read_user_cstring`、`read_user_string_array`、`write_user_i32`

### 次要 (Minor)
1. [pulse_syscalls/src/impls/task/process.rs](pulse_syscalls/src/impls/task/process.rs#L1)
- 问题 (Issue): `sys_get*` 系列仍全部聚集在同一文件里，函数很短但数量较多，和 `user.rs` 这类凭据管理逻辑相比，语义上仍有进一步分组空间。
- 建议 (Suggestion): 如果后续继续扩展 task getter 类 syscall，可考虑将只读查询类接口和凭据变更类接口拆成更明确的子分组。

## 3) 结论 (Decision)
- 最终结论 (Final): REQUEST_CHANGES
- 原因 (Reason):
  - 本轮改动已比初始状态更干净，但 task 子系统的组织结构仍偏集中，边界还可以继续收紧。
  - 这类问题不会立刻影响运行，但会在 syscall 数量继续增长时放大维护成本。

## 4) 需要的修改 (Required Changes)
1. 继续收紧 [pulse_syscalls/src/impls/task/mod.rs](pulse_syscalls/src/impls/task/mod.rs) 的导出面，只保留稳定 syscall 入口。
2. 控制 [pulse_syscalls/src/impls/task/common.rs](pulse_syscalls/src/impls/task/common.rs) 的职责密度，避免继续扩大为泛化工具箱。
3. 如后续新增 task 相关 syscall，再按职责继续拆分子模块，而不是回填到现有门面。

## 5) 测试缺失 (Test Gaps)
- 缺少针对 task 模块拆分后的编译级回归验证说明，尤其是 `execve`、`wait4`、`get*` 接口的连通性。
- 缺少针对 helper 下沉后，模块路径与可见性边界是否稳定的验证记录。

## 6) 遗留风险 (Residual Risks)
- 目前结构已经可用，但如果继续把新 helper 塞进 `common.rs`，问题会重新积累。
- 导出面如果不持续收紧，task 子系统很容易再次退化成“大而全”的入口层。