---
reviewer: Reviewer
timestamp: 2026-04-16
branch: <branch-name>
commit_range: <start-commit>..<end-commit>
pr_or_task: fs module structure review
decision: REQUEST_CHANGES
---

# 审查日志 (Reviewer Log)

## 1) 审查范围 (Scope)
- 已审查的 Rust 文件:
  - [pulse_syscalls/src/impls/fs/mod.rs](pulse_syscalls/src/impls/fs/mod.rs#L1)
  - [pulse_syscalls/src/impls/fs/common.rs](pulse_syscalls/src/impls/fs/common.rs#L1)
  - [pulse_syscalls/src/impls/fs/path.rs](pulse_syscalls/src/impls/fs/path.rs#L1)
  - [pulse_syscalls/src/impls/fs/meta.rs](pulse_syscalls/src/impls/fs/meta.rs#L1)
  - [pulse_syscalls/src/impls/fs/io.rs](pulse_syscalls/src/impls/fs/io.rs#L1)
  - [pulse_syscalls/src/impls/fs/control.rs](pulse_syscalls/src/impls/fs/control.rs#L1)
- 审查重点:
  - 模块边界是否清晰
  - 是否存在职责混杂/重复抽象
  - 后续扩展时是否容易定位与维护

## 2) 发现的问题 (Findings - 按严重程度排序)

### 主要 (Major)
1. [pulse_syscalls/src/impls/fs/common.rs](pulse_syscalls/src/impls/fs/common.rs#L1)
- 问题 (Issue): `common.rs` 同时承担了用户内存读写、fd/dirfd 解析、权限判断、时间转换、mount 目标缓存等多类职责，已经接近“公共杂物箱”。
- 建议的迁移 (Recommended migration): 拆成更细的辅助模块，例如 `user_memory.rs`、`fd.rs`、`path_resolve.rs`、`permission.rs`、`time.rs`，让 syscall 实现只组合而不承载全部基础设施。
- 影响 (Impact): 新增或修改 syscall 时，依赖面会继续膨胀，阅读成本上升，也更容易把本应隔离的行为耦合到一起。
- 信心指数 (Confidence): 高 (High)
- 证据路径 (Evidence path): `read_user_*`、`get_fd_*`、`context_for_dirfd`、`resolve_location_at_ptr`、`check_faccess_permission`、`MOUNTED_TARGETS`

2. [pulse_syscalls/src/impls/fs/mod.rs](pulse_syscalls/src/impls/fs/mod.rs#L1)
- 问题 (Issue): 当前 `mod.rs` 只做 re-export，没有显式区分“对外 syscall 入口”和“内部辅助函数”，模块边界不够清楚。
- 建议的迁移 (Recommended migration): 仅保留最小入口导出；内部 helper 尽量通过子模块路径使用，避免把所有符号平铺到同一层。
- 影响 (Impact): 外部调用者难以判断哪些 API 是稳定入口，哪些只是实现细节，后续重构时也更容易误用内部函数。
- 信心指数 (Confidence): 中 (Medium)
- 证据路径 (Evidence path): `pub(crate) use common::*;` / `pub(crate) use io::*;` / `pub(crate) use meta::*;` 等整层导出

### 次要 (Minor)
1. [pulse_syscalls/src/impls/fs/path.rs](pulse_syscalls/src/impls/fs/path.rs#L181)
- 问题 (Issue): `sys_getcwd` 与路径创建/删除/挂载等逻辑放在同一个文件里，语义上偏离“路径操作”的单一职责。
- 建议 (Suggestion): 将 cwd / fs_context 相关逻辑单独拆出，和通用 path 操作分组，减少 `path.rs` 的职责跨度。

## 3) 结论 (Decision)
- 最终结论 (Final): REQUEST_CHANGES
- 原因 (Reason):
  - 当前实现能工作，但 `fs` 子模块的职责边界不够清晰，后续维护会持续放大复杂度。
  - 这类组织问题不会立刻造成 ABI 崩溃，但会显著提高新 syscall 接入和 bug 定位成本。

## 4) 需要的修改 (Required Changes)
1. 拆分 `common.rs` 的跨领域辅助逻辑，降低单文件职责密度。
2. 收紧 `fs/mod.rs` 的 re-export 面积，明确哪些符号属于稳定入口。
3. 将 `getcwd` / cwd 状态相关逻辑从 `path.rs` 中分离。

## 5) 测试缺失 (Test Gaps)
- 缺少针对模块边界调整的编译级验证，确保拆分后所有 syscall 入口仍能通过。
- 缺少针对 `getcwd`、`chdir`、`openat`、`statx` 的最小回归用例，验证拆分没有改变语义。

## 6) 遗留风险 (Residual Risks)
- 现有结构还能运行，但继续往 `common.rs` 叠加功能会让后续修复变得更脆弱。
- 如果不先收紧导出面，未来重构很容易把内部 helper 当作稳定 API 继续依赖。