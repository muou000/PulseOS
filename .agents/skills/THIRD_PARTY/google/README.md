# google/rust-skills（第三方来源说明）

| 项目 | 内容 |
| --- | --- |
| 上游仓库 | <https://github.com/google/rust-skills> |
| 导入 commit | `7b55b5222d73bb251f3b0360d41cdb23ae94d2a8`（2026-10-22） |
| 许可证 | Apache-2.0，Copyright 2026 Google LLC，全文见同目录 [LICENSE](./LICENSE) |
| 导入日期 | 2026-10-24 |

## 保留内容

保留上游关于 unsafe Rust 审核与规范的两个 skill 目录，平铺到 `.agents/skills/<name>/`：

- `unsafe-rust-review`：基于形式化证明义务的严格 Unsafe Rust 审查与 `# Safety` / `// SAFETY:` 文档编写规范。
  - 保留内容：`SKILL.md`。
- `unsafe-rust-review-experimental`：源自 `google/zerocopy` 的高严密性 Unsafe Rust 形式化审计、设计与验证套件。
  - 依据上游 `maintainers/stage-runtime.sh` 规范，仅保留运行时所需包：
    - `SKILL.md`
    - `agents/openai.yaml`
    - `assets/`（`tcb-audit-log-template.md`、`unsafe-code-audit-report-template.md`）
    - `references/`（`abstraction-design.md`、`api-boundaries-and-evolution.md`、`audit-reporting.md`、`configurations-and-generated-code.md`、`proof-obligations.md`、`tcb-and-evidence.md`）

## 相对上游的修改

- 删除了仓库级内容：`.git`、`CONTRIBUTING.md`、根目录 `README.md`。
- `unsafe-rust-review`：
  - 目录名由上游的 `unsafe_rust_review` 重命名为与 `SKILL.md` frontmatter `name` 一致的 `unsafe-rust-review`。
  - 删除了仅用于评测的 `EVAL.yml`、`testcases/` 以及上游背景说明 `README.md`（相关背景保留在下方说明）。
- `unsafe-rust-review-experimental`：
  - 目录名由上游的 `unsafe_rust_review_experimental` 重命名为与 `SKILL.md` frontmatter `name` 一致的 `unsafe-rust-review-experimental`。
  - 删除了仅用于评估和维护的 `evals/`、`maintainers/` 以及非运行时说明文档 `README.md`、`UPSTREAM.md`。
- 已保留的运行时文件内容**均保持上游原文，未作任何改动**。

> 以后如果修改了某个 skill 的文件内容，请把修改补充到本节。Apache-2.0 许可证要求保留
> 版权声明和许可声明，所以不要删除 `LICENSE`。

## 其他署名与背景说明

### unsafe-rust-review

- **主要作者**：@joshlf 与 AI agent 合作开发。
- **扩展与优化**：@manishearth 根据 Google 内部大规模 unsafe Rust review 经验补充了规则、策略对齐和操作指导。
- **理论与实践基础**：
  - [The Rust Reference](https://doc.rust-lang.org/reference/)
  - Rust 标准库文档与 [The Rustonomicon](https://doc.rust-lang.org/nomicon/)
  - [The Unsafe Code Guidelines](https://rust-lang.github.io/unsafe-code-guidelines/)
  - Rust RFCs 及 [Clippy documentation](https://rust-lang.github.io/rust-clippy/master/index.html)
  - 结合了开源仓库 [google/rust-crate-audits](https://github.com/google/rust-crate-audits) 中记录的真实 bug 模式与安全性发现。

### unsafe-rust-review-experimental

- 移植自 `google/zerocopy`（commit `2dad389b030e9268d6645ac0bf0626b867e96068`）。

## 同步上游

```bash
git clone https://github.com/google/rust-skills /tmp/google-rust-skills
git -C /tmp/google-rust-skills diff 7b55b5222d73bb251f3b0360d41cdb23ae94d2a8 HEAD
```

