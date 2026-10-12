# mattpocock/skills（第三方来源说明）

| 项目 | 内容 |
| --- | --- |
| 上游仓库 | <https://github.com/mattpocock/skills> |
| 导入 commit | `49dd158d1076134a641b33efb035946536778336`（2026-10-09） |
| 许可证 | MIT，Copyright (c) 2026 Matt Pocock，全文见同目录 [LICENSE](./LICENSE) |
| 导入日期 | 2026-10-12 |

## 保留内容

只保留上游 `skills/engineering/` 和 `skills/productivity/` 下的 skill 目录。每个目录里的
`SKILL.md`、参考文档、脚本和 `agents/openai.yaml` 都按原样保留，然后平铺到
`.agents/skills/<name>/`。

- engineering：`ask-matt`、`code-review`、`codebase-design`、`diagnosing-bugs`、
  `domain-modeling`、`grill-with-docs`、`implement`、
  `improve-codebase-architecture`、`pr`、`prototype`、`research`、`retro`、
  `setup-matt-pocock-skills`、`tdd`、`to-spec`、`to-tickets`、`triage`、`wayfinder`、`wizard`
- productivity：`grill-me`、`grilling`、`handoff`、`teach`、`to-questionnaire`、
  `wait-what`、`writing-for-agents`

## 相对上游的修改

- 删除了仓库级内容：`.git`、`.github`、`.changeset`、`.claude-plugin`、`.out-of-scope`、
  `.agents`、`docs/`、`scripts/`、`package*.json`、`README.md`、`CHANGELOG.md`、
  `AGENTS.md`、`CLAUDE.md`、`GLOSSARY.md`、`SCOPE.md`、`.gitignore`。
- 删除了 `in-progress`、`misc`、`deprecated` 三个分类，以及各分类的 `README.md`。
- 目录从 `skills/<分类>/<name>/` 改成 `.agents/skills/<name>/`，方便 agent 发现。
- **删除 `implement-spec`**：移除多 subagent 并发编排技能，统一使用逐票 `implement` + 手动会话模式。
- **修改 `to-tickets`**：改为强模型专用；拆分工单时要求在工单中包含符号级实施计划（`Implementation plan`）和可检查事实锚点（`Anchors`）；限定发布至 GitHub 并打上 `model:weak` 标签；采用 GitHub 原生阻塞依赖；每票 PR 独立合入 `main`。
- **修改 `implement`**：适配弱模型；开始前验证票的 anchors；按计划以 TDD 实现并打开合入 `main` 的 PR；实现后对同父 spec 的未关闭兄弟票执行漂移检查（`Drift check`）；遇到阻塞或无法推进时开 `needs-replan` / `needs-strong` 升级工单；支持 `needs-fix` 修复循环。
- **修改 `ask-matt`**：更新主流程为分层协作模式（强模型 grill/spec/tickets/review/replan + 弱模型 implement/drift check），移除 `implement-spec`，增加 `review-ticket` 与 `replan`。
- **新增 PulseOS 自建技能**：`replan`（强模型处理重规划与卡住升级）和 `review-ticket`（强模型逐票 PR 双轴评审与合并），详见 `docs/agents/ticket-workflow.md`。

## 其他署名

`pr/CREDITS.md` 是上游自带的署名文件，说明 `pr` skill 的 Summary 部分改编自
[Dex Horthy](https://github.com/dexhorthy) 的 `show-me` skill
（[humanlayer/humanlayer](https://github.com/humanlayer/humanlayer)）。请随 `pr` 一起保留这个文件。

## 同步上游

```bash
git clone https://github.com/mattpocock/skills /tmp/mattpocock-skills
git -C /tmp/mattpocock-skills diff 49dd158d1076134a641b33efb035946536778336 HEAD -- skills/engineering skills/productivity LICENSE
```

按需把变更拷回对应的 `.agents/skills/<name>/`，然后更新本文件里的 commit 和保留清单。

