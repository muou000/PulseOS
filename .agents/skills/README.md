# PulseOS Agent Skills

本目录存放 PulseOS 工作区使用的 agent skills，是所有工具共用的唯一一份 skill 源文件。

## 工具兼容

| 工具 | 项目级 skill 读取路径 | 本仓库的接入方式 |
| --- | --- | --- |
| Antigravity | `.agents/skills/` | 直接读取 |
| Codex | `.agents/skills/` | 直接读取 |
| Cursor | `.cursor/skills/` | 软链接 `.cursor/skills -> ../.agents/skills`（部分新版虽支持探测 `.agents`，软链接可确保完全兼容） |
| Claude Code | `.claude/skills/` | 软链接 `.claude/skills -> ../.agents/skills` |
| ZCode | `.zcode/skills/` | 软链接 `.zcode/skills -> ../.agents/skills` |

- 只在本目录增删或修改 skill，不要往 `.cursor/skills`、`.claude/skills` 或 `.zcode/skills` 里写文件，因为它们只是软链接。
- 软链接以相对路径提交到 git。在 Windows 上检出时需要开启 `core.symlinks=true` 和开发者模式，否则链接会变成纯文本文件。
- ZCode 修改 skill 后，需要到「设置 → Skills」点击刷新。

## 目录约定

```text
.agents/skills/
├── README.md                 # 本索引
├── <skill-name>/             # 每个 skill 一个目录，统一平铺，不要嵌套分类
│   ├── SKILL.md              # 必需：YAML frontmatter（name、description）+ 指令正文
│   ├── *.md / scripts/       # 可选：SKILL.md 引用的参考文档和脚本
│   └── agents/openai.yaml    # 可选：Codex 调用策略
└── THIRD_PARTY/<来源>/        # 第三方 skill 的 LICENSE 和来源说明（这里不放 SKILL.md）
```

- 目录名必须和 `SKILL.md` frontmatter 里的 `name` 一致，并且全局唯一。
- 不要用多级目录给 skill 分类，分类只写在下方索引表的「来源」和「分类」列。
- 新增或删除 skill 后，同步更新下方索引表。

## 添加 skill

- **自建 skill**：新建 `<name>/SKILL.md`，在索引表里把「来源」写成 `PulseOS`。
- **第三方 skill**：
  1. 把 skill 目录平铺拷贝到 `<name>/`。
  2. 在 `THIRD_PARTY/<来源>/` 放入上游许可证原文，以及记录上游地址、commit、保留清单和修改说明的 `README.md`。
  3. 在索引表里登记这些 skill。
  4. 拷贝前先确认许可证允许再分发。
- **修改第三方 skill**：可以直接修改，但要在对应的 `THIRD_PARTY/<来源>/README.md` 里写明修改内容。

## 索引

「调用方式」列中，`用户` 表示 frontmatter 设置了 `disable-model-invocation: true`，只在用户显式
调用时使用；`模型` 表示 agent 可以按需自动选用。

| Skill | 来源 | 分类 | 调用方式 |
| --- | --- | --- | --- |
| [ask-matt](./ask-matt/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [code-review](./code-review/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 模型 |
| [codebase-design](./codebase-design/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 模型 |
| [diagnosing-bugs](./diagnosing-bugs/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 模型 |
| [domain-modeling](./domain-modeling/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 模型 |
| [grill-with-docs](./grill-with-docs/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [implement](./implement/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [implement-spec](./implement-spec/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [improve-codebase-architecture](./improve-codebase-architecture/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [pr](./pr/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 模型 |
| [prototype](./prototype/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 模型 |
| [research](./research/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 模型 |
| [retro](./retro/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [setup-matt-pocock-skills](./setup-matt-pocock-skills/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [tdd](./tdd/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 模型 |
| [to-spec](./to-spec/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [to-tickets](./to-tickets/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [triage](./triage/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [unsafe-rust-review](./unsafe-rust-review/SKILL.md) | [google](./THIRD_PARTY/google/README.md) | engineering | 模型 |
| [unsafe-rust-review-experimental](./unsafe-rust-review-experimental/SKILL.md) | [google](./THIRD_PARTY/google/README.md) | engineering | 模型 |
| [wayfinder](./wayfinder/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 用户 |
| [wizard](./wizard/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | engineering | 模型 |
| [grill-me](./grill-me/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | productivity | 用户 |
| [grilling](./grilling/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | productivity | 模型 |
| [handoff](./handoff/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | productivity | 用户 |
| [teach](./teach/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | productivity | 用户 |
| [to-questionnaire](./to-questionnaire/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | productivity | 用户 |
| [wait-what](./wait-what/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | productivity | 用户 |
| [writing-for-agents](./writing-for-agents/SKILL.md) | [mattpocock](./THIRD_PARTY/mattpocock/README.md) | productivity | 模型 |

## 许可证

本目录中的第三方 skill 按各自上游许可证分发，详见 `THIRD_PARTY/` 下对应的子目录。

