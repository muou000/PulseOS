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
  `domain-modeling`、`grill-with-docs`、`implement`、`implement-spec`、
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
- 已保留的 skill 文件内容**没有改动**。

> 以后如果修改了某个 skill 的文件内容，请把修改补充到本节。MIT 许可证要求保留
> 版权声明和许可声明，所以不要删除 `LICENSE`。

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

