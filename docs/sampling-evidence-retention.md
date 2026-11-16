# 采样证据保留策略

2026-11-16 起，Git 保留采样验收的关键结果、复现代码和必要的最小回归输入。
完整运行产物放在被忽略的 `tests/bpf_record/runs/`、`tests/bpf_sampling/runs/`
或独立产物存储中，不再随每次运行提交原始数据包。

## 保留什么

- 验收范围、通过/失败结论、Query、样本数、权重、分层 loss、partial/unknown
  和未覆盖边界，以及性能改善或退化和测量环境。
- 源码版本、实际 kernel/image/工具身份与 SHA-256、原始归档及成员索引、
  历史独立回放结果。哈希只能标识字节，不能恢复已移除的数据。
- 复现命令、runner、独立 oracle，以及自动测试确实依赖的小型 fixture。
  fixture 必须注明来源和用途；历史测试输入不是新 guest 运行证据。

## 不常驻 Git 的产物

完整 RAW/串口日志、capture、perf.data、批量 SVG、重复的 kernel/用户 ELF、
镜像和包含这些内容的压缩包。需要分享完整可回放实验时，将包放在独立产物存储，
在验收记录中写明获取位置、保留期限和 SHA；没有保存位置时明确说明不可再回放。
不把运行数据改名为 fixture 来绕过这一规则。

现有打包、哈希验证和回放工具仍可用于本地或外部保存的完整产物。
新运行按 [recorder 说明](../tests/bpf_record/README.md) 和
[sampling 说明](../tests/bpf_sampling/README.md) 生成；不能通过放宽 oracle、
伪造完整状态或省略必需负例来减少产物。

## 本次历史数据清理

从当前树移除 63 个历史包，共 219,009,303 bytes（208.86 MiB）；清单和原 SHA
见 [清理索引](../records/sampling-evidence-retention.json)。保留原 `index.json`、
回放摘要、验收记录；#213 的关键消费者结果、构建身份和测量环境单独提取到
[`key-results/`](../tests/bpf_record/evidence/213/key-results/)。
三个自动测试共享约 361 KiB 的[最小原字节 fixture](../tests/bpf_record/fixtures/README.md)。

历史 README 中的包内容和回放命令描述当时的完整归档。当前检出仅凭摘要和哈希
无法执行全量回放；旧命令需要另行持有完整原包。验收是否通过与原始字节是否继续
常驻 Git 是不同事实，不能把历史的验证结果说成本次重新运行 QEMU。

## 历史重写

维护者随后明确授权提交并重写历史。已从 92 个相关提交中移除上述 63 个路径的
全部 64 个历史 blob 版本，并同步 main 和仍引用原始包的 fix/161 分支。
无关早期历史和 `rootfs-base-20260929` 标签身份保留，三个旧工作树的源码改动、
暂存状态和三个 stash 均保留。当前清理提交的文件树在过滤前后完全相同。

全新远端克隆的 Git 对象文件从约 386.0 MiB 降至 182.0 MiB（减少 52.8%）。
范围、相同口径的字节统计和校验见[重写记录](../records/sampling-history-rewrite.json)，
旧新提交对应见[提交映射](../records/sampling-history-commit-map.json)。
历史构建 provenance 中的旧 SHA 保留其原始含义，不改写成新提交来冒充原构建身份。

其他已有克隆建议在保存本地工作后重新克隆，避免把旧历史合并推回。
GitHub 的旧 PR 引用、缓存及服务端回收可能继续保留旧对象；上述体积是实际重新
克隆的对象文件大小，不表示 GitHub 服务端立即物理删除全部缓存。
