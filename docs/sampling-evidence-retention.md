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

本次清理不重写已发布 Git 历史。旧提交中的大对象仍会影响完整克隆体积；
当前树变小并阻止新增归档，不代表 `.git` 立即缩小。历史重写需要单独协调分支、
标签和协作者克隆，不能用普通删除提交或 `git gc` 消除仍被历史引用的对象。
