# 报告与提交

先读[采样证据保留策略](../../../../docs/sampling-evidence-retention.md)。报告建议用
`records/bpf-<问题或issue>-<日期>.md`，关键统计可另存相邻小 JSON。
使用[模板](../assets/report-template.md)，按实际问题裁剪，不用历史验收数字填新报告。

## 报告需要支持哪些判断

- **事实来源**：分别标记新 guest 采样、历史原字节重放、合成 fixture；写出实际
  架构、负载/线程、生产或 acceptance variant，避免把测试负载说成业务表现。
- **复现身份**：源码 commit、dirty/source-input 身份、实际 boot kernel/image、
  recorder/analyzer/相关 ELF 和工具版本/SHA；命令包含事件、period/频率、时长、
  CPU、容量、调用栈和降级请求。未知值直接记 unknown。
- **选择与结果**：完整 Query、单位、实际记录数及所选范围、逐源样本/period，
  回答问题的热点/链、调度或 fault 统计；会话质量和 Query 覆盖度分开记录。
- **诊断**：原 capture status、partial/unknown/unavailable/栈终止原因、各层 loss，
  以及缺端点、歧义、censored、拒绝的 Query 和原因。未执行的检查明确注明。
- **可重复性**：复现命令、独立核对结果和原始产物的获取位置、保留期限、SHA。
  没有完整原包时明确“摘要不能完整回放”；已退役 evidence 的索引不能冒充原件。

做性能对比时列出相同负载/迭代定义、各阶段 wall/throughput/资源、次数和环境干扰。
同时记录改善和退化；单次观测不能支持统计显著性或稳态开销结论。
历史构建 provenance 的旧 SHA 保留原义，需要时查
[`sampling-history-commit-map.json`](../../../../records/sampling-history-commit-map.json)。

## 提交范围

提交精简报告、关键统计/身份/哈希索引和必要复现代码。完整 RAW、串口日志、capture、
perf.data、批量 SVG、ELF/image 和全量压缩包留在 ignored runs 或外部产物存储。
JSON 也可能是大体量逐记录原始输出，先提取关键统计，不能只按扩展名决定保留。

只有自动测试确实依赖时才保留最小 fixture：记来源、原成员 SHA、用途与局限，
验证原断言仍成立；可参考[现有 fixture](../../../../tests/bpf_record/fixtures/README.md)。
普通运行包不能改名为 fixture。报告本身不授权外部上传或删除用户现有运行目录。

授权包含提交时，先检查已有工作区/暂存区，再显式暂存本任务路径，例如
`git add -- records/bpf-example.md records/bpf-example-summary.json`（替换为实际文件）。
保留无关修改和既有暂存内容，确保本次提交只包含获准范围。检查暂存 blob 而非工作区大小：

```sh
git diff --cached --check
git diff --cached --stat
python3 - <<'PY'
import os
import subprocess

names = subprocess.check_output([
    "git", "diff", "--cached", "--name-only", "--diff-filter=ACMRT", "-z",
]).split(b"\0")
for raw in filter(None, names):
    path = os.fsdecode(raw)
    size = int(subprocess.check_output(["git", "cat-file", "-s", ":" + path]))
    print(f"{size:>10}  {path!r}")
PY
```

逐项判断内容是否必要，不设置未经约定的固定体积阈值。忽略规则是防误加护栏，
不使用强制添加来规避保留策略。最终说明已生成、已暂存、已提交、已推送中的实际状态。
