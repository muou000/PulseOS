# 生产 bpf-record 到 perf / 函数火焰图验收（#213）

日期：2026-11-16。实现基线：`c51e43db`（已合并 #210–#212）。
测试边界由 [验收定义](../tests/bpf_record/ACCEPTANCE.md) 和
[固定 Query](../tests/bpf_record/QUALIFICATION.md) 规定。

## 修复的实际缺口

- 旧 guest runner 对所有用例默认构建 acceptance。正向用例现在构建、校验并运行
  `--features guest`；只有故障注入、dup/close 和 loaded-detached 控制探针使用
  acceptance。独立 workload 先启动，再把实际 TID 交给生产 CLI。
- 旧 mixed 门禁只证明重复类型；现在还要求同 CPU、同 period 的不同来源实际产出，
  并要求实际 task-clock 样本，不能用 CPU 或 tracepoint 记录代替。
- 原生 perf 把 RV64 用户函数显示成 `$xrv64...` / `.L...` 标签。现有 visibility-only
  符号视图扩展到已核验的用户 ELF；原 ELF、PT_LOAD 字节和全部函数符号不改动。
  旧脚本对同一原始 capture / ELF 的真实失败与新脚本通过输出单独归档。
  perf 6.8.12 不解码这些 Rust v0 名字时保留原 `STT_FUNC` 拼写；oracle 将函数
  名、范围和真实保存的调用链地址对应，不修改 perf 或 FlameGraph 输出。
- RV 已安装 shell 的加载器身份已在 guest capture 中，host 候选列表漏取 ELF。
  新 runner 显式收集 `/lib/ld-musl-riscv64.so.1`。本轮原文件先保留失败证据，再从
  哈希不变的实际 boot image 补收匹配 SHA/GNU build-id 的文件；新增补收报告，
  不覆盖原 capture、原 collection 报告或运行索引。
- LA 已安装 bash 的部分共享库没有 guest SHA。全用户态严格导出作为真实负例
  保留，不能由同名 host ELF 补身份。频繁 exec 的 dd 工作流还会命中真实 mapping
  mutation interval；该严格拒绝也保留。另用已启动的长期 dd 进程和其实际 TID
  采集内核态调用链，验证已安装程序的正向流程。

## 证据语义

`e2e.py` 从原 capture v6 字节独立解码 typed source、绑定、栈、journal 和 artifact，
与同一个 Query 的 table/JSON/folded、原生 perf 全字段、函数调用链和 SVG 核对。
每条记录检查 logical source、IP、PID/TID、稳定 task identity、时间、CPU、period、
mode/context marker 和调用链顺序。每个正向 Query 都检查 samples / period_ns 两种
权重，以及缺失/错误符号包、缺/坏 trailer、损坏/移除记录六种派生负例。

单次完整矩阵为每架构 18 组：13 组生产 CLI，5 组 acceptance 控制/开销探针。
本轮先保存原 34 组矩阵，再用两组 `installed-io` 补充门禁；两份原索引保持不变。
`qualify.py --additional` 要求它们的并集恰好包含完整双架构契约，逐份核对原 plan、
index、日志、结果和文件哈希，不能跳过失败的架构或重复用例。

数值 PID/TID 重用由 adversarial host / native-perf 测试验证；本轮 guest 不强行
耗尽 PID 空间。地址重用、fork/exec、非 leader exec、rename、pgoff=4096、
remap/unmap/exit 来自真实运行。duration、SIGINT/SIGTERM、目标退出、dup/close、
第二 load/attach 失败、snapshot/journal 失败、输出失败、容量丢弃、停止后无增长和
资源回收保留原始控制日志。未完成的栈、journal gap 和分层 loss 均不升级为完整。

## 三阶段实测

QEMU 11.1.50 (`v11.1.0-2112-g2a0ac9c8ac`)，每 guest 八 CPU / 8 GiB，按 AGENTS.md
启动。两架构测量串行，期间没有其他 QEMU、编译或 native-perf 重负载。
相同外部 workload、迭代定义和时长；CPU source period=10 ms。
这是包含准备/结束余量的整个 workload 测量，每阶段一次，不是稳态开销或统计结论。

| 架构 | 阶段 | wall ms | iterations | iterations/s | 相对 baseline |
| --- | --- | ---: | ---: | ---: | ---: |
| RV64 | baseline | 2500.243 | 5381 | 2152.191 | 0% |
| RV64 | loaded-detached | 2500.257 | 5376 | 2150.179 | -0.093% |
| RV64 | attached | 2500.518 | 5262 | 2104.364 | -2.222% |
| LA64 | baseline | 2500.212 | 11199 | 4479.220 | 0% |
| LA64 | loaded-detached | 2500.091 | 11800 | 4719.827 | +5.372% |
| LA64 | attached | 2500.147 | 10576 | 4230.151 | -5.561% |

loaded-detached / attached 各持有 35 / 43 个 FD、557056 字节 ring 映射、16 个
registered events，结束后均回到先前资源数量；512 MiB heap 是虚拟地址预留，
不是 RSS，观察到的 rounded-allocation 峰值为 12584448 字节。
attached 的 system `timer_busy` 为 RV 21 / LA 29；各 source 的 skipped 为
RV 2/0/1/0/0/0/0/1、LA 0/1/0/0/1/0/0/0，RV source 5 另有 cancelled=1。
这些层次不能相加成样本总损失。transport/export/consumer/journal 对应计数为零，
不消除其它 partial 原因，也不据此声称无损或精确 CPU 利用率。

## 完整复现

```sh
set -o pipefail
make test 2>&1 | tail -30
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
cargo build -p bpf-analyzer
python3 tests/bpf_record/acceptance.py \
  --output tests/bpf_record/runs/213-new --analyzer target/debug/bpf-analyzer
python3 tests/bpf_record/qualify.py tests/bpf_record/runs/213-new \
  --analyzer target/debug/bpf-analyzer --perf /usr/local/bin/perf \
  --flamegraph /path/to/pinned/FlameGraph --output /tmp/213-new-native
```

FlameGraph 固定 `41fee1f99f9276008b7cd112fca19dc3ea84ac32` 并校验脚本内容。
两架构 rootfs、实际 boot image、kernel/recorder/fixture ELF、工具版本/SHA 和命令
分别保存在输入、构建和 consumer 报告。`acceptance.py --plan` 可查看全部用例。
独立控制回归继续运行：

```sh
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode sched --archive
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode sched --archive
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode fault --archive --fault-classes --timeout 240
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode fault --archive --fault-classes --timeout 240
```

这些专项运行只证明原 scheduler/fault 功能没有回归，不代替生产 recorder 流程。
本轮还分别执行 `--mode task --archive --fault zero-producer|zero-consumer`，要求
真实零生产/零消费被拒绝；proc 快照 CRC、source observed/delivered 和零帧计数单独
核对。所有原始失败日志保留，不制造可被当成成功的 capture。

## 剩余边界

原始 finalized capture 保留 partial；strict-negative 不计作成功 perf/SVG。
LA 动态库缺 guest 身份、mutation interval 中的样本仍不可严格符号化；成功的
显式 Query 不抹去被排除上下文的未知或丢失。物理 PMU/板卡、x86/aarch64 guest、
未验证 fault backend、分配追踪、精确 busy/idle 不属于本次软件采样验收。
这也不是 ADR-0005 的具名上游 libbpf-bootstrap profile 兼容声明。

## 本轮结果与审查

36 组 guest 运行全部通过，保存 **60 份原始 finalized capture、94842 条记录**，
以及两份实际写失败的 1024-byte 前缀。60 份 capture 均为 `IncompleteError`。
最终 qualification 完成 **21 组正向 Query、42 份原生 perf / SVG**，另有一组
LA 用户态严格拒绝；每组正向 Query 的六种派生负例均按正常错误退出及预期诊断核对。

| 显式 Query | RV64 samples | LA64 samples |
| --- | ---: | ---: |
| 独立 CPU user / kernel | 96 / 681 | 101 / 686 |
| 独立 task user | 98 | 94 |
| 混合源 user / kernel | 26 / 1608 | 54 / 1588 |
| 已安装 shell user | 98 | 严格拒绝，缺 guest SHA |
| mapping 目标 stable task user | 160 | 159 |
| 已启动 dd 的 task kernel | 101 | 119 |
| nonleader exec user | 128（两 TID：95 / 33） | 128（两 TID：98 / 30） |

user fixture 实际最大栈深两架构均为 6；mixed 内核栈最大深度 RV 15 / LA 13，
dd 内核栈两者均为 10。未知和截断链仍逐条保留。所有 period 原值、逐源条数和
权重可在归档的 `native/qualification.json` 和各 Query 的 `e2e.json` 中重放。

新的 scheduler 回归逐字段核对 RV 1386 / LA 1675 条 RAW，分别得到 259 / 267
个有效 blocked/wake 实例。两架构 fault 回归各 265 条记录，冷目标/冷邻页各有
8 个真实完成扇区，匿名/热页/COW/缓存目标无对应数据页读取。零生产的 source
observed/delivered 均为 0；零消费时两者分别为 RV 372/337、LA 54/41，但保留帧
均为 0，门禁拒绝成功归档。最初回归汇总脚本只匹配 `no real samples`，未匹配
正确的 `empty capture` 错误而停止；原日志保留，随后按原始零计数/CRC 和明确的
空 capture 诊断验证，没有重跑或冒充已通过的正向运行。

主机常规 Rust 515、原生 perf Rust 7、sampling Python 110、recorder Python 38
项通过。默认/BPF-enabled 双架构门禁在源码固定后复验；完整日志、实际输入和
文件索引见 [归档说明](../tests/bpf_record/evidence/213/README.md)。

### Standards

初审发现两个 P2 和一个代码异味：任意非零退出可误算成负例通过；硬编码 partial
会拒绝真实 Complete；匿名位置元组降低来源/period/调用链核对可读性。已改为
权限错误立即停止、正常错误码与语义诊断精确匹配、与原 status 比较，并使用
`CPUFields`。复审 **0 项剩余发现**。

### Spec

初审发现一个 P2：自有 folded 仅核对总权重，同权重假调用链可通过。现从原字节
独立构造每栈身份、mode、termination、反向 PC 顺序及权重的 multiset，精确比较。
复审另独立验证 42 份实际 folded 通过、42 份同总权重伪栈被拒绝；**0 项剩余发现**。

两轴发现均已处理，最终 Query 门禁在修复后重新运行。Spec 复审确认动态库身份
边界和原矩阵加独立扩展的方式没有将拒绝伪装为成功，也没有删掉必需覆盖。

解包后的全量 `verify.py` 回放还发现 installed-I/O 分支在 JSON report 初始化前
使用它；同一原 capture 重现 `UnboundLocalError` 后，将检查移到当前 report
解码/校验之后。36 组可移植功能回放随后全部通过，两轴再次确认无剩余问题。
该检查顺序修复不改变原 guest 或 native 导出数据，红绿输出保存在 validation 归档。
