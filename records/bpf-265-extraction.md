# #265 BPF 状态机迁出前后的双架构验收

RV64、LA64 的 BPF smoke gate 在迁出前后均通过，两个版本也都通过了独立的栈与映射检查。共 20 次客户机采集，全部首次通过。两版均保留了可归属的采样事件、映射关系、部分栈和分层丢失计数。20 份 capture 的最终状态均为 `IncompleteError`，完整会话归因均被禁止。

2026-11-24，在基线 `857371f3` 与迁出后的 `a30dea5f` 上，用同一套 QEMU 客户机负载比较实际输出。`task` 绑定测试线程，时钟周期为 10 ms。`trace` 记录调度切换，`sched` 记录调度事件组，`fault` 记录已完成的缺页处理。补充的 `cpu` 负载在 8 个 vCPU 上分别打开 50 ms、100 ms 时钟源，执行映射变更、已知用户调用链和内核 `mmap`。每次运行使用 8 GiB 内存、16 页输出环和独立的测试镜像副本。

## 事件与丢失计数

箭头表示基线 → 迁出后。记录条数来自实际导出并解码的 capture。`timer_busy` 是系统级计数，记录 IRQ 取样时因采样队列或任务时钟状态繁忙而放弃的快照。

| 架构 | 模式 | 记录条数 | `timer_busy` 增量 | 运行 ID |
| --- | --- | ---: | ---: | --- |
| RV64 | task | 347 → 393 | 115 → 72 | `rkuv8pwa` → `shmjt16k` |
| RV64 | trace | 574 → 574 | 7 → 26 | `5gi7atls` → `6zz_tvfn` |
| RV64 | sched | 1407 → 1423 | 11 → 14 | `jrmsod5g` → `yxq7o3gx` |
| RV64 | fault | 259 → 259 | 17 → 17 | `3ks17xr2` → `ti5jsm7w` |
| RV64 | cpu | 3728 → 3696 | 1226 → 1625 | `2tuem7o5` → `dvebis9m` |
| LA64 | task | 45 → 46 | 7 → 11 | `aunky6b_` → `h5f3nku3` |
| LA64 | trace | 560 → 589 | 3 → 1 | `30jylerd` → `5_nz949m` |
| LA64 | sched | 1666 → 1683 | 13 → 6 | `aq1w8m_d` → `bapra94n` |
| LA64 | fault | 259 → 259 | 89 → 9 | `u_r4ybxi` → `_mxnpafe` |
| LA64 | cpu | 800 → 740 | 699 → 702 | `t670ysur` → `bilyz59u` |

`sched` 在两版均记录到 switch、block、wake 和 enqueue，调度报告的有效配对数在 RV64 为 262 → 263，在 LA64 为 266 → 269。每份 `fault` 报告均有 259 条有效 minor fault，major 和分类未知均为 0。smoke gate 的普通时钟样本使用 `software-v2`，映射日志和栈由下节补充运行验证。

两版每份 RAW 归档的 `transport_lost`、`export_dropped` 均为 0，消费者观察到的 `PERF_RECORD_LOST`、损坏和越界记录也均为 0。系统队列仍有上表所列争用丢失。事件级 `skipped` 在 RV64 `task` 为 1 → 3，`cancelled` 在 RV64 `sched` 为 4 → 5，在 LA64 `sched` 为 13 → 9。校验、加载、挂载失败次数以及进程 RSS、内核分配字节均未提供计数。这些作用域不相加。各版本每个模式各有一次成功运行，条数和争用增量只反映当次采集窗口。

## 映射与调用栈

下表统计补充 `cpu` 运行的 `software_stack_v3` 样本。栈类别取自 analyzer 的 `stack_status`。地址列针对样本的指令指针，ELF 身份校验成功时仍可能缺少函数名。

| 架构与版本 | 完整栈 | 部分栈 | 栈不可用 | 用户映射命中 | 已验证 ELF / 地址未知 | 已验证 ELF 中无函数名 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RV64 基线 | 400 | 331 | 2997 | 442 | 3728 / 0 | 363 |
| RV64 迁出后 | 504 | 293 | 2899 | 446 | 3696 / 0 | 343 |
| LA64 基线 | 122 | 53 | 625 | 84 | 800 / 0 | 41 |
| LA64 迁出后 | 102 | 50 | 588 | 88 | 740 / 0 | 44 |

两版均复核了 16 个 CPU 时钟源、两条已知用户调用链和实际 `mmap` 内核栈。六个负例分别触发无帧指针、读失败、帧循环、返回地址无效、帧未对齐和深度限制。analyzer 将无帧指针归入不可用，guest 的 `SAMPLING STACKS partial` 计数则包含所有未完整终止的栈。

同一补充运行执行了映射、改名、fork、exec、整体重映射和局部重映射。六个工作阶段内，RV64 可按映射日志证实的用户样本为 29/29 → 28/28，LA64 为 28/28 → 21/21。四份映射日志的 `journal_dropped` 均为 0。逐一移除 ELF 或替换为同名不同内容的 ELF 后，六个阶段均保留映射记录，并将地址的 ELF 归属记为未知。

## 运行与复核方法

在两个源码版本上分别执行以下命令。QEMU 为 `11.1.50 (v11.1.0-2112-g2a0ac9c8ac)`，内核工具链为 `rustc 1.101.0-nightly (c1070d693)`。统计覆盖每份 capture 的全部记录，按条数计。不同次运行的记录条数会随调度和采集窗口改变。

```sh
make test APP_FEATURES="qemu bpf-trace"
python3 tests/bpf_smoke/run.py gate
for arch in riscv64 loongarch64; do
    python3 tests/bpf_sampling/run.py guest --arch "$arch" --mode cpu --archive --mappings --stacks --timeout 300
done
```

迁出后的默认 `make test` 和启用 `bpf-trace` 的双架构构建均通过。`2db6e90c` 的 `guest-checks` 内核在 RV64、LA64 各通过六组断言，覆盖 map、程序校验与执行、perf event 控制、link 和采样。`a30dea5f` 更新了验收命令和主机测试。该版 `pulse_syscalls` 通过 232 个单元测试和 2 个集成测试，`bpf` 包通过 3 项。记录工具文档所列的 Rust 组合命令合计通过 518 项（含上述 237 项），Python smoke runner 通过 14 项，recorder 通过 38 项。另用 Cargo 默认并行运行 `pulse_syscalls` 时，两版的 BPF 测试均出现共享 CPU 重入状态串扰，基线出现等待超时，迁出后出现重入计数与 helper 失败断言不符。上述 Rust 通过数采用 #265 指定的 `--test-threads=1`。

## 数据来源

两版的内核构建输入均记录为干净工作树。来源树 SHA-256 前缀为 `a5a20605591b` → `f6d9032361f3`。下表列各架构实际输入与补充采样文件的 SHA-256 前缀，箭头顺序为基线 → 迁出后。

| 架构 | 原始 rootfs（两版共用） | 启动内核 | CPU capture |
| --- | --- | --- | --- |
| RV64 | `efc83112f60d` | `45a42c4a71af` → `a9b1be59e815` | `c71564fd0976` → `03c1f8e3f8fd` |
| LA64 | `ef9a74f8c7fd` | `be3e20616d19` → `4eae9b7d3c5b` | `3a8c56336dff` → `dea666a4aeb9` |

基线原包在 `/tmp/pulse265-baseline/PulseOS/tests/bpf_sampling/runs/`，迁出后原包在 `tests/bpf_sampling/runs/`。运行 ID 是目录名的最后一段，可用 `*-<运行 ID>` 定位。每次运行的 `result.json` 记录实际启动内核、原始 rootfs、注入测试程序后的启动镜像、测试 ELF 和 capture 的 SHA-256。`kernel.provenance.json` 记录构建输入。`archive.json` 和 `analyzer-loss.txt` 提供各作用域的诊断，含映射和栈的运行另存 `mapping-report.json` 和 `stack-evidence.json`。原包保存在本机，保留期限未约定。重新检出的仓库需要重新运行或取得这些原包才能回放。
