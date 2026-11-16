# 采集与分析操作

命令从仓库根目录执行。示例中的 TID、路径、时间窗必须换成实际值。
先查当前 `--help`；guest 参数还可查 `tools/bpf-record/src/runtime.rs` 的 usage。

## 新采样

先固定源码并明确测试范围。单架构分析只构建该架构；完整交付再跑双架构门禁。
完整日志留在 ignored runs 目录，管道启用 `pipefail`：

```bash
set -o pipefail
mkdir -p tests/bpf_record/runs
BPF_BUILD_LOG=$(mktemp tests/bpf_record/runs/build-XXXXXX.log)
make rv APP_FEATURES="qemu bpf-trace" 2>&1 | tee "$BPF_BUILD_LOG" | tail -30
# LA64 用 make la；双架构用 make test，均保留 APP_FEATURES。
cargo build -p bpf-analyzer
python3 tools/bpf-record/build.py --arch riscv64
```

生产 recorder 在 `tools/bpf-record/build/ARCH/guest/bpf-record`，相邻 `build.json`
记录身份。`--acceptance` 只服务故障注入/控制探针。部署匹配架构的生产 recorder，
并将与实际启动内核匹配的 ELF 放入 guest，例如 `/boot/kernel.elf`；保留 build
provenance 和镜像身份。`--kernel-elf` 会核对运行内核身份，host 不能事后补造它。

先启动用户指定负载，再在 **guest** 中执行需要的一条：

```sh
bpf-record --events cpu --cpus all --period-ns 10000000 \
  --duration-ms 1000 --callchain fp --kernel-elf /boot/kernel.elf \
  --output /tmp/cpu.pbcapture
bpf-record --events task --tid 123 --frequency 99 \
  --duration-ms 1000 --callchain fp --kernel-elf /boot/kernel.elf \
  --output /tmp/task.pbcapture
bpf-record --events sched,fault --cpus all --duration-ms 1000 \
  --kernel-elf /boot/kernel.elf --output /tmp/events.pbcapture
```

recorder 不启动目标、不自动跟随子进程。频率和 period 互斥；请求频率不保证达到。
纯 tracepoint 会话不接受频率/period/FP。当前软件源支持 `--callchain fp|none`，
FP 限额只接受 depth=32、bytes=512；`none` 保留单 IP。重复事件是独立来源。
无 duration 时 SIGINT/SIGTERM 或 task exit 停止；记录实际退出码与停止边界。

工具烟测可用固定 runner，它复制镜像、部署工具/匹配 ELF，按 AGENTS.md 的 QEMU
形状启动，回收原 capture 并校验传输：

```sh
python3 tests/bpf_record/run.py guest --arch riscv64 --suite stacks-cpu
python3 tests/bpf_record/run.py guest --arch loongarch64 --suite smoke
```

只运行与本次问题相关的套件。输出默认位于 `tests/bpf_record/runs/`；自定义
`--run-dir` 必须是尚不存在的新目录。查该目录的 `inputs.json`、`result.json`、
`cases.sh` 和 capture，使用实际文件名。runner 没有任意负载 `--command` 参数；
业务采样需驱动实际负载，必要时复用其镜像/串口传输逻辑编写窄范围 harness。

手工采样要在 guest 退出前传回原文件，核对 `RECORD SAVED ... sha256=`。
参考 `tests/bpf_record/capture.py`、runner 的 `verify_saved_hash` 和 fixture dump
协议，检查偏移、长度、CRC、SHA。`snapshot=on` 后不能从底层镜像假定取回输出。

## 分析已有 capture

把 `BPF_CAPTURE`、`BPF_ANALYSIS` 设置为实际输入和 ignored runs 下的新分析目录。
目录可先创建，原 capture 不覆盖。保存原文件 SHA、生产者基线和来源类型。

```bash
target/debug/bpf-analyzer "$BPF_CAPTURE" --loss
target/debug/bpf-analyzer "$BPF_CAPTURE" --json > "$BPF_ANALYSIS/session.json"
target/debug/bpf-analyzer "$BPF_CAPTURE" --sched-report --json > "$BPF_ANALYSIS/sched.json"
target/debug/bpf-analyzer "$BPF_CAPTURE" --fault-report --json > "$BPF_ANALYSIS/fault.json"
```

仅执行所需报告。`--loss` 输出文本，不能与 `--json` 混成一个 JSON 文件。
sched/fault/mapping 报告每次选一种，`--sched-report` 不接受 `--mode`；
`--artifact-manifest` 独立调用，不能附加 Query。
当前仅接受 capture v6；历史版本拒绝不等于数据损坏，也不应重编码冒充当前运行。

先从 JSON 读取身份和时间，再声明相交的 Query。以下是 Bash 示例；按问题添加
`--task`、`--pid`、`--tid`、`--cpu`、半开时间窗或唯一闭合 `--phase`。
无筛选参数选全部记录，当前没有 `--source` CLI。

```bash
BPF_QUERY=(--mode user --weight period)
target/debug/bpf-analyzer "$BPF_CAPTURE" "${BPF_QUERY[@]}" --table > "$BPF_ANALYSIS/selected.table"
target/debug/bpf-analyzer "$BPF_CAPTURE" "${BPF_QUERY[@]}" --json > "$BPF_ANALYSIS/selected.json"
target/debug/bpf-analyzer "$BPF_CAPTURE" "${BPF_QUERY[@]}" \
  --oncpu "$BPF_ANALYSIS/selected.folded" --timeline "$BPF_ANALYSIS/timeline.json"
```

## 函数热点与火焰图

读[导出契约](../../../../docs/perf-export.md)。`BPF_BUNDLE` 指向采集对应的 artifact
目录。已有 runner bundle 先核验；缺少文件时只从实际 kernel/rootfs/目标构建收集
候选，包括必要 loader/共享库。匹配 capture 的身份后才会写入 `artifacts/<sha>.elf`：

```bash
python3 tools/bpf-record/collect.py "$BPF_CAPTURE" --bundle "$BPF_BUNDLE" \
  --candidate /path/to/actual-boot-kernel.elf --candidate /path/to/actual-target.elf \
  --analyzer target/debug/bpf-analyzer
target/debug/bpf-analyzer "$BPF_CAPTURE" --mapping-report --bundle "$BPF_BUNDLE"
target/debug/bpf-analyzer "$BPF_CAPTURE" "${BPF_QUERY[@]}" \
  --bundle "$BPF_BUNDLE" --perf-data "$BPF_ANALYSIS/perf.data"
python3 scripts/perf_pipeline.py "$BPF_ANALYSIS/perf.data" --bundle "$BPF_BUNDLE" \
  --perf /path/to/installed/perf --flamegraph /path/to/pinned/FlameGraph \
  --output "$BPF_ANALYSIS/native"
```

`native` 必须尚不存在。工具路径显式提供，流水线不下载工具；FlameGraph 固定版本
及内容校验以导出契约为准。检查实际 perf report/script/buildid-list、链顺序、
逐源 counts/period、folded 权重和 SVG 单位。缺身份、mutation interval 或错 ELF
拒绝时，报告原因及受影响范围；明确筛选出的成功子集不能代表整个会话。
两种权重需要比较时用各自输出目录重跑同一 Query，仅改 `--weight`。

## 完整生产流程验收

仅在任务需要完整能力证明时，阅读 [ACCEPTANCE](../../../../tests/bpf_record/ACCEPTANCE.md)
和 [QUALIFICATION](../../../../tests/bpf_record/QUALIFICATION.md)。固定源码后跑默认和
BPF-enabled `make test`，然后执行完整矩阵：

```sh
python3 tests/bpf_record/acceptance.py --plan
python3 tests/bpf_record/acceptance.py --output tests/bpf_record/runs/DATE-TASK \
  --analyzer target/debug/bpf-analyzer
python3 tests/bpf_record/qualify.py tests/bpf_record/runs/DATE-TASK \
  --analyzer target/debug/bpf-analyzer --perf /path/to/installed/perf \
  --flamegraph /path/to/pinned/FlameGraph --output tests/bpf_record/runs/DATE-TASK-native
```

两个输出目录均须新建。`--suite full` 是 acceptance 控制套件，不代替完整生产矩阵；
`tests/bpf_sampling/run.py` 是专项回归，也不代替通用 recorder 门禁。
需证明具体控制/来源/负例时再运行相应 host 或专项 guest 回归，记录实际执行范围。
