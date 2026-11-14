# 软件采样生产接线与真实 guest 验证（#190）

日期：2026-11-14。变更基线 `1e518236e2882d89fe9721840755c332f8f77181`；实现、测试和本记录随同一次变更交付。此记录证明软件 timer / tracepoint → BPF → Perf Buffer 消费链，不证明完整调用栈、物理 PMU 或 capture 归档（#191）已经完成。

## 实现契约

- RV64/LA64 的架构 trap 入口在正常 IRQ 分发之前调用只读 `IRQ_OBSERVER`，保留被中断 PC/privilege mode。平台 device IRQ ABI 没有改变；linkme observer sections 明确放入链接脚本。
- IRQ 仅复制标量到预分配 128 槽 FIFO，`try_lock` 失败/队列满均丢弃并计数，不执行 BPF、不分配、不跨回调保留 Thread/TrapFrame 引用。成功入队的同一任务快照在迁移前完成发布，因此不会按 CPU 编号消费而颠倒 task-clock；独立 CPU/任务之间不承诺全局时间排序。共享 FIFO 的争用成本必须在后续性能门禁中测量。
- worker 每轮最多处理 128 个 timer 快照和每 CPU 16 个 tracepoint context；复制出队后释放锁/IRQ guard，再运行 verifier 允许的有界解释器。当前用 1ms worker sleep 提供消费机会，不宣称采样精度优于实际平台 timer 或保证请求频率。
- CPU_CLOCK 使用观察时间；TASK_CLOCK 使用所选 Thread 的 scheduler enter/leave 运行累计。控制面读者使用仅保存 IRQ 状态的短 guard，防止持时钟锁时被 timer 调度转出自锁。事件绑定创建时的稳定 task ID，exec 重绑 TID 不会将旧事件改指向另一线程；FD 保持所选 Thread clock，退出后不会误读复用的数字 ID。
- 软件样本 v2 是 64 字节显式小端编码：原 48 字节 prefix 保留，`ip:u64@48`、`mode:u32@56`（kernel=1/user=2）、`version:u32@60=2`。旧 `addr` 继续是 data address，未偷换成 PC。模型用的旧 `sample_at` 仍是合成检查入口，生产 worker 使用冻结的 v2 记录。
- 每个观察 PC 最多产生一次执行；跨过多个 period 的其余周期记为 `skipped_periods`，不复制当前 PC 冒充过去样本。period 重设从控制操作所选时钟重新起算。
- enable/disable/reset/period/attach/detach/任务绑定使用共享 observation generation。旧排队记录不交给新 attachment；锁内已接受的旧 invocation 可完成，绝不在解锁后重取新程序。generation 饱和时拒绝交付，不回绕。
- tracepoint wire context 不变；私有队列 envelope 增加 generation（96 bytes，不是用户 ABI）。生产的 common PID/TID 与 common.task_id 的主体对应，wake 的主体是 waker、target 保留在 payload。多订阅者 refcount 与 mask 更新串行化。
- Perf Event Array 只接受对应 CPU 的 BPF_OUTPUT sink；在 Map 变更前拒绝 source event 或 CPU 错配，阻止 source→program→map→source 引用环。Link/dup/final-close 生命周期分别验证。
- 尚未实现的 exclude_user/kernel/hv/idle 明确返回 EOPNOTSUPP；不无声接受后混入被排除的模式。其余 Linux BPF 限制仍遵循 fixed-context tier。

## 测试与范围

先在旧内核观察失败：v2 程序在 offset48 被 verifier 拒绝；独立旧 tracepoint 程序成功加载/attach，但实际 workload 后事件数为零。这些 RED 记录详见 `tests/bpf_sampling/README.md`。新的 guest 不生成 capture、不合成样本，使用实际 mmap ring 的 RAW 字节作为唯一正例来源。

通过的构建：

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
make test 2>&1 | tail -30
```

前者验证运行路径；后者验证 feature-off 的 RV64/LA64 构建。运行时保存前者的内核副本，未用后者冒充采样支持。host 验证包括 syscall/runtime（226 tests）、schema/context（19+1 tests）、线程时钟（2 tests）、既有 capture/analyzer suites，以及 Python guest evidence validator（11 tests）。新增 runtime tests 覆盖真实执行环境字段、周期、跨 CPU scope、稳定任务身份、stale epoch、budget/helper/reentry failure、多订阅者，以及使用公开 output sink 暂停旧 invocation 时并发 detach/reattach 的确切程序归属。直接构造的预算/非法 helper 模型用例不表示生产 verifier 接受这些程序。

复现正式运行：

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
for arch in riscv64 loongarch64; do
    for mode in task cpu trace block wake; do
        python3 tests/bpf_sampling/run.py guest --arch "$arch" --mode "$mode"
    done
done
```

harness 每次重建 payload，并复制内核与架构镜像，只注入镜像副本；QEMU 使用 8 GiB、8 CPU、snapshot disk 和 UTC RTC，完整命令、输入 hash、原始日志与验证结果写入各 run 目录。运行期间不需要修改原镜像。

## 最终十组结果

全部使用同一份当前 guest 源文件。`lost` 仅表示消费到的 PERF_RECORD_LOST；它不证明 IRQ queue busy/full、跳过周期或所有分层错误均为零。分层统计的持久化与完整性判断仍由 #191 实现。

| 架构 | 模式 | 实际记录/样本 | 日志目录 |
| --- | --- | --- | --- |
| loongarch64 | block | `BLOCK_RESULT PASS blocks=1200 subjects=12 subjects_capped=0 target_contexts=459 lost=0 source=kernel_ring` | `loongarch64-block-20261114-224316-m47285uf` |
| loongarch64 | cpu | `RESULT PASS mode=cpu samples=75 foreign=476 a=34 b=40 lost=0 source=kernel_ring` | `loongarch64-cpu-20261114-224618-z2osrgzc` |
| loongarch64 | task | `RESULT PASS mode=task samples=66 foreign=0 a=30 b=34 lost=0 source=kernel_ring` | `loongarch64-task-20261114-224613-zuhaiagh` |
| loongarch64 | trace | `TRACE_RESULT PASS sched=2401 subjects=20 subjects_capped=0 target_contexts=462 lost=0 source=kernel_ring` | `loongarch64-trace-20261114-224625-x7iwnjyx` |
| loongarch64 | wake | `WAKE_RESULT PASS wakes=1173 subjects=21 subjects_capped=0 target_contexts=3 lost=0 source=kernel_ring` | `loongarch64-wake-20261114-224320-drlfsi5b` |
| riscv64 | block | `BLOCK_RESULT PASS blocks=1103 subjects=12 subjects_capped=0 target_contexts=424 lost=0 source=kernel_ring` | `riscv64-block-20261114-224316-hamzmd8a` |
| riscv64 | cpu | `RESULT PASS mode=cpu samples=70 foreign=483 a=34 b=35 lost=0 source=kernel_ring` | `riscv64-cpu-20261114-224618-5yssowtn` |
| riscv64 | task | `RESULT PASS mode=task samples=66 foreign=0 a=34 b=32 lost=0 source=kernel_ring` | `riscv64-task-20261114-224613-ufbirqjr` |
| riscv64 | trace | `TRACE_RESULT PASS sched=2221 subjects=20 subjects_capped=0 target_contexts=446 lost=0 source=kernel_ring` | `riscv64-trace-20261114-224623-vzjz43xy` |
| riscv64 | wake | `WAKE_RESULT PASS wakes=1119 subjects=21 subjects_capped=0 target_contexts=6 lost=0 source=kernel_ring` | `riscv64-wake-20261114-224320-yuhdrzn6` |

TASK_CLOCK 检查两段汇编函数符号范围内的真实用户 IP，以及 100ms 睡眠前后实际 CPU counter。CPU_CLOCK 统计全部 source CPU，同时分别保留目标进程和 foreign 记录；停止门禁检查两者总数。trace/block/wake 检查各自 ID、版本、长度、源 CPU、task/sequence 字段与真实睡眠/唤醒/调度负载，不能用 CPU sample 标记替代。

两个额外 FD 会话分别验证：关闭 target FD 后 Link 仍保活，detach 后停止；ioctl attach 后 dup 保活，最后 FD close 后停止。允许已接受 invocation 的有限尾部排空，然后继续 workload 时记录不得增加。所有模式还验证两个无效 sink 更新返回 EINVAL，且原 Map slot 完整保留。

下列摘要把关键原始输出和文件身份保留在版本库；完整 run 文件是本地可复现实验产物，未把虚拟机磁盘和内核二进制加入 Git。

```json
{
  "guest_source_sha256": "ca75905d0fc8cccd2f2692dab0f9d256ae51af23df9d06cadd3ebee72d298ebc",
  "kernel_build": {
    "base_commit": "1e518236e2882d89fe9721840755c332f8f77181",
    "tracked_diff_sha256": "b0f29a5168d1c116b6c4b6be668d316faa09ddc0bcaf8e3228046ad82fb8e3e3",
    "new_files": {
      "pulse_core/src/bpf/sampling.rs": "a7325bb002972ace68d9892c8065164710c82cab09b0af160b80dfcd6198f9c6",
      "pulse_core/src/task/sampling_clock.rs": "07b081ced55fa78803bb70f349e1bdf572ba09b34de0c9518ee7bf1c7ce6e80f",
      "crates/pulse_bpf_schema/tests/perf_sample_tests.rs": "ead288b11a2ffe9b702ad8bbb978da02b282ddb4b14ca2e57a35c6ccea07eea9",
      "pulse_syscalls/tests/sampling_clock.rs": "0ce99f3d8a6b90a4eb68791f67444ac6fe88a62de637adfe75b25d970d7d9e0d"
    },
    "kernels": {
      "kernel-rv": "8b942693d3d7c8170a12d486e3202065571e4f791189541e64fca650c099190e",
      "kernel-la": "22aba550c1f3dacdbef1c305dbf8c19efeea721b9a46915c24bb3d73f5cd8182"
    }
  },
  "qemu_rv": "QEMU emulator version 11.1.50 (v11.1.0-2112-g2a0ac9c8ac)",
  "qemu_la": "QEMU emulator version 11.1.50 (v11.1.0-2112-g2a0ac9c8ac)",
  "rustc": "rustc 1.101.0-nightly (c1070d693 2026-09-28)",
  "runs": [
    {
      "arch": "loongarch64",
      "mode": "block",
      "run": "tests/bpf_sampling/runs/loongarch64-block-20261114-224316-m47285uf",
      "kernel_sha256": "22aba550c1f3dacdbef1c305dbf8c19efeea721b9a46915c24bb3d73f5cd8182",
      "payload_sha256": "0eca46a2d7efaea3f8afa37b44112503aaff8ff9fff16c509d1140d1277b5238",
      "image_sha256": "be6db16bd4d97af342844bc4653760b50a3d5b4dfb66e75d13c8163927ecd040",
      "guest_log_sha256": "781b50d4e5ec27e799b51eebb6123676150ff923ee5b4b82df417f60725071b7",
      "result_json_sha256": "63a09e1a29c3202286988e2c8caba9fc3dcd895ed05c4f3bd68196645b9682f3",
      "evidence": [
        "SAMPLING START version=2 mode=block cpus=8 pid=52 tid=52",
        "SAMPLING RANGES a=0x4000d0..0x4000dc b=0x4000e0..0x4000f0",
        "SAMPLING SINK_REJECT mode=block source_errno=-22 cpu_errno=-22 preserved=1",
        "SAMPLING BLOCK_OBSERVED blocks=1200 subjects=12 subjects_capped=0 target_contexts=459 lost=0 cpu_mask=0xff",
        "SAMPLING PASS disabled mode=block records=1200",
        "SAMPLING PASS detached mode=block records=1200",
        "SAMPLING BLOCK_RESULT PASS blocks=1200 subjects=12 subjects_capped=0 target_contexts=459 lost=0 source=kernel_ring"
      ]
    },
    {
      "arch": "loongarch64",
      "mode": "cpu",
      "run": "tests/bpf_sampling/runs/loongarch64-cpu-20261114-224618-z2osrgzc",
      "kernel_sha256": "22aba550c1f3dacdbef1c305dbf8c19efeea721b9a46915c24bb3d73f5cd8182",
      "payload_sha256": "c80232d2dd083ff5b4d1b926ec5ec0db087cf0c87e3d8d39fe2665b39f7dfa0e",
      "image_sha256": "be6db16bd4d97af342844bc4653760b50a3d5b4dfb66e75d13c8163927ecd040",
      "guest_log_sha256": "e8fed9dbaa40b9c75b0fedbe8d29ac7c7c446ceb3952d7d10e58580a7cd53ed7",
      "result_json_sha256": "e995c83b060356431f04464c4a90643e9597ea781c6418b1f61feb31055e277b",
      "evidence": [
        "SAMPLING START version=2 mode=cpu cpus=8 pid=52 tid=52",
        "SAMPLING RANGES a=0x4000d0..0x4000dc b=0x4000e0..0x4000f0",
        "SAMPLING SINK_REJECT mode=cpu source_errno=-22 cpu_errno=-22 preserved=1",
        "SAMPLING OBSERVED mode=cpu samples=75 foreign=476 a=34 b=40 lost=0 cpu_mask=0xff",
        "SAMPLING PASS disabled mode=cpu records=551",
        "SAMPLING PASS detached mode=cpu records=551",
        "SAMPLING RESULT PASS mode=cpu samples=75 foreign=476 a=34 b=40 lost=0 source=kernel_ring"
      ]
    },
    {
      "arch": "loongarch64",
      "mode": "task",
      "run": "tests/bpf_sampling/runs/loongarch64-task-20261114-224613-zuhaiagh",
      "kernel_sha256": "22aba550c1f3dacdbef1c305dbf8c19efeea721b9a46915c24bb3d73f5cd8182",
      "payload_sha256": "546534e891f7c8bb0f43572d433de88d4888d9142c24650949289fb0630bf3ab",
      "image_sha256": "be6db16bd4d97af342844bc4653760b50a3d5b4dfb66e75d13c8163927ecd040",
      "guest_log_sha256": "8158a2275ab935472129bcd6593f1d2b54b67f1a0b441395fadba2e3a6c1b354",
      "result_json_sha256": "20c70cf9bd079390c484c2d41103b043039a3ddb9124a1a12eee9c1f2db9af18",
      "evidence": [
        "SAMPLING START version=2 mode=task cpus=8 pid=52 tid=52",
        "SAMPLING RANGES a=0x4000d0..0x4000dc b=0x4000e0..0x4000f0",
        "SAMPLING SINK_REJECT mode=task source_errno=-22 cpu_errno=-22 preserved=1",
        "SAMPLING TASK_SLEEP before_ns=21600 after_ns=1185100 wall_ns=100794090",
        "SAMPLING OBSERVED mode=task samples=66 foreign=0 a=30 b=34 lost=0 cpu_mask=0x7e",
        "SAMPLING PASS disabled mode=task records=66",
        "SAMPLING PASS detached mode=task records=66",
        "SAMPLING FD_LIFECYCLE kind=link_target_close alive=23 loop_a=23 settled=23 after_stop=23 lost=0",
        "SAMPLING FD_LIFECYCLE kind=ioctl_dup_final_close alive=24 loop_a=24 settled=24 after_stop=24 lost=0",
        "SAMPLING RESULT PASS mode=task samples=66 foreign=0 a=30 b=34 lost=0 source=kernel_ring"
      ]
    },
    {
      "arch": "loongarch64",
      "mode": "trace",
      "run": "tests/bpf_sampling/runs/loongarch64-trace-20261114-224625-x7iwnjyx",
      "kernel_sha256": "22aba550c1f3dacdbef1c305dbf8c19efeea721b9a46915c24bb3d73f5cd8182",
      "payload_sha256": "b966e1acc020c5966c0c0dd284b0e4135a1e4adaa99839e2be7e1157da9d3415",
      "image_sha256": "be6db16bd4d97af342844bc4653760b50a3d5b4dfb66e75d13c8163927ecd040",
      "guest_log_sha256": "183ec33745924b4edee2a3fb894667f3008d2aa4aebe14283ecf877f89075871",
      "result_json_sha256": "4b9a5777c41e6894c32d6e4ace29c64a81b7f86893ff5fdbb47651b42be68fb7",
      "evidence": [
        "SAMPLING START version=2 mode=trace cpus=8 pid=52 tid=52",
        "SAMPLING RANGES a=0x4000d0..0x4000dc b=0x4000e0..0x4000f0",
        "SAMPLING SINK_REJECT mode=trace source_errno=-22 cpu_errno=-22 preserved=1",
        "SAMPLING TRACE_OBSERVED sched=2401 subjects=20 subjects_capped=0 target_contexts=462 lost=0 cpu_mask=0xff",
        "SAMPLING PASS disabled mode=trace records=2401",
        "SAMPLING PASS detached mode=trace records=2401",
        "SAMPLING TRACE_RESULT PASS sched=2401 subjects=20 subjects_capped=0 target_contexts=462 lost=0 source=kernel_ring"
      ]
    },
    {
      "arch": "loongarch64",
      "mode": "wake",
      "run": "tests/bpf_sampling/runs/loongarch64-wake-20261114-224320-drlfsi5b",
      "kernel_sha256": "22aba550c1f3dacdbef1c305dbf8c19efeea721b9a46915c24bb3d73f5cd8182",
      "payload_sha256": "1047a757026b09c1c76d541506971f828cd2a36c31d784912ee6742832d4eb79",
      "image_sha256": "be6db16bd4d97af342844bc4653760b50a3d5b4dfb66e75d13c8163927ecd040",
      "guest_log_sha256": "f1565384a41485ea14aecc8e4b57deee30306c0e7e7544fe92fe7b1faad113a3",
      "result_json_sha256": "280c817d86d4fad622a74d194c36b11f25ccce355a78be52dc7e49c80d439244",
      "evidence": [
        "SAMPLING START version=2 mode=wake cpus=8 pid=52 tid=52",
        "SAMPLING RANGES a=0x4000d0..0x4000dc b=0x4000e0..0x4000f0",
        "SAMPLING SINK_REJECT mode=wake source_errno=-22 cpu_errno=-22 preserved=1",
        "SAMPLING WAKE_OBSERVED wakes=1173 subjects=21 subjects_capped=0 target_contexts=3 lost=0 cpu_mask=0xff",
        "SAMPLING PASS disabled mode=wake records=1173",
        "SAMPLING PASS detached mode=wake records=1173",
        "SAMPLING WAKE_RESULT PASS wakes=1173 subjects=21 subjects_capped=0 target_contexts=3 lost=0 source=kernel_ring"
      ]
    },
    {
      "arch": "riscv64",
      "mode": "block",
      "run": "tests/bpf_sampling/runs/riscv64-block-20261114-224316-hamzmd8a",
      "kernel_sha256": "8b942693d3d7c8170a12d486e3202065571e4f791189541e64fca650c099190e",
      "payload_sha256": "80af87feae86c327acc9ebc20128701d0f1e0d25610d183803bf9e4d81c92d65",
      "image_sha256": "ac636610f014325eb0ab3f56decf3f719850064e0191e2974e409da8022e150e",
      "guest_log_sha256": "cc3194e3cbe08c081d4a653a2da8740dd25f202e7e2d24b8e886779c69f14b0a",
      "result_json_sha256": "2a237d554cf94abc015672bf3ba61b97afafcbe535709e1d41c27280d36303e6",
      "evidence": [
        "SAMPLING START version=2 mode=block cpus=8 pid=46 tid=46",
        "SAMPLING RANGES a=0x400110..0x40011a b=0x400120..0x40012c",
        "SAMPLING SINK_REJECT mode=block source_errno=-22 cpu_errno=-22 preserved=1",
        "SAMPLING BLOCK_OBSERVED blocks=1103 subjects=12 subjects_capped=0 target_contexts=424 lost=0 cpu_mask=0xff",
        "SAMPLING PASS disabled mode=block records=1103",
        "SAMPLING PASS detached mode=block records=1103",
        "SAMPLING BLOCK_RESULT PASS blocks=1103 subjects=12 subjects_capped=0 target_contexts=424 lost=0 source=kernel_ring"
      ]
    },
    {
      "arch": "riscv64",
      "mode": "cpu",
      "run": "tests/bpf_sampling/runs/riscv64-cpu-20261114-224618-5yssowtn",
      "kernel_sha256": "8b942693d3d7c8170a12d486e3202065571e4f791189541e64fca650c099190e",
      "payload_sha256": "a9cfd80cabdeae2f87545055641cdfdaec6296c4870162b1a72d1594d09bcc6a",
      "image_sha256": "ac636610f014325eb0ab3f56decf3f719850064e0191e2974e409da8022e150e",
      "guest_log_sha256": "ee1df1eefc6893213eaeaf8a4c1fe7cf6c8ebb747463df735bdec827f0a1d6bf",
      "result_json_sha256": "2478e10ce07bb73253a76fee004798f89dbe0910adedef9c78f3dba39b44f358",
      "evidence": [
        "SAMPLING START version=2 mode=cpu cpus=8 pid=46 tid=46",
        "SAMPLING RANGES a=0x400110..0x40011a b=0x400120..0x40012c",
        "SAMPLING SINK_REJECT mode=cpu source_errno=-22 cpu_errno=-22 preserved=1",
        "SAMPLING OBSERVED mode=cpu samples=70 foreign=483 a=34 b=35 lost=0 cpu_mask=0xff",
        "SAMPLING PASS disabled mode=cpu records=553",
        "SAMPLING PASS detached mode=cpu records=553",
        "SAMPLING RESULT PASS mode=cpu samples=70 foreign=483 a=34 b=35 lost=0 source=kernel_ring"
      ]
    },
    {
      "arch": "riscv64",
      "mode": "task",
      "run": "tests/bpf_sampling/runs/riscv64-task-20261114-224613-ufbirqjr",
      "kernel_sha256": "8b942693d3d7c8170a12d486e3202065571e4f791189541e64fca650c099190e",
      "payload_sha256": "16885bc42f76a409a7871ee6ce7f5a3100ce63b9dc288de77f917a92811c68ae",
      "image_sha256": "ac636610f014325eb0ab3f56decf3f719850064e0191e2974e409da8022e150e",
      "guest_log_sha256": "e7bb721fdc3d07ae048b928363431c9143e21d264b9bf29916936e70fee99b8d",
      "result_json_sha256": "ee345741dd81dd39c03a493d41aa8dd9864c7c69d1fc50fb85df1daa9f73398d",
      "evidence": [
        "SAMPLING START version=2 mode=task cpus=8 pid=46 tid=46",
        "SAMPLING RANGES a=0x400110..0x40011a b=0x400120..0x40012c",
        "SAMPLING SINK_REJECT mode=task source_errno=-22 cpu_errno=-22 preserved=1",
        "SAMPLING TASK_SLEEP before_ns=25600 after_ns=1007900 wall_ns=100775600",
        "SAMPLING OBSERVED mode=task samples=66 foreign=0 a=34 b=32 lost=0 cpu_mask=0x8",
        "SAMPLING PASS disabled mode=task records=66",
        "SAMPLING PASS detached mode=task records=66",
        "SAMPLING FD_LIFECYCLE kind=link_target_close alive=24 loop_a=24 settled=24 after_stop=24 lost=0",
        "SAMPLING FD_LIFECYCLE kind=ioctl_dup_final_close alive=24 loop_a=24 settled=24 after_stop=24 lost=0",
        "SAMPLING RESULT PASS mode=task samples=66 foreign=0 a=34 b=32 lost=0 source=kernel_ring"
      ]
    },
    {
      "arch": "riscv64",
      "mode": "trace",
      "run": "tests/bpf_sampling/runs/riscv64-trace-20261114-224623-vzjz43xy",
      "kernel_sha256": "8b942693d3d7c8170a12d486e3202065571e4f791189541e64fca650c099190e",
      "payload_sha256": "705b33fef0f8e47bb3980c5fa322d50cfe09ccb481f4bfbdcfa93c3106358e14",
      "image_sha256": "ac636610f014325eb0ab3f56decf3f719850064e0191e2974e409da8022e150e",
      "guest_log_sha256": "1d5ab00c3699c76c7fbc0970cbc848c0b93148c65b353c33ba0040f1a4a4e053",
      "result_json_sha256": "efae5aa66d186aa6109a7a5ea8ba039c439aae514f0c40f24a1710714ad5643c",
      "evidence": [
        "SAMPLING START version=2 mode=trace cpus=8 pid=46 tid=46",
        "SAMPLING RANGES a=0x400110..0x40011a b=0x400120..0x40012c",
        "SAMPLING SINK_REJECT mode=trace source_errno=-22 cpu_errno=-22 preserved=1",
        "SAMPLING TRACE_OBSERVED sched=2221 subjects=20 subjects_capped=0 target_contexts=446 lost=0 cpu_mask=0xff",
        "SAMPLING PASS disabled mode=trace records=2221",
        "SAMPLING PASS detached mode=trace records=2221",
        "SAMPLING TRACE_RESULT PASS sched=2221 subjects=20 subjects_capped=0 target_contexts=446 lost=0 source=kernel_ring"
      ]
    },
    {
      "arch": "riscv64",
      "mode": "wake",
      "run": "tests/bpf_sampling/runs/riscv64-wake-20261114-224320-yuhdrzn6",
      "kernel_sha256": "8b942693d3d7c8170a12d486e3202065571e4f791189541e64fca650c099190e",
      "payload_sha256": "651b2768d4cbe823448c9d4b0ab3a76872e9c3a9e4b797475e80a7220ad7fd9d",
      "image_sha256": "ac636610f014325eb0ab3f56decf3f719850064e0191e2974e409da8022e150e",
      "guest_log_sha256": "071ff022b5e61f6782858d0ab0b84ffc657fbf9e17db6f5e7bde938e7d88b17f",
      "result_json_sha256": "6b343d896d3b21856834487de1a58a320c79bbf03a23183e2cf2a96b68587bf4",
      "evidence": [
        "SAMPLING START version=2 mode=wake cpus=8 pid=46 tid=46",
        "SAMPLING RANGES a=0x400110..0x40011a b=0x400120..0x40012c",
        "SAMPLING SINK_REJECT mode=wake source_errno=-22 cpu_errno=-22 preserved=1",
        "SAMPLING WAKE_OBSERVED wakes=1119 subjects=21 subjects_capped=0 target_contexts=6 lost=0 cpu_mask=0xff",
        "SAMPLING PASS disabled mode=wake records=1119",
        "SAMPLING PASS detached mode=wake records=1119",
        "SAMPLING WAKE_RESULT PASS wakes=1119 subjects=21 subjects_capped=0 target_contexts=6 lost=0 source=kernel_ring"
      ]
    }
  ]
}
```

## 并发审查与剩余边界

本轮新增 observer/FIFO/时钟代码没有新增 unsafe 块。现有 tracepoint 字节化与 UnsafeCell queue 增加 generation 后仍为无 padding 的固定整数/字节布局；producer head Release / consumer Acquire、consumer tail Release / producer Acquire 未削弱。独立审阅纠正了按 CPU 排空误序、TID 重用、IRQ 打断时钟读取自锁及输出引用环。

审阅依赖的既有前提是：RV64/LA64 trap assembly 提供有效 TrapFrame 且关闭 IRQ；scheduler 同一 task 同时只有一个 CPU owner；spin::Mutex 的互斥/Acquire-Release 契约；kernel_guard 的 IrqSave 仅恢复 IRQ、不触发 preempt callback；linkme typed sections 和平台单调时钟。引用的语义可在本地工具链 Rust core/Reference 文档及锁依赖中复核。测试不是整个仓库或所有平台的普遍 soundness 证明。

没有完成：真实 capture 归档和分层 counter 导出、完整用户/内核 FP 链、no-fault stack reader、perf.data writer、PMU driver、板卡运行、调度延迟统计或缺页分析。旧 `tests/bpf_smoke` 静态 capture 不能因本接线通过而升级为真实归因证据；其误把 CPU_CLOCK 当输出 sink 的用法现在被拒绝，应在 #191 改为真实 BPF_OUTPUT 消费流程。
