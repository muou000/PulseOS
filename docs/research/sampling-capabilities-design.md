# PulseOS 采样能力探测与 BPF 移植边界草案

状态：**Draft，供 #183 / #186 决策，不是已批准或已实现的能力承诺。**

日期：2026-11-14。PulseOS 审计基线为 `758fa083dde3d9c7a36e2f9f5b9c8266439cb889`；本轮仅独立修正了 Linux 硬件事件编号，见 §7。RISC-V 依据 SBI v2.0，Linux 参考实现固定 v6.12；QEMU 的源码示例固定 v9.2.0，不能代表所有 QEMU 版本。LoongArch 官方手册固定提交 `e0d6592229d9e00e512bd28b688a7f20b171714f`。

本草案的建议是：第一阶段完成真实软件 period 采样和准确的能力报告；PMU 的“硬件存在”“能计数”“能溢出采样”“驱动可用”分别记录。Linux 形状的 `perf_event_open` 不静默改变请求语义；只有用户工具的显式自动模式可以在会话开始时选择软件替代，并保存原因。BPF 第一阶段声明 PulseOS 固定 context 的兼容层，不能把标准 eBPF 字节码与部分 Linux syscall 编号等同于任意 Linux BPF 程序兼容。

## 1. 先验证的接口和场景

实施前先定义以下验收，不以寄存器字段解码通过代替真实采样：

| 可观察接口 | 应覆盖 | 不能单独证明 |
| --- | --- | --- |
| 能力快照（只读、版本化） | 未初始化/不支持/仅计数/可采样区别、每 CPU 差异、已知失败原因 | 板卡上的溢出中断确实能工作 |
| `perf_event_open` 的原始请求/返回 | 软件周期、未知配置、硬件不支持、作用域与权限错误 | 事件已进入 BPF 程序 |
| 用户工具自动选择 | 请求事件、最终事件、单位、降级原因、零样本失败 | 硬件 cycles 与软件 ns 可相互换算 |
| 真实 guest 采样会话 | CPU/task scope、实际 PC、enable/disable、丢失与 teardown | 没有运行过的物理板卡或 ISA 组合 |
| BPF ELF 预检 + 目标 verifier | section、map/helper/context/relocation 要求、明确拒绝 | 任意 Linux loader 可在 PulseOS 运行 |

#190 与 #191 的真实事件/消费链是软件能力可验收的前提；能力报告不能在接线前把已有状态模型写成“采样 ready”。

## 2. 架构与平台事实

### 2.1 RISC-V：SBI PMU 不等于采样中断

SBI PMU extension 的 EID 是 `0x504d55`。Supervisor 软件通过 SBI 发现和配置每 hart 计数器；`mcycle/minstret/mhpmcounter*` 的控制属于更高特权层，不能因为能读 `cycle` 就直接写 M-mode CSR。SBI BASE 的 probe-extension 应先确认 PMU extension 存在，再调用 PMU 的 `num_counters` 和 `counter_get_info`。[S1][S2]

`counter_get_info` 返回逻辑 counter index 对应的 CSR、位宽和 hardware/firmware 类型；位宽字段保存 `width-1`。不要假设 logical counter index 等于 CSR 编号，或所有索引都连续有效；对 firmware counter 忽略硬件 CSR/width 字段。`counter_config_matching` 是选择和配置计数器的操作，不是无副作用的“列出事件”接口，必须在受控 ownership 下进行。[S1][S3]

**可读计数器不保证 overflow sampling。** Linux v6.12 的 SBI PMU 驱动在不能建立适用的溢出 IRQ 时保留计数能力，但设置 `PERF_PMU_CAP_NO_INTERRUPT`；标准 `Sscofpmf` 与特定厂商 PMU 是不同分支，不能从“RISCV64”或“SBI PMU 存在”推出两者之一已可用。SBI firmware counters 也不应自动列入可溢出采样的集合。[S3]

首版 generic event 映射应显式写表，不依赖数值巧合：

| 用户 Linux 请求 | Linux config | SBI hardware-general event code | `event_data` |
| --- | ---: | ---: | ---: |
| `PERF_COUNT_HW_CPU_CYCLES` | 0 | 1 | 0 |
| `PERF_COUNT_HW_INSTRUCTIONS` | 1 | 2 | 0 |

Linux 与 SBI 的事件编号并不相同。cycles 可能随 CPU 频率变化，WFI/挂起期间是否计数也由事件语义决定；不能当作墙钟纳秒。剩余 cache/raw/vendor events 在定义、过滤和测试齐备前保持不支持。[S1][S3][S4]

仓库现有 RISC-V QEMU 平台 IRQ 分发只显式处理 supervisor software/timer/external interrupt，其他 CPU-side cause 会 panic；因此仅发现扩展后立即开启 PMU interrupt 是错误的接入次序。需要先扩展受控的 CPU-local IRQ 注册/分发、保存采样现场和停止/清除/重装周期的顺序，再开放 hardware sampling。[P1]

### 2.2 LoongArch：CPUCFG6 是能力输入，不是驱动完成证据

官方手册对 CPUCFG word 6 的定义如下：[S5]

| 位 | 字段 | 解码/含义 |
| --- | --- | --- |
| 0 | PMP | 1 表示支持 performance counter |
| 3:1 | PMVER | 架构定义事件版本；1 是初始版本 |
| 7:4 | PMNUM | performance monitor 数量减 1 |
| 13:8 | PMBITS | counter 位数减 1 |
| 14 | UPM | 支持用户态读 counter |

先检查 PMP，再解释后续字段；PMP=0 时不能把零字段解码成“1 个 1-bit counter”。仓库已有 `axcpu::asm::read_cpucfg`，可在架构层封装纯字段解码；读取结果仍应按 CPU 记录。未知 PMVER、超出实现支持的数量/位宽、缺失 IRQ 支持都必须限制能力，不能盲目遍历 CSR。[P2][S5]

PMCFG 的 EvCode、PLV 过滤与 PMIEn 控制计数和溢出中断；PMCNT 的最高位为 1 且中断启用时触发中断，清除该位可取消中断。不能把 64-bit 无符号自然回绕当作唯一溢出条件。Linux v6.12 的 LoongArch 驱动还实现计数器保存/停止、周期重装与 IRQ 注册；其 generic event 表以 `0x00` 表示 cycles、`0x01` 表示 instructions，但这仍需匹配实际 PMVER/处理器支持并实测。[S6][S7][S8]

现有 LoongArch QEMU/LS2K1000 平台 IRQ 适配显式管理 timer、IPI 与外部控制器路径，没有一个可以据此宣布就绪的 PMU handler。硬件 driver 应在平台完成 CPU-local IRQ 配置后注册中断，并在 ownership/现场读取/关闭路径全部完成后公开采样能力。[P3]

### 2.3 QEMU 与两块物理板的边界

QEMU 不能整体标为“无 PMU”。固定 v9.2.0 的 RISC-V PMU 模型包含可编程计数器、`pmu_mask` 和依赖 `ext_sscofpmf` 的溢出计时路径；它的 cycle/instruction 计数实现受 icount/host ticks 等模拟配置影响，不能用其值推断物理 CPU 微架构性能。相同固定版本的 LoongArch `la464` 初始化令 CPUCFG6 保持零，且 PMU 属性在 KVM 分支注册；这说明必须记录版本、CPU model、accelerator 和 firmware，而不是仅判断是否使用 QEMU。[S9][S10]

本机 `qemu-system-riscv64 --version` 与 `qemu-system-loongarch64 --version` 实际报告 `11.1.50 (v11.1.0-2112-g2a0ac9c8ac)`；本次没有在该版本 guest 内做 PMU 探测，不能套用 v9.2.0 示例宣称本机 PMU 支持或不支持。

| 目标 | 本次可以确认 | 本次未确认 / 后续必测 |
| --- | --- | --- |
| RISC-V QEMU virt | 源码上有软件 timer 路径；固定 QEMU 版本存在 PMU 模型 | 实际 firmware 的 SBI PMU、Sscofpmf/IRQ、所选事件计数及采样 |
| LoongArch QEMU virt | 存在 CPUCFG 读取和 timer/IRQ 平台适配 | 当前 QEMU CPUCFG6、PMU 中断和计数行为 |
| VisionFive 2 | 当前平台有 SBI/DTB、每 CPU timer 和 IRQ 初始化入口 | 实际 SBI firmware 是否提供 PMU、counter/event/overflow 路径；未上板 |
| LS2K1000 | 当前平台有 CPUCFG 读取、每 CPU timer 和 IRQ 初始化入口 | 实际 CPUCFG6/PMVER/位宽/IRQ 与事件表；未上板 |

物理平台在没有实测数据时标记 `not_tested/unknown`，不能从板名编译特性硬编码为 sampling ready。软件基线需各自运行验证；同样不能仅凭 timer 初始化代码就写成已通过采样验收。[P1][P2][P3][P4]

## 3. 推荐的能力分层与初始化位置

建议新增一个专门的采样能力 module，而不是把 PMU 探测放进 paging/MM 模块：

1. **架构/平台层**执行有限的只读发现：RISC-V 的 SBI probe/counter info，LoongArch 的 CPUCFG6；提供原始能力、平台身份及失败原因。寄存器访问和 CPU-local interrupt 操作留在该层。
2. **每 CPU late init**在 trap/percpu/平台 IRQ 就绪后运行发现；仅 boot CPU 的结果不能代表其他 CPU。必要的 PMU backend ownership/reset/handler 配置按各 CPU 完成。当前 `axruntime` 经 `axhal::init_later` 再初始化 scheduler 的顺序可作为接入审计入口，但具体 hook 必须结合 secondary boot 路径核对。[P4]
3. **`pulse_core` 采样 module**合并已在线 CPU 的可用能力，维护 backend 状态和授权/作用域检查；查询快照不启动计数器，也不修改运行会话。
4. **用户工具**读取快照并选择事件；`perf_event_open` 再作权威校验，防止快照过期/CPU 下线/资源占用后错误成功。能力报告与实际 open 结果不一致必须诊断。

建议能力记录至少包含下列概念，具体 wire schema 随 #187 决定：

- `version`、target arch/platform/build identity、CPU id 与 online 状态；
- software CPU/task-clock 的 `implemented`、`sampling_ready`、单位、实际时钟与 period 范围；
- hardware 的 `advertised`、counter count/width、可访问性、overflow IRQ/backend 状态；
- 每事件的 `counting_supported`、`sampling_supported`、scope/privilege filters；
- `reason` 枚举，如 `not_probed`、`no_extension`、`no_hardware`、`unsupported_version`、`no_overflow_irq`、`driver_not_implemented`、`probe_failed`；
- stack/callchain/context schema 能力单独列出，不能从“能采样”推出“完整用户栈”。

`not_probed/unknown` 与 `unsupported` 不合并；driver 未实现时可以保存硬件宣称字段，但 `sampling_supported=false`。多 CPU scope 默认选共同支持的能力，不在一个事件流中混用 cycles 与 ns；选择部分 CPU 的限制必须在 CLI 和 capture 中可见。

**推荐公开入口**：一个明确命名且版本化的 PulseOS 只读能力文件（例如 `/proc/pulse/perf_caps`），用户工具将其转为 `capabilities --json`。它是 PulseOS 自有扩展，不是 Linux `/proc/cpuinfo` 或 BPF syscall 的隐式新 ABI。现有 procfs 已有动态文件/provider 机制可扩展；不要在它里面主动编程 PMU。[P5] 另一可行方案是自有控制设备的 query ioctl，但不应为了能力查询发明新的 Linux `BPF_*` command number。最终路径由 #187 的控制入口决定。

## 4. 降级必须保留语义

建议策略：

| 用户请求 | 无可用 PMU 时 | 必须保存 |
| --- | --- | --- |
| 明确 `cpu-clock` / `task-clock` | 直接选择对应已就绪软件事件 | 实际 clock、period、scope；不出现伪硬件事件 |
| 明确 `cycles` / `instructions` | 返回明确不支持；除非用户显式另给 fallback 策略 | 请求事件、错误与能力原因 |
| 工具 `auto` | 优先所选 scope 内已就绪的硬件事件，否则选择软件 CPU clock | requested/effective event、原始配置、fallback reason、单位和 backend |
| 运行中 backend/CPU 失效 | 停止并标 incomplete，或未来显式切为新的 segment | 失效时间、丢失/未知数量、分段配置；不混成原硬件流 |

降级在用户工具完成，不能让内核收到 `PERF_TYPE_HARDWARE/config=0` 后悄悄返回软件 event FD；否则 read 值、period 单位与 perf.data attr 全部误导。`EACCES/EPERM`、无效参数、内存/资源错误不应被自动解释成“缺 PMU”，防止掩盖权限和配置问题。首版 `auto` 可只在能力不支持/缺设备时降级，其他失败直接诊断。

硬件 driver 未接入之前，现有 `validate_perf_event_attr` 对 HARDWARE/HW_CACHE/RAW/BREAKPOINT 和 frequency mode 返回 `EOPNOTSUPP` 的行为应保留。软件 period 模式与 ns 权重是 #86 的现有契约；不能单为“支持频率参数”就改变 ABI。可由工具换算固定 period，但必须说明不是 Linux 内核自适应 freq 模式。[P6]

## 5. BPF 移植边界：区分字节码、context 与工具

### 5.1 现状矩阵

下表是本次代码审计，**实现入口存在不等于真实 guest 路径已通过**。#190/#191 的验证仍适用。

| 面向程序/工具的能力 | 当前证据 | 本阶段建议边界 |
| --- | --- | --- |
| eBPF 指令 | 已有 verifier/interpreter，指令/步数/栈/指针来源受限 | 声明接受的子集和资源上限；Linux verifier 接受的程序不一定被本 verifier 接受 |
| program type | TRACEPOINT(5)、PERF_EVENT(7) | 仅这两类；KPROBE/raw tracepoint/fentry 等无承诺 |
| context | PulseOS 固定标量 `PerfEventContext` 与版本化语义 tracepoint | 不是任意 Linux `pt_regs`、`bpf_perf_event_data` 或 sched tracepoint layout |
| map | HASH(1)、ARRAY(2)、PERF_EVENT_ARRAY(4)、RINGBUF(27) 有实现 | 逐类列明 flags/大小/更新与生命周期，不能推出所有 Linux map 类型 |
| helper | 1/2/3 map 操作、5 time、8 CPU、25 perf output、130 ringbuf output 有分发 | 每个 helper 的 verifier/运行时错误/上下文语义都须验证 |
| ringbuf reserve/submit/discard/query | IDs 131–134 明确拒绝 `EOPNOTSUPP` | 不称为完整 ringbuf helper 支持 |
| `bpf_get_current_task` / probe_read 家族 | 不在可用 helper 分发集合 | 不返回 `TaskInner` 伪装 Linux `task_struct`，不允许按 Linux 偏移读 Rust 对象 |
| BTF/CO-RE | BTF commands deferred；PROG_LOAD 相关字段非零拒绝；fixture checker 禁止相关段 | 不跳过 CO-RE 当成功；以后单独具名兼容层再审计需求 |
| bpffs pin/get、map batch 等 | 已知 deferred commands 返回 `EOPNOTSUPP` | 保留可诊断的显式拒绝 |
| kprobe symbol | 当前没有通用 kprobe 附着实现 | 内核 ELF 有符号不等于可 probe；以语义事件替代函数地址依赖 |

依据：[P7][P8][P9][P10]。Linux `bpf_perf_event_data` 前面含架构相关 `bpf_user_pt_regs_t regs`，之后才是 sample_period/addr；当前 PulseOS context 以 sample_period/addr 开始。因此即使两者都叫 PERF_EVENT，按 Linux 头文件编译的 field offset 也不能直接视为可移植。[S11]

当前拒绝码并不完全统一：未知 helper/program type 常为 `EINVAL`，明确 deferred ringbuf helper/命令为 `EOPNOTSUPP`，非法访问为 verifier 的权限/边界错误。预检工具应保留实际 errno 与 verifier log，不为整齐而把所有失败改成同一个泛化错误；后续契约变更必须测试。[P7][P8]

### 5.2 不暴露 Linux 内部结构的替身

`bpf_get_current_task` 在 Linux 返回当前 task struct 指针，probe_read helpers 是带错误返回的受控读取，CO-RE 依赖目标类型信息及重定位语义；它们不是通过把 PulseOS 内核对象放进同名 C 结构体就能兼容的功能。[S12][S13]

建议 #186 明确：现阶段移植方式是按 PulseOS 发布的 context schema 重编译 BPF 程序，使用稳定标量身份/事件字段；不要导出 `task_struct/mm_struct` 假布局或任意 Rust 地址。#182 的 stack capture 通过受控 snapshot/stack helper 契约实现，也不能顺带开放任意 kernel probe_read。不同 schema 使用明确版本，旧程序得到拒绝/匹配版本，不把字段位置悄然改义。

### 5.3 两项已经找到的兼容性缺口

**时间 helper。** 审计基线 `DefaultBpfEnv::ktime_get_ns` 使用 `wall_time_nanos()`，而 Linux helper 5 的契约是自启动以来、排除 suspend 的 monotonic ns。事件 context 已有独立采样时间；需要修正默认 helper 的时钟语义，并明确延后执行时 helper 返回执行时钟，事件时间仍从 snapshot 读。CPU helper 同理返回运行 BPF 的 CPU；若需要产生事件的 CPU，读取明确的 event field，不能暗中交换两种概念。[P9][S12]

**固定 libbpf fixture 的 loader 矛盾。** `tools/bpf-fixture/README.md` 固定 libbpf 1.3.0，同时 fixture 使用 classic `SEC("maps") struct bpf_map_def` 并禁止 BTF；上游 libbpf v1.3.0 在遇到 `maps` 段时直接返回 `-ENOTSUP`，明确说明 v1.0+ 不再支持 legacy map definitions。现有 guest sampler 自行创建对象/装载指令，不能因此宣称 libbpf 1.3 open/load 工作流已通过。[P10][P11][S14]

本次主机实验已复现第二项：本机 `pkg-config --modversion libbpf` 为 1.3.0；仅 `bpf_object__open_file` 即得到 `open_error=-95`，尚未进行 `BPF_PROG_LOAD` 或任何 guest 采样。复现（不需要 live BPF 权限）：

```bash
clang-18 -target bpfel -O2 -g0 -c tools/bpf-fixture/fixture.bpf.c \
  -o /tmp/pulse-fixture.bpf.o
cat > /tmp/pulse-libbpf-open.c <<'C'
#include <stdio.h>
#include <bpf/libbpf.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    long error = libbpf_get_error(obj);
    printf("libbpf=%s open_error=%ld\n", libbpf_version_string(), error);
    if (!error) bpf_object__close(obj);
    return error ? 1 : 0;
}
C
gcc /tmp/pulse-libbpf-open.c -lbpf -o /tmp/pulse-libbpf-open
/tmp/pulse-libbpf-open /tmp/pulse-fixture.bpf.o
```

预期当前失败输出为 `legacy map definitions in 'maps' section are not supported by libbpf v1.0+` 和 `libbpf=v1.3 open_error=-95`。这是已复现的不兼容证据，不是权限不足，也不是 PMU 缺失。

推荐沿 #130 的转向明确自有 loader 工作流，把 libbpf 工具兼容另建经过真实 open/load/attach/consume 验证的具名层级。若决定保留 libbpf 1.3 工作流承诺，就必须另选 BTF map metadata/loader 方案、审计生成 ELF 与 syscalls，不能简单删除失败检查或把 libbpf 版本改到未知的旧版。[P12][P13]

## 6. 兼容预检与报告建议

复用 `tools/bpf-fixture/check.py` 的 ELF 解析基础，但区分“固定 fixture 哈希校验”和“任意候选程序兼容预检”，不能把后者绑定某一 fixture hash。建议预检输出以下内容：

- ELF machine/endianness、program section 与程序类型；
- map type/flags、relocation target/type、所有调用 helper ID；
- context schema 要求以及是否含 BTF、CO-RE、全局数据或不支持的 BPF-to-BPF calls；
- loader 版本与 ABI layer，`loadable/unsupported/unknown` 分级及明确原因。

预检只能筛出确定的不兼容，不能证明运行安全或功能正确；目标 verifier 和真实执行仍是权威门禁。内核只看到最终指令时无法仅由指令推断某 loader 之前是否应用过 CO-RE，所以 artifact 来源与 loader policy 必须在用户工具中保存，不能把“内核没有看到 BTF”当成“原程序没有依赖它”。

文档和 `capabilities --json` 应共用同一兼容矩阵来源，至少按 program type/helper/map/context/attach kind/error 分类；每一项同时区分 available entry、真实 guest validated、deferred。不要输出一个没有语义边界的 `Linux BPF supported=true`。

## 7. 本轮已完成的独立 ABI 修复

审计发现旧代码把 `PERF_COUNT_HW_INSTRUCTIONS=0`、`PERF_COUNT_HW_CYCLES=1` 颠倒。Linux UAPI 的事实是 CPU_CYCLES=0、INSTRUCTIONS=1；硬件请求目前全部被拒绝，因此该修复没有新增 PMU 支持。[S4][P6]

本轮在 `pulse_syscalls/src/impls/bpf/perf_event.rs` 定义规范名 `PERF_COUNT_HW_CPU_CYCLES=0`，修正 INSTRUCTIONS=1，保留旧 CYCLES 名称为别名。`pulse_syscalls/src/validation/bpf_perf_event.rs` 新测试使用 Linux 字面值为 oracle，并对 type=0/config=0、1 分别断言仍返回 EOPNOTSUPP。

验证顺序：新增测试后先观察失败（旧 CYCLES 值 1 与预期 0 不符）；修复后运行：

```bash
cargo test -p pulse_syscalls --target x86_64-unknown-linux-gnu \
  --no-default-features bpf_perf_event -- --nocapture
```

结果 14 passed、0 failed。此 host 验证只覆盖编号和已有拒绝行为，不是硬件/guest 验证。

## 8. 待确认的少量决定与后续验收

建议把真正需要范围选择的事项集中为三项，其他字段事实不交给用户猜测：

1. **第一阶段硬件范围**：完成真实软件采样、有限只读 PMU 发现与准确能力报告；两架构硬件 overflow driver 和板卡采样作为独立后续任务。若本 map 要求物理 PMU 运行完成，则必须取得实际板卡/firmware 与可复现 IRQ 证据，不能将 unknown 记作已完成。
2. **自动降级与发现入口**：接受工具显式 auto、内核不改请求语义、只读 PulseOS 能力接口的方案；最终命令/文件路径与 #187 一起确定。
3. **Linux 工具兼容目标**：当前交付为自有 loader + 明确固定 context 层；不以原样 libbpf-bootstrap profile 或 libbpf 1.3 现有 fixture 为强制目标，并在 ADR-0005 的后继决定中记录转向。如果保留 libbpf 目标，则需要额外 metadata/loader 设计与实际加载验收。

后续实现门禁：

| 用例 | 预期 |
| --- | --- |
| RISC-V 无 SBI PMU / 有 counter 无 overflow / 有 overflow 未注册 handler | 分别报告原因，硬件采样不误报 ready，无非法 CSR/未知 IRQ |
| LoongArch PMP=0、字段极值、未知 PMVER | 纯解码有测试；不访问超范围 PMCFG/PMCNT，不“解码”出虚构的计数器 |
| 两 CPU 能力不同 / CPU 下线 | scope 内能力可解释；不把 boot CPU 结果复制到其他 CPU |
| 明确 cycles 与 auto | 前者不支持时失败；后者可记录降为 cpu-clock，perf.data 的 type/config/period 单位一起改变 |
| mid-session PMU 错误 / buffer loss | 结果停止或分段且 incomplete，不继续写虚假的硬件样本 |
| helper 时间与 CPU | monotonic clock 不受 RTC 修改影响；执行 CPU 与事件 CPU 分别测试 |
| 候选程序需 get_current_task/probe_read/CO-RE/kprobe | 加载前/目标 verifier 明确诊断，不跳过要求后返回成功 |
| 声明支持的 loader 工作流 | 实测 open、load、attach、消费、detach、close；静态 ELF 校验和裸 syscall 测试不能替代 |
| RV64/LA64 软件 smoke | #190/#191 的真实非零记录、实际身份、完整性、失效路径通过 |
| 任何新增硬件支持 | 固定板卡或 QEMU 配置，计数增量、overflow IRQ、采样 PC、filters、SMP、disable/close 和丢失测试全部归档 |

涉及内核实现时按仓库 `make test` 和 AGENTS.md 指定的双架构 QEMU 命令验证；物理平台结果单独报告。最终关闭 #183/#186 需要采纳明确设计，关闭整个 map 则还需要对应实现和真实运行证据。

## 一手来源

- [S1] [SBI v2.0 PMU extension](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v2.0/src/ext-pmu.adoc)：EID、per-hart counters、counter info、事件编号与配置/启动/停止语义。
- [S2] [SBI v2.0 BASE](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v2.0/src/ext-base.adoc)：probe-extension。
- [S3] [Linux v6.12 RISC-V SBI PMU driver](https://github.com/torvalds/linux/blob/v6.12/drivers/perf/riscv_pmu_sbi.c)：generic event map、IRQ 分支、NO_INTERRUPT、firmware counters。
- [S4] [Linux v6.12 perf UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/perf_event.h)：perf_hw_id 与 event/attr 定义。
- [S5] [LoongArch 官方 CPUCFG 说明](https://github.com/loongson/LoongArch-Documentation/blob/e0d6592229d9e00e512bd28b688a7f20b171714f/docs/LoongArch-Vol1-EN/basic-integer-instructions/overview-of-basic-integer-instructions/other-miscellaneous-instructions.adoc#cpucfg-pmp)：CPUCFG6 字段。
- [S6] [LoongArch 官方 PMCFG](https://github.com/loongson/LoongArch-Documentation/blob/e0d6592229d9e00e512bd28b688a7f20b171714f/docs/LoongArch-Vol1-EN/control-and-status-registers/control-and-status-registers-related-to-performance-monitoring/performance-monitor-configuration-n.adoc)：事件、PLV 和中断控制。
- [S7] [LoongArch 官方 PMCNT](https://github.com/loongson/LoongArch-Documentation/blob/e0d6592229d9e00e512bd28b688a7f20b171714f/docs/LoongArch-Vol1-EN/control-and-status-registers/control-and-status-registers-related-to-performance-monitoring/performance-monitor-overall-counter-n.adoc)：计数与最高位溢出中断语义。
- [S8] [Linux v6.12 LoongArch perf driver](https://github.com/torvalds/linux/blob/v6.12/arch/loongarch/kernel/perf_event.c)：事件表、IRQ、counter 生命周期。
- [S9] [QEMU v9.2.0 RISC-V PMU](https://github.com/qemu/qemu/blob/v9.2.0/target/riscv/pmu.c)：pmu_mask、Sscofpmf 和模拟计数/溢出。
- [S10] [QEMU v9.2.0 LoongArch CPU](https://github.com/qemu/qemu/blob/v9.2.0/target/loongarch/cpu.c)：la464 CPUCFG 初始化与 KVM PMU 属性。
- [S11] [Linux v6.12 bpf_perf_event_data](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/bpf_perf_event.h)：架构相关 regs 前缀。
- [S12] [Linux v6.12 BPF helper UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/bpf.h)：ktime、SMP CPU、current_task、probe_read 家族。
- [S13] [Linux v6.12 BTF 文档](https://github.com/torvalds/linux/blob/v6.12/Documentation/bpf/btf.rst)：类型元数据与 CO-RE relocation 记录。
- [S14] [libbpf v1.3.0 ELF parser](https://github.com/libbpf/libbpf/blob/v1.3.0/src/libbpf.c#L3570-L3572)：拒绝 legacy maps 段。

## 仓库依据

- [P1] [RISC-V QEMU IRQ](../../platforms/axplat-riscv64-qemu-virt/src/irq.rs)。
- [P2] [LoongArch CPUCFG accessor](../../modules/axcpu/src/loongarch64/asm.rs)。
- [P3] [LoongArch QEMU IRQ](../../platforms/axplat-loongarch64-qemu-virt/src/irq.rs)、[LS2K1000 IRQ](../../platforms/axplat-loongarch64-ls2k1000/src/irq.rs)。
- [P4] [axruntime 初始化](../../modules/axruntime/src/lib.rs)、[VisionFive 2 init](../../platforms/axplat-riscv64-visionfive2/src/init.rs)、[LS2K1000 init](../../platforms/axplat-loongarch64-ls2k1000/src/init.rs)。
- [P5] [procfs 动态文件](../../modules/axfs/src/fs/procfs.rs)。
- [P6] [perf-event ABI validation](../../pulse_syscalls/src/impls/bpf/perf_event.rs) 与 [#86 软件事件约定](https://github.com/muou000/PulseOS/issues/86#issuecomment-6138057642)。
- [P7] [Program type](../../modules/bpf/src/program.rs)、[verifier](../../modules/bpf/src/verifier.rs)、[PROG_LOAD](../../pulse_syscalls/src/impls/bpf/prog.rs)。
- [P8] [BPF command ABI](../../pulse_syscalls/src/impls/bpf/abi.rs)、[syscall dispatch](../../pulse_syscalls/src/impls/bpf/sys.rs)。
- [P9] [interpreter/helpers](../../modules/bpf/src/interpreter.rs)、[map types](../../modules/bpf/src/map.rs)、[context schema](../../crates/pulse_bpf_schema/src/lib.rs)。
- [P10] [fixture 契约](../../tools/bpf-fixture/README.md)、[fixture source](../../tools/bpf-fixture/fixture.bpf.c)、[checker](../../tools/bpf-fixture/check.py)。
- [P11] [guest sampler](../../tests/bpf_smoke/guest_sampler.rs)。
- [P12] [#130 的方向调整](https://github.com/muou000/PulseOS/issues/130#issuecomment-6542849311)。
- [P13] [ADR-0005](../adr/0005-profile-specific-linux-bpf-compatibility-tier.md)：需由后继决定显式协调，不能静默覆写。
