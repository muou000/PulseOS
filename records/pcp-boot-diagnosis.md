# PCP 启动自检全局快照竞争：诊断与修正

日期：2026-11-15。为恢复 #180 的实际 BPF 门禁而诊断；未修改 allocator 的生产分配算法，
未删除、放宽或用重试掩盖任何原 PCP 断言。

## 症状与反馈环

原命令 `python3 tests/bpf_smoke/run.py gate` 的第一个 RV task 运行在
`modules/axalloc/src/buddy_slab.rs:862` 的 `used_pages == used_init` 失败，尚未进入
userspace。原始记录：`tests/bpf_sampling/runs/riscv64-task-20261115-020058-dbdf71dn/guest.log`。
该 harness 发现 panic 前缀立即停止，left/right 数字被截断，所以建立了
`tests/pcp_boot/run.py`，仅 boot 到精确 PCP marker、panic 后再读取短暂尾部。
每 boot 约 0.3–0.6 秒，每个固定批次保留全部结果，任何失败使批次失败。

保留同一故障 kernel/image 的首批 20 次碰巧全绿，没有把它算作修复。与原 driver 的
stdin PIPE/new-session/select 时序对齐后，第二批 20 次抓到一红：同一 CPU3 上
`used_pages=9584`，原断言预期 `9583`；上一 `cached_pages==0` 已通过。
源文件位置为旧 `buddy_slab.rs:847`，日志 `baseline-matched-io-7qkms3n4/boot-017.log`。
初版 runner 对分片 panic 前缀标了 other_panic，完整原始日志明确是 PCP；后续分类已改为
使用 grace period 后完整输出。这一解码修正没有改动或丢弃该原始失败。

## 假设与逐变量实验

测试前向用户说明的排序：

1. 后台 allocator client 改变全局占用快照；扩大窗口应更容易失败，当前 CPU pinning
   不能阻止远端分配，必须在真正 quiescent 的启动位置测量。
2. 当前任务迁移导致 PCP 从不同 CPU 反复 refill；全程 NoPreempt/IRQ guard 应消除它。
3. 实际分配器计数错误；若相同分配/归还步骤在隔离环境仍失败，应调查生产算法。

| 条件 | 架构 | 结果 | 证据目录（`tests/pcp_boot/runs/`） |
|---|---|---:|---|
| 原 kernel，初始最小 driver | RV64 | 20 PASS / 0 FAIL | `baseline-b_0hd8na` |
| 原 kernel，匹配原 driver I/O | RV64 | 19 PASS / 1 FAIL | `baseline-matched-io-7qkms3n4` |
| 原调用位置，snapshot 后仅增加 20ms 窗口 | RV64 | 7 PASS / 3 FAIL | `window-probe-vd6pmzv6` |
| 同位置/窗口，再加全程 NoPreemptIrqSave | RV64 | 7 PASS / 3 FAIL | `guard-window-probe-c1ju7heb` |
| 保留 guard/窗口，仅移到 main 第一行 | RV64 | 20 PASS / 0 FAIL | `early-window-uyghz5e5` |
| main 第一行 + guard，移除临时窗口 | RV64 | 20 PASS / 0 FAIL | `final-rv-fyb311_l` |
| 同一 main-first clean 候选 | LA64 | 7 PASS / **13 FAIL** | `final-la-i73hwrj1` |
| 真正 runtime barrier 隔离，无临时 probe | RV64 | **20 PASS / 0 FAIL** | `isolated-rv-2tgeu4uk` |
| 同一 runtime barrier 隔离 | LA64 | **20 PASS / 0 FAIL** | `isolated-la-7h793f17` |

20ms probe 中，自检尚未申请第一张测试页时，`used` 已增 1、`available` 减 1、
`cached` 仍为 0；同样变化在全程 NoPreemptIrqSave 下仍出现。窗口里只有无堆分配的
时钟 busy-wait、日志和统计读取。它证明存在当前检查之外的全局占用变化，纯当前任务
迁移不能解释；并未用这段观察给额外页面指定未经追踪确认的单一调用者。

**main-first 候选被 LA 反例否决。** LA 中 used 增 2–12 页或 available 减 1–7 页。
因此“在 itimer 前”仍不等于安静环境；axruntime 已经放行 secondary scheduler/GC。
RV 的 20/20 绿以及其 probe 前后端点相等都不能证明整个并发窗口没有瞬态活动。

## 实际隔离点与最小修正

源码依据：

- `modules/axruntime/src/mp.rs`：secondary 先初始化 per-CPU allocator、MMU、scheduler
  和 IPI queue/ready，然后发布 INITED；原有 `is_init_ok()` 循环之后才启用 IRQ、标 online、
  进入 `axtask::run_idle()`。新增 opt-in 动态断言要求发布前 IRQ 仍关闭。
- `modules/axtask/src/run_queue.rs` / `api.rs`：secondary scheduler 初始化只创建并排入 GC
  task，不在该初始化函数中运行它。GC loop 有 timeout/wait 路径；释放 secondary 后它是
  合法 allocator client，不能把此时的全局占用变化算成 PCP 自检自身的泄漏。
- `modules/axmm/src/lib.rs::init_memory_management_secondary` 只安装内核页表并本地 flush；
  `modules/axipi/src/lib.rs::mark_current_cpu_ready` 只发布该 CPU ready。等待其 INITED 的
  primary 不持有 allocator 锁，不需要 secondary 收到 primary release 后才完成初始化。
- 两平台 `init_early_secondary` / `init_later_secondary` 设置 trap、timer/source mask；
  secondary 的全局 IRQ enable 仍在 runtime barrier 后。两架构实际跑到了该新断言并通过。

只让 Pulse 的 axruntime 依赖显式启用 `pcp-boot-checks`；axruntime 默认 feature 未改变。
新增的 kernel_guard 依赖也是 optional，并仅由该 feature 启用。root 不再直接依赖仅供旧
main 调用使用的 axalloc；Cargo.lock 只有这两条依赖边变化。

primary 保持 constructors 的原 IRQ-enabled 环境；ctor 完成后取得 outer
NoPreemptIrqSave，等待 secondary 的 `n-1` 个 INITED，执行所有原 PCP 检查，发布自身
INITED 后才释放 outer guard。secondary 仍在 IRQ-off spin，不能运行 GC/其它任务。
这样保留了八个已初始化 PCP cache 的远端 drain 检查，而没有提前释放它们的客户端。
自检自身也持有 guard，使 local refill/hit 步骤固定在一个 CPU。main 中的旧调用完全移除。
`KernelGuardIf` 的 preempt hook 依据 `current_may_uninit()`，不依据 `is_init_ok()`；primary
CurrentTask 已在 scheduler 初始化时建立，guard 期间不切换，所以跨 INITED 发布不会
出现 enter/drop 两侧对 preempt 计数条件不一致的问题。

结构回归 `--require-early` 验证：7 个 secondary init OK 在 PCP 前、8 个 cache、PCP
全部 PASS 在 primary init OK/release marker 前。旧 kernel 和被否决的 main-first kernel
都实际被此门禁判为 unsafe_startup_order，即使当次计数断言碰巧全过：
`isolated-contract-old-red-71enm13q`、`barrier-contract-red-hudd7lb3`。

## 清理与原始场景复验

- 临时 `[DEBUG-PCP]` 和 20ms busy-wait 已从生产源文件移除；probe 只保留在明确的 runs
  证据目录及打包日志中。没有新增 production allocator 算法或弱化断言。
- 原 `run_pcp_guest_checks` 所有 assert 表达式与 probe 前源副本逐项比较完全相同。
- `make test APP_FEATURES="qemu bpf-trace"` 双架构通过，见 `records/pcp-isolated-build.log`。
- 原失败命令 **`python3 tests/bpf_smoke/run.py gate` 全部通过**：当前 task/trace/sched/fault
  四模式 × RV64/LA64，共八次完整 boot→实际消费→capture→analyzer。
  日志 `records/pcp-original-bpf-gate.log`，全部 run 路径已保留在其中。
- 实际门禁最后的 RV sched/fault 为 `riscv64-sched-20261115-032300-p2ixq3hb` /
  `riscv64-fault-20261115-032305-4zypjw9d`；LA 为
  `loongarch64-sched-20261115-032322-ujid_c4x` /
  `loongarch64-fault-20261115-032328-pniuo3_9`。

这修正了全局计数自检的调用环境与隔离契约；不把 used/available 的多个快照变成全系统
原子事务，也不声称已证明 allocator 在任意并发负载下完全正确。
