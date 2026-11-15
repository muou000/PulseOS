# 时间有效的映射与符号产物（#193）

日期：2026-11-15。范围为 RV64/LA64 的 BPF capture 映射、任务生命周期和符号产物身份；不包含 #194 的 perf.data 导出，也不把调度选中时间视为 CPU busy/idle 驻留时间。

## 验收约束

1. 原 capture 保存初始地址空间和后续映射快照，具有单调 sequence、时间、地址空间身份、revision、任务身份与 exec generation；分析不读取采集结束时的 `/proc/maps`。
2. 先按稳定 task identity 关联生命周期，再按采样时间选择映射。PID/TID 重用、exec、fork、rename、unmap、mprotect 和 mremap 分别验证；未来快照不能补写过去。
3. 地址空间修改和跨 CPU TLB 可见性完成之间保持 unknown。元数据丢失、缺初始事实、越过快照覆盖终点或处于模糊同戳边界时，不能声明确定归属。
4. 用户映射保留虚拟 start/len、字节 pgoff、权限和对象身份。对象路径只是描述；内容身份来自 guest 实际文件。可变文件不能仅凭一次读取就声称内容始终匹配。
5. Artifact bundle 用完整 ELF SHA-256 定位文件，校验 ELF 的真实 GNU build-id；缺少该 note 明确 absent。错误同名文件、缺失文件和篡改 build-id 必须失败或保留 unknown。
6. 对 PIE 和非零 pgoff 使用 ELF PT_LOAD 的文件偏移转换；核对内核运行 text 范围和参考符号重定位。原始记录、实际 ELF 和逐文件哈希可以重放。
7. 两架构运行真实文件映射、改名、fork/exec、权限变化、迁移和解除映射负载，使用仓库规定的 QEMU 形态。

## 实现接口与覆盖

启用 `bpf-trace` 时，内核保留 8 MiB 有界的启动期元数据日志，通过 `/proc/pulse_bpf_mappings` 导出稳定快照。日志从地址空间创建开始记录，因此采样启用之前的初始事实也在 capture 内。容量耗尽显式记录 dropped，不用终态重建已丢失的前史；无法确定丢失的具体影响时，整个映射关联保守降级。

`AddressSpaceLock` 的写租约在 VMA revision 改变时发布完整快照，保存写操作起始时间。所有映射共享同一记录位置，避免只在部分系统调用中插入观测点。`AddrSpace` 的软件身份不会因硬件 ASID 重用而复用。

journal **v2** 的 `MUTATION` begin 在暴露写访问、exec teardown/rebind、rename 或 exit 之前发布；快照或 TASK 事实发布后才结束。导出截断时仍在进行的事务有可见 begin，相关样本返回 unknown。仅在事务结束时补记起始时间会漏掉截断时的在途写操作，因此未发布的 journal-v1 原型不被最终解析器当作可靠前史。capture 容器 v1/v2/v3 的既有兼容性不变。

capture **v4** 把原始 journal、实际 ELF/debug 身份及内核参考信息保存在带 checksum 的元数据区，required-extension mask `0x2` 表示必须理解映射扩展；可与 mask `0x1` 的真实 stack-v3 共存。diagnostics 单独用长度分隔，避免其 1 MiB 上限误拒大于 1 MiB 的合法映射日志。映射元数据上限为 16 MiB，未知必需扩展、损坏或矛盾字段明确拒绝。

`axmm` 的 `mapping-observer` 特性为 `TlbShootdown` 增加独立的观测 token：构造时记录 begin，所有合并失效都取得可见性保证后记录 complete。观测回调不参与所有权协议；原有 invalidate → completion → dirty publication → reclaim 顺序不变。失败或未执行的 shootdown 不生成 complete。token 在创建时携带软件地址空间身份，不在完成时重新查找可能重用的硬件 ASID。

这个接口完全使用标量和安全 Rust；新增观测数据不会持有裸指针或延长页框借用。回调的锁顺序只进入日志，不反向获取地址空间锁。测试和构建不能替代对既有 TLB/页框回收协议的全内核 soundness 证明，本任务也不作该声明。

ELF loader 在既有 deny-write 执行租约内读取实际文件 SHA-256；同文件 mmap 复用当前地址空间持有的同一 source，fork 继承该来源。普通可变文件保留对象身份而 SHA 为 unknown，不新增 deny-write 租约改变 mmap 行为。文件改名不会改变对象身份；路径保留其观测时的标签。任务只发布已知 user 类别，其他任务类别及 CPU busy/idle 驻留保持 unknown。

部分区间 mremap 曾在移动后保留原 backend 起点对应的文件偏移。修复先对克隆出的中间 backend 按旧子区间起点重定位文件窗口，检查 offset+size，之后才修改原 VMA/PTE；两侧残留区间保持原窗口。真实负载单独移动原 pgoff=0 映射的第二页，并在迁移后执行对应 pgoff=4096 的代码，验证后续缺页与元数据同时正确。

ELF 的 `p_offset` 是文件字节偏移，PT_LOAD 的文件与虚拟地址要按段转换；不能把 runtime IP 直接作为 ELF 地址，也不能把零填充区当作文件内容。[ELF gABI program headers](https://gabi.xinuos.com/elf/08-pheader.html)

GNU build-id 是实际 ELF note 的值，链接后文件再改变时 build-id 不一定随之改变，因此 bundle 同时绑定完整文件 SHA-256。[GNU ld build-id options](https://sourceware.org/binutils/docs/ld/Options.html)

新的 guest fixture 有一处将 mmap 原始指针转换为 C 函数指针的 unsafe 调用。范围仅为 RV64/LA64：注入的实际 ELF、文件偏移 4096、精确机器码均由主机校验，执行期间保持 RX 映射和文件执行租约；叶函数只修改参数寄存器并经返回地址寄存器返回。测试依赖这两个平台的数据/函数指针宽度一致、C ABI、加载器与汇编器遵守上述部署契约。转换先取 `*const ()` 再 transmute，不将任意整数视为可调用地址。[Rust transmute contract](https://doc.rust-lang.org/std/mem/fn.transmute.html)、[global assembly scope](https://doc.rust-lang.org/reference/inline-assembly.html#asm.scope.global_asm)。这些是具体构建/运行的验证前提，不是对所有工具链或平台的通用 soundness 认证。

## 验证命令

```bash
cargo test -p pulse_bpf_schema -p bpf-capture -p bpf-analyzer
cargo check -p bpf-capture --no-default-features --features alloc
python3 -m unittest discover -s tests/bpf_sampling -p 'test_*.py'
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode cpu --archive --mappings
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode cpu --archive --mappings
make test 2>&1 | tail -30
```

## 最终结果与重放

默认和启用 BPF 的 `make test` 均通过。schema/capture/analyzer 194 项、syscalls 233 项，共 **427 项 Rust 测试**通过；**75 项 Python 测试**及 capture no_std check 通过。最终 importer 描述修正后单独重跑其 23 项测试通过，不重复计入 75 项。独立 axmm host 单测因既有 `x86_64 0.15.4` 不兼容当前 nightly `Step` 接口而无法编译；没有修改依赖绕过，partial-range mremap 的实际验证由以下双架构第六阶段完成。

最终证据见 [evidence/193](../tests/bpf_sampling/evidence/193/README.md)：

| 架构 | 原始 RAW 样本 | 可关联用户样本 | mapped / renamed / fork / exec / remapped / partial_remapped | 完成的 TLB token |
|---|---:|---:|---|---:|
| RV64 | 1,442 | 168 | 15 / 16 / 14 / 15 / 12 / 14 | 39 |
| LA64 | 1,133 | 136 | 15 / 17 / 13 / 14 / 15 / 15 | 85 |

六阶段的实际用户 IP 都按当时 task、地址空间、exec generation、对象 SHA、字节偏移及 PT_LOAD 独立核对，并与 Rust analyzer 的实际结果一致。父 ELF 没有 GNU build-id，子 ELF 有真实 GNU note；二者都有实际嵌入的调试信息。内核 ELF 的 `_stext`/`_etext` 与 guest 运行范围匹配，本次运行 relocation 为 0，非零重定位及错误参考符号另有主机正反例。

共 **2,575 条 RAW**与 capture normalized record 逐条核对。正例均匹配实际 ELF；同一批实际样本分别经过缺 ELF、同名错误 ELF 的负例，保留映射而拒绝错误符号归属。按 child PID、user mode 和 exec 时间窗的真实 CLI 查询分别得到 15/14 条样本，仍使用窗口外的前史；不指定 bundle 时可读取时序映射，符号保持 unknown。两组 metadata dropped、transport loss 和 export drop 均为 0；源级跳过及其他未测量诊断分别保留。

capture 状态仍为 `IncompleteError` / partial，`attribution_claim_allowed=false`，busy/idle 为 null。这里验证的是已记录事实及样本归属，不宣称完整 scheduler、IRQ 驻留或 CPU 利用率。普通可变文件没有稳定内容 SHA、缺失 ELF/debug、日志耗尽、在途变更和同戳不确定性仍会降级为 unknown。

证据包保存原始串口日志、两个 proc 快照、RAW、capture、实际 ELF/debug、content-addressed bundle、构建 provenance、payload 源码和正负报告，逐成员 SHA-256 位于 index。重放在新的临时目录检查成员、从 ELF 重建启动字节、校验 kernel provenance、重建 capture 并比较映射报告，不依赖运行目录或主机同名 ELF：

```bash
python3 tests/bpf_sampling/verify_mapping_evidence.py tests/bpf_sampling/evidence/193
target/debug/bpf-analyzer capture.pbcapture --mapping-report --bundle /path/to/unpacked/run
```

中间失败保留原事实：首轮编译缺少 `Ordering` 导入，随后构建拒绝并发编辑期间的 source provenance；首轮运行的 exec 标记带 ANSI reset，原始运行成功但解析验收失败。修正并加回归后，journal-v1 中间结果因最终发现的在途事务缺口被替换为 journal-v2；最终归档只使用上述 journal-v2 重新运行结果。没有把旧运行包改写成新 producer 的证据。
