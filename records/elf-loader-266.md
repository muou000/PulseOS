# ELF 装载拆分验收（#266）

基线为 `708d4c80`，迁移后的默认内核为 `6fd11cb3`，打开 `bpf-trace` 的内核为 `86223fdb`。后二者的内核源码相同。回归程序在所有运行中都使用 `86223fdb` 的版本。使用 QEMU 11.1.50（`2a0ac9c8ac`）、8 vCPU、8 GiB、测试 rootfs 副本和 `snapshot=on`。RV64 启动 .bin，LA64 启动 .elf，均核对了构建清单中的 SHA-256。

## 默认内核

| 检查 | 基线 RV64 / LA64 | 迁移后 RV64 / LA64 |
| --- | --- | --- |
| 启动首个用户程序，进入发行版 shell | 均通过 | 均通过 |
| LTP `execve01` 至 `execve06` | 各 170 项通过 | 各 170 项通过，失败、跳过和损坏均为 0 |
| ELF 主程序存在、`PT_INTERP` 路径缺失 | 均返回 `ENOENT`，原有两线程再次会合 | 两架构结果相同 |
| 设置不同的实际和有效身份后重新执行自身 | 两架构 auxv 均为 UID/EUID 1000/1001、GID/EGID 1002/1003、SECURE 0 | 两架构结果相同 |
| RV64 `AT_HWCAP`，关闭 V / VLEN=128 / VLEN=256 | `0x112d` / `0x20112d` / `0x20112d` | 三种配置相同，两组向量状态切换均通过 |
| LA64 `AT_HWCAP` | CPUCFG1 `0x3f2f2fe`、UAL 开启、HWCAP `0xf` | 相同 |

在 guest 中设置 `LTPROOT=/opt/ltp`，将 `$LTPROOT/testcases/bin` 加入 PATH 并进入该目录。逐项运行六个程序，`execve05 -i 5 -n 32` 使用 LTP runtest 的参数。六项分别通过 1、1、6、1、160、1 条断言。凭证探针先设置 `setresgid(1002,1003,1003)`、`setresuid(1000,1001,1001)`，再 exec 并将 auxv 与四个身份系统调用的返回值逐项核对。[同组线程回归的构建与运行](../tests/exec/README.md)

```sh
make test
cargo test --locked -p elf_loader -p axfeat --lib \
  --features axfeat/multitask,axfeat/irq,axfeat/fs,axtask/test
python3 tests/hwcap/run_rvv.py off --image "$RV_24_04_IMAGE"
python3 tests/hwcap/run_rvv.py on --image "$RV_26_10_IMAGE"
python3 tests/hwcap/run_rvv.py on --vlen 256 --image "$RV_26_10_IMAGE"
python3 tests/hwcap/run.py guest --primary disk-la.img
```

上述主机命令启用装载器所需的文件系统、分配器和任务配置，7 项装载测试全部通过。两种目标的 `cargo tree --locked -p elf_loader --target <target>` 均解析到本地 `axfs` 和 `axmm`，依赖树中没有 `pulse_core` 或 `bpf`。

## BPF 可执行映射

在启用观测的内核中运行以下 guest 命令，保留初始 shell 和新执行的 Bash 的映射记录。

```sh
/usr/bin/bash -c 'echo BPF266_CHILD $$'
cat /proc/pulse_bpf_mappings > /tmp/j266
sha256sum /tmp/j266
```

按 PID 找到 `TASK kind=exec`，取其地址空间在该序号前最近的 `SPACE`。对带执行权限的映射，用对象 ID 找到 `OBJECT`，与 rootfs 中对应 ELF 的 SHA-256、GNU build ID 和 `PT_LOAD` 文件偏移核对。两次 exec 的主文件和动态解释器均匹配，导出日志的 SHA-256 也与 guest 内一致。

| 架构 | PID 1 → 新 exec 的主文件 | 两次 exec 的解释器 | 空间 ID | 日志条数 / 丢失 |
| --- | --- | --- | --- | ---: |
| RV64 | `/usr/bin/dash` → `/usr/bin/bash` | `/usr/lib/riscv64-linux-gnu/ld-linux-riscv64-lp64d.so.1` | 3 → 4 | 331 / 0 |
| LA64 | `/usr/bin/bash` → `/usr/bin/bash` | `/usr/lib64/ld-2.28.so` | 3 → 5 | 1105 / 0 |

再运行现有的六阶段映射测试。两个架构的 `mapped`、`renamed`、`fork`、`exec`、`remapped` 和 `partial_remapped` 断言全部通过。exec 阶段可解析样本为 RV64 13/13、LA64 16/16。整个 capture 分别采到 4866 和 1117 条样本，传输和导出丢失均为 0。两份 capture 的状态均为 `IncompleteError`，分析器禁止完整归因。本次验收只使用映射身份和上述阶段断言。

```sh
make test APP_FEATURES='qemu bpf-trace'
python3 tests/bpf_sampling/run.py guest --arch riscv64 --image disk.img --mode cpu --archive --mappings --timeout 300
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --image disk-la.img --mode cpu --archive --mappings --timeout 300
```

| SHA-256 | RV64 | LA64 |
| --- | --- | --- |
| 基线启动内核 | `7c8e8b298fc37677bfd01253145751cc0db591ad1c5d904c8d3c9f86eb7c9a81` | `fd06f237f2bfbcf5e15962b86246693e73050c163a24f8ea60d8b548b0c4a8db` |
| 迁移后默认启动内核 | `6c0095cc57c58be43217492fc27cecefbc33924587803bf245fe81aa86d5b6a7` | `67568d1eeac4289540f2d503c297ef0b897043d80f95105c8c1e51a3bed47187` |
| BPF 启动内核 | `5b7fb744d7f8c3c88f5683278362337fa6f6833d7df48de23f09390ca0b7088b` | `ea75e8d43c9c7335a47e61ace3c70c44181759a52465b01868b535d6e498a045` |
| 动态解释器检查的 rootfs | `efc83112f60d929ca347d35bea5567f4a00b4272128a615efa16e74325508d1c` | `ef9a74f8c7fdde1e61b10dbe49c1264b8fea859a77571e9b8f5ea4411c86a04f` |
| 两次 exec 的映射日志 | `0822b9fc4a7b324ca564c143946659d6d49308b29226aaea2e363d5e6dfce66d` | `8428618815efcabb25e6e0f213fdc74831074c5f48638af7c11c2c2b065af6c1` |

原始日志在运行主机的 `/tmp/pulse266/`，采样原包在 `tests/bpf_sampling/runs/{riscv64-cpu-20261124-183157-yhf9u48u,loongarch64-cpu-20261124-183242-qriwxdgg}/`。这些本地产物可用于复核，保留期取决于运行主机。
