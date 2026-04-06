# LoongArch64 无输出排查与修复记录

日期: 2026-04-05 (Asia/Shanghai)

## 目标
修复 `./run_test.sh > tmp.txt 2>&1` 后 loongarch64 无法正常输出的问题，仅修改项目代码，不修改测评程序。

## 结论（结果）
- loongarch64 目前可以正常输出并进入用户态运行基础测试。
- 最新测试汇总显示总数 284，其中 `basic-glibc-la=64`、`basic-musl-la=64`。
- 仍有部分 syscall 未实现导致测试失败：`times(153)`、`mount(40)`、`unlinkat(35)`。

## 关键排查过程（摘要）
1. 在测评 docker 环境使用 `QEMU 10` 时无输出；开启 `-d guest_errors` 发现 instruction fetch 地址异常（非 canonical VA）。
2. 确认 LoongArch 高半区 VA 需要 canonical（`0xffff_8000_...`），并且链接脚本需要设置 LMA（物理加载地址）与 VMA（虚拟地址）分离。
3. 修改 `linker.lds.S` 增加 `%PHYS_VIRT_OFFSET%` 并为 `.text/.rodata/.data/.bss/.percpu` 设置 `AT()`，保证 LMA=PA，VMA=VA。
4. 调整 `axconfig.toml` 的 `kernel-base-vaddr / phys-virt-offset / kernel-aspace-*` 以匹配 canonical VA 与高半区映射。
5. 修复 LoongArch 启动页表映射、FP 不可用 trap（开启 FP/LSX），以及 trap 处理中 `ecode==0` 的未知异常回退为 IRQ 处理。
6. 运行后 loongarch 输出恢复，进入测试阶段。

## 修改点（文件级）
- `arceos/modules/axhal/linker.lds.S`
  - 增加 `%PHYS_VIRT_OFFSET%` 占位符。
  - `.text.boot` 单独 section。
  - `.text/.rodata/.data/.bss/.percpu` 使用 `AT(ADDR(...) - PHYS_VIRT_OFFSET)`。
  - `. = BASE_ADDRESS;` 在 `.text.boot` 前。
- `arceos/modules/axhal/build.rs`
  - 替换 `%PHYS_VIRT_OFFSET%` 占位符。
- `vendor/axplat-loongarch64-qemu-virt/axconfig.toml`
  - `kernel-base-vaddr = 0xffff_8000_8000_0000`
  - `phys-virt-offset = 0xffff_8000_0000_0000`
  - `kernel-aspace-base = 0xffff_8000_0000_0000`
  - `kernel-aspace-size = 0x0000_7fff_ffff_f000`
- `vendor/axplat-loongarch64-qemu-virt/src/boot.rs`
  - 添加 `BOOT_PT_L0[0x100]` 映射。
  - `enable_fp_simd()` 调用 `enable_fp()` 与 `enable_lsx()`（启用 FP/LSX）。
- `vendor/axplat-loongarch64-qemu-virt/src/console.rs`
  - 初始化 UART 与直接输出；去重输出路径。
- `vendor/axplat-loongarch64-qemu-virt/src/init.rs`
  - `init_early()` 调用 `console::init()`。
- `vendor/axcpu/src/loongarch64/trap.rs`
  - `Trap::Unknown` 且 `ecode==0` 时回退为 IRQ 处理。
  - panic 信息增加 `ecode/esub/is/from_user`。
- `Cargo.toml` 与 `Cargo.lock`
  - 添加 `[patch.crates-io] axplat-loongarch64-qemu-virt = { path = "vendor/axplat-loongarch64-qemu-virt" }`。
- `Makefile`
  - loongarch 构建参数启用（如 `FEATURES=bus-pci`），日志级别调整。

## 关键验证信息
- `readelf -l kernel-la` 显示 VMA 为 `0xffff_8000_8000_0000`，LMA 为 `0x8000_0000`。
- `PulseOS/os_serial_out_la.txt` 有完整 boot + 测试输出。

## 仍待处理（下一步方向）
- 实现或对接 syscall：`times(153)`、`mount(40)`、`unlinkat(35)`。
- 继续跑全量测试并对残余失败项逐个定位。
