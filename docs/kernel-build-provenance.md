# Kernel build provenance

根目录 Pulse Rust 内核的 `make rv`、`make la`、`make test` 构建在成功后生成
`<OUT_ELF>.provenance.json`。例如 RV64 的文件为
`PulseOS_riscv64-qemu-virt.elf.provenance.json`；保留内核时应同时保留它。

`scripts/build_provenance.py start` 在配置生成后、Cargo 编译前记录：

- 当时的 Git commit、受管输入范围内的 Git dirty 状态，以及实际文件内容的 SHA-256；
- 实际 `.axconfig.toml` 内容与 SHA-256、目标架构、target、平台、profile、展开后的 features；
- `RUSTFLAGS`、内核使用的 `AX_*` 配置和 rustc/Cargo 版本。

objcopy 完成后，`finish` 再次检查源文件与配置未变化，记录最终 ELF、裸二进制和
链接脚本的 SHA-256。编译期间修改了受管输入会让构建失败，必须重新构建。
开始新构建时清除旧 sidecar，失败构建不能留下被误认成新结果的来源文件。
`make clean` 会清除这些生成文件。

受管源目录是 `.cargo/`、`api/`、`crates/`、`modules/`、`platforms/`、
`pulse_syscalls/`、`src/`、`configs/` 和 `scripts/make/`。
进程、SysV IPC、ELF 装载和 BPF 实现均由 `modules/` 覆盖。
根 `Cargo.toml`、`Cargo.lock`、`Makefile`、存在时的 `rust-toolchain[.toml]`
和 provenance 脚本自身也计入。文件树摘要包含未跟踪及被 Git 忽略的嵌入文件，
避免漏掉 `.incbin` / `include_bytes!` 输入；排除 `.git`、`target`、Python 缓存目录。
`git_worktree_dirty` 仅表示上述范围的 Git 状态，实际内容以 `tree_sha256` 标识。
这是保守的工作区范围，包含部分不进入当前内核的 crate；并行修改这些 crate
也会使检查失败。guest harness、run artifact 和文档不在该范围内。

采集工具应调用 `verify_manifest(manifest_path, elf_path, boot_path)`，校验保存的
ELF 和实际启动镜像的哈希。该函数不读取当前 Git HEAD；事后切换分支或编辑工作区
不会改变旧内核的来源。没有匹配 sidecar 时，source commit 应标记为 unknown，
不能用采集时的 HEAD 补填。artifact 路径只是记录，匹配依据是传入文件的实际哈希。

此文件用于构建证据，不是签名或 hermetic/reproducible-build 证明。外部 Cargo
依赖由 `Cargo.lock` 标识，未证明本机依赖缓存的内容；前后检查也不能侦测期间修改后
又还原的输入。该机制适用于本仓库根内核构建；外部 `APP` 或 C app 不生成本协议文件。

协议回归：

```bash
python3 -m unittest discover -s scripts -p test_build_provenance.py
```
