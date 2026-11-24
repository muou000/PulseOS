<h1 align="center">poll</h1>

<p align="center">A library for polling I/O events and waking up tasks</p>

<div align="center">

[![Crates.io](https://img.shields.io/crates/v/axpoll.svg)](https://crates.io/crates/axpoll)
[![Docs.rs](https://docs.rs/axpoll/badge.svg)](https://docs.rs/axpoll)
[![Rust](https://img.shields.io/badge/edition-2024-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

</div>

[English](README.md) | 中文

# 介绍

PulseOS 的 `poll` 提供 I/O 就绪事件和任务唤醒，源自 TGOSKits 的 `axpoll` 组件。

## 快速开始

### 添加依赖

在 PulseOS 工作区成员的 `Cargo.toml` 中加入以下依赖。

```toml
[dependencies]
poll.workspace = true
```

### 检查与测试

```bash
# 进入 crate 目录
cd modules/poll

# 代码格式化
cargo fmt --all

# 运行 clippy
cargo clippy --all-targets --all-features

# 运行测试
cargo test --locked -p poll --features ax-kspin/host-test,ax-kspin/smp

# 生成文档
cargo doc --no-deps
```

## 集成方式

### 示例

```rust
use poll::IoEvents;

fn main() {
    assert!(IoEvents::ALWAYS_POLL.contains(IoEvents::ERR));
}
```

### 文档

生成并查看 API 文档：

```bash
cargo doc --no-deps --open
```

在线文档：[docs.rs/axpoll](https://docs.rs/axpoll)

# 贡献

1. Fork 仓库并创建分支
2. 在本地运行格式化与检查
3. 运行与该 crate 相关的测试
4. 提交 PR 并确保 CI 通过

# 许可证

本项目采用 Apache License 2.0 许可证。详情见 [LICENSE](./LICENSE)。
