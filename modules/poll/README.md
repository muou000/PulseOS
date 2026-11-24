<h1 align="center">poll</h1>

<p align="center">A library for polling I/O events and waking up tasks</p>

<div align="center">

[![Crates.io](https://img.shields.io/crates/v/axpoll.svg)](https://crates.io/crates/axpoll)
[![Docs.rs](https://docs.rs/axpoll/badge.svg)](https://docs.rs/axpoll)
[![Rust](https://img.shields.io/badge/edition-2024-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

</div>

English | [中文](README_CN.md)

# Introduction

The PulseOS `poll` crate provides I/O readiness events and task wakeups. It derives from the TGOSKits `axpoll` component.

## Quick Start

### Installation

For a PulseOS workspace member, add the dependency to its `Cargo.toml`.

```toml
[dependencies]
poll.workspace = true
```

### Run Check and Test

```bash
# Enter the crate directory
cd modules/poll

# Format code
cargo fmt -p poll

# Run clippy
cargo clippy --all-targets --all-features

# Run tests
cargo test --locked -p poll --features ax-kspin/host-test,ax-kspin/smp

# Build documentation
cargo doc --no-deps
```

## Integration

### Example

```rust
use poll::IoEvents;

fn main() {
    assert!(IoEvents::ALWAYS_POLL.contains(IoEvents::ERR));
}
```

### Documentation

Generate and view API documentation:

```bash
cargo doc --no-deps --open
```

Online documentation: [docs.rs/axpoll](https://docs.rs/axpoll)

# Contributing

1. Fork the repository and create a branch
2. Run local format and checks
3. Run local tests relevant to this crate
4. Submit a PR and ensure CI passes

# License

Licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for details.
