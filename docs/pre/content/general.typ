#import "../components/prelude.typ": *

= 概述

== 介绍

PulseOS 是一款使用 Rust 语言编写的、基于 ArceOS 组件化内核构建的、支持多架构的组件化宏内核操作系统。PulseOS 针对 RISC-V 64 与 LoongArch 64 双架构进行了深度适配与统一抽象，完整实现了进程管理、文件系统、内存管理、信号系统，以及网络模块。

PulseOS 提供了POSIX兼容的系统调用接口，以提供Linux兼容的功能，能够运行musl-libc与glibc编译的用户态应用程序，并且通过了 `basic`, `busybox`, `cyclictest`, `iozone`, `iperf`, `libcbench`, `libctest`, `lmbench`, `ltp`, `lua`, `netperf` 等初赛测例，并在部分性能测试项中取得了较为优秀的成绩。

== 整体架构

PulseOS 的整体软件栈可分为四个层次：

#align(center)[
  #image("../img/1.png", width: 103%)
]

用户空间程序通过 musl-libc 或 glibc 提供的 C 库接口发起系统调用。当触发软中断时，系统陷入内核的 Trap 异常分发模块。系统调用派发器将控制权分发给内核服务层对应的模块，这些模块通过 ArceOS 的高度组件化基础单元提供硬件隔离的安全保障，并在 RISC-V 64 与 LoongArch 64 上完美运行。
