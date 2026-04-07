# PulseOS

基于ArceOS组件化操作系统构建的，尽可能与Linux兼容的宏内核项目。

## 如何开始

```bash
make all #构建用于参与测评的镜像
make test #构建带日志的可参与测评的镜像
make run #构建并运行进入shell环境的Riscv PulseOS
make la #快速构建并运行进入shell环境的Loongarch64 PulseOS
make img_all #构建两种架构的rootfs镜像
```
