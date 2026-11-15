# #73 / #74：移除闲置网卡驱动的验证记录

日期：2026-11-15。基线：`4270e15c`（与分诊时的 `e9ddf8cd` 源码树一致）。

## 改动边界

移除 ixgbe / FXmac 的三级 Cargo feature、驱动注册与探测、专用适配代码、
外部 Git 依赖和当前功能说明。旧 feature 请求明确报不存在，不保留空兼容入口。
共享 DMA/PCI/IRQ、通用网络缓冲接口、VirtIO、VisionFive 2 DWMAC 和其他设备支持保留。

锁文件仅移除 `ixgbe-driver`、`fxmac_rs` 及不再可达的 `core_detect 1.0.0`、
`volatile 0.3.0`，没有升级或新增其他包。`axdriver` 不再直接依赖 `crate_interface`，
其他使用者和 workspace 定义保留。

## 构建与已有测试

构建均保留默认日志，使用 `set -o pipefail`，通过 `tee` 保存输出后取末 30 行。

| 检查 | 改动前 | 改动后 |
| --- | --- | --- |
| `make test`：RV64 + LoongArch64 | 通过（分诊期间） | 通过 |
| `make vf2` | 通过 | 通过 |
| `make ls2k1000` | 通过 | 通过 |
| `cargo metadata --locked --format-version 1` | — | 通过 |
| `cargo test --locked -p axdriver_net --features starfive-jh7110-dwmac --lib` | — | 41 passed |
| `git diff --check` | — | 通过 |

`cargo metadata` 的首次离线尝试发现本机缺少已锁定的 `serde 1.0.229`；允许正常下载后通过，
未更新版本。构建有既存 warning，本次没有顺带修改无关代码。

以下六条检查均按预期失败，诊断为 `the package ... does not contain this feature`：

```bash
cargo check --locked -p axfeat --features driver-ixgbe
cargo check --locked -p axfeat --features driver-fxmac
cargo check --locked -p axdriver --features ixgbe
cargo check --locked -p axdriver --features fxmac
cargo check --locked -p axdriver_net --features ixgbe
cargo check --locked -p axdriver_net --features fxmac
```

生效源码、构建配置和当前文档中的对应驱动引用已清除；本记录中的历史名称不作为残留。

## QEMU 启动与网络回归

改动前、后均在两个架构完成以下检查：

1. 按仓库规定的 QEMU 参数启动：8 GiB、8 vCPU、`snapshot=on`。
2. 日志确认选择 `virtio-net`，加载用户程序并到达 shell。
3. 从主机 HTTP 服务下载 65,536 字节固定 ASCII 数据，在客体内校验 SHA-256。
4. 将完整数据 POST 回主机，由主机逐字节比较并返回 HTTP 200。
5. 所有客体命令返回 0，捕获日志中没有 panic。测试结束后终止并回收 QEMU，关闭测试 HTTP 服务。

RV 使用根目录的 `disk.img`（BusyBox），LA 使用 `disk-la.img`（bash/curl/coreutils）。
每次运行在临时目录将匹配的镜像链接为 `disk.img`，内核链接为 `kernel-rv` / `kernel-la`，
因此使用的是下列原始命令；未写入源磁盘镜像。

```bash
qemu-system-riscv64 -machine virt -kernel kernel-rv -m 8G -nographic -smp 8 -bios default -drive file=disk.img,if=none,format=raw,id=x0,snapshot=on -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -no-reboot -device virtio-net-device,netdev=net -netdev user,id=net -rtc base=utc
qemu-system-loongarch64 -machine virt -kernel kernel-la -m 8G -nographic -smp 8 -drive file=disk.img,if=none,format=raw,id=x0,snapshot=on -device virtio-blk-pci,drive=x0 -no-reboot -device virtio-net-pci,netdev=net0 -netdev user,id=net0 -rtc base=utc
```

测试数据由下面的表达式生成，SHA-256 为
`4deb7c76478522bb1ebb06a9581f1f5ac606bcf201c65600455842e77015e2a9`：

```python
(b'PulseOS network regression payload 0123456789abcdef\n' * 2048)[:65536]
```

主机服务只监听 `127.0.0.1` 的临时端口，客体通过 `10.0.2.2` 访问。
`GET /payload.bin` 返回上述数据，`POST /verify` 检查长度及逐字节一致性，失败返回非 2xx。
RV 使用 `busybox wget` 下载和 `--post-file` 上传，`busybox sha256sum -c -` 校验；
LA 使用 `curl -f --noproxy '*' --max-time 20` 下载和 `--data-binary` 上传，
`coreutils --coreutils-prog=sha256sum -c -` 校验。两端客体保存的下载内容都是上传的来源。

改动后主机端证据（两个架构均相同）：

```text
GET /payload.bin HTTP/1.1 -> 200
GET_SENT bytes=65536 sha256=4deb7c76478522bb1ebb06a9581f1f5ac606bcf201c65600455842e77015e2a9
POST_PASS bytes=65536 sha256=4deb7c76478522bb1ebb06a9581f1f5ac606bcf201c65600455842e77015e2a9
POST /verify HTTP/1.1 -> 200
NET_GET_RC=0
NET_HASH_RC=0
NET_POST_RC=0
NET_POST_RESULT_RC=0
```

实际运行的改后内核 SHA-256：

| 内核 | SHA-256 |
| --- | --- |
| RV64 `kernel-rv` | `19383362ed86bff25fd3005b02df6f989caa0725d6e3a37b1f63f6f4b119353c` |
| LoongArch64 `kernel-la` | `9b643374bec4b07e83a5b2adc6082f5155a89311a08387d37af13a168a12c139` |

两者均不同于基线内核，复测后再次核对文件哈希一致。完整本地构建日志、QEMU argv、
客体日志、主机 HTTP 日志和可重跑的临时脚本保存在 `/tmp/pulseos-73-74-validation/`；
本记录保留核心结果、命令和判据。

## 验证边界

- 初始基线曾尝试含 NUL 的二进制 POST。RV BusyBox `wget --post-file` 实际发送
  `Content-Length: 0`，被测试服务拒绝；改用固定 ASCII 后改动前后均通过。
  此处只记录观察到的客体工具限制，不据此推断内核网络缺陷。
- 分诊时 LA 误用 RV 磁盘的 `InvalidExecutable` 已通过匹配镜像解决；本次 LA 到达真实 shell。
- 未进行 VisionFive 2 或 LS2K1000LA 实板运行测试。交叉构建和 QEMU VirtIO 回归不等于板载网口验收。
- 本任务没有实现 AIC8800 或 LS2K1000LA GMAC，也不再验证已经移除的 Intel/Phytium 驱动。
