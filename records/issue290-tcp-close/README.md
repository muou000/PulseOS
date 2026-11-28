# TCP 正常关闭验收（#290）

QEMU virt，8 vCPU、8 GiB，user 网络转发到来宾的 stock darkhttpd 1.17。每次短连接都请求 65,536 个零字节并读至 EOF。完成一次要求 HTTP 200、Content-Length 和实收长度均为 65,536、SHA256 为 `de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31`。每个表格单元的三项分别是三轮的完整响应数，每轮 32 次。

| 内核 | 架构 | 并发 1 | 并发 8 | 服务端 access log 中 HTTP 200 |
|---|---|---|---|---|
| 基线 | RV64 | 32 / 32 / 32 | 32 / 32 / 32 | 192/192 |
| 基线 | LA64 | 26 / 27 / 21 | 15 / 14 / 11 | 192/192 |
| 修复 | RV64 | 32 / 32 / 32 | 32 / 32 / 32 | 192/192 |
| 修复 | LA64 | 32 / 32 / 32 | 32 / 32 / 32 | 192/192 |

RV64 基线另一次单轮并发 1 有 31/32 完整。三轮中的 64 KiB 慢读对照也在 56,472 字节处提前 EOF。LA64 基线三轮共 114/192 完整，其余 68 次在正文提前 EOF，7 次超时，3 次在状态行之前 EOF。

在最终内核上，LA64 还做了两组三轮复测。按运行顺序，第一组有 191/192 次成功，之后的共享宿主与单独运行 QEMU 两组均为 192/192。表中选取的是单独运行的一组。第一组的失败发生在状态行之前，逐请求表记录了该请求的超时，服务端访问日志和链路统计仍显示后续完整响应。独立临时抓包显示，QEMU 在旧连接关闭约 1.55 秒后重用相同四元组，仍处于 TIME-WAIT，握手约等待 17.95 秒，超过主机客户端 8 秒读超时。该抓包没有纳入仓库，仓库保留了逐请求结果和访问日志。当前实现保留 smoltcp 的 TIME-WAIT 处理，相同四元组快速重连可能需要等待。[两次共享宿主复测的逐请求结果](http-la-shared.tsv.gz) · [RFC 9293 §3.6.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.6.1)

## 关闭因果链

在 RV64 基线内核 `3f8b3396` 上加入三个临时日志点。一次短响应中，darkhttpd 的 `sendfile(fd=5, count=65536)` 在来宾单调时钟 4.679022 s 返回 65,536。4.681148 s 关闭 FD 5。4.682511 s 移除 handle #1 时，TCP 处于 FIN-WAIT-1，发送队列还有 65,766 字节（含 230 字节响应头）。VirtIO 抓包中的同一连接只送出并确认了 65,535 字节，客户端收到 HTTP 200 和 65,305 字节正文。首个 RST 由来宾发出，连接上未出现 FIN。对照客户端读完响应头后主动终止连接，链路的首个 RST 由对端发出。观测 BIN 的 SHA256 为 `3da43f1cb43558ec4e7da1f1f773e25f245e3a8620ec38df4620bd99e0f8cf8b`。

## 生命周期对照

- 两架构在同一个持续连接上分别完成 8 个请求。把主机接收缓冲设为 4 KiB 并推迟 500 ms 读取后，64 KiB 与 2 MiB 正文均完整。2 MiB 传输中实际观察到了对端通告零窗口，恢复读取后 FIN 得到确认。主动放弃对照从主机读到 200 后以零 linger 关闭，链路上首个 RST 来自对端，后续请求正常。
- 用来宾 loopback 使接收窗口饱和。通过 `dup` 保留 FD，关闭原 FD 后成功发送 393,216 字节，再关闭最后一个 FD，最后才读取。基线在 RV64 / LA64 分别收到 262,140 / 262,141 字节就返回 EOF。修复后每架构连续 5 轮均收齐 393,216 字节，随后收到 EOF，源端口在约 10 秒后可复用。
- 480 KiB 慢读对照在第 35 秒读出 128 KiB，再等 35 秒读完，单次接收超时保持 5 秒。评审中的中间内核 `0d059ca2` 曾在收到 401,404 字节后返回 ETIMEDOUT。修复在实际消费 RX 数据后唤醒网络轮询，使新窗口及时送达。每架构连续两轮收齐全部 491,520 字节并收到 EOF，仓库中的 `slow` 子命令也单独在两架构上复跑。
- 在对端收到 FIN 后保持写半端打开，确认本地源端口仍然占用。静置 65 秒后可重新绑定。另用 1 秒建连超时走本地显式 abort 路径，再验证源端口释放。跨线程最后关闭能唤醒 epoll 的 HUP/ERR 注册。控制日志记录了固定源端口在 TIME-WAIT 内建连超时，以及等待后用相同四元组重新建立连接并成功传输。

[来宾结果摘录](controls.tsv) 逐条记录测试命令的退出码、实收字节、EOF 和端口回收。主机 smoltcp 库的 589 项单元测试和 7 项文档测试全部通过。双架构内核构建使用 `make test`。

## 环境与证据

QEMU 11.1.50 (v11.1.0-2112-g2a0ac9c8ac)，双架构使用相同版本的 [rootfs 测试镜像](https://github.com/muou000/PulseOS/releases/tag/rootfs-tests-20261125)，磁盘以快照模式打开。VirtIO 抓包取自 QEMU 的 guest-facing 接口，表中的 peer 是 QEMU user 网络栈。主机客户端独立测量最终交付的正文。

| 启动产物 | RV64 BIN SHA256 | LA64 ELF SHA256 |
|---|---|---|
| `3f8b3396` | `58a3a18d2af7b25c7f77068dddd351b07ebafa4bedd83c996e5ce51cb73151ef` | `845eb9a9198d3fb77ad5d48d072351f878d8b7aeb19f8ccc46ee558509d79465` |
| `516bff19` | `b7ab89500bc6a68b4db9befff4e081002e22eb72ddfd05abf3adc610463f64ef` | `6136fc1566d833d239edcc6fbee4589f04ec9e0358de6272b2d7a5f3c193d435` |

磁盘 SHA256 分别为 RV64 `1c85641c81d923211ca2229275ab9870203a098341d9e1363c237831cc79a1ab` 和 LA64 `1a0f51586aaf24f9d8c652e55d44b648c9fd949e068ab31b41a38c49573e6df3`。

[三轮逐请求记录](http-responses.tsv.gz) 和 [额外单轮基线](http-first-baseline.tsv.gz) 记录了客户端的 HTTP 状态、声明与实收长度、正文 SHA256 和 EOF。相同 User-Agent 关联独立采集的 [darkhttpd 访问日志](access-logs.tar.gz) 与链路事件。服务端字节数含响应头。数据和 ACK 的位置以 TCP 的第一个数据字节为零点，ACK 到 FIN 位置加一表示 FIN 已被确认。持续连接的八条记录共享同一条 TCP 流的链路统计。

## 复跑

在仓库 README 的 QEMU 启动命令中，为 user netdev 添加 `,hostfwd=tcp:127.0.0.1:18080-:8080`。在来宾执行以下命令。

```sh
dd if=/dev/zero of=/opt/netbench/www/large.bin bs=65536 count=1
dd if=/dev/zero of=/opt/netbench/www/slow.bin bs=65536 count=32
darkhttpd /opt/netbench/www --addr 0.0.0.0 --port 8080 --log /tmp/access
```

在宿主的仓库根目录执行 `python3 tests/tcp_close/http_close.py --port 18080 > responses.json`，再从来宾单独读取 `/tmp/access`。脚本为每次请求设置独立的 User-Agent。慢读对照请求 4 KiB 接收缓冲，发送请求后等 500 ms 再读取。持续连接对照的八个请求复用同一 TCP 连接。

用目标架构的 Linux GCC 静态编译生命周期探针，例如 `riscv64-linux-gnu-gcc -O2 -static tests/tcp_close/lifecycle.c -o tcp-close`。将可执行文件装入测试镜像副本的根目录，在来宾分别运行 `/tcp-close drain`、`/tcp-close slow`、`/tcp-close orphan` 和 `/tcp-close abort`。最后一项使用 QEMU user 子网上未分配的 10.0.2.250 触发建连超时。
