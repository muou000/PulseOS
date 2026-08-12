= 测试问题与解决

== 跑通测试遇到的问题

跑通测试的过程中遇到了以下问题：

+ 旧 `PipeObject` 仅处理 `FIONREAD`，对未知请求返回 `ENOTTY`：为 pipe 增加`FIONBIO`支持。

+ TTY ioctl 的兼容回退被错误地应用到 pipe 等非终端对象：将兼容回退限制为真实的 devfs TTY，其他文件描述符返回 `ENOTTY`。

+ `execve/execveat` 会对多线程执行直接返回`EAGAIN`： 将整个 exec 串行化，并在不可逆切换前完成新映像装载，随后请求并等待 sibling 退出，再替换映像。

+ 将不含 PT_INTERP 的 direct ET_DYN 误判为不受支持：增加对 direct ET_DYN 的支持，并补齐 load bias、auxv 与初始栈。

+ 动态装载窗口约 62 MiB，无法容纳约 147 MiB 的 PT_LOAD 段，导致 rust-lld 映射时报 ENOMEM：在共享动态区域按 p_align 搜索不重叠的空闲区进行装载。

== 测试计时

测试评分依据是内核提供的`/proc/uptime`,因此我们为PulseOS实现了`/proc/uptime`这一评分时间来源。
