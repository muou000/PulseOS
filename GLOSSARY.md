# PulseOS

PulseOS is a multi-architecture kernel whose domain model spans processes, descriptors, user memory, filesystems, and guest-visible system calls.

## Language

### Descriptor and I/O behavior

**就绪等待**:
等待一组描述符达到请求事件，同时处理通知、信号和 deadline，并返回每个描述符的观察结果。
_Avoid_: readiness polling, generic waiting

**I/O 操作**:
在用户缓冲区、描述符对象和文件位置之间完成一次或多次读写，并定义部分完成、错误和信号结果。
_Avoid_: read/write helper, transport operation

### Memory and process lifecycle

**映射页生命周期**:
文件或匿名页从准备、发布到映射、TLB 完成、脏页发布和退休的全过程。`prepared` 资源尚未发布，只能由其准备对象清理；`published` 映射必须等待 TLB completion 后才能退休。文件 fault 的准备还携带 mapping identity 和权限快照，用于拒绝同一虚拟地址上的陈旧提交。脏页发布只更新 page-cache 状态，storage durability 还需要显式同步。
_Avoid_: page-cache wrapper, mapping helper

**子进程退休**:
终态 child 被 wait 消费后，完成 accounting、task 引用、资源缩减、描述符影响和全局注销的过程。
_Avoid_: child cleanup, process deletion
