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
## 注

对于loongarch64 musl对于cyclictest中进程调度相关syscalls的实现不完整，直接在build_img.sh中添加了对应的patch修补libc，使其能调用对应syscalls（由ai实现，详见 [records/ai-logs/Coder/2026-05-02-cyclictest-musl-scheduler.md](records/ai-logs/Coder/2026-05-02-cyclictest-musl-scheduler.md)）
``` sh
patch_loongarch64_musl_sched_stubs() {
    local stage_dir="$1"
    local ld_musl="${stage_dir}/lib64/ld-musl-loongarch-lp64d.so.1"

    [[ -f "${ld_musl}" ]] || return 0

    # Alpine's current loongarch64 musl keeps a few scheduler entry points as
    # ENOSYS stubs.  rt-tests/cyclictest calls these libc symbols directly, so
    # the kernel never sees sched_getparam/sched_getscheduler unless the loader
    # forwards them to the Linux syscalls.
    perl -0pi -e '
        s/\x63\xc0\xff\x02\x04\x68\xbf\x02\x61\x20\xc0\x29\xff\x83\xbf\x54/\x0b\xe4\x81\x02\x00\x00\x2b\x00\x84\x80\x40\x00\x20\x00\x00\x4c/g;
        s/\x63\xc0\xff\x02\x04\x68\xbf\x02\x61\x20\xc0\x29\xff\x63\xbf\x54/\x0b\xe0\x81\x02\x00\x00\x2b\x00\x84\x80\x40\x00\x20\x00\x00\x4c/g;
        s/\x63\xc0\xff\x02\x04\x68\xbf\x02\x61\x20\xc0\x29\xff\x1f\xbf\x54/\x0b\xd8\x81\x02\x00\x00\x2b\x00\x84\x80\x40\x00\x20\x00\x00\x4c/g;
        s/\x63\xc0\xff\x02\x04\x68\xbf\x02\x61\x20\xc0\x29\xff\xff\xbe\x54/\x0b\xdc\x81\x02\x00\x00\x2b\x00\x84\x80\x40\x00\x20\x00\x00\x4c/g;
    ' "${ld_musl}"
}
```

以上为对于测例的针对性修改的说明，个人认为并不违反比赛规则，并没有对测例文件进行直接修改，也并没有对某些测试测试时进行作弊式修改。