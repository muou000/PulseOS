# Debug Record

## 1. Basic Info
- Date: 2026-04-03
- Author: GitHub Copilot (GPT-5.3-Codex)
- Branch/Commit: local workspace state (commit not captured in this run)
- Platform/Arch: riscv64 / qemu-virt
- Build Mode: release (boot log shows `build_mode = release`)

## 2. Problem Summary
- Symptom: Kernel panic after `Testing clone` in OS COMP test group.
- Impact: System shuts down before test suite completes.
- First Seen In: manual QEMU run with current `kernel-rv`.
- Reproducibility: 100% in current environment.

## 3. Environment
- Host OS: Linux
- Toolchain: Rust-based ArceOS/PulseOS build outputs
- QEMU/Emulator Command:
```bash
sudo qemu-system-riscv64 -machine virt -kernel kernel-rv -m 1G -nographic -smp 1 -bios default -drive file=sdcard-rv.img,if=none,format=raw,id=x0 -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -no-reboot -device virtio-net-device,netdev=net -netdev user,id=net -rtc base=utc -drive file=disk.img,if=none,format=raw,id=x1 -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
```
- Image/Artifacts: `kernel-rv`, `sdcard-rv.img`, `disk.img`

## 4. Reproduction Steps
1. Start QEMU with the exact command above.
2. Wait for boot and userland test execution (`basic-musl`).
3. Observe panic right after `Testing clone` output.

## 5. Observed Logs
- Key timestamps:
  - `[  8.120945 ... ] Task exit with code: 0`
  - `[  8.122294 ... ] Page fault in kernel space: vaddr=VA:0x3fffffeac`
- Panic/Oops lines:
  - `panicked at ... Unhandled Supervisor Page Fault @ 0xffffffc080201588`
- Register/Trap summary:
  - `sepc = 0xffffffc080201588`
  - Fault access: `WRITE`
  - Fault VA: `0x3fffffeac`

## 6. Investigation Timeline
1. Re-ran QEMU command and captured full console logs.
2. Mapped panic `sepc` via `addr2line` on `target/riscv64gc-unknown-none-elf/release/Pulse`.
3. Confirmed faulting function is `pulse_syscalls::impls::task::sys_wait4`.
4. Inspected source and found direct kernel dereference of user-provided `status` pointer.

## 7. Root Cause Analysis (RCA)
- Trigger condition: `wait4` called with userspace `status` pointer that is not safely writable from kernel direct access path.
- Faulting path: `sys_wait4` writes exit status through raw pointer.
- Why it panics instead of returning errno: no user-pointer validation/copy helper is used; invalid access escalates to supervisor page fault and trap panic.

## 8. Evidence Mapping
- Fault PC -> function/source:
  - `0xffffffc080201588` -> `pulse_syscalls::impls::task::sys_wait4`
- Fault VA:
  - `0x3fffffeac`
- Related source file/line:
  - `pulse_syscalls/src/impls/task.rs` lines near direct write in `sys_wait4`
  - `vendor/axcpu/src/riscv/trap.rs` panic path in `handle_page_fault`

## 9. Fix Plan
- Minimal fix:
  - Replace direct `*status_ptr = ...` with checked userspace write helper.
  - Return `-EFAULT` on invalid pointer or copy failure.
- Safer long-term fix:
  - Centralize `copy_to_user/copy_from_user` APIs and ban raw user pointer dereference in syscall layer.
- Compatibility notes:
  - Linux-compatible `wait4` should fail gracefully with errno, not panic kernel.

## 10. Validation Plan
1. Rebuild kernel image.
2. Re-run the same QEMU command.
3. Confirm:
   - No supervisor page-fault panic in `wait4` path.
   - `basic-musl` clone-related cases continue.
   - Invalid pointer case returns `-EFAULT`.

## 11. Result
- Status: Open
- Notes: RCA completed and fix direction明确，尚未提交代码修复。

## 12. Follow-ups
- TODO-1: Implement safe userspace status write in `sys_wait4`.
- TODO-2: Add regression test for invalid `status` pointer.

## 13. Appendix
```text
[  8.122294 0:9 pulse_core::trap:19] Page fault in kernel space: vaddr=VA:0x3fffffeac
[  8.123863 0:9 axruntime::lang_items:5] panicked at ...
Unhandled Supervisor Page Fault @ 0xffffffc080201588, fault_vaddr=VA:0x3fffffeac (WRITE)
```
