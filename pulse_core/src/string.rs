#[cfg(target_arch = "riscv64")]
use core::arch::global_asm;

#[cfg(target_arch = "riscv64")]
global_asm!(
    r#"
    .section .text
    .global memcpy
    .type memcpy, @function
memcpy:
    mv t6, a0
    li t0, 32
    bltu a2, t0, .L_memcpy_small
.L_memcpy_loop32:
    ld t0, 0(a1)
    ld t1, 8(a1)
    ld t2, 16(a1)
    ld t3, 24(a1)
    sd t0, 0(a0)
    sd t1, 8(a0)
    sd t2, 16(a0)
    sd t3, 24(a0)
    addi a1, a1, 32
    addi a0, a0, 32
    addi a2, a2, -32
    li t0, 32
    bgeu a2, t0, .L_memcpy_loop32

.L_memcpy_small:
    li t0, 8
    bltu a2, t0, .L_memcpy_bytes
.L_memcpy_loop8:
    ld t0, 0(a1)
    sd t0, 0(a0)
    addi a1, a1, 8
    addi a0, a0, 8
    addi a2, a2, -8
    li t0, 8
    bgeu a2, t0, .L_memcpy_loop8

.L_memcpy_bytes:
    beqz a2, .L_memcpy_end
.L_memcpy_loop1:
    lb t0, 0(a1)
    sb t0, 0(a0)
    addi a1, a1, 1
    addi a0, a0, 1
    addi a2, a2, -1
    bnez a2, .L_memcpy_loop1

.L_memcpy_end:
    mv a0, t6
    ret

    .global memset
    .type memset, @function
memset:
    mv t6, a0
    andi a1, a1, 0xff
    slli t0, a1, 8
    or a1, a1, t0
    slli t0, a1, 16
    or a1, a1, t0
    slli t0, a1, 32
    or a1, a1, t0

    li t0, 32
    bltu a2, t0, .L_memset_small
.L_memset_loop32:
    sd a1, 0(a0)
    sd a1, 8(a0)
    sd a1, 16(a0)
    sd a1, 24(a0)
    addi a0, a0, 32
    addi a2, a2, -32
    li t0, 32
    bgeu a2, t0, .L_memset_loop32

.L_memset_small:
    li t0, 8
    bltu a2, t0, .L_memset_bytes
.L_memset_loop8:
    sd a1, 0(a0)
    addi a0, a0, 8
    addi a2, a2, -8
    li t0, 8
    bgeu a2, t0, .L_memset_loop8

.L_memset_bytes:
    beqz a2, .L_memset_end
.L_memset_loop1:
    sb a1, 0(a0)
    addi a0, a0, 1
    addi a2, a2, -1
    bnez a2, .L_memset_loop1

.L_memset_end:
    mv a0, t6
    ret
    "#
);
