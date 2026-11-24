// The baseline kernel uses RV64GC. Only the platform-gated routines here may
// issue vector instructions. Keep the object-level ISA attribute at baseline.
.section .text
.option push
.option arch, +v
.balign 4

.macro vector_groups op
    \op v0, (a0)
    add a0, a0, a2
    \op v8, (a0)
    add a0, a0, a2
    \op v16, (a0)
    add a0, a0, a2
    \op v24, (a0)
.endm

.global riscv_save_vectors
.type riscv_save_vectors, @function
riscv_save_vectors:
    csrrw t0, vstart, zero
    csrr t1, vl
    csrr t2, vtype
    csrr t3, vcsr
    sd t0, {vstart}(a1)
    sd t1, {vl}(a1)
    sd t2, {vtype}(a1)
    sd t3, {vcsr}(a1)
    vector_groups vs8r.v
    csrw vstart, t0
    ret
.size riscv_save_vectors, .-riscv_save_vectors

.global riscv_restore_vectors
.type riscv_restore_vectors, @function
riscv_restore_vectors:
    csrw vstart, zero
    vector_groups vl8re8.v
    ld t0, {vl}(a1)
    ld t1, {vtype}(a1)
    vsetvl zero, t0, t1
    ld t0, {vcsr}(a1)
    csrw vcsr, t0
    ld t0, {vstart}(a1)
    csrw vstart, t0
    ret
.size riscv_restore_vectors, .-riscv_restore_vectors

.global riscv_zero_vectors
.type riscv_zero_vectors, @function
riscv_zero_vectors:
    csrw vstart, zero
    vsetvli t0, zero, e8, m8, ta, ma
    vmv.v.i v0, 0
    vmv.v.i v8, 0
    vmv.v.i v16, 0
    vmv.v.i v24, 0
    vsetivli zero, 0, e8, m1, tu, mu
    csrw vcsr, zero
    ret
.size riscv_zero_vectors, .-riscv_zero_vectors
.option pop
