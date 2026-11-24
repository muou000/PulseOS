    # The C driver runs on RV64GC and enters these routines only in V mode.
    .option push
    .option arch, +v
    .text
    .global vector_bytes
vector_bytes:
    csrr a0, vlenb
    ret

    # a0/a1: full banks of input/output bytes, a2: four observed CSRs,
    # a3: worker index, a4/a5: own/peer {ready, acknowledged}, a6: round.
    .global vector_round
vector_round:
    csrr t0, vlenb
    slli t0, t0, 3
    .irp n,0,8,16,24
        vl8re8.v v\n, (a0)
        add a0, a0, t0
    .endr

    bnez a3, 1f
    vsetivli zero, 5, e8, m1, tu, mu
    csrwi vcsr, 3
    csrwi vstart, 1
    j 2f
1:  vsetivli zero, 3, e16, m1, ta, ma
    csrwi vcsr, 4
    csrwi vstart, 2

    # The peer can acknowledge this round only after seeing our ready flag.
    # Both workers must execute here after the other's vector writes. They
    # share a single hart and neither makes a syscall or yields in this region.
2:  fence rw, w
    sw a6, 0(a4)
3:  lw t1, 0(a5)
    bltu t1, a6, 3b
    fence rw, rw
    sw a6, 4(a4)
4:  lw t1, 4(a5)
    bltu t1, a6, 4b
    fence r, rw

    csrr t1, vl
    sd t1, 0(a2)
    csrr t1, vtype
    sd t1, 8(a2)
    csrr t1, vcsr
    sd t1, 16(a2)
    csrrw t1, vstart, zero
    sd t1, 24(a2)
    .irp n,0,8,16,24
        vs8r.v v\n, (a1)
        add a1, a1, t0
    .endr
    ret
    .option pop
    .section .note.GNU-stack,"",@progbits
