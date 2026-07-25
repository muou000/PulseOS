macro_rules! include_asm_macros {
    () => {
        r#"
        .ifndef REGS_MACROS_FLAG
        .equ REGS_MACROS_FLAG, 1

        // CSR list
        .equ LA_CSR_PRMD,          0x1
        .equ LA_CSR_EUEN,          0x2
        .equ LA_CSR_ERA,           0x6
        .equ LA_CSR_PGDL,          0x19    // Page table base address when VA[47] = 0
        .equ LA_CSR_PGDH,          0x1a    // Page table base address when VA[47] = 1
        .equ LA_CSR_PGD,           0x1b    // Page table base
        .equ LA_CSR_PWCL,          0x1c
        .equ LA_CSR_PWCH,          0x1d
        .equ LA_CSR_TLBRENTRY,     0x88    // TLB refill exception entry
        .equ LA_CSR_TLBRBADV,      0x89    // TLB refill badvaddr
        .equ LA_CSR_TLBRERA,       0x8a    // TLB refill ERA
        .equ LA_CSR_TLBRSAVE,      0x8b    // KScratch for TLB refill exception
        .equ LA_CSR_TLBRELO0,      0x8c    // TLB refill entrylo0
        .equ LA_CSR_TLBRELO1,      0x8d    // TLB refill entrylo1
        .equ LA_CSR_TLBREHI,       0x8e    // TLB refill entryhi
        .equ LA_CSR_DMW0,          0x180
        .equ LA_CSR_DMW1,          0x181

        .equ KSAVE_KSP,            0x30
        .equ KSAVE_TEMP,           0x31
        .equ KSAVE_R21,            0x32
        .equ KSAVE_TP,             0x33

        .macro STD rd, rj, off
            st.d   \rd, \rj, \off*8
        .endm
        .macro LDD rd, rj, off
            ld.d   \rd, \rj, \off*8
        .endm

        .macro PUSH_POP_GENERAL_REGS, op
            \op    $r0,  $sp, 0
            \op    $ra,  $sp, 1
            // 2: tp handled manually
            // 3: sp handled manually
            \op    $a0,  $sp, 4
            \op    $a1,  $sp, 5
            \op    $a2,  $sp, 6
            \op    $a3,  $sp, 7
            \op    $a4,  $sp, 8
            \op    $a5,  $sp, 9
            \op    $a6,  $sp, 10
            \op    $a7,  $sp, 11
            \op    $t0,  $sp, 12
            \op    $t1,  $sp, 13
            \op    $t2,  $sp, 14
            \op    $t3,  $sp, 15
            \op    $t4,  $sp, 16
            \op    $t5,  $sp, 17
            \op    $t6,  $sp, 18
            \op    $t7,  $sp, 19
            \op    $t8,  $sp, 20
            // 21: r21 handled manually
            \op    $fp,  $sp, 22
            \op    $s0,  $sp, 23
            \op    $s1,  $sp, 24
            \op    $s2,  $sp, 25
            \op    $s3,  $sp, 26
            \op    $s4,  $sp, 27
            \op    $s5,  $sp, 28
            \op    $s6,  $sp, 29
            \op    $s7,  $sp, 30
            \op    $s8,  $sp, 31
        .endm

        .macro PUSH_GENERAL_REGS
            PUSH_POP_GENERAL_REGS STD
        .endm
        .macro POP_GENERAL_REGS
            PUSH_POP_GENERAL_REGS LDD
        .endm

        .macro _asm_extable, from, to
            .pushsection __ex_table, "a"
            .balign 4
            .word   \from - _ex_table_start
            .word   \to - _ex_table_start
            .popsection
        .endm

        .endif"#
    };
}

#[cfg(feature = "fp-simd")]
macro_rules! include_fp_asm_macros {
    () => {
        r#"
        .ifndef FP_MACROS_FLAG
        .equ FP_MACROS_FLAG, 1

        .macro SAVE_FCC, base
            movcf2gr    $t0, $fcc0
            move        $t1, $t0
            movcf2gr    $t0, $fcc1
            bstrins.d   $t1, $t0, 15, 8
            movcf2gr    $t0, $fcc2
            bstrins.d   $t1, $t0, 23, 16
            movcf2gr    $t0, $fcc3
            bstrins.d   $t1, $t0, 31, 24
            movcf2gr    $t0, $fcc4
            bstrins.d   $t1, $t0, 39, 32
            movcf2gr    $t0, $fcc5
            bstrins.d   $t1, $t0, 47, 40
            movcf2gr    $t0, $fcc6
            bstrins.d   $t1, $t0, 55, 48
            movcf2gr    $t0, $fcc7
            bstrins.d   $t1, $t0, 63, 56
            st.d        $t1, \base, 0
        .endm

        .macro RESTORE_FCC, base
            ld.d        $t0, \base, 0
            bstrpick.d  $t1, $t0, 7, 0
            movgr2cf    $fcc0, $t1
            bstrpick.d  $t1, $t0, 15, 8
            movgr2cf    $fcc1, $t1
            bstrpick.d  $t1, $t0, 23, 16
            movgr2cf    $fcc2, $t1
            bstrpick.d  $t1, $t0, 31, 24
            movgr2cf    $fcc3, $t1
            bstrpick.d  $t1, $t0, 39, 32
            movgr2cf    $fcc4, $t1
            bstrpick.d  $t1, $t0, 47, 40
            movgr2cf    $fcc5, $t1
            bstrpick.d  $t1, $t0, 55, 48
            movgr2cf    $fcc6, $t1
            bstrpick.d  $t1, $t0, 63, 56
            movgr2cf    $fcc7, $t1
        .endm

        .macro SAVE_FCSR, base
            movfcsr2gr  $t0, $fcsr0
            st.w        $t0, \base, 0
        .endm

        .macro RESTORE_FCSR, base
            ld.w        $t0, \base, 0
            movgr2fcsr  $fcsr0, $t0
        .endm

        // LoongArch64 specific floating point macros
        .macro PUSH_POP_FLOAT_REGS, op, base_reg
            \op $vr0,  \base_reg, 0*16
            \op $vr1,  \base_reg, 1*16
            \op $vr2,  \base_reg, 2*16
            \op $vr3,  \base_reg, 3*16
            \op $vr4,  \base_reg, 4*16
            \op $vr5,  \base_reg, 5*16
            \op $vr6,  \base_reg, 6*16
            \op $vr7,  \base_reg, 7*16
            \op $vr8,  \base_reg, 8*16
            \op $vr9,  \base_reg, 9*16
            \op $vr10, \base_reg, 10*16
            \op $vr11, \base_reg, 11*16
            \op $vr12, \base_reg, 12*16
            \op $vr13, \base_reg, 13*16
            \op $vr14, \base_reg, 14*16
            \op $vr15, \base_reg, 15*16
            \op $vr16, \base_reg, 16*16
            \op $vr17, \base_reg, 17*16
            \op $vr18, \base_reg, 18*16
            \op $vr19, \base_reg, 19*16
            \op $vr20, \base_reg, 20*16
            \op $vr21, \base_reg, 21*16
            \op $vr22, \base_reg, 22*16
            \op $vr23, \base_reg, 23*16
            \op $vr24, \base_reg, 24*16
            \op $vr25, \base_reg, 25*16
            \op $vr26, \base_reg, 26*16
            \op $vr27, \base_reg, 27*16
            \op $vr28, \base_reg, 28*16
            \op $vr29, \base_reg, 29*16
            \op $vr30, \base_reg, 30*16
            \op $vr31, \base_reg, 31*16
        .endm

        .macro SAVE_FP, base_reg
            PUSH_POP_FLOAT_REGS vst, \base_reg
        .endm

        .macro RESTORE_FP, base_reg
            PUSH_POP_FLOAT_REGS vld, \base_reg
        .endm

        .endif"#
    };
}
