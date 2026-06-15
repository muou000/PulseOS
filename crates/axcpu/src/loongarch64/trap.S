.macro SAVE_REGS, from_user
    move    $t0,  $sp
.if \from_user == 1
    csrrd   $sp,  KSAVE_KSP                   // restore kernel sp
    addi.d  $sp,  $sp, -{trapframe_size}

    STD     $tp,  $sp, 2
    STD     $r21, $sp, 21
    csrrd   $tp,  KSAVE_TP
    csrrd   $r21, KSAVE_R21
.else
    addi.d  $sp,  $sp, -{trapframe_size}
    STD     $tp,  $sp, 2
    STD     $r21, $sp, 21
.endif

    STD     $t0,  $sp, 3
    csrrd   $t0,  KSAVE_TEMP
    PUSH_GENERAL_REGS
    csrrd   $t1,  LA_CSR_PRMD
    csrrd   $t2,  LA_CSR_ERA
    STD     $t1,  $sp, 32        // prmd
    STD     $t2,  $sp, 33        // era
.endm

.macro RESTORE_REGS, from_user
.if \from_user == 1
    csrwr   $tp,  KSAVE_TP
    csrwr   $r21, KSAVE_R21
    LDD     $tp,  $sp, 2
    LDD     $r21, $sp, 21
.else
    LDD     $tp,  $sp, 2
    LDD     $r21, $sp, 21
.endif

    LDD     $t1,  $sp, 33       // era
    LDD     $t2,  $sp, 32       // prmd
    csrwr   $t1,  LA_CSR_ERA
    csrwr   $t2,  LA_CSR_PRMD
    POP_GENERAL_REGS
    LDD     $sp,  $sp, 3
.endm

.section .text
.balign 4096
.global exception_entry_base
exception_entry_base:
    csrwr   $t0, KSAVE_TEMP
    csrrd   $t0, LA_CSR_PRMD
    andi    $t0, $t0, 0x3
    bnez    $t0, .Lfrom_userspace

.Lfrom_kernel:
    SAVE_REGS 0
    move    $a0, $sp
    addi.d  $a1, $zero, 0
    bl      loongarch64_trap_handler
    RESTORE_REGS 0
    ertn

.Lfrom_userspace:
    SAVE_REGS 1
    move    $a0, $sp
    addi.d  $a1, $zero, 1
    bl      loongarch64_trap_handler
    RESTORE_REGS 1
    ertn

.section .text
.balign 4096
.global handle_tlb_refill
handle_tlb_refill:
    csrwr   $t0, LA_CSR_TLBRSAVE
    csrrd   $t0, LA_CSR_PGD
    lddir   $t0, $t0, 3
    beqz    $t0, .Lrefill_fail
    lddir   $t0, $t0, 2
    beqz    $t0, .Lrefill_fail

    // Save PUD entry to TLBRELO0 temporarily
    csrwr   $t0, LA_CSR_TLBRELO0
    // Read PUD entry back to check bit 6 (HUGE)
    csrrd   $t0, LA_CSR_TLBRELO0
    andi    $t0, $t0, 0x40
    bnez    $t0, .Lhuge_page_1g

    // Restore PUD entry from TLBRELO0
    csrrd   $t0, LA_CSR_TLBRELO0
    lddir   $t0, $t0, 1
    beqz    $t0, .Lrefill_fail

    // Save PMD entry to TLBRELO0 temporarily
    csrwr   $t0, LA_CSR_TLBRELO0
    // Read PMD entry back to check bit 6 (HUGE)
    csrrd   $t0, LA_CSR_TLBRELO0
    andi    $t0, $t0, 0x40
    bnez    $t0, .Lhuge_page_2m

    // Normal 4KB page path: set TLBREHI.PS to 12
    csrrd   $t0, LA_CSR_TLBREHI
    srli.d  $t0, $t0, 6
    slli.d  $t0, $t0, 6
    ori     $t0, $t0, 12
    csrwr   $t0, LA_CSR_TLBREHI

    // Restore PMD entry from TLBRELO0
    csrrd   $t0, LA_CSR_TLBRELO0

    ldpte   $t0, 0
    ldpte   $t0, 1
    tlbfill
    csrrd   $t0, LA_CSR_TLBRSAVE
    ertn

.Lhuge_page_1g:
    // Set page size to 30 (1GB) in TLBREHI and clear bits 13-29 of TLBREHI
    csrrd   $t0, LA_CSR_TLBREHI
    srli.d  $t0, $t0, 30
    slli.d  $t0, $t0, 30
    ori     $t0, $t0, 30
    csrwr   $t0, LA_CSR_TLBREHI

    // Save t1 in KSAVE_TEMP
    csrwr   $t1, KSAVE_TEMP

    // Determine even or odd page from TLBRBADV (bit 30)
    csrrd   $t1, LA_CSR_TLBRBADV
    srli.d  $t1, $t1, 30
    andi    $t1, $t1, 1
    // Restore entry from TLBRELO0 into t0
    csrrd   $t0, LA_CSR_TLBRELO0
    bnez    $t1, .Lhuge_1g_odd

    // Even page:
    csrwr   $t0, LA_CSR_TLBRELO0
    addi.d  $t1, $zero, 1
    bstrins.d $t0, $t1, 30, 30
    csrwr   $t0, LA_CSR_TLBRELO1
    b       .Ltlb_fill_exit_1g

.Lhuge_1g_odd:
    csrwr   $t0, LA_CSR_TLBRELO1
    move    $t1, $zero
    bstrins.d $t0, $t1, 30, 30
    csrwr   $t0, LA_CSR_TLBRELO0

.Ltlb_fill_exit_1g:
    csrrd   $t1, KSAVE_TEMP
    b       .Ltlb_fill_exit

.Lhuge_page_2m:
    // Set page size to 21 (2MB) in TLBREHI and clear bits 13-20 of TLBREHI
    csrrd   $t0, LA_CSR_TLBREHI
    srli.d  $t0, $t0, 21
    slli.d  $t0, $t0, 21
    ori     $t0, $t0, 21
    csrwr   $t0, LA_CSR_TLBREHI

    // Save t1 in KSAVE_TEMP
    csrwr   $t1, KSAVE_TEMP

    // Determine even or odd page from TLBRBADV (bit 21)
    csrrd   $t1, LA_CSR_TLBRBADV
    srli.d  $t1, $t1, 21
    andi    $t1, $t1, 1
    // Restore entry from TLBRELO0 into t0
    csrrd   $t0, LA_CSR_TLBRELO0
    bnez    $t1, .Lhuge_2m_odd

    // Even page:
    csrwr   $t0, LA_CSR_TLBRELO0
    addi.d  $t1, $zero, 1
    bstrins.d $t0, $t1, 21, 21
    csrwr   $t0, LA_CSR_TLBRELO1
    b       .Ltlb_fill_exit_2m

.Lhuge_2m_odd:
    csrwr   $t0, LA_CSR_TLBRELO1
    move    $t1, $zero
    bstrins.d $t0, $t1, 21, 21
    csrwr   $t0, LA_CSR_TLBRELO0

.Ltlb_fill_exit_2m:
    csrrd   $t1, KSAVE_TEMP
    b       .Ltlb_fill_exit

.Ltlb_fill_exit:
    tlbfill
    csrrd   $t0, LA_CSR_TLBRSAVE
    ertn

.Lrefill_fail:
    csrwr   $zero, LA_CSR_TLBRELO0
    csrwr   $zero, LA_CSR_TLBRELO1
    tlbfill
    csrrd   $t0, LA_CSR_TLBRSAVE
    ertn
