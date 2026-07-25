.macro fixup op, rd, rj, off
100:
    \op     \rd, \rj, \off
    _asm_extable 100b, .Lout_copy_user
.endm

.section .text
.balign 4
.global user_copy
user_copy:
    beqz    $a2, .Lout_copy_user

    // Wide copies are safe when source and destination have the same
    // alignment. Otherwise use the byte loop without reading outside the
    // requested range.
    xor     $t0, $a0, $a1
    andi    $t0, $t0, 7
    bnez    $t0, .Lbyte_copy

.Lalign_copy:
    andi    $t0, $a0, 7
    beqz    $t0, .Lbulk_check
    fixup   ld.b, $t0, $a1, 0
    fixup   st.b, $t0, $a0, 0
    addi.d  $a0, $a0, 1
    addi.d  $a1, $a1, 1
    addi.d  $a2, $a2, -1
    bnez    $a2, .Lalign_copy
    b       .Lout_copy_user

.Lbulk_check:
    addi.d  $t8, $zero, 64
    bltu    $a2, $t8, .Lword_check

    fixup   ld.d, $t0, $a1, 0
    fixup   ld.d, $t1, $a1, 8
    fixup   ld.d, $t2, $a1, 16
    fixup   ld.d, $t3, $a1, 24
    fixup   ld.d, $t4, $a1, 32
    fixup   ld.d, $t5, $a1, 40
    fixup   ld.d, $t6, $a1, 48
    fixup   ld.d, $t7, $a1, 56

    fixup   st.d, $t0, $a0, 0
    addi.d  $a0, $a0, 8
    addi.d  $a1, $a1, 8
    addi.d  $a2, $a2, -8
    fixup   st.d, $t1, $a0, 0
    addi.d  $a0, $a0, 8
    addi.d  $a1, $a1, 8
    addi.d  $a2, $a2, -8
    fixup   st.d, $t2, $a0, 0
    addi.d  $a0, $a0, 8
    addi.d  $a1, $a1, 8
    addi.d  $a2, $a2, -8
    fixup   st.d, $t3, $a0, 0
    addi.d  $a0, $a0, 8
    addi.d  $a1, $a1, 8
    addi.d  $a2, $a2, -8
    fixup   st.d, $t4, $a0, 0
    addi.d  $a0, $a0, 8
    addi.d  $a1, $a1, 8
    addi.d  $a2, $a2, -8
    fixup   st.d, $t5, $a0, 0
    addi.d  $a0, $a0, 8
    addi.d  $a1, $a1, 8
    addi.d  $a2, $a2, -8
    fixup   st.d, $t6, $a0, 0
    addi.d  $a0, $a0, 8
    addi.d  $a1, $a1, 8
    addi.d  $a2, $a2, -8
    fixup   st.d, $t7, $a0, 0
    addi.d  $a0, $a0, 8
    addi.d  $a1, $a1, 8
    addi.d  $a2, $a2, -8
    b       .Lbulk_check

.Lword_check:
    addi.d  $t8, $zero, 8
    bltu    $a2, $t8, .Lbyte_copy
.Lword_copy:
    fixup   ld.d, $t0, $a1, 0
    fixup   st.d, $t0, $a0, 0
    addi.d  $a0, $a0, 8
    addi.d  $a1, $a1, 8
    addi.d  $a2, $a2, -8
    bgeu    $a2, $t8, .Lword_copy

.Lbyte_copy:
    beqz    $a2, .Lout_copy_user
    fixup   ld.b, $t0, $a1, 0
    fixup   st.b, $t0, $a0, 0
    addi.d  $a0, $a0, 1
    addi.d  $a1, $a1, 1
    addi.d  $a2, $a2, -1
    bnez    $a2, .Lbyte_copy

.Lout_copy_user:
    move    $a0, $a2
    jr      $ra
