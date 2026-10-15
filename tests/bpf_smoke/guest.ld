/* Standalone Linux-ABI guest ELF for BPF guest sampler smoke (#104).
 * ENTRY(_start) at 0x400000. Static link, no PT_INTERP.
 */
ENTRY(_start)
PHDRS {
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    data PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x400000 + SIZEOF_HEADERS;
    .text : ALIGN(16) { KEEP(*(.text._start)) *(.text .text.*) } :text
    .rodata : ALIGN(16) { *(.rodata .rodata.* .srodata .srodata.*) } :text
    . = ALIGN(4096);
    .data : { *(.data .data.*) __global_pointer$ = . + 0x800; *(.sdata .sdata.*) } :data
    .bss (NOLOAD) : ALIGN(16) { *(.bss .bss.* .sbss .sbss.*) *(COMMON) } :data
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment) }
}

