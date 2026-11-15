/* A relocation-free loop at file byte offset 4096 exercises executable pgoff. */
ENTRY(_start)
PHDRS {
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    data PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x400000 + SIZEOF_HEADERS;
    .start : { KEEP(*(.text._start)) } :text
    . = 0x401000;
    .mapping : { KEEP(*(.text.mapping_loop)) } :text
    . = 0x402000;
    .text : { *(.text .text.*) } :text
    .rodata : ALIGN(16) { *(.rodata .rodata.* .srodata .srodata.*) } :text
    .note.gnu.build-id : { *(.note.gnu.build-id) } :text
    . = ALIGN(4096);
    .data : { *(.data .data.*) __global_pointer$ = . + 0x800; *(.sdata .sdata.*) } :data
    .bss (NOLOAD) : ALIGN(16) { *(.bss .bss.* .sbss .sbss.*) *(COMMON) } :data
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment) }
}
