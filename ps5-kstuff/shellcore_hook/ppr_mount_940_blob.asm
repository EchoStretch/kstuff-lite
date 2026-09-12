BITS 64

SECTION .rodata align=16
GLOBAL ppr_mount_940_blob_start
GLOBAL ppr_mount_940_blob_end

ppr_mount_940_blob_start:
    INCBIN "ppr_mount_940.bin"
ppr_mount_940_blob_end:

SECTION .note.GNU-stack noalloc noexec nowrite progbits
