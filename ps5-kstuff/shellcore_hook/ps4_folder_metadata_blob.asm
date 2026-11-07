BITS 64
SECTION .rodata align=16
GLOBAL ps4_folder_metadata_blob_start
GLOBAL ps4_folder_metadata_blob_end
ps4_folder_metadata_blob_start:
    INCBIN "ps4_folder_metadata.bin"
ps4_folder_metadata_blob_end:
SECTION .note.GNU-stack noalloc noexec nowrite progbits
