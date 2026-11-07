ENTRY(ps4_folder_metadata_read)
SECTIONS {
 . = 0;
 .text : { *(.text*) }
 .forbidden_data : { *(.rodata*) *(.data*) *(.bss*) }
 ASSERT(SIZEOF(.forbidden_data) == 0, "folder metadata code contains readable data")
 /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) }
}
