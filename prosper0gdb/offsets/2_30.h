// offsets/2_30.h
#ifndef OFFSETS_2_30_H
#define OFFSETS_2_30_H
#include "../offsets.h"

START_FW(230)
DEF(allproc, 0x3711c28)
DEF(idt, 0x73bcad0)
DEF(gdt_array, 0x73bdc70)
DEF(tss_array, 0x73bf670)
DEF(pcpu_array, 0x73c1080)
DEF(doreti_iret, -0x966F6C) // IDA 0x209094
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x92789A) // IDA 0x248766
DEF(rdmsr_start, -0x96E003) // IDA 0x201FFD
DEF(wrmsr_ret, -0x9697EC) // IDA 0x206814
DEF(dr2gpr_start, -0x96E152) // IDA 0x201EAE
DEF(gpr2dr_1_start, -0x96E0DC) // IDA 0x201F24
DEF(gpr2dr_2_start, -0x96E0BD) // IDA 0x201F43
DEF(mov_cr3_rax_mov_ds, -0x96DD19) // IDA 0x2022E7
DEF(mov_rax_cr3, -0x365FC0) // IDA 0x80A040
DEF(nop_ret, wrmsr_ret + 2)
DEF(cpu_switch, -0x96E340) // IDA 0x201CC0
DEF(mprotect_fix_start, -0x8A7351) // IDA 0x2C8CAF
DEF(mprotect_fix_end, mprotect_fix_start + 6)
DEF(aslr_fix_start, -0x7FDFC4) // IDA 0x37203C
DEF(aslr_fix_end, -0x7FDF72) // IDA 0x37208E
DEF(sysents, 0x1176DE0) // IDA 0x1CE6DE0
DEF(sysents_ps4, 0x116E5C0) // IDA 0x1CDE5C0
DEF(sysentvec, 0x1C50458) // IDA 0x27C0458
DEF(sysentvec_ps4, 0x1C505D0) // IDA 0x27C05D0
DEF(sceSblServiceMailbox, -0x63BF40) // IDA 0x5340C0
DEF(sceSblAuthMgrSmIsLoadable2, -0x8441A0) // IDA 0x32BE60
DEF(syscall_before, -0x7A7F8F) // IDA 0x3C8071
DEF(syscall_after, -0x7A7F6C) // IDA 0x3C8094
DEF(malloc, -0x9E200) // IDA 0xAD1E00
DEF(M_something, 0x2283630) // IDA 0x2DF3630
DEF(loadSelfSegment_epilogue, -0x843952) // IDA 0x32C6AE
DEF(loadSelfSegment_watchpoint, -0x2ABFE8) // IDA 0x8C4018
DEF(loadSelfSegment_watchpoint_lr, -0x843BB7) // IDA 0x32C449
// KDATA_OFFSET(decryptSelfBlock_watchpoint) remains intentionally disabled.
DEF(decryptSelfBlock_watchpoint_lr, -0x84381A) // IDA 0x32C7E6
DEF(decryptSelfBlock_epilogue, -0x84375C) // IDA 0x32C8A4
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x843305) // IDA 0x32CCFB
DEF(decryptMultipleSelfBlocks_epilogue, -0x842E7C) // IDA 0x32D184
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x843DE1) // IDA 0x32C21F
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x8439C6) // IDA 0x32C63A
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x8434DC) // IDA 0x32CB24
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x842F36) // IDA 0x32D0CA
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x84420E) // IDA 0x32BDF2
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x8E61C5) // IDA 0x289E3B
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x8E679C) // IDA 0x289864
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x8E6730) // IDA 0x2898D0
DEF(sceSblServiceMailbox_lr_npdrm_cmd_5, -0x2F219F) // IDA 0x87DE61
DEF(sceSblServiceMailbox_lr_npdrm_cmd_6, -0x2F1EFA) // IDA 0x87E106
DEF(sceSblPfsSetKeys, -0x8E64A0) // IDA 0x289B60
DEF(sceSblServiceCryptAsync, -0x88AA70) // IDA 0x2E5590
DEF(sceSblServiceCryptAsync_deref_singleton, -0x88AA32) // IDA 0x2E55CE
DEF(copyin, -0x928030) // IDA 0x247FD0
DEF(copyout, -0x9280D0) // IDA 0x247F30
DEF(crypt_message_resolve, -0x4498C0) // IDA 0x726740
DEF(justreturn, -0x9670B0) // IDA 0x208F50
DEF(justreturn_pop, justreturn + 8)
DEF(mini_syscore_header, 0x1CFE628) // IDA 0x286E628
DEF(pop_all_iret, -0x966FCB) // IDA 0x209035
DEF(pop_all_except_rdi_iret, pop_all_iret + 4)
DEF(push_pop_all_iret, -0x9071E0) // IDA 0x268E20
DEF(kernel_pmap_store, 0x41438c8)
DEF(crypt_singleton_array, 0x3d22390)
DEF(mov_rax_cr0, -0x4F5E59) // IDA 0x67A1A7
DEF(syscall_cfi_table_jmp_int3, -0x903520) // IDA 0x26CAE0

DEF(cr0_load, -0x8BEFC0) // IDA 0x2B1040
DEF(cr0_clear_store, -0x52A9C6) // IDA 0x64563A
DEF(cr0_write_ret, -0x4F5B07) // IDA 0x67A4F9
DEF(store_rax_rdi, -0x96E52E) // IDA 0x201AD2


// PPR/fPKG continuations and wrapper-local ABI sites.
DEF(ppr_pfs_get_xts_index, -0x106c90)
DEF(ppr_pfs_get_cmac_index, -0x106b30)
DEF(ppr_pfs_get_xts_return, -0x8115bf)
DEF(ppr_pfs_get_cmac_return, -0x811571)
DEF(ppr_pfs_cleanup_keys, -0x818390)
DEF(ppr_pfs_clear_key_missing, -0x8e6997)
DEF(sceSblServiceMailbox_lr_verifyImage, -0x8e7dff)
DEF(ppr_pfs_verify_image_no_key_success, -0x8e7958)

// non data-relative offsets
DEF(p_sysent, 0x988)

#include "offset_list.txt"
END_FW()

#endif
