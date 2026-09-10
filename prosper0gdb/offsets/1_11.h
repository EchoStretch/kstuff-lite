// offsets/1_11.h
#ifndef OFFSETS_1_11_H
#define OFFSETS_1_11_H
#include "../offsets.h"

START_FW(111)
DEF(allproc, 0x36e1c18)
DEF(idt, 0x721c8c0)
DEF(gdt_array, 0x721da60)
DEF(tss_array, 0x721f460)
DEF(pcpu_array, 0x7220e80)
DEF(doreti_iret, -0x93ea03)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x8ff44c)
DEF(rdmsr_start, -0x945a83)
DEF(wrmsr_ret, -0x94127c)
DEF(nop_ret, wrmsr_ret + 2)
DEF(dr2gpr_start, -0x945bd2)
DEF(gpr2dr_1_start, -0x945b5c)
DEF(gpr2dr_2_start, -0x945b3d)
DEF(mov_cr3_rax_mov_ds, -0x945799)
DEF(mov_rax_cr3, -0x3343ac)
DEF(cpu_switch, -0x945dc0)
DEF(mprotect_fix_start, -0x81d481)
DEF(mprotect_fix_end, mprotect_fix_start + 6)
DEF(aslr_fix_start, -0x77c001)
DEF(aslr_fix_end, -0x77bfb5)
DEF(sysents, 0x117a890)
DEF(sysents_ps4, 0x1172690)
DEF(sysentvec, 0x1c2a5c8)
DEF(sysentvec_ps4, 0x1c2a720)
DEF(sceSblServiceMailbox, -0x5cc040)
DEF(sceSblAuthMgrSmIsLoadable2, -0x7bf500)
DEF(syscall_before, -0x72a0b0)
DEF(syscall_after, -0x72a0ad)
DEF(malloc, -0x92ef0)
DEF(M_something, 0x2259810)
DEF(loadSelfSegment_epilogue, -0x7becb2)
DEF(loadSelfSegment_watchpoint, -0x288b58)
DEF(loadSelfSegment_watchpoint_lr, -0x7bef17)
DEF(decryptSelfBlock_watchpoint_lr, -0x7beb5a)
DEF(decryptSelfBlock_epilogue, -0x7bea9c)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x7be645)
DEF(decryptMultipleSelfBlocks_epilogue, -0x7be1bc)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x7bf141)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x7bed26)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x7be81c)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x7be276)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x7bf56e)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x85a945)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x85af1c)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x85aeb0)
DEF(sceSblServiceMailbox_lr_npdrm_cmd_5, -0x2c88ef)
DEF(sceSblServiceMailbox_lr_npdrm_cmd_6, -0x2c864a)
DEF(sceSblPfsSetKeys, -0x85ac20)
DEF(sceSblServiceCryptAsync, -0x801cd0)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x801c92)
DEF(copyin, -0x8ffb60)
DEF(copyout, -0x8ffc00)
DEF(crypt_message_resolve, -0x405f10)
DEF(justreturn, -0x93eb40)
DEF(justreturn_pop, justreturn + 8)
DEF(mini_syscore_header, 0x1da1c58)
DEF(pop_all_iret, -0x93ea62)
DEF(pop_all_except_rdi_iret, pop_all_iret + 4)
DEF(push_pop_all_iret, -0x874ad0)
DEF(kernel_pmap_store, 0x3faf328)
DEF(crypt_singleton_array, 0x3c6de10)

// 1.xx has no compatible fast CR0 chain.  The checked UELF fallback
// single-steps mov_rax_cr0 and writes the saved value through cr0_write_ret.
DEF(mov_rax_cr0, -0x250770)
DEF(cr0_load, 0)
DEF(cr0_clear_store, 0)
DEF(cr0_write_ret, -0x250767)
DEF(store_rax_rdi, -0x945fae)

// 1.xx dispatches sy_call directly and has no syscall CFI table.  This shared
// hook field therefore names a verified raw INT3 byte in retail RX text.
DEF(syscall_cfi_table_jmp_int3, -0xb2fff0)

// PPR/fPKG continuations and wrapper-local ABI sites.
DEF(ppr_pfs_get_xts_index, -0xf4710)
DEF(ppr_pfs_get_cmac_index, -0xf45b0)
DEF(ppr_pfs_get_xts_return, -0x78f35f)
DEF(ppr_pfs_get_cmac_return, -0x78f311)
DEF(ppr_pfs_cleanup_keys, -0x794b90)
DEF(ppr_pfs_clear_key_missing, -0x85b117)
DEF(sceSblServiceMailbox_lr_verifyImage, -0x85c57f)
DEF(ppr_pfs_verify_image_no_key_success, -0x85c0d8)

// non data-relative offsets
DEF(p_sysent, 0x988)

#include "offset_list.txt"
END_FW()

#endif
