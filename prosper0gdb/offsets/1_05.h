// offsets/1_05.h
#ifndef OFFSETS_1_05_H
#define OFFSETS_1_05_H
#include "../offsets.h"

START_FW(105)
DEF(allproc, 0x36e1c18)
DEF(idt, 0x721c8c0)
DEF(gdt_array, 0x721da60)
DEF(tss_array, 0x721f460)
DEF(pcpu_array, 0x7220e80)
DEF(doreti_iret, -0x93ea43)
DEF(add_rsp_iret, doreti_iret - 7)
DEF(swapgs_add_rsp_iret, doreti_iret - 10)
DEF(rep_movsb_pop_rbp_ret, -0x8ff48c)
DEF(rdmsr_start, -0x945ac3)
DEF(wrmsr_ret, -0x9412bc)
DEF(nop_ret, wrmsr_ret + 2)
DEF(dr2gpr_start, -0x945c12)
DEF(gpr2dr_1_start, -0x945b9c)
DEF(gpr2dr_2_start, -0x945b7d)
DEF(mov_cr3_rax_mov_ds, -0x9457d9)
DEF(mov_rax_cr3, -0x3344ac)
DEF(cpu_switch, -0x945e00)
DEF(mprotect_fix_start, -0x81d4c1)
DEF(mprotect_fix_end, mprotect_fix_start + 6)
DEF(aslr_fix_start, -0x77c041)
DEF(aslr_fix_end, -0x77bff5)
DEF(sysents, 0x117a890)
DEF(sysents_ps4, 0x1172690)
DEF(sysentvec, 0x1c2a5c8)
DEF(sysentvec_ps4, 0x1c2a720)
DEF(sceSblServiceMailbox, -0x5cc0a0)
DEF(sceSblAuthMgrSmIsLoadable2, -0x7bf540)
DEF(syscall_before, -0x72a0f0)
DEF(syscall_after, -0x72a0ed)
DEF(malloc, -0x93070)
DEF(M_something, 0x2259810)
DEF(loadSelfSegment_epilogue, -0x7becf2)
DEF(loadSelfSegment_watchpoint, -0x288c68)
DEF(loadSelfSegment_watchpoint_lr, -0x7bef57)
DEF(decryptSelfBlock_watchpoint_lr, -0x7beb9a)
DEF(decryptSelfBlock_epilogue, -0x7beadc)
DEF(decryptMultipleSelfBlocks_watchpoint_lr, -0x7be685)
DEF(decryptMultipleSelfBlocks_epilogue, -0x7be1fc)
DEF(sceSblServiceMailbox_lr_verifyHeader, -0x7bf181)
DEF(sceSblServiceMailbox_lr_loadSelfSegment, -0x7bed66)
DEF(sceSblServiceMailbox_lr_decryptSelfBlock, -0x7be85c)
DEF(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks, -0x7be2b6)
DEF(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize, -0x7bf5ae)
DEF(sceSblServiceMailbox_lr_verifySuperBlock, -0x85a985)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_1, -0x85af5c)
DEF(sceSblServiceMailbox_lr_sceSblPfsClearKey_2, -0x85aef0)
DEF(sceSblServiceMailbox_lr_npdrm_cmd_5, -0x2c89ff)
DEF(sceSblServiceMailbox_lr_npdrm_cmd_6, -0x2c875a)
DEF(sceSblPfsSetKeys, -0x85ac60)
DEF(sceSblServiceCryptAsync, -0x801d10)
DEF(sceSblServiceCryptAsync_deref_singleton, -0x801cd2)
DEF(copyin, -0x8ffba0)
DEF(copyout, -0x8ffc40)
DEF(crypt_message_resolve, -0x406010)
DEF(justreturn, -0x93eb80)
DEF(justreturn_pop, justreturn + 8)
DEF(mini_syscore_header, 0x1da1c58)
DEF(pop_all_iret, -0x93eaa2)
DEF(pop_all_except_rdi_iret, pop_all_iret + 4)
DEF(push_pop_all_iret, -0x874b10)
DEF(kernel_pmap_store, 0x3faf328)
DEF(crypt_singleton_array, 0x3c6de10)

// 1.xx has no compatible fast CR0 chain.  The checked UELF fallback
// single-steps mov_rax_cr0 and writes the saved value through cr0_write_ret.
DEF(mov_rax_cr0, -0x2508d0)
DEF(cr0_load, 0)
DEF(cr0_clear_store, 0)
DEF(cr0_write_ret, -0x2508c7)
DEF(store_rax_rdi, -0x945fee)

// 1.xx dispatches sy_call directly and has no syscall CFI table.  This shared
// hook field therefore names a verified raw INT3 byte in retail RX text.
DEF(syscall_cfi_table_jmp_int3, -0xb2fff0)

// PPR/fPKG continuations and wrapper-local ABI sites.
DEF(ppr_pfs_get_xts_index, -0xf4890)
DEF(ppr_pfs_get_cmac_index, -0xf4730)
DEF(ppr_pfs_get_xts_return, -0x78f39f)
DEF(ppr_pfs_get_cmac_return, -0x78f351)
DEF(ppr_pfs_cleanup_keys, -0x794bd0)
DEF(ppr_pfs_clear_key_missing, -0x85b157)
DEF(sceSblServiceMailbox_lr_verifyImage, -0x85c5bf)
DEF(ppr_pfs_verify_image_no_key_success, -0x85c118)

// non data-relative offsets
DEF(p_sysent, 0x988)

#include "offset_list.txt"
END_FW()

#endif
