/*
 * The SDK's crt/kernel.h is an internal build header and is not shipped in
 * every SDK package. Keep the dynlib layouts needed by the ShellCore import
 * resolver here. Layouts are from ps5-payload-dev/sdk/crt/kernel.h (GPL-3.0).
 */
#pragma once

#include <stddef.h>

typedef struct shellcore_dynlib_dynsec {
    struct {
        unsigned long le_next;
        unsigned long le_prev;
    } list_entry;
    unsigned long sysvec;
    unsigned int refcount;
    unsigned long size;
    unsigned long symtab;
    unsigned long symtabsize;
    unsigned long strtab;
    unsigned long strtabsize;
    unsigned long pltrela;
    unsigned long pltrelasize;
    unsigned long rela;
    unsigned long relasize;
    unsigned long hash;
    unsigned long hashsize;
    unsigned long dynamic;
    unsigned long dynamicsize;
    unsigned long sce_comment;
    unsigned long sce_commentsize;
    unsigned long sce_dynlib;
    unsigned long sce_dynlibsize;
    unsigned long unknown1;
    unsigned long unknown1size;
    unsigned long buckets;
    unsigned long bucketssize;
    unsigned int nbuckets;
    unsigned long chains;
    unsigned long chainssize;
    unsigned int nchains;
    unsigned long unknown2[7];
} shellcore_dynlib_dynsec_t;

typedef struct shellcore_dynlib_obj {
    unsigned long next;
    unsigned long path;
    unsigned long unknown0[2];
    unsigned int refcount;
    unsigned long handle;
    unsigned long mapbase;
    unsigned long mapsize;
    unsigned long textsize;
    unsigned long database;
    unsigned long datasize;
    unsigned long unknown1;
    unsigned long unknown1size;
    unsigned long entry;
    unsigned long unknown2;
    unsigned long vaddrbase;
    unsigned int tlsindex;
    unsigned long tlsinit;
    unsigned long tlsinitsize;
    unsigned long tlssize;
    unsigned long tlsoffset;
    unsigned long tlsalign;
    unsigned long pltgot;
    unsigned long unknown3[6];
    unsigned long init;
    unsigned long fini;
    unsigned long eh_frame_hdr;
    unsigned long eh_frame_hdr_size;
    unsigned long eh_frame;
    unsigned long eh_frame_size;
    int status;
    int flags;
    unsigned long unknown4[5];
    unsigned long dynsec;
    unsigned long unknown5[6];
} shellcore_dynlib_obj_t;

_Static_assert(sizeof(shellcore_dynlib_obj_t) == 0x180
               && offsetof(shellcore_dynlib_obj_t, mapbase) == 0x30
               && offsetof(shellcore_dynlib_obj_t, mapsize) == 0x38
               && offsetof(shellcore_dynlib_obj_t, dynsec) == 0x148,
               "unexpected dynlib object layout");
_Static_assert(sizeof(shellcore_dynlib_dynsec_t) == 0x120
               && offsetof(shellcore_dynlib_dynsec_t, symtab) == 0x28
               && offsetof(shellcore_dynlib_dynsec_t, strtab) == 0x38
               && offsetof(shellcore_dynlib_dynsec_t, pltrela) == 0x48,
               "unexpected dynlib section layout");

int kernel_dynlib_obj(int pid, unsigned int handle, shellcore_dynlib_obj_t *obj);
