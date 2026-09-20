#include <elf.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ps5/kernel.h>

#include "shellcore_dynlib_abi.h"
#include "../../lib/shellcore-imports.h"

enum { SHELLCORE_JUMP_SLOT_RELOCATION = 7 };

_Static_assert(sizeof(Elf64_Rela) == 24 && sizeof(Elf64_Sym) == 24,
               "unexpected ShellCore relocation ABI");

int shellcore_import_got(int pid, uint64_t image_base, uint32_t required_mask,
                         uint64_t got[SHELLCORE_IMPORT_COUNT])
{
    shellcore_dynlib_obj_t obj;
    shellcore_dynlib_dynsec_t dynsec;
    unsigned char *tables = NULL;
    int result = -1;
    const uint32_t valid_mask = (1u << SHELLCORE_IMPORT_COUNT) - 1;

    if(!got)
        return -1;
    memset(got, 0, sizeof(uint64_t) * SHELLCORE_IMPORT_COUNT);
    if(!required_mask || (required_mask & ~valid_mask))
        return -1;
    if(kernel_dynlib_obj(pid, 0, &obj) || obj.mapbase != image_base
    || !obj.dynsec || kernel_copyout(obj.dynsec, &dynsec, sizeof(dynsec)))
        return -1;

    if(obj.mapbase < 0x10000
    || obj.mapbase >= 0x0000800000000000ull
    || obj.mapsize < sizeof(uint64_t)
    || obj.mapsize >= 0x0000800000000000ull - obj.mapbase
    || !dynsec.pltrela || !dynsec.symtab || !dynsec.strtab
    || !dynsec.pltrelasize || dynsec.pltrelasize > 0x100000
    || dynsec.pltrelasize % sizeof(Elf64_Rela)
    || !dynsec.symtabsize || dynsec.symtabsize > 0x100000
    || dynsec.symtabsize % sizeof(Elf64_Sym)
    || !dynsec.strtabsize || dynsec.strtabsize > 0x100000)
        return -1;

    size_t tables_size = dynsec.pltrelasize + dynsec.symtabsize
                       + dynsec.strtabsize;
    tables = malloc(tables_size);
    if(!tables)
        return -1;
    Elf64_Rela *rela = (Elf64_Rela *)tables;
    Elf64_Sym *sym = (Elf64_Sym *)(tables + dynsec.pltrelasize);
    char *str = (char *)(tables + dynsec.pltrelasize + dynsec.symtabsize);
    if(kernel_copyout(dynsec.pltrela, rela, dynsec.pltrelasize)
    || kernel_copyout(dynsec.symtab, sym, dynsec.symtabsize)
    || kernel_copyout(dynsec.strtab, str, dynsec.strtabsize))
        goto done;

    size_t sym_count = dynsec.symtabsize / sizeof(*sym);
    size_t rela_count = dynsec.pltrelasize / sizeof(*rela);
    for(size_t i = 0; i < rela_count; i++)
    {
        if((uint32_t)rela[i].r_info != SHELLCORE_JUMP_SLOT_RELOCATION)
            continue;
        size_t sym_index = rela[i].r_info >> 32;
        if(sym_index >= sym_count)
            goto done;
        size_t name_offset = sym[sym_index].st_name;
        if(name_offset >= dynsec.strtabsize)
            goto done;
        if(dynsec.strtabsize - name_offset < 12)
            continue;
        const char *name = str + name_offset;
        for(size_t j = 0; j < SHELLCORE_IMPORT_COUNT; j++)
        {
            if(!(required_mask & SHELLCORE_IMPORT_BIT(j))
            || memcmp(name, shellcore_import_nids[j], 11)
            || name[11] != '#')
                continue;
            if(got[j] || rela[i].r_offset > obj.mapsize - sizeof(uint64_t)
            || (rela[i].r_offset & (sizeof(uint64_t) - 1)))
                goto done;
            got[j] = image_base + rela[i].r_offset;
        }
    }
    for(size_t j = 0; j < SHELLCORE_IMPORT_COUNT; j++)
    {
        if((required_mask & SHELLCORE_IMPORT_BIT(j)) && !got[j])
            goto done;
        for(size_t previous = 0; previous < j; previous++)
            if(got[j] && got[j] == got[previous])
                goto done;
    }
    result = 0;

done:
    free(tables);
    if(result)
        memset(got, 0, sizeof(uint64_t) * SHELLCORE_IMPORT_COUNT);
    return result;
}
