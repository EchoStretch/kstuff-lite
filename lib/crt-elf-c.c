#include <sys/types.h>
#include "r0gdb-bootstrap.h"
#include "shellcore-imports.h"

struct specter_args
{
    void* dlsym;
    int* pipe;
    int* rwpair;
    uint64_t kpipe_addr;
    uint64_t kdata_base;
    int* retval;
};

uint64_t _start(void* dlsym, int master, int victim, uint64_t pktopts, uint64_t kdata_base);

intptr_t (*kstuff_dynlib_resolve)(int pid, uint32_t handle, const char* nid);
int (*kstuff_dynlib_handle)(int pid, const char* name, uint32_t* handle);
kstuff_shellcore_imports_fn kstuff_shellcore_imports;

void elf_main(struct specter_args* args, uint64_t resolver_magic,
              intptr_t (*resolver)(int, uint32_t, const char*),
              int (*handle_lookup)(int, const char*, uint32_t*),
              kstuff_shellcore_imports_fn import_lookup)
{
    if(resolver_magic == KSTUFF_DYNLIB_RESOLVER_MAGIC)
    {
        kstuff_dynlib_resolve = resolver;
        kstuff_dynlib_handle = handle_lookup;
        kstuff_shellcore_imports = import_lookup;
    }
    struct r0gdb_bootstrap bootstrap = {
        .magic = R0GDB_BOOTSTRAP_MAGIC,
        .rwpipe = {args->pipe[0], args->pipe[1]},
        .kpipe_addr = args->kpipe_addr,
    };
    *args->retval = _start(args->dlsym,
                           args->rwpair[0],
                           args->rwpair[1],
                           (uint64_t)&bootstrap,
                           args->kdata_base);
}
