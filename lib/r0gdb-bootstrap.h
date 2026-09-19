#ifndef R0GDB_BOOTSTRAP_H
#define R0GDB_BOOTSTRAP_H

#include <stdint.h>

#define R0GDB_BOOTSTRAP_MAGIC UINT64_C(0x5230474442504950)
#define KSTUFF_DYNLIB_RESOLVER_MAGIC UINT64_C(0x4b53544650524731)

struct r0gdb_bootstrap {
    uint64_t magic;
    int rwpipe[2];
    uint64_t kpipe_addr;
};

#endif
