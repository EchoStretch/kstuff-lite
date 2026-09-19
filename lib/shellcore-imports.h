#ifndef KSTUFF_SHELLCORE_IMPORTS_H
#define KSTUFF_SHELLCORE_IMPORTS_H

#include <stdint.h>

enum {
    SHELLCORE_IMPORT_CLOSE,
    SHELLCORE_IMPORT_OPEN,
    SHELLCORE_IMPORT_PREAD,
    SHELLCORE_IMPORT_MOUNT_GAME,
    SHELLCORE_IMPORT_UMOUNT_GAME,
    SHELLCORE_IMPORT_MOUNT_PPR,
    SHELLCORE_IMPORT_UMOUNT_PPR,
    SHELLCORE_IMPORT_COUNT
};

#define SHELLCORE_IMPORT_BIT(index) (1u << (index))

static const char *const shellcore_import_nids[SHELLCORE_IMPORT_COUNT] = {
    "bY-PO6JhzhQ", /* close */
    "wuCroIGjt2g", /* open */
    "ezv-RSBNKqI", /* pread */
    "FtGP5aXKFQU", /* sceFsMountGamePkg */
    "UQTSykySQ40", /* sceFsUmountGamePkg */
    "MiUxeleLYUc", /* sceFsMountPprPkg */
    "S5+bpaH0TWk", /* sceFsUmountPprPkg */
};

typedef int (*kstuff_shellcore_imports_fn)(int pid, uint64_t image_base,
                                            uint32_t required_mask,
                                            uint64_t got[SHELLCORE_IMPORT_COUNT]);

#endif
