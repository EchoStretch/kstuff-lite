#ifndef SHELLCORE_PATCHES_1_12
#define SHELLCORE_PATCHES_1_12

static const struct shellcore_fpkg_offsets shellcore_fpkg_offsets_112 = {
    .ppr_call = 0x4638f1,
    .ppr_cave = 0x11281d0,
    .ppr_cave_size = 0x3e30,
    .close_plt = 0x1120610,
    .open_plt = 0x11213f0,
    .pread_plt = 0x1121560,
    .mount_ppr_pkg_plt = 0x11231c0,
    .getpid_plt = 0x1120310,
};

static struct shellcore_patch shellcore_patches_112_retail[] = {
    {0x7e0ccf, "\x31\xc0\x50\xeb\x00", 5},
    {0x7e0cd4, "\xe8\x77\x1a\x00\x00\x58\xc3", 7},
    {0x7e0cc3, "\x31\xc0\x50\xeb\xd1", 5},
    {0x7e0c99, "\xe8\x22\x19\x00\x00\x58\xc3", 7},
    {0x41acc3, "\xeb\x04", 2},
    {0x1e1270, "\xeb\x04", 2},
    {0x1e5207, "\xeb\x04", 2},
    {0x4357b3, "\x90\x90", 2},
    {0x42070d, "\x90\xe9", 2},
    {0x43521a, "\xeb", 1},
    {0x438035, "\x1a\x02\x00\x00", 4},
    {0x147d31, "\xe8\x9a\x39\x3a\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x147e51, "\x83\xf8\x02\x0f\x43\xc1\xe9\x8d\xfc\xff\xff", 11},
    {0x147ac7, "\xe9\x65\x02\x00\x00", 5},
    {0x35094c, "\x66\x0f\x1f\x44\x00\x00", 6},
    {0x734894, "\xeb", 1},
    {0x717ee6, "\x90\x90\x90\x90\x90", 5},
    {0x1ddafb, "\x90\xe9", 2},
    {0x1ddb78, "\x90\xe9", 2},
    {0x1ddc7b, "\xeb", 1},
    {0x1ddd4f, "\xeb", 1},
    {0x1de1ba, "\x90\xe9", 2},
    {0x1de38e, "\xeb", 1},
    {0x1de73e, "\x90\xe9", 2},
    {0x1de804, "\x90\xe9", 2},
    {0x41cb67, "\xeb", 1},
    {0x41cc7c, "\xeb", 1},
};

static struct shellcore_patch shellcore_patches_112_testkit[] = {
};

static struct shellcore_patch shellcore_patches_112_devkit[] = {
};

#endif // SHELLCORE_PATCHES_1_12
