#ifndef SHELLCORE_PATCHES_1_01
#define SHELLCORE_PATCHES_1_01

static const struct shellcore_fpkg_offsets shellcore_fpkg_offsets_101 = {
    .ppr_call = 0x463461,
    .ppr_cave = 0x1127640,
    .ppr_cave_size = 0x9c0,
    .close_plt = 0x111fa90,
    .open_plt = 0x1120870,
    .pread_plt = 0x11209e0,
    .mount_ppr_pkg_plt = 0x1122620,
    .getpid_plt = 0x111f790,
};

static struct shellcore_patch shellcore_patches_101_retail[] = {
    {0x7e06bf, "\x31\xc0\x50\xeb\x00", 5},
    {0x7e06c4, "\xe8\x77\x1a\x00\x00\x58\xc3", 7},
    {0x7e06b3, "\x31\xc0\x50\xeb\xd1", 5},
    {0x7e0689, "\xe8\x22\x19\x00\x00\x58\xc3", 7},
    {0x41a833, "\xeb\x04", 2},
    {0x1e1320, "\xeb\x04", 2},
    {0x1e52b7, "\xeb\x04", 2},
    {0x435323, "\x90\x90", 2},
    {0x42027d, "\x90\xe9", 2},
    {0x434d8a, "\xeb", 1},
    {0x437ba5, "\x1a\x02\x00\x00", 4},
    {0x147d31, "\xe8\x0a\x35\x3a\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x147e51, "\x83\xf8\x02\x0f\x43\xc1\xe9\x8d\xfc\xff\xff", 11},
    {0x147ac7, "\xe9\x65\x02\x00\x00", 5},
    {0x35053c, "\x66\x0f\x1f\x44\x00\x00", 6},
    {0x734424, "\xeb", 1},
    {0x717a76, "\x90\x90\x90\x90\x90", 5},
    {0x1ddb1b, "\x90\xe9", 2},
    {0x1ddb98, "\x90\xe9", 2},
    {0x1ddc9b, "\xeb", 1},
    {0x1ddd6f, "\xeb", 1},
    {0x1de1da, "\x90\xe9", 2},
    {0x1de3ae, "\xeb", 1},
    {0x1de75e, "\x90\xe9", 2},
    {0x1de824, "\x90\xe9", 2},
    {0x41c6d7, "\xeb", 1},
    {0x41c7ec, "\xeb", 1},
};

static struct shellcore_patch shellcore_patches_101_testkit[] = {
};

static struct shellcore_patch shellcore_patches_101_devkit[] = {
};

#endif // SHELLCORE_PATCHES_1_01
