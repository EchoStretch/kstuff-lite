#ifndef SHELLCORE_PATCHES_2_25
#define SHELLCORE_PATCHES_2_25

static const struct shellcore_fpkg_offsets shellcore_fpkg_offsets_225 = {
    .ppr_call = 0x4d0301,
    .ppr_cave = 0x12a5070,
    .ppr_cave_size = 0x2f90,
    .close_plt = 0x129d220,
    .open_plt = 0x129e1d0,
    .pread_plt = 0x129e2c0,
    .mount_ppr_pkg_plt = 0x129feb0,
    .getpid_plt = 0x129cef0,
};

static struct shellcore_patch shellcore_patches_225_retail[] = {
    {0x883e7c, "\x31\xc0\x50\xeb\x08", 5},
    {0x883e89, "\xe8\x02\x1e\x00\x00\x58\xc3", 7},
    {0x883e84, "\x31\xc0\x50\xeb\xa0", 5},
    {0x883e29, "\xe8\x82\x1c\x00\x00\x58\xc3", 7},
    {0x4862ee, "\xeb\x04", 2},
    {0x2194f0, "\xeb\x04", 2},
    {0x21d517, "\xeb\x04", 2},
    {0x4a2f0e, "\x90\x90", 2},
    {0x48c23d, "\x90\xe9", 2},
    {0x4a2906, "\xeb", 1},
    {0x4a5783, "\x0f\x02\x00\x00", 4},
    {0x176911, "\xe8\x8a\x5e\x3e\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x176a31, "\x83\xf8\x02\x0f\x43\xc1\xe9\x22\xfc\xff\xff", 11},
    {0x17663c, "\xe9\xd0\x02\x00\x00", 5},
    {0x3af45c, "\x66\x0f\x1f\x44\x00\x00", 6},
    {0x7d4e84, "\xeb", 1},
    {0x7b8836, "\x90\x90\x90\x90\x90", 5},
    {0x215afb, "\x90\xe9", 2},
    {0x215b78, "\x90\xe9", 2},
    {0x215c7b, "\xeb", 1},
    {0x215d4f, "\xeb", 1},
    {0x2161ba, "\x90\xe9", 2},
    {0x21638e, "\xeb", 1},
    {0x216745, "\x90\xe9", 2},
    {0x2167e2, "\x90\xe9", 2},
    {0x4880e7, "\xeb", 1},
    {0x4881fc, "\xeb", 1},
    {0x48a050, "\x48\x31\xc0\xc3", 4},
};

static struct shellcore_patch shellcore_patches_225_testkit[] = {
};

static struct shellcore_patch shellcore_patches_225_devkit[] = {
};

#endif // SHELLCORE_PATCHES_2_25
