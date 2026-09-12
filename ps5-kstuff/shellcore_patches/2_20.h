#ifndef SHELLCORE_PATCHES_2_20
#define SHELLCORE_PATCHES_2_20

static const struct shellcore_fpkg_offsets shellcore_fpkg_offsets_220 = {
    .ppr_call = 0x4cfdb1,
    .ppr_cave = 0x12a4160,
    .ppr_cave_size = 0x3ea0,
    .close_plt = 0x129c310,
    .open_plt = 0x129d2c0,
    .pread_plt = 0x129d3b0,
    .mount_ppr_pkg_plt = 0x129efa0,
    .getpid_plt = 0x129bfe0,
};

static struct shellcore_patch shellcore_patches_220_retail[] = {
    {0x88392c, "\x31\xc0\x50\xeb\x08", 5},
    {0x883939, "\xe8\x02\x1e\x00\x00\x58\xc3", 7},
    {0x883934, "\x31\xc0\x50\xeb\xa0", 5},
    {0x8838d9, "\xe8\x82\x1c\x00\x00\x58\xc3", 7},
    {0x485d9e, "\xeb\x04", 2},
    {0x218fa0, "\xeb\x04", 2},
    {0x21cfc7, "\xeb\x04", 2},
    {0x4a29be, "\x90\x90", 2},
    {0x48bced, "\x90\xe9", 2},
    {0x4a23b6, "\xeb", 1},
    {0x4a5233, "\x0f\x02\x00\x00", 4},
    {0x176911, "\xe8\x3a\x59\x3e\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x176a31, "\x83\xf8\x02\x0f\x43\xc1\xe9\x22\xfc\xff\xff", 11},
    {0x17663c, "\xe9\xd0\x02\x00\x00", 5},
    {0x3aef0c, "\x66\x0f\x1f\x44\x00\x00", 6},
    {0x7d4934, "\xeb", 1},
    {0x7b82e6, "\x90\x90\x90\x90\x90", 5},
    {0x215afb, "\x90\xe9", 2},
    {0x215b78, "\x90\xe9", 2},
    {0x215c7b, "\xeb", 1},
    {0x215d4f, "\xeb", 1},
    {0x2161ba, "\x90\xe9", 2},
    {0x21638e, "\xeb", 1},
    {0x216745, "\x90\xe9", 2},
    {0x2167e2, "\x90\xe9", 2},
    {0x487b97, "\xeb", 1},
    {0x487cac, "\xeb", 1},
    {0x489b00, "\x48\x31\xc0\xc3", 4},
};

static struct shellcore_patch shellcore_patches_220_testkit[] = {
};

static struct shellcore_patch shellcore_patches_220_devkit[] = {
};

#endif // SHELLCORE_PATCHES_2_20
