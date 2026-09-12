#ifndef SHELLCORE_PATCHES_2_00
#define SHELLCORE_PATCHES_2_00

static const struct shellcore_fpkg_offsets shellcore_fpkg_offsets_200 = {
    .ppr_call = 0x4cfa61,
    .ppr_cave = 0x12a3cf0,
    .ppr_cave_size = 0x310,
    .close_plt = 0x129bea0,
    .open_plt = 0x129ce50,
    .pread_plt = 0x129cf40,
    .mount_ppr_pkg_plt = 0x129eb30,
    .getpid_plt = 0x129bb70,
};

static struct shellcore_patch shellcore_patches_200_retail[] = {
    {0x8835dc, "\x31\xc0\x50\xeb\x08", 5},
    {0x8835e9, "\xe8\x02\x1e\x00\x00\x58\xc3", 7},
    {0x8835e4, "\x31\xc0\x50\xeb\xa0", 5},
    {0x883589, "\xe8\x82\x1c\x00\x00\x58\xc3", 7},
    {0x485a4e, "\xeb\x04", 2},
    {0x218d00, "\xeb\x04", 2},
    {0x21cd27, "\xeb\x04", 2},
    {0x4a266e, "\x90\x90", 2},
    {0x48b99d, "\x90\xe9", 2},
    {0x4a2066, "\xeb", 1},
    {0x4a4ee3, "\x0f\x02\x00\x00", 4},
    {0x176691, "\xe8\x6a\x58\x3e\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x1767b1, "\x83\xf8\x02\x0f\x43\xc1\xe9\x22\xfc\xff\xff", 11},
    {0x1763bc, "\xe9\xd0\x02\x00\x00", 5},
    {0x3aec3c, "\x66\x0f\x1f\x44\x00\x00", 6},
    {0x7d45e4, "\xeb", 1},
    {0x7b7f96, "\x90\x90\x90\x90\x90", 5},
    {0x21585b, "\x90\xe9", 2},
    {0x2158d8, "\x90\xe9", 2},
    {0x2159db, "\xeb", 1},
    {0x215aaf, "\xeb", 1},
    {0x215f1a, "\x90\xe9", 2},
    {0x2160ee, "\xeb", 1},
    {0x2164a5, "\x90\xe9", 2},
    {0x216542, "\x90\xe9", 2},
    {0x487847, "\xeb", 1},
    {0x48795c, "\xeb", 1},
    {0x4897b0, "\x48\x31\xc0\xc3", 4},
};

static struct shellcore_patch shellcore_patches_200_testkit[] = {
};

static struct shellcore_patch shellcore_patches_200_devkit[] = {
};

#endif // SHELLCORE_PATCHES_2_00
