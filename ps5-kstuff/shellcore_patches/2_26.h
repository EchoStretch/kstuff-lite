#ifndef SHELLCORE_PATCHES_2_26
#define SHELLCORE_PATCHES_2_26

static const struct shellcore_fpkg_offsets shellcore_fpkg_offsets_226 = {
    .ppr_call = 0x4d1ab1,
    .ppr_cave = 0x12a6a00,
    .ppr_cave_size = 0x1600,
    .close_plt = 0x129ebb0,
    .open_plt = 0x129fb60,
    .pread_plt = 0x129fc50,
    .mount_ppr_pkg_plt = 0x12a1840,
    .getpid_plt = 0x129e880,
};

static struct shellcore_patch shellcore_patches_226_retail[] = {
    {0x88562c, "\x31\xc0\x50\xeb\x08", 5},
    {0x885639, "\xe8\x02\x1e\x00\x00\x58\xc3", 7},
    {0x885634, "\x31\xc0\x50\xeb\xa0", 5},
    {0x8855d9, "\xe8\x82\x1c\x00\x00\x58\xc3", 7},
    {0x487a5e, "\xeb\x04", 2},
    {0x21ac60, "\xeb\x04", 2},
    {0x21ec87, "\xeb\x04", 2},
    {0x4a46be, "\x90\x90", 2},
    {0x48d9ed, "\x90\xe9", 2},
    {0x4a40b6, "\xeb", 1},
    {0x4a6f33, "\x0f\x02\x00\x00", 4},
    {0x176911, "\xe8\x3a\x76\x3e\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x176a31, "\x83\xf8\x02\x0f\x43\xc1\xe9\x22\xfc\xff\xff", 11},
    {0x17663c, "\xe9\xd0\x02\x00\x00", 5},
    {0x3b0bcc, "\x66\x0f\x1f\x44\x00\x00", 6},
    {0x7d6634, "\xeb", 1},
    {0x7b9fe6, "\x90\x90\x90\x90\x90", 5},
    {0x21726b, "\x90\xe9", 2},
    {0x2172e8, "\x90\xe9", 2},
    {0x2173eb, "\xeb", 1},
    {0x2174bf, "\xeb", 1},
    {0x21792a, "\x90\xe9", 2},
    {0x217afe, "\xeb", 1},
    {0x217eb5, "\x90\xe9", 2},
    {0x217f52, "\x90\xe9", 2},
    {0x489897, "\xeb", 1},
    {0x4899ac, "\xeb", 1},
    {0x48b800, "\x48\x31\xc0\xc3", 4},
};

static struct shellcore_patch shellcore_patches_226_testkit[] = {
};

static struct shellcore_patch shellcore_patches_226_devkit[] = {
};

#endif // SHELLCORE_PATCHES_2_26
