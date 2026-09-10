#ifndef SHELLCORE_PATCHES_2_30
#define SHELLCORE_PATCHES_2_30

static const struct shellcore_fpkg_offsets shellcore_fpkg_offsets_230 = {
    .ppr_call = 0x4d2251,
    .ppr_cave = 0x12a7880,
    .ppr_cave_size = 0x780,
    .close_plt = 0x129fa30,
    .open_plt = 0x12a09e0,
    .pread_plt = 0x12a0ad0,
    .mount_ppr_pkg_plt = 0x12a26c0,
    .getpid_plt = 0x129f700,
};

static struct shellcore_patch shellcore_patches_230_retail[] = {
    {0x8861cc, "\x31\xc0\x50\xeb\x08", 5},
    {0x8861d9, "\xe8\x02\x1e\x00\x00\x58\xc3", 7},
    {0x8861d4, "\x31\xc0\x50\xeb\xa0", 5},
    {0x886179, "\xe8\x82\x1c\x00\x00\x58\xc3", 7},
    {0x4881fe, "\xeb\x04", 2},
    {0x21ae10, "\xeb\x04", 2},
    {0x21ee37, "\xeb\x04", 2},
    {0x4a4e5e, "\x90\x90", 2},
    {0x48e18d, "\x90\xe9", 2},
    {0x4a4856, "\xeb", 1},
    {0x4a76d3, "\x0f\x02\x00\x00", 4},
    {0x176a41, "\xe8\x8a\x81\x3e\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x176b61, "\x83\xf8\x02\x0f\x43\xc1\xe9\x22\xfc\xff\xff", 11},
    {0x17676c, "\xe9\xd0\x02\x00\x00", 5},
    {0x3b136c, "\x66\x0f\x1f\x44\x00\x00", 6},
    {0x7d71d4, "\xeb", 1},
    {0x7bab76, "\x90\x90\x90\x90\x90", 5},
    {0x21741b, "\x90\xe9", 2},
    {0x217498, "\x90\xe9", 2},
    {0x21759b, "\xeb", 1},
    {0x21766f, "\xeb", 1},
    {0x217ada, "\x90\xe9", 2},
    {0x217cae, "\xeb", 1},
    {0x218065, "\x90\xe9", 2},
    {0x218102, "\x90\xe9", 2},
    {0x48a037, "\xeb", 1},
    {0x48a14c, "\xeb", 1},
    {0x48bfa0, "\x48\x31\xc0\xc3", 4},
};

static struct shellcore_patch shellcore_patches_230_testkit[] = {
};

static struct shellcore_patch shellcore_patches_230_devkit[] = {
};

#endif // SHELLCORE_PATCHES_2_30
