#ifndef SHELLCORE_PATCHES_1_14
#define SHELLCORE_PATCHES_1_14

static const struct shellcore_fpkg_offsets shellcore_fpkg_offsets_114 = {
    .ppr_call = 0x463af1,
    .ppr_cave = 0x11285f0,
    .ppr_cave_size = 0x3a10,
    .close_plt = 0x1120a30,
    .open_plt = 0x1121810,
    .pread_plt = 0x1121980,
    .mount_ppr_pkg_plt = 0x11235e0,
    .getpid_plt = 0x1120730,
};

static struct shellcore_patch shellcore_patches_114_retail[] = {
    {0x7e0ecf, "\x31\xc0\x50\xeb\x00", 5},
    {0x7e0ed4, "\xe8\x77\x1a\x00\x00\x58\xc3", 7},
    {0x7e0ec3, "\x31\xc0\x50\xeb\xd1", 5},
    {0x7e0e99, "\xe8\x22\x19\x00\x00\x58\xc3", 7},
    {0x41ad23, "\xeb\x04", 2},
    {0x1e1270, "\xeb\x04", 2},
    {0x1e5207, "\xeb\x04", 2},
    {0x4358c3, "\x90\x90", 2},
    {0x42076d, "\x90\xe9", 2},
    {0x43532a, "\xeb", 1},
    {0x438152, "\x1a\x02\x00\x00", 4},
    {0x147c91, "\xe8\x3a\x3c\x3a\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x147db1, "\x83\xf8\x02\x0f\x43\xc1\xe9\x8d\xfc\xff\xff", 11},
    {0x147a27, "\xe9\x65\x02\x00\x00", 5},
    {0x35094c, "\x66\x0f\x1f\x44\x00\x00", 6},
    {0x734a94, "\xeb", 1},
    {0x7180e6, "\x90\x90\x90\x90\x90", 5},
    {0x1ddafb, "\x90\xe9", 2},
    {0x1ddb78, "\x90\xe9", 2},
    {0x1ddc7b, "\xeb", 1},
    {0x1ddd4f, "\xeb", 1},
    {0x1de1ba, "\x90\xe9", 2},
    {0x1de38e, "\xeb", 1},
    {0x1de73e, "\x90\xe9", 2},
    {0x1de804, "\x90\xe9", 2},
    {0x41cbc7, "\xeb", 1},
    {0x41ccdc, "\xeb", 1},
};

static struct shellcore_patch shellcore_patches_114_testkit[] = {
};

static struct shellcore_patch shellcore_patches_114_devkit[] = {
};

#endif // SHELLCORE_PATCHES_1_14
