#ifndef SHELLCORE_PATCHES_2_70
#define SHELLCORE_PATCHES_2_70

static const struct shellcore_fpkg_offsets shellcore_fpkg_offsets_270 = {
    .ppr_call = 0x4d3601,
    .ppr_cave = 0x12aa7c0,
    .ppr_cave_size = 0x1840,
    .close_plt = 0x12a2970,
    .open_plt = 0x12a3920,
    .pread_plt = 0x12a3a10,
    .mount_ppr_pkg_plt = 0x12a5610,
    .getpid_plt = 0x12a2640,
};

static struct shellcore_patch shellcore_patches_270_retail[] = {
    {0x88757c, "\x31\xc0\x50\xeb\x08", 5},
    {0x887589, "\xe8\x02\x1e\x00\x00\x58\xc3", 7},
    {0x887584, "\x31\xc0\x50\xeb\xa0", 5},
    {0x887529, "\xe8\x82\x1c\x00\x00\x58\xc3", 7},
    {0x4895ae, "\xeb\x04", 2},
    {0x21abb0, "\xeb\x04", 2},
    {0x21ebd7, "\xeb\x04", 2},
    {0x4a620e, "\x90\x90", 2},
    {0x48f53d, "\x90\xe9", 2},
    {0x4a5c06, "\xeb", 1},
    {0x4a8a83, "\x0f\x02\x00\x00", 4},
    {0x176a41, "\xe8\x3a\x95\x3e\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x176b61, "\x83\xf8\x02\x0f\x43\xc1\xe9\x22\xfc\xff\xff", 11},
    {0x17676c, "\xe9\xd0\x02\x00\x00", 5},
    {0x3b271c, "\x66\x0f\x1f\x44\x00\x00", 6},
    {0x7d8584, "\xeb", 1},
    {0x7bbf26, "\x90\x90\x90\x90\x90", 5},
    {0x2171bb, "\x90\xe9", 2},
    {0x217238, "\x90\xe9", 2},
    {0x21733b, "\xeb", 1},
    {0x21740f, "\xeb", 1},
    {0x21787a, "\x90\xe9", 2},
    {0x217a4e, "\xeb", 1},
    {0x217e05, "\x90\xe9", 2},
    {0x217ea2, "\x90\xe9", 2},
    {0x48b3e7, "\xeb", 1},
    {0x48b4fc, "\xeb", 1},
    {0x48d350, "\x48\x31\xc0\xc3", 4},
};

static struct shellcore_patch shellcore_patches_270_testkit[] = {
};

static struct shellcore_patch shellcore_patches_270_devkit[] = {
};

#endif // SHELLCORE_PATCHES_2_70
