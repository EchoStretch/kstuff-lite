#ifndef SHELLCORE_PATCHES_4_50
#define SHELLCORE_PATCHES_4_50

static struct shellcore_patch shellcore_patches_450_retail[] = {
    {0x97595e, "\x52\xeb\x08", 3},
    {0x975969, "\xe8\xd2\xfb\xff\xff\x58\xc3", 7},
    {0x975531, "\x31\xc0\x50\xeb\xe3", 5},
    {0x975519, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x530f42, "\xeb\x04", 2},
    {0x26fa8c, "\xeb\x04", 2},
    {0x26fe9c, "\xeb\x04", 2},
    {0x54eb60, "\xeb", 1},
    {0x5376bd, "\x90\xe9", 2},
    {0x54e4ff, "\xeb", 1},
    {0x551cea, "\xc8\x00\x00\x00", 4},
    {0x1a12d1, "\xe8\x5a\x92\x47\x00\x31\xc9\xff\xc1\xe9\xf4\x02\x00\x00", 14},
    {0x1a15d3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x29\xfa\xff\xff", 11},
    {0x1a0fe5, "\xe9\xe7\x02\x00\x00", 5},

    {0x12C1E70, "\x31\xC0\xC3", 3}, //VR2 Min Fw Check
    {0x43e29c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x834117, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x81D3C6, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x2684eb, "\x90\xe9", 2}, //PS4 Disc Installer Patch 1
    {0x268582, "\x90\xe9", 2}, //PS5 Disc Installer Patch 1
    {0x26869b, "\xeb", 1}, //PS4 PKG Installer Patch 1
    {0x26876f, "\xeb", 1}, //PS5 PKG Installer Patch 1
    {0x268bd8, "\x90\xe9", 2}, //PS4 PKG Installer Patch 2
    {0x268da9, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x269175, "\x90\xe9", 2}, //PS4 PKG Installer Patch 3
    {0x269212, "\x90\xe9", 2}, //PS5 PKG Installer Patch 3
    {0x533137, "\xeb", 1}, //PS4 PKG Installer Patch 4
    {0x53324c, "\xeb", 1}, //PS5 PKG Installer Patch 4
    {0x535160, "\x48\x31\xc0\xc3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_450_testkit[] = {
};

static struct shellcore_patch shellcore_patches_450_devkit[] = {
};

#endif // SHELLCORE_PATCHES_4_50