#ifndef SHELLCORE_PATCHES_6_00
#define SHELLCORE_PATCHES_6_00

static struct shellcore_patch shellcore_patches_600_retail[] = {
    {0xa7d30e, "\x52\xeb\x08", 3},
    {0xa7d319, "\xe8\x82\xfa\xff\xff\x58\xc3", 7},
    {0xa7cd91, "\x31\xc0\x50\xeb\xe3", 5},
    {0xa7cd79, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x5d2bb4, "\xeb\x04", 2},
    {0x2c0982, "\xeb\x04", 2},
    {0x2c0dc2, "\xeb\x04", 2},
    {0x5f01bf, "\xeb", 1},
    {0x5d9c0d, "\x90\xe9", 2},
    {0x5f0ef0, "\xeb", 1},
    {0x5f248a, "\x3b\x01\x00\x00", 4},
    {0x1d8c71, "\xe8\x7a\xb4\x4e\x00\x31\xc9\xff\xc1\xe9\x24\x02\x00\x00", 14},
    {0x1d8ea3, "\x83\xf8\x02\x0f\x43\xc1\xe9\xc5\xfb\xff\xff", 11},
    {0x1d897e, "\xe9\xee\x02\x00\x00", 5},

    {0x14128f0, "\x31\xC0\xC3", 3}, //VR
    {0x1416D30, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x4d3bec, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x92e937, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x91B466, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x2b93cb, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2b9448, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x2b954b, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x2b961f, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x2b9a80, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x2b9c50, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2ba025, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2ba0c2, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x5d42f7, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x5d440c, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x5d7270, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_600_testkit[] = {
    {0x14220D0, "\x31\xC0\xC3", 3}, //VR
    {0x1426500, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x4dfeac, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x93d7c7, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x92A2F6, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x2C255B, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2C25D8, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x2C26DB, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x2C27AF, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x2C2C10, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x2C2DE0, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2C31B5, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2C3252, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x5E0457, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x5E056C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x5E30D0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_600_devkit[] = {
};

#endif // SHELLCORE_PATCHES_6_00


