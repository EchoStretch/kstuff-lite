#ifndef SHELLCORE_PATCHES_6_50
#define SHELLCORE_PATCHES_6_50

static struct shellcore_patch shellcore_patches_650_retail[] = {
    {0xa7dade, "\x52\xeb\x08", 3},
    {0xa7dae9, "\xe8\x82\xfa\xff\xff\x58\xc3", 7},
    {0xa7d561, "\x31\xc0\x50\xeb\xe3", 5},
    {0xa7d549, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x5d2c24, "\xeb\x04", 2},
    {0x2c09f2, "\xeb\x04", 2},
    {0x2c0e32, "\xeb\x04", 2},
    {0x5f022f, "\xeb", 1},
    {0x5d9c7d, "\x90\xe9", 2},
    {0x5f0f60, "\xeb", 1},
    {0x5f24fa, "\x3b\x01\x00\x00", 4},
    {0x1d8c71, "\xe8\xea\xaf\x4e\x00\x31\xc9\xff\xc1\xe9\x24\x02\x00\x00", 14},
    {0x1d8ea3, "\x83\xf8\x02\x0f\x43\xc1\xe9\xc5\xfb\xff\xff", 11},
    {0x1d897e, "\xe9\xee\x02\x00\x00", 5},

    {0x1413110, "\x31\xC0\xC3", 3}, //VR
    {0x1417550, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x4d3c5c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x92f107, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x91BC36, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x2b943b, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2b94b8, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x2b95bb, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x2b968f, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x2b9af0, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x2b9cc0, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2ba095, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2ba132, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x5d4367, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x5d447c, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x5d72e0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_650_testkit[] = {
};

static struct shellcore_patch shellcore_patches_650_devkit[] = {
};

#endif // SHELLCORE_PATCHES_6_50
