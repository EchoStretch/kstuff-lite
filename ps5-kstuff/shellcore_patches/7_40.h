#ifndef SHELLCORE_PATCHES_7_40
#define SHELLCORE_PATCHES_7_40

static struct shellcore_patch shellcore_patches_740_retail[] = {
    {0xb4e4ae, "\x52\xeb\x08", 3},
    {0xb4e4b9, "\xe8\xD2\xf9\xff\xff\x58\xc3", 7},
    {0xb4de81, "\x31\xc0\x50\xeb\xe3", 5},
    {0xb4de69, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x68c03f, "\xeb\x04", 2},
    {0x2e13b9, "\xeb\x04", 2},
    {0x2e1809, "\xeb\x04", 2},
    {0x6aa6da, "\xeb", 1},
    {0x693c6d, "\x90\xe9", 2},
    {0x6ab4a4, "\xeb", 1},
    {0x6aca48, "\x5e\x01\x00\x00", 4},
    {0x1e5f81, "\xe8\xba\xd5\x59\x00\x31\xc9\xff\xc1\xe9\x24\x02\x00\x00", 14},
    {0x1e61b3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x55\xfb\xff\xff", 11},
    {0x1e5c1e, "\xe9\x5e\x03\x00\x00", 5},

    {0x1584BE0, "\x31\xC0\xC3", 3}, //VR
    {0x1589010, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x57e166, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x9f3e66, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x9D6CF6, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x2d9d9b, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2d9e19, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x2d9f1b, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x2d9ff0, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x2da45a, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x2da62d, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2daa05, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2daaa3, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x68ab2d, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x68d987, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x690d40, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_740_testkit[] = {
};

static struct shellcore_patch shellcore_patches_740_devkit[] = {
};

#endif // SHELLCORE_PATCHES_7_40
