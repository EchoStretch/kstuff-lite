#ifndef SHELLCORE_PATCHES_3_00
#define SHELLCORE_PATCHES_3_00

static struct shellcore_patch shellcore_patches_300_retail[] = {
    {0x9d1cae, "\x52\xeb\x08", 3},
    {0x9d1cb9, "\xe8\x02\xfc\xff\xff\x58\xc3", 7},
    {0x9d18b1, "\x31\xc0\x50\xeb\xe3", 5},
    {0x9d1899, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x4dcfb4, "\xeb\x04", 2},
    {0x2569b1, "\xeb\x04", 2},
    {0x25af5a, "\xeb\x04", 2},
    {0x4fafca, "\x90\x90", 2},
    {0x4e335d, "\x90\xe9", 2},
    {0x4fbb63, "\xeb", 1},
    {0x4ff329, "\xd0\x00\x00\x00", 4},
    {0x1968c1, "\xe8\x4a\xde\x42\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x1969e1, "\x83\xf8\x02\x0f\x43\xc1\xe9\xff\xfb\xff\xff", 11},
    {0x1965c9, "\xe9\xf3\x02\x00\x00", 5},

    {0x3fc24c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x8b5634, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x899166, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x25284B, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2528C8, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x2529CB, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x252A9F, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x252F35, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x253120, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2534E5, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x253582, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x4DEF37, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x4DF04C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x4E0F10, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_300_testkit[] = {
    {0x40377c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x8bf934, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x8A3466, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x25C3EB, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x25C468, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x25C56B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x25C63F, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x25CAD5, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x25CCC0, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x25D085, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x25D122, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x4E6207, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x4E631C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x4E7C10, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_300_devkit[] = {
};

#endif // SHELLCORE_PATCHES_3_00


