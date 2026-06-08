#ifndef SHELLCORE_PATCHES_3_10
#define SHELLCORE_PATCHES_3_10

static struct shellcore_patch shellcore_patches_310_retail[] = {
    {0x9d1cee, "\x52\xeb\x08", 3},
    {0x9d1cf9, "\xe8\x02\xfc\xff\xff\x58\xc3", 7},
    {0x9d18f1, "\x31\xc0\x50\xeb\xe3", 5},
    {0x9d18d9, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x4dcff4, "\xeb\x04", 2},
    {0x2569f1, "\xeb\x04", 2},
    {0x25af9a, "\xeb\x04", 2},
    {0x4fb00a, "\x90\x90", 2},
    {0x4e339d, "\x90\xe9", 2},
    {0x4fbba3, "\xeb", 1},
    {0x4ff369, "\xd0\x00\x00\x00", 4},
    {0x1968c1, "\xe8\x8a\xde\x42\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x1969e1, "\x83\xf8\x02\x0f\x43\xc1\xe9\xff\xfb\xff\xff", 11},
    {0x1965c9, "\xe9\xf3\x02\x00\x00", 5},

    {0x131FA50, "\x31\xC0\xC3", 3}, //VR2 Min Fw Check
    {0x3fc28c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x8b5674, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x8991A6, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x25288B, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x252908, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x252A0B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x252ADF, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x252F75, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x253160, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x253525, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2535C2, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x4DEF77, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x4DF08C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x4E0F50, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_310_testkit[] = {
};

static struct shellcore_patch shellcore_patches_310_devkit[] = {
};

#endif // SHELLCORE_PATCHES_3_10