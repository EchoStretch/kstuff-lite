#ifndef SHELLCORE_PATCHES_5_02
#define SHELLCORE_PATCHES_5_02

static struct shellcore_patch shellcore_patches_502_retail[] = {
    {0xa2e61e, "\x52\xeb\x08", 3},
    {0xa2e629, "\xe8\x22\xfb\xff\xff\x58\xc3", 7},
    {0xa2e141, "\x31\xc0\x50\xeb\xe3", 5},
    {0xa2e129, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x59c2a8, "\xeb\x04", 2},
    {0x2a013c, "\xeb\x04", 2},
    {0x2a054c, "\xeb\x04", 2},
    {0x5b9367, "\xeb", 1},
    {0x5a2f0d, "\x90\xe9", 2},
    {0x5ba09f, "\xeb", 1},
    {0x5bb603, "\x3b\x01\x00\x00", 4},
    {0x1c33c1, "\xe8\xda\x7d\x4c\x00\x31\xc9\xff\xc1\xe9\x24\x02\x00\x00", 14},
    {0x1c35f3, "\x83\xf8\x02\x0f\x43\xc1\xe9\xca\xfb\xff\xff", 11},
    {0x1c30ee, "\xe9\xce\x02\x00\x00", 5},

    {0x1382470, "\x31\xC0\xC3", 3}, //VR
    {0x1386840, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x4a3e6c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x8e2c77, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x8CEAB6, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x298CDB, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x298D58, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x298E5B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x298F2F, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x299396, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x299567, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x299935, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2999D2, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x59D737, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x59D84C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x5A02D0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_502_testkit[] = {
};

static struct shellcore_patch shellcore_patches_502_devkit[] = {
};

#endif // SHELLCORE_PATCHES_5_02
