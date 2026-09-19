#ifndef SHELLCORE_PATCHES_7_01
#define SHELLCORE_PATCHES_7_01

static struct shellcore_patch shellcore_patches_701_retail[] = {
    {0xb424de, "\x52\xeb\x08", 3},
    {0xb424e9, "\xe8\xd2\xf9\xff\xff\x58\xc3", 7},
    {0xb41eb1, "\x31\xc0\x50\xeb\xe3", 5},
    {0xb41e99, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x68752f, "\xeb\x04", 2},
    {0x2dcfe9, "\xeb\x04", 2},
    {0x2dd439, "\xeb\x04", 2},
    {0x6a5bca, "\xeb", 1},
    {0x68f15d, "\x90\xe9", 2},
    {0x6a6994, "\xeb", 1},
    {0x6a7f38, "\x5e\x01\x00\x00", 4},
    {0x1e1bb1, "\xe8\xca\xc5\x59\x00\x31\xc9\xff\xc1\xe9\x24\x02\x00\x00", 14},
    {0x1e1de3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x55\xfb\xff\xff", 11},
    {0x1e184e, "\xe9\x5e\x03\x00\x00", 5},

    {0x15771F0, "\x31\xC0\xC3", 3}, //VR
    {0x157B620, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x579656, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x9e7e96, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x9CAD26, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x2d59cb, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2d5a49, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x2d5b4b, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x2d5c20, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x2d608a, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x2d625d, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2d6635, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2d66d3, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x68601d, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x688e77, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x68c230, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_701_testkit[] = {
    {0x1587960, "\x31\xC0\xC3", 3}, //VR
    {0x158BD80, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x5852e6, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x9f6f16, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x9D9DA6, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x2DE6DB, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2DE759, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x2DE85B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x2DE930, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x2DED9A, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x2DEF6D, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2DF345, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2DF3E3, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x691BAD, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x694A07, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x697AC0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_701_devkit[] = {
};

#endif // SHELLCORE_PATCHES_7_01
