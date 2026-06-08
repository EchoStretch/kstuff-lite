#ifndef SHELLCORE_PATCHES_5_50
#define SHELLCORE_PATCHES_5_50

static struct shellcore_patch shellcore_patches_550_retail[] = {
    {0xa319ee, "\x52\xeb\x08", 3},
    {0xa319f9, "\xe8\x22\xfb\xff\xff\x58\xc3", 7},
    {0xa31511, "\x31\xc0\x50\xeb\xe3", 5},
    {0xa314f9, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x59ed78, "\xeb\x04", 2},
    {0x2a100c, "\xeb\x04", 2},
    {0x2a141c, "\xeb\x04", 2},
    {0x5bbe37, "\xeb", 1},
    {0x5a59dd, "\x90\xe9", 2},
    {0x5bcb6f, "\xeb", 1},
    {0x5be0d3, "\x3b\x01\x00\x00", 4},
    {0x1c3511, "\xe8\xba\xb4\x4c\x00\x31\xc9\xff\xc1\xe9\x24\x02\x00\x00", 14},
    {0x1c3743, "\x83\xf8\x02\x0f\x43\xc1\xe9\xca\xfb\xff\xff", 11},
    {0x1c323e, "\xe9\xce\x02\x00\x00", 5},

    {0x1389c00, "\x31\xC0\xC3", 3}, //VR
    {0x138DFD0, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x4a5d9c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x8e6057, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x8D1E96, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x299BAB, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x299C28, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x299D2B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x299DFF, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x29A266, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x29A437, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x29A805, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x29A8A2, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x5A0207, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x5A031C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x5A2DA0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_550_testkit[] = {
};

static struct shellcore_patch shellcore_patches_550_devkit[] = {
    {0x138BD90, "\x31\xC0\xC3", 3},  //VR
    {0x1390150, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x4a4dcc, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x8e78f7, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x8D3736, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x29598B, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x295A08, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x295B0B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x295BDF, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x296046, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x296217, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2965E5, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x296682, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x59F027, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x59F13C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x5A13A0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};


#endif // SHELLCORE_PATCHES_5_50
