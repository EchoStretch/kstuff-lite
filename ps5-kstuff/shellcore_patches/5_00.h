#ifndef SHELLCORE_PATCHES_5_00
#define SHELLCORE_PATCHES_5_00

static struct shellcore_patch shellcore_patches_500_retail[] = {
    {0xa2e62e, "\x52\xeb\x08", 3},
    {0xa2e639, "\xe8\x22\xfb\xff\xff\x58\xc3", 7},
    {0xa2e151, "\x31\xc0\x50\xeb\xe3", 5},
    {0xa2e139, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x59c2b8, "\xeb\x04", 2},
    {0x2a013c, "\xeb\x04", 2},
    {0x2a054c, "\xeb\x04", 2},
    {0x5b9377, "\xeb", 1},
    {0x5a2f1d, "\x90\xe9", 2},
    {0x5ba0af, "\xeb", 1},
    {0x5bb613, "\x3b\x01\x00\x00", 4},
    {0x1c33c1, "\xe8\xea\x7d\x4c\x00\x31\xc9\xff\xc1\xe9\x24\x02\x00\x00", 14},
    {0x1c35f3, "\x83\xf8\x02\x0f\x43\xc1\xe9\xca\xfb\xff\xff", 11},
    {0x1c30ee, "\xe9\xce\x02\x00\x00", 5},

    {0x1382490, "\x31\xC0\xC3", 3}, //VR
    {0x1386860, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x4a3e7c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x8e2c87, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x8CEAC6, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x298CDB, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x298D58, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x298E5B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x298F2F, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x299396, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x299567, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x299935, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2999D2, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x59D747, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x59D85C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x5A02E0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_500_testkit[] = {
    {0x1384340, "\x31\xC0\xC3", 3}, //VR
    {0x1388700, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x8D0076, "\x90\x90\x90\x90\x90", 5}, //disable game error message
    {0x29455B, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2945D8, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x2946DB, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x2947AF, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x294C16, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x294DE7, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2951B5, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x295252, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x59C247, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x59C35C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x59E5C0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_500_devkit[] = {
    {0x13845A0, "\x31\xC0\xC3", 3}, //VR
    {0x1388960, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x8D02F6, "\x90\x90\x90\x90\x90", 5}, //disable game error message
    {0x294ABB, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x294B38, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x294C3B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x294D0F, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x295176, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x295347, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x295715, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2957B2, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x59C4F7, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x59C60C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x59E870, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

#endif // SHELLCORE_PATCHES_5_00
