#ifndef SHELLCORE_PATCHES_4_51
#define SHELLCORE_PATCHES_4_51

static struct shellcore_patch shellcore_patches_451_retail[] = {
    {0x97596e, "\x52\xeb\x08", 3},
    {0x975979, "\xe8\xd2\xfb\xff\xff\x58\xc3", 7},
    {0x975541, "\x31\xc0\x50\xeb\xe3", 5},
    {0x975529, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x530f52, "\xeb\x04", 2},
    {0x26fa8c, "\xeb\x04", 2},
    {0x26fe9c, "\xeb\x04", 2},
    {0x54eb70, "\xeb", 1},
    {0x5376cd, "\x90\xe9", 2},
    {0x54e50f, "\xeb", 1},
    {0x551cfa, "\xc8\x00\x00\x00", 4},
    {0x1a12d1, "\xe8\x6a\x92\x47\x00\x31\xc9\xff\xc1\xe9\xf4\x02\x00\x00", 14},
    {0x1a15d3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x29\xfa\xff\xff", 11},
    {0x1a0fe5, "\xe9\xe7\x02\x00\x00", 5},

    {0x12C1E70, "\x31\xC0\xC3", 3}, //VR2 Min Fw Check
    {0x43e29c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x834127, "\xEB", 1}, // fix trophies not unlocking in certain games 
    {0x81D3D6, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x2684eb, "\x90\xe9", 2}, //PS4 Disc Installer Patch 1
    {0x268582, "\x90\xe9", 2}, //PS5 Disc Installer Patch 1
    {0x26869b, "\xeb", 1}, //PS4 PKG Installer Patch 1
    {0x26876f, "\xeb", 1}, //PS5 PKG Installer Patch 1
    {0x268bd8, "\x90\xe9", 2}, //PS4 PKG Installer Patch 2
    {0x268da9, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x269175, "\x90\xe9", 2}, //PS4 PKG Installer Patch 3
    {0x269212, "\x90\xe9", 2}, //PS5 PKG Installer Patch 3
    {0x533147, "\xeb", 1}, //PS4 PKG Installer Patch 4
    {0x53325c, "\xeb", 1}, //PS5 PKG Installer Patch 4
    {0x535170, "\x48\x31\xc0\xc3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_451_testkit[] = {
    {0x4701D0, "\xEB", 1},
    {0x12CE030, "\x31\xC0\xC3", 3}, //VR2 Min Fw Check
    {0x4471ac, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x83f517, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x8287C6, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x2724DB, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x272572, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x27268B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x27275F, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x272BC8, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x272D99, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x273165, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x273202, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x53BCF7, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x53BE0C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x53D750, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_451_devkit[] = {
    {0x4703B0, "\xEB", 1},
    {0x12CE110, "\x31\xC0\xC3", 3}, //VR2 Min Fw Check
    {0x44738c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x83f687, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x828936, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x272A4B, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x272AE2, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x272BFB, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x272CCF, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x273138, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x273309, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2736D5, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x273772, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x53BE67, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x53BF7C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x53D8C0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

#endif // SHELLCORE_PATCHES_4_51
