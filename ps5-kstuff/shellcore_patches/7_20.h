#ifndef SHELLCORE_PATCHES_7_20
#define SHELLCORE_PATCHES_7_20

static struct shellcore_patch shellcore_patches_720_retail[] = {
    {0xb42dbe, "\x52\xeb\x08", 3},
    {0xb42dc9, "\xe8\xd2\xf9\xff\xff\x58\xc3", 7},
    {0xb42791, "\x31\xc0\x50\xeb\xe3", 5},
    {0xb42779, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x68754f, "\xeb\x04", 2},
    {0x2dcfe9, "\xeb\x04", 2},
    {0x2dd439, "\xeb\x04", 2},
    {0x6a5bea, "\xeb", 1},
    {0x68f17d, "\x90\xe9", 2},
    {0x6a69b4, "\xeb", 1},
    {0x6a7f58, "\x5e\x01\x00\x00", 4},
    {0x1e1bb1, "\xe8\x9a\xce\x59\x00\x31\xc9\xff\xc1\xe9\x24\x02\x00\x00", 14},
    {0x1e1de3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x55\xfb\xff\xff", 11},
    {0x1e184e, "\xe9\x5e\x03\x00\x00", 5},

    {0x1577AD0, "\x31\xC0\xC3", 3}, //VR
    {0x157BF00, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x579676, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x9e8776, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x9CB606, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x2d59cb, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2d5a49, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x2d5b4b, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x2d5c20, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x2d608a, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x2d625d, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2d6635, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x2d66d3, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x68603d, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x688e97, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x68c250, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_720_testkit[] = {
};

static struct shellcore_patch shellcore_patches_720_devkit[] = {
};

#endif // SHELLCORE_PATCHES_7_20
