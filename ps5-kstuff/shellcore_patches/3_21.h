#ifndef SHELLCORE_PATCHES_3_21
#define SHELLCORE_PATCHES_3_21

static struct shellcore_patch shellcore_patches_321_retail[] = {
    {0x9d1f9e, "\x52\xeb\x08", 3},
    {0x9d1fa9, "\xe8\x02\xfc\xff\xff\x58\xc3", 7},
    {0x9d1ba1, "\x31\xc0\x50\xeb\xe3", 5},
    {0x9d1b89, "\xe8\x22\x00\x00\x00\x58\xc3", 7},
    {0x4dd284, "\xeb\x04", 2},
    {0x256aa1, "\xeb\x04", 2},
    {0x25b04a, "\xeb\x04", 2},
    {0x4fb29a, "\x90\x90", 2},
    {0x4e362d, "\x90\xe9", 2},
    {0x4fbe33, "\xeb", 1},
    {0x4ff5f9, "\xd0\x00\x00\x00", 4},
    {0x1968c1, "\xe8\x3a\xe1\x42\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14},
    {0x1969e1, "\x83\xf8\x02\x0f\x43\xc1\xe9\xff\xfb\xff\xff", 11},
    {0x1965c9, "\xe9\xf3\x02\x00\x00", 5},

    {0x131FEA0, "\x31\xC0\xC3", 3}, //VR2 Min Fw Check
    {0x3fc33c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x8b5924, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x899456, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x25293B, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2529B8, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x252ABB, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x252B8F, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x253025, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x253210, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x2535D5, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x253672, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x4DF207, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x4DF31C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x4E11E0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_321_testkit[] = {
};

static struct shellcore_patch shellcore_patches_321_devkit[] = {
};

#endif // SHELLCORE_PATCHES_3_21