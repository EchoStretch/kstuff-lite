#ifndef SHELLCORE_PATCHES_9_60
#define SHELLCORE_PATCHES_9_60

static struct shellcore_patch shellcore_patches_960_retail[] = {
    {0xC18073, "\x52\xeb\xe2", 3}, //push rdx; jmp 0xC18058
    {0xC18058, "\xe8\xe3\xf8\xff\xff\x58\xc3", 7}, //call 0xC17940; pop rax; ret
    {0xC17926, "\xe9\x06\x00\x00\x00", 5},  // jmp 0xC17931
    {0xC17931, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, //xor eax, eax; push rax; call 0xC17940; pop rax; ret
    {0x6F20B8, "\xeb\x04", 2},
    {0x30E62F, "\xeb\x04", 2},
    {0x30E9FF, "\xeb\x04", 2},
    {0x711D4B, "\xeb", 1},
    {0x6FA5E5, "\x90\xe9", 2},
    {0x7124B5, "\xeb", 1},
    {0x71449F, "\x61\x01\x00\x00", 4}, // 0x714604
    {0x20A511, "\xe8\xba\x02\x60\x00\x31\xc9\xff\xc1\xe9\x84\x03\x00\x00", 14}, // call 0x80A7D0; xor ecx; inc ecx; jmp 0x20A8A3
    {0x20A8A3, "\x83\xf8\x02\x0f\x43\xc1\xe9\xe1\xf3\xff\xff", 11},// cmp eax, 2; cmovae eax, ecx; jmp 0x209C8F
    {0x209A91, "\xe9\x7b\x0a\x00\x00", 5}, // jmp 0x20A511

    {0x734780, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x16AD8E0, "\x31\xc0\xc3", 3}, // VR
    {0x16B1CE0, "\x31\xc0\xc3", 3}, // VR2 Update bypass
    {0x5dad7a, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xabb4f1, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xA972E6, "\xeb\x03", 2}, // disable game error message

    {0x306D4B, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x306DC9, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x306ECC, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x306FA0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x3073A6, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x30754D, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x30790E, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3079A1, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x6F0D3A, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x6F3C74, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x6F72C0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_960_testkit[] = {
};

static struct shellcore_patch shellcore_patches_960_devkit[] = {
};

#endif // SHELLCORE_PATCHES_9_60
