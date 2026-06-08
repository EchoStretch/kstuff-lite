#ifndef SHELLCORE_PATCHES_10_40
#define SHELLCORE_PATCHES_10_40

static struct shellcore_patch shellcore_patches_1040_retail[] = {
    {0xC07DB3, "\x52\xeb\xe2", 3}, // push rdx; jmp 0xC07D98
    {0xC07D98, "\xe8\x33\xf8\xff\xff\x58\xc3", 7}, // call 0xC075D0; pop rax; ret
    {0xC075B6, "\xe9\x06\x00\x00\x00", 5}, // jmp 0xC075C1
    {0xC075C1, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xC075D0; pop rax; ret
    {0x702574, "\xeb\x04", 2},
    {0x30D1FF, "\xeb\x04", 2},
    {0x30D5CF, "\xeb\x04", 2},
    {0x7222B5, "\xeb", 1},
    {0x70AEE5, "\x90\xe9", 2},
    {0x7229F3, "\xeb", 1},
    {0x72498F, "\x61\x01\x00\x00", 4}, // 0x724AF4
    {0x206C71, "\xe8\x5a\x71\x60\x00\x31\xc9\xff\xc1\xe9\xd4\x01\x00\x00", 14}, // call 0x80DDD0; xor ecx; inc ecx; jmp 0x206E53
    {0x206E53, "\x83\xf8\x02\x0f\x43\xc1\xe9\x82\xf4\xff\xff", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x2062E0
    {0x2067E3, "\xe9\x89\x04\x00\x00", 5}, // jmp 0x206C71

    {0x745FF0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x16A5C60, "\x31\xc0\xc3", 3}, // VR
    {0x16AA070, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x5d8461, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xaadfa1, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xA8B053, "\xeb\x03", 2}, // disable game error message

    {0x3057F0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x30586A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x30596C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x305A40, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x305E47, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x305FEF, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x30639E, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x306431, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x700C78, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x704142, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x707820, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1040_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1040_devkit[] = {
};

#endif // SHELLCORE_PATCHES_10_40
