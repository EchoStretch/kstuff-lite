#ifndef SHELLCORE_PATCHES_9_20
#define SHELLCORE_PATCHES_9_20

static struct shellcore_patch shellcore_patches_920_retail[] = {
    {0xC0F553, "\x52\xeb\xe2", 3}, //push rdx; jmp 0xC0F538
    {0xC0F538, "\xe8\xe3\xf8\xff\xff\x58\xc3", 7}, //call 0xC0EE20; pop rax; ret
    {0xC0EE06, "\xe9\x06\x00\x00\x00", 5},  // jmp 0xC0EE11
    {0xC0EE11, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, //xor eax, eax; push rax; call 0xC0EE20; pop rax; ret
    {0x6F1978, "\xeb\x04", 2},
    {0x30DEEF, "\xeb\x04", 2},
    {0x30E2BF, "\xeb\x04", 2},
    {0x71160B, "\xeb", 1},
    {0x6F9EA5, "\x90\xe9", 2},
    {0x711D75, "\xeb", 1},
    {0x713D5F, "\x61\x01\x00\x00", 4}, // 0x713EC4
    {0x209DD1, "\xe8\x4a\x02\x60\x00\x31\xc9\xff\xc1\xe9\x84\x03\x00\x00", 14}, // call 0x80A020; xor ecx; inc ecx; jmp 0x20A163
    {0x20A163, "\x83\xf8\x02\x0f\x43\xc1\xe9\x01\xf4\xff\xff", 11},// cmp eax, 2; cmovae eax, ecx; jmp 0x20956F
    {0x209371, "\xe9\x5b\x0a\x00\x00", 5}, // jmp 0x209DD1

    {0x734040, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x16A4D70, "\x31\xc0\xc3", 3}, // VR
    {0x16A9170, "\x31\xc0\xc3", 3}, // VR2 Update bypass
    {0x5da63a, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xab29d1, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xA8E7C6, "\xeb\x03", 2}, // disable game error message

    {0x30660B, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x306689, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x30678C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x306860, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x306C66, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x306E0D, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x3071CE, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x307261, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x6F05FA, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x6F3534, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x6F6B80, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_920_testkit[] = {
};

static struct shellcore_patch shellcore_patches_920_devkit[] = {
};

#endif // SHELLCORE_PATCHES_9_20
