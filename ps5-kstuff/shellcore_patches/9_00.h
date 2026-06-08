#ifndef SHELLCORE_PATCHES_9_00
#define SHELLCORE_PATCHES_9_00

static struct shellcore_patch shellcore_patches_900_retail[] = {
    {0xC0F813, "\x52\xeb\xe2", 3}, //push rdx; jmp 0xC0F7F8
    {0xC0F7F8, "\xe8\xe3\xf8\xff\xff\x58\xc3", 7}, //call 0xC0F0E0; pop rax; ret
    {0xC0F0C6, "\xe9\x06\x00\x00\x00", 5},  // jmp 0xC0F0D1
    {0xC0F0D1, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, //xor eax, eax; push rax; call 0xC0F0E0; pop rax; ret
    {0x6F1C08, "\xeb\x04", 2},
    {0x30E1CF, "\xeb\x04", 2},
    {0x30E59F, "\xeb\x04", 2},
    {0x7118CB, "\xeb", 1},
    {0x6FA165, "\x90\xe9", 2},
    {0x712035, "\xeb", 1},
    {0x71401F, "\x61\x01\x00\x00", 4}, // 0x714184
    {0x209DD1, "\xe8\x0a\x05\x60\x00\x31\xc9\xff\xc1\xe9\x84\x03\x00\x00", 14}, // call 0x80A2E0; xor ecx; inc ecx; jmp 0x20A163
    {0x20A163, "\x83\xf8\x02\x0f\x43\xc1\xe9\x01\xf4\xff\xff", 11},// cmp eax, 2; cmovae eax, ecx; jmp 0x20956F
    {0x209371, "\xe9\x5b\x0a\x00\x00", 5}, // jmp 0x209DD1

    {0x734300, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x16A4690, "\x31\xc0\xc3", 3}, //VR
    {0x16A8A90, "\x31\xc0\xc3", 3}, // VR2 Update bypass
    {0x5da91a, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xab2c91, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xA8EA86, "\xeb\x03", 2}, // disable game error message

    {0x3068EB, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x306969, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x306A6C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x306B40, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x306F46, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x3070ED, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x3074AE, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x307541, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x6F088A, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x6F37C4, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x6F6E40, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_900_testkit[] = {
};

static struct shellcore_patch shellcore_patches_900_devkit[] = {
};

#endif // SHELLCORE_PATCHES_9_00
