#ifndef SHELLCORE_PATCHES_12_40
#define SHELLCORE_PATCHES_12_40

static struct shellcore_patch shellcore_patches_1240_retail[] = {
    {0xC870C3, "\x52\xeb\xe2", 3}, // push rdx; jmp 0xC870A8
    {0xC870A8, "\xe8\x23\xf8\xff\xff\x58\xc3", 7}, // call 0xC868D0; pop rax; ret
    {0xC868B6, "\xe9\x07\x00\x00\x00", 5}, // jmp 0xC868C2
    {0xC868C2, "\x31\xc0\x50\xe8\x06\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xC868D0; pop rax; ret
    {0x789EE6, "\xeb\x04", 2},
    {0x330D81, "\xeb\x04", 2},
    {0x331151, "\xeb\x04", 2},
    {0x7AC232, "\xeb", 1},
    {0x7930A5, "\x90\xe9", 2},
    {0x7AC9C8, "\xeb", 1},
    {0x7AEF86, "\x9E\x01\x00\x00", 4}, // 0x7AF128
    {0x214E81, "\xE8\x3A\xFC\x67\x00\x31\xC9\xFF\xC1\xE9\xC4\xFE\xFF\xFF", 14}, // call 0x894AC0; xor ecx; inc ecx; jmp 0x214D53
    {0x214D53, "\x83\xF8\x02\x0F\x43\xC1\xE9\x60\x0A\x00\x00", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x2157BE
    {0x215260, "\xE9\x1C\xFC\xFF\xFF", 5}, // jmp 0x214E81

    {0x7D2350, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x17438E0, "\x31\xc0\xc3", 3}, // VR
    {0x1747E40, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x6557aa, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xb1beba, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xAF9483, "\xeb\x03", 2}, // disable game error message

    {0x328EE0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x328F5A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x32905C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x329130, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x329351, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x329462, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x32993A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3299CD, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x788378, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x78BF72, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x78FE10, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1240_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1240_devkit[] = {
};

#endif // SHELLCORE_PATCHES_12_40
