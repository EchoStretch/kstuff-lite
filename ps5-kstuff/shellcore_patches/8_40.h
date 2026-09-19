#ifndef SHELLCORE_PATCHES_8_40
#define SHELLCORE_PATCHES_8_40

static struct shellcore_patch shellcore_patches_840_retail[] = {
    {0xBAF83E, "\x52\xeb\x08", 3}, //push rdx; jmp 0xBAF849 **
    {0xBAF849, "\xe8\xe2\xf8\xff\xff\x58\xc3", 7}, //call 0xBAF130; pop rax; ret
    {0xBAF121, "\xe9\xae\xfd\xff\xff", 5},  // jmp 0xBAEED4 **
    {0xBAEED4, "\x31\xc0\x50\xe8\x54\x02\x00\x00\x58\xc3", 10}, //xor eax, eax; push rax; call 0xBAF130; pop rax; ret
    {0x6B5673, "\xeb\x04", 2},
    {0x2f1d22, "\xeb\x04", 2},
    {0x2f2172, "\xeb\x04", 2},
    {0x6d4b71, "\xeb", 1},
    {0x6bd8b5, "\x90\xe9", 2},
    {0x6d58bd, "\xeb", 1},
    {0x6d6e39, "\x61\x01\x00\x00", 4}, // 0x6D6F9E **
    {0x1f72e2, "\xe8\x29\x6b\x5c\x00\x31\xc9\xff\xc1\xe9\xb3\x02\x00\x00", 14}, // call 0x7BDE10; xor ecx; inc ecx; jmp 0x1f75a3
    {0x1f75a3, "\x83\xf8\x02\x0f\x43\xc1\xe9\xa7\xfb\xff\xff", 11},//cmp eax, 2; cmovae eax, ecx; jmp 0x1F7155
    {0x1f6f9e, "\xe9\x3f\x03\x00\x00", 5}, // JMP 0x1f72e2

    {0x6F3870, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1607a20, "\x31\xc0\xc3", 3}, //VR
    {0x160BE30, "\x31\xc0\xc3", 3}, // VR2 Update bypass
    {0x5a7023, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xa50b0d, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xa33f36, "\xeb\x03", 2}, // disable game error message

    {0x2ea7bb, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x2ea839, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x2ea93c, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x2eaa10, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x2eadf7, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x2eaf7f, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x2eb33e, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x2eb3d1, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x6b438a, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x6b71d4, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x6ba660, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_840_testkit[] = {
};

static struct shellcore_patch shellcore_patches_840_devkit[] = {
};

#endif // SHELLCORE_PATCHES_8_40
