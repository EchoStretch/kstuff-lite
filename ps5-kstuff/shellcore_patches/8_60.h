#ifndef SHELLCORE_PATCHES_8_60
#define SHELLCORE_PATCHES_8_60

static struct shellcore_patch shellcore_patches_860_retail[] = {
    {0xBAF84E, "\x52\xeb\x08", 3}, //push rdx; jmp 0xBAF859 **
    {0xBAF859, "\xe8\xe2\xf8\xff\xff\x58\xc3", 7}, //call 0xBAF140; pop rax; ret
    {0xBAF131, "\xe9\xae\xfd\xff\xff", 5},  // jmp 0xBAEEE4 **
    {0xBAEEE4, "\x31\xc0\x50\xe8\x54\x02\x00\x00\x58\xc3", 10}, //xor eax, eax; push rax; call 0xBAF140; pop rax; ret
    {0x6B5503, "\xeb\x04", 2},
    {0x2F1AD2, "\xeb\x04", 2},
    {0x2F1F22, "\xeb\x04", 2},
    {0x6D4A01, "\xeb", 1},
    {0x6BD745, "\x90\xe9", 2},
    {0x6D574D, "\xeb", 1},
    {0x6D6CC9, "\x61\x01\x00\x00", 4}, // 0x6D6E2E **
    {0x1f72e2, "\xe8\xb9\x69\x5c\x00\x31\xc9\xff\xc1\xe9\xb3\x02\x00\x00", 14}, // call 0x7BDCA0; xor ecx; inc ecx; jmp 0x1f75a3
    {0x1f75a3, "\x83\xf8\x02\x0f\x43\xc1\xe9\xa7\xfb\xff\xff", 11},//cmp eax, 2; cmovae eax, ecx; jmp 0x1F7155
    {0x1f6f9e, "\xe9\x3f\x03\x00\x00", 5}, // JMP 0x1f72e2

    {0x6F3700, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1607A40, "\x31\xc0\xc3", 3}, //VR
    {0x160BE50, "\x31\xc0\xc3", 3}, // VR2 Update bypass
    {0x5a6e03, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xa5099d, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xA33DC6, "\xeb\x03", 2}, // disable game error message

    {0x2EA56B, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x2EA5E9, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x2EA6EC, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x2EA7C0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x2EABA7, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x2EAD2F, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x2EB0EE, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x2EB181, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x6B421A, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x6B7064, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x6BA4F0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_860_testkit[] = {
};

static struct shellcore_patch shellcore_patches_860_devkit[] = {
};

#endif // SHELLCORE_PATCHES_8_60
