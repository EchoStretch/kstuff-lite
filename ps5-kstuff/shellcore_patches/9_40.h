#ifndef SHELLCORE_PATCHES_9_40
#define SHELLCORE_PATCHES_9_40

static struct shellcore_patch shellcore_patches_940_retail[] = {
    {0xC0FCA3, "\x52\xeb\xe2", 3}, //push rdx; jmp 0xC0FC88
    {0xC0FC88, "\xe8\xe3\xf8\xff\xff\x58\xc3", 7}, //call 0xC0F570; pop rax; ret
    {0xC0F556, "\xe9\x06\x00\x00\x00", 5},  // jmp 0xC0F561
    {0xC0F561, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, //xor eax, eax; push rax; call 0xC0F570; pop rax; ret
    {0x6F2048, "\xeb\x04", 2},
    {0x30E5BF, "\xeb\x04", 2},
    {0x30E98F, "\xeb\x04", 2},
    {0x711CDB, "\xeb", 1},
    {0x6FA575, "\x90\xe9", 2},
    {0x712445, "\xeb", 1},
    {0x71442F, "\x61\x01\x00\x00", 4}, // 0x714594
    {0x1FCEB2, "\xe8\x89\xd8\x60\x00\x31\xc9\xff\xc1\xe9\xd2\x01\x00\x00", 14}, // call 0x80A740; xor ecx; inc ecx; jmp 0x1FD092
    {0x1FD092, "\x83\xf8\x02\x0f\x43\xc1\xe9\xa2\xcb\x00\x00", 11},// cmp eax, 2; cmovae eax, ecx; jmp 0x209C3F
    {0x209A41, "\xe9\x6c\x34\xff\xff", 5}, // jmp 0x1FCEB2

    {0x734710, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x16A5510, "\x31\xc0\xc3", 3}, // VR
    {0x16A9910, "\x31\xc0\xc3", 3}, // VR2 Update bypass
    {0x5dad0a, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xab3121, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xA8EF16, "\xeb\x03", 2}, // disable game error message

    {0x306CDB, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x306D59, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x306E5C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x306F30, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x307336, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x3074DD, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x30789E, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x307931, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x6F0CCA, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x6F3C04, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x6F7250, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_940_testkit[] = {
};

static struct shellcore_patch shellcore_patches_940_devkit[] = {
};

#endif // SHELLCORE_PATCHES_9_40
