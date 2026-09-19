#ifndef SHELLCORE_PATCHES_11_20
#define SHELLCORE_PATCHES_11_20

static struct shellcore_patch shellcore_patches_1120_retail[] = {
    {0xC57CE3, "\xE9\xC1\x01\x00\x00", 5}, // jmp 0xC57EA9
    {0xC57EA9, "\x52\xE9\x53\x06\x00\x00", 6}, // push rdx; jmp 0xC58502
    {0xC58502, "\xE8\xC9\xEF\xFF\xFF\x58\xC3", 7}, // call 0xC574D0; pop rax; ret
    {0xC574B6, "\xe9\x06\x00\x00\x00", 5}, // jmp 0xC574C1
    {0xC574C1, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xC574D0; pop rax; ret
    {0x762D19, "\xeb\x04", 2},
    {0x31B7B1, "\xeb\x04", 2},
    {0x31BB81, "\xeb\x04", 2},
    {0x785931, "\xeb", 1},
    {0x76C6A5, "\x90\xe9", 2},
    {0x7860C7, "\xeb", 1},
    {0x7883C5, "\x9e\x01\x00\x00", 4}, // 0x788567
    {0x202F61, "\xe8\x6a\x9b\x66\x00\x31\xc9\xff\xc1\xe9\xd4\x01\x00\x00", 14}, // call 0x86CAD0; xor ecx; inc ecx; jmp 0x203143
    {0x203143, "\x83\xf8\x02\x0f\x43\xc1\xe9\x02\xf4\xff\xff", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x202550
    {0x202A51, "\xe9\x0b\x05\x00\x00", 5}, // jmp 0x202F61

    {0x7AAB30, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1725FB0, "\x31\xc0\xc3", 3}, // VR
    {0x172A4F0, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x638e1a, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xaecada, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xAC9F63, "\xeb\x03", 2}, // disable game error message

    {0x3137C0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x31383A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x31393C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x313A10, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x313C31, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x313D42, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x31421A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3142AD, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7610D8, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x764B32, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x768740, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1120_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1120_devkit[] = {
};

#endif // SHELLCORE_PATCHES_11_20
