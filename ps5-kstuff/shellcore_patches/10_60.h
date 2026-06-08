#ifndef SHELLCORE_PATCHES_10_60
#define SHELLCORE_PATCHES_10_60

static struct shellcore_patch shellcore_patches_1060_retail[] = {
    {0xC09643, "\x52\xeb\xe2", 3}, // push rdx; jmp 0xC09628
    {0xC09628, "\xe8\x33\xf8\xff\xff\x58\xc3", 7}, // call 0xC08E60; pop rax; ret
    {0xC08E46, "\xe9\x06\x00\x00\x00", 5}, // jmp 0xC08E51
    {0xC08E51, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xC08E60; pop rax; ret
    {0x703E04, "\xeb\x04", 2},
    {0x30EB5F, "\xeb\x04", 2},
    {0x30EF2F, "\xeb\x04", 2},
    {0x723B45, "\xeb", 1},
    {0x70C775, "\x90\xe9", 2},
    {0x724283, "\xeb", 1},
    {0x72621F, "\x61\x01\x00\x00", 4}, // 0x726384
    {0x206CD1, "\xe8\x8a\x89\x60\x00\x31\xc9\xff\xc1\xe9\xd4\x01\x00\x00", 14}, // call 0x80F660; xor ecx; inc ecx; jmp 0x206EB3
    {0x206EB3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x82\xf4\xff\xff", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x206340
    {0x206843, "\xe9\x89\x04\x00\x00", 5}, // jmp 0x206CD1

    {0x747880, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x16A74E0, "\x31\xc0\xc3", 3}, // VR
    {0x16AB8F0, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x5d9cf1, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xaaf831, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xA8C8E3, "\xeb\x03", 2}, // disable game error message

    {0x307150, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x3071CA, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x3072CC, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x3073A0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x3077A7, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x30794F, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x307CFE, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x307D91, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x702508, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7059D2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7090B0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1060_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1060_devkit[] = {
};

#endif // SHELLCORE_PATCHES_10_60
