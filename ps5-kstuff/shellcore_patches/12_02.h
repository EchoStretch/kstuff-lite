#ifndef SHELLCORE_PATCHES_12_02
#define SHELLCORE_PATCHES_12_02

static struct shellcore_patch shellcore_patches_1202_retail[] = {
    {0xC86233, "\x52\xeb\xe2", 3}, // push rdx; jmp 0xC86218
    {0xC86218, "\xe8\x23\xf8\xff\xff\x58\xc3", 7}, // call 0xC85A40; pop rax; ret
    {0xC85A26, "\xe9\x07\x00\x00\x00", 5}, // jmp 0xC85A32
    {0xC85A32, "\x31\xc0\x50\xe8\x06\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xC85A40; pop rax; ret
    {0x789236, "\xeb\x04", 2},
    {0x330D81, "\xeb\x04", 2},
    {0x331151, "\xeb\x04", 2},
    {0x7AB582, "\xeb", 1},
    {0x7923F5, "\x90\xe9", 2},
    {0x7ABD18, "\xeb", 1},
    {0x7AE2D6, "\x9E\x01\x00\x00", 4}, // 0x7AE478
    {0x215D71, "\xe8\x0a\xe2\x67\x00\x31\xc9\xff\xc1\xe9\xb4\xfc\xff\xff", 14}, // call 0x893F80; xor ecx; inc ecx; jmp 0x215A33
    {0x215A33, "\x83\xf8\x02\x0f\x43\xc1\xe9\x80\xfd\xff\xff", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x2157BE
    {0x215260, "\xe9\x0c\x0b\x00\x00", 5}, // jmp 0x215D71

    {0x7D16A0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1742A40, "\x31\xc0\xc3", 3}, // VR
    {0x1746FA0, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x6557aa, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xb1b02a, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xAF85F3, "\xeb\x03", 2}, // disable game error message

    {0x328EE0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x328F5A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x32905C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x329130, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x329351, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x329462, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x32993A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3299CD, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7876C8, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x78B2C2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x78F160, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1202_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1202_devkit[] = {
};

#endif // SHELLCORE_PATCHES_12_02
