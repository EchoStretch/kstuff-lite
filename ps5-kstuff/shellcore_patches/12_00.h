#ifndef SHELLCORE_PATCHES_12_00
#define SHELLCORE_PATCHES_12_00

static struct shellcore_patch shellcore_patches_1200_retail[] = {
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

static struct shellcore_patch shellcore_patches_1200_testkit[] = {
    {0x7EE760, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1761110, "\x31\xc0\xc3", 3}, // VR
    {0x1765660, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x66FE1F, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xB3855A, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xB15AB3, "\xeb\x03", 2}, // disable game error message

    {0x334C10, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x334C8A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x334D8C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x334E60, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x335081, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x335192, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x33566A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3356FD, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7A1BD8, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7A5742, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7A9380, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1200_devkit[] = {
    {0x7F0310, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1762D10, "\x31\xc0\xc3", 3}, // VR
    {0x1767260, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x6719CF, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xB3A18A, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xB176E3, "\xeb\x03", 2}, // disable game error message

    {0x336720, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x33679A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x33689C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x336970, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x336B91, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x336CA2, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x33717A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x33720D, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7A3788, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7A72F2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7AAF30, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

#endif // SHELLCORE_PATCHES_12_00
