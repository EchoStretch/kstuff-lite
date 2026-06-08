#ifndef SHELLCORE_PATCHES_11_60
#define SHELLCORE_PATCHES_11_60

static struct shellcore_patch shellcore_patches_1160_retail[] = {
    {0xC615F3, "\xE9\xC1\x01\x00\x00", 5}, // jmp 0xC617B9
    {0xC617B9, "\x52\xE9\x53\x06\x00\x00", 6}, // push rdx; jmp 0xC61E12
    {0xC61E12, "\xE8\xC9\xEF\xFF\xFF\x58\xC3", 7}, // call 0xC60DE0; pop rax; ret
    {0xC60DC6, "\xe9\x06\x00\x00\x00", 5}, // jmp 0xC60DD1
    {0xC60DD1, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xC60DE0; pop rax; ret
    {0x76B769, "\xeb\x04", 2},
    {0x320A91, "\xeb\x04", 2},
    {0x320E61, "\xeb\x04", 2},
    {0x78E381, "\xeb", 1},
    {0x7750F5, "\x90\xe9", 2},
    {0x78EB17, "\xeb", 1},
    {0x7910D5, "\x9e\x01\x00\x00", 4}, // 0x791277
    {0x2030C1, "\xe8\xca\x2d\x67\x00\x31\xc9\xff\xc1\xe9\xd4\x01\x00\x00", 14}, // call 0x875E90; xor ecx; inc ecx; jmp 0x2032A3
    {0x2032A3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x58\xf9\xff\xff", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x202C06
    {0x202B82, "\xe9\x3a\x05\x00\x00", 5}, // jmp 0x2030C1

    {0x7B3CD0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1731330, "\x31\xc0\xc3", 3}, // VR
    {0x1735870, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x64186a, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xaf63ea, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xAD3873, "\xeb\x03", 2}, // disable game error message

    {0x318AC0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x318B1A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x318C1C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x318CF0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x318F11, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x319022, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x3194FA, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x31958D, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x769B28, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x76D582, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x771190, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1160_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1160_devkit[] = {
};

#endif // SHELLCORE_PATCHES_11_60
