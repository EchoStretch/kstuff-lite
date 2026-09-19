#ifndef SHELLCORE_PATCHES_13_20
#define SHELLCORE_PATCHES_13_20

static struct shellcore_patch shellcore_patches_1320_retail[] = {
    {0xD44CB3, "\x52\xeb\xdc", 3}, // push rdx; jmp 0xD44C92
    {0xD44C92, "\xe8\x19\xf8\xff\xff\x58\xc3", 7}, // call 0xD444B0; pop rax; ret
    {0xD44496, "\xe9\x06\x00\x00\x00", 5}, // jmp 0xD444A1
    {0xD444A1, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xD444B0; pop rax; ret
    {0x7D769E, "\xeb\x04", 2},
    {0x3719A1, "\xeb\x04", 2},
    {0x371D71, "\xeb\x04", 2},
    {0x7FA91A, "\xeb", 1},
    {0x7E1195, "\x90\xe9", 2},
    {0x7FB0A4, "\xeb", 1},
    {0x7FD654, "\x9E\x01\x00\x00", 4}, // 0x7FD7F6
    {0x254701, "\xe8\x0a\xf1\x68\x00\x31\xc9\xff\xc1\xe9\xc4\xfe\xff\xff", 14}, // call 0x8E3810; xor ecx; inc ecx; jmp 0x2545D3
    {0x2545D3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x0f\x09\x00\x00", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x254EED
    {0x254AD0, "\xe9\x2c\xfc\xff\xff", 5}, // jmp 0x254701

    {0x8217E0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback
	
    {0x181DF30, "\x31\xc0\xc3", 3}, // VR
    {0x1822490, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x69B99A, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xBE149A, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xBBE413, "\xeb\x03", 2}, // disable game error message
	
    {0x369B80, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x369BFA, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x369CFC, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x369DD0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x369FF1, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x36A102, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x36A5DA, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x36A66D, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7D5A98, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7D9742, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7DDF20, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1320_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1320_devkit[] = {
};

#endif // SHELLCORE_PATCHES_13_20