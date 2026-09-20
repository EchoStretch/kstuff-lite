#ifndef SHELLCORE_PATCHES_13_60
#define SHELLCORE_PATCHES_13_60

static struct shellcore_patch shellcore_patches_1360_retail[] = {
    {0xD45963, "\x52\xeb\xdc", 3}, // push rdx; jmp 0xD45942
    {0xD45942, "\xe8\x19\xf8\xff\xff\x58\xc3", 7}, // call 0xD45160; pop rax; ret
    {0xD45146, "\xe9\x06\x00\x00\x00", 5}, // jmp 0xD45151
    {0xD45151, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xD45160; pop rax; ret
    {0x7D83DE, "\xeb\x04", 2},
    {0x3726C1, "\xeb\x04", 2},
    {0x372A91, "\xeb\x04", 2},
    {0x7FB65A, "\xeb", 1},
    {0x7E1ED5, "\x90\xe9", 2},
    {0x7FBDE4, "\xeb", 1},
    {0x7FE394, "\x9E\x01\x00\x00", 4}, // 0x7FE536
    {0x255421, "\xe8\x2a\xf1\x68\x00\x31\xc9\xff\xc1\xe9\xc4\xfe\xff\xff", 14}, // call 0x8E4550; xor ecx; inc ecx; jmp 0x2552F3
    {0x2552F3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x0f\x09\x00\x00", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x255C0D
    {0x2557F0, "\xe9\x2c\xfc\xff\xff", 5}, // jmp 0x255421

    {0x822520, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x181EBF0, "\x31\xc0\xc3", 3}, // VR
    {0x1823150, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x69C6CA, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xBE214A, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xBBF0C3, "\xeb\x03", 2}, // disable game error message

    // Allow ps4_nongame_mini launches through the three category checks.
    {0x6CD331, "\xeb", 1}, // preLaunchCheck
    {0x6CD5C2, "\xeb", 1}, // category check
    {0x6CD889, "\xeb", 1}, // workspace category check
	
    {0x36A8A0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x36A91A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x36AA1C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x36AAF0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x36AD11, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x36AE22, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x36B2FA, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x36B38D, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7D67D8, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7DA482, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7DEC60, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1360_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1360_devkit[] = {
};

#endif // SHELLCORE_PATCHES_13_60