#ifndef SHELLCORE_PATCHES_13_42
#define SHELLCORE_PATCHES_13_42

static struct shellcore_patch shellcore_patches_1342_retail[] = {
    {0xD44E33, "\x52\xeb\xdc", 3}, // push rdx; jmp 0xD44E12
    {0xD44E12, "\xe8\x19\xf8\xff\xff\x58\xc3", 7}, // call 0xD44630; pop rax; ret
    {0xD44616, "\xe9\x06\x00\x00\x00", 5}, // jmp 0xD44621
    {0xD44621, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xD44630; pop rax; ret
    {0x7D782E, "\xeb\x04", 2},
    {0x371B21, "\xeb\x04", 2},
    {0x371EF1, "\xeb\x04", 2},
    {0x7FAAAA, "\xeb", 1},
    {0x7E1325, "\x90\xe9", 2},
    {0x7FB234, "\xeb", 1},
    {0x7FD7E4, "\x9E\x01\x00\x00", 4}, // 0x7FD986
    {0x254881, "\xe8\x1a\xf1\x68\x00\x31\xc9\xff\xc1\xe9\xc4\xfe\xff\xff", 14}, // call 0x8E39A0; xor ecx; inc ecx; jmp 0x254753
    {0x254753, "\x83\xf8\x02\x0f\x43\xc1\xe9\x0f\x09\x00\x00", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x25506D
    {0x254C50, "\xe9\x2c\xfc\xff\xff", 5}, // jmp 0x254881

    {0x821970, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback
	
    {0x181E0B0, "\x31\xc0\xc3", 3}, // VR
    {0x1822610, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x69BB1A, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xBE161A, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xBBE593, "\xeb\x03", 2}, // disable game error message
	
    {0x369D00, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x369D7A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x369E7C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x369F50, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x36A171, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x36A282, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x36A75A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x36A7ED, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7D5C28, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7D98D2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7DE0B0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1342_testkit[] = {
    {0x6E7581, "\xEB", 1},
    {0x183C580, "\x31\xc0\xc3", 3}, // VR
    {0x1840AD0, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x6B5E1A, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xBFE8CA, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xBDB7D3, "\xeb\x03", 2}, // disable game error message
	
    {0x375560, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x3755DA, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x3756DC, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x3757B0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x3759D1, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x375AE2, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x375FBA, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x37604D, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7EFE18, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7F3A32, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7F7FB0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1342_devkit[] = {
};

#endif // SHELLCORE_PATCHES_13_42