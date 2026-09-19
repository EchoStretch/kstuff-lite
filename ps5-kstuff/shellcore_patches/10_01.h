#ifndef SHELLCORE_PATCHES_10_01
#define SHELLCORE_PATCHES_10_01

static struct shellcore_patch shellcore_patches_1001_retail[] = {
    {0xC03AC3, "\x52\xeb\xe2", 3}, //push rdx; jmp 0xC03AA8
    {0xC03AA8, "\xe8\x33\xf8\xff\xff\x58\xc3", 7}, //call 0xC032E0; pop rax; ret
    {0xC032C6, "\xe9\x06\x00\x00\x00", 5},  // jmp 0xC032D1
    {0xC032D1, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, //xor eax, eax; push rax; call 0xC032E0; pop rax; ret
    {0x702624, "\xeb\x04", 2},
    {0x30D19F, "\xeb\x04", 2},
    {0x30D56F, "\xeb\x04", 2},
    {0x722365, "\xeb", 1},
    {0x70AF95, "\x90\xe9", 2},
    {0x722AA3, "\xeb", 1},
    {0x724A3F, "\x61\x01\x00\x00", 4}, // 0x724BA4
    {0x206C11, "\xe8\x6a\x72\x60\x00\x31\xc9\xff\xc1\xe9\xd4\x01\x00\x00", 14}, // call 0x80DE80; xor ecx; inc ecx; jmp 0x206DF3
    {0x206DF3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x9e\xf9\xff\xff", 11},// cmp eax, 2; cmovae eax, ecx; jmp 0x20679C
    {0x20675D, "\xe9\xaf\x04\x00\x00", 5}, // jmp 0x206C11

    {0x7460A0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x16A1980, "\x31\xc0\xc3", 3}, // VR
    {0x16A5D90, "\x31\xc0\xc3", 3}, // VR2 Update bypass
    {0x5d8511, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xaa9cc1, "\xEB", 1}, // fix trophies not unlocking in certain game
    {0xA86D73, "\xeb\x03", 2}, // disable game error message

    {0x305790, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x30580A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x30590C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x3059E0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x305DE7, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x305F8F, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x30633E, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3063D1, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x700D28, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7041F2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7078D0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};


static struct shellcore_patch shellcore_patches_1001_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1001_devkit[] = {
};

#endif // SHELLCORE_PATCHES_10_01
