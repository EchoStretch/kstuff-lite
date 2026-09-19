#ifndef SHELLCORE_PATCHES_13_00
#define SHELLCORE_PATCHES_13_00

static struct shellcore_patch shellcore_patches_1300_retail[] = {
    {0xD43183, "\x52\xeb\xdc", 3}, // push rdx; jmp 0xD43162
    {0xD43162, "\xe8\x19\xf8\xff\xff\x58\xc3", 7}, // call 0xD42980; pop rax; ret
    {0xD42966, "\xe9\x06\x00\x00\x00", 5}, // jmp 0xD42971
    {0xD42971, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xD42980; pop rax; ret
    {0x7D2E4E, "\xeb\x04", 2},
    {0x371161, "\xeb\x04", 2},
    {0x371531, "\xeb\x04", 2},
    {0x7F60CA, "\xeb", 1},
    {0x7DC945, "\x90\xe9", 2},
    {0x7F6854, "\xeb", 1},
    {0x7F8E04, "\x9E\x01\x00\x00", 4}, // 0x7F8FA6
    {0x253ED1, "\xE8\xAA\xB0\x68\x00\x31\xC9\xFF\xC1\xE9\xC4\xFE\xFF\xFF", 14}, // call 0x8DEF80; xor ecx; inc ecx; jmp 0x253DA3
    {0x253DA3, "\x83\xF8\x02\x0F\x43\xC1\xE9\x60\x0A\x00\x00", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x25480E
    {0x2542B0, "\xE9\x1C\xFC\xFF\xFF", 5}, // jmp 0x253ED1

    {0x81CF90, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x18145D0, "\x31\xc0\xc3", 3}, // VR
    {0x1818B30, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x69714A, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xBDF9FA, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xBBC973, "\xeb\x03", 2}, // disable game error message
	
    {0x369340, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x3693BA, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x3694BC, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x369590, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x3697B1, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x3698C2, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x369D9A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x369E2D, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7D1248, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7D4EF2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7D96D0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1300_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1300_devkit[] = {
};

#endif // SHELLCORE_PATCHES_13_00