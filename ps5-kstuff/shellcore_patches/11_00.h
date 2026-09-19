#ifndef SHELLCORE_PATCHES_11_00
#define SHELLCORE_PATCHES_11_00

static struct shellcore_patch shellcore_patches_1100_retail[] = {
    {0xC57953, "\xE9\xC1\x01\x00\x00", 5}, // jmp 0xC57B19
    {0xC57B19, "\x52\xE9\x53\x06\x00\x00", 6}, // push rdx; jmp 0xC58172
    {0xC58172, "\xE8\xC9\xEF\xFF\xFF\x58\xC3", 7}, // call 0xC57140; pop rax; ret
    {0xC57126, "\xe9\x06\x00\x00\x00", 5}, // jmp 0xC57131
    {0xC57131, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xC57140; pop rax; ret
    {0x762BA9, "\xeb\x04", 2},
    {0x31B701, "\xeb\x04", 2},
    {0x31BAD1, "\xeb\x04", 2},
    {0x7857C1, "\xeb", 1},
    {0x76C535, "\x90\xe9", 2},
    {0x785F57, "\xeb", 1},
    {0x788255, "\x9e\x01\x00\x00", 4}, // 0x7883F7
    {0x202F61, "\xe8\xfa\x99\x66\x00\x31\xc9\xff\xc1\xe9\xd4\x01\x00\x00", 14}, // call 0x86C960; xor ecx; inc ecx; jmp 0x203143
    {0x203143, "\x83\xf8\x02\x0f\x43\xc1\xe9\x02\xf4\xff\xff", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x202550
    {0x202A51, "\xe9\x0b\x05\x00\x00", 5}, // jmp 0x202F61

    {0x7AA9C0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x1725BB0, "\x31\xc0\xc3", 3}, // VR
    {0x172A0F0, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x638caa, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xaec74a, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xAC9BD3, "\xeb\x03", 2}, // disable game error message

    {0x313710, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x31378A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x31388C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x313960, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x313B81, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x313C92, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x31416A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x3141FD, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x760F68, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7649C2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x7685D0, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1100_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1100_devkit[] = {
};

#endif // SHELLCORE_PATCHES_11_00
