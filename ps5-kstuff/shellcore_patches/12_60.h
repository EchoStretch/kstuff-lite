#ifndef SHELLCORE_PATCHES_12_60
#define SHELLCORE_PATCHES_12_60

static struct shellcore_patch shellcore_patches_1260_retail[] = {
    {0xC8CF23, "\x52\xeb\xe2", 3}, // push rdx; jmp 0xC8CF08
    {0xC8CF08, "\xe8\x23\xf8\xff\xff\x58\xc3", 7}, // call 0xC8C730; pop rax; ret
    {0xC8C716, "\xe9\x07\x00\x00\x00", 5}, // jmp 0xC868C2
    {0xC8C722, "\x31\xc0\x50\xe8\x06\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xC8C730; pop rax; ret
    {0x78B136, "\xeb\x04", 2},
    {0x331471, "\xeb\x04", 2},
    {0x331841, "\xeb\x04", 2},
    {0x7AD482, "\xeb", 1},
    {0x7942F5, "\x90\xe9", 2},
    {0x7ADC18, "\xeb", 1},
    {0x7B01D6, "\x9E\x01\x00\x00", 4}, // 0x7B0378
    {0x214E81, "\xE8\x8A\x0E\x68\x00\x31\xC9\xFF\xC1\xE9\xC4\xFE\xFF\xFF", 14}, // call 0x895D10; xor ecx; inc ecx; jmp 0x214D53
    {0x214D53, "\x83\xF8\x02\x0F\x43\xC1\xE9\x60\x0A\x00\x00", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x2157BE
    {0x215260, "\xE9\x1C\xFC\xFF\xFF", 5}, // jmp 0x214E81

    {0x7D35A0, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x174A680, "\x31\xc0\xc3", 3}, // VR
    {0x174EBE0, "\x31\xC0\xC3", 3}, // VR2 Update bypass
    {0x6569fa, "\x66\x90", 2}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0xb21d1a, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0xAFF2E3, "\xeb\x03", 2}, // disable game error message

    {0x3295D0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x32964A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x32974C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x329820, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x329A41, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x329B52, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x32A02A, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x32A0BD, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7895C8, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x78D1C2, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x791060, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1260_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1260_devkit[] = {
};

#endif // SHELLCORE_PATCHES_12_60
