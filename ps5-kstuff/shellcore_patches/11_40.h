#ifndef SHELLCORE_PATCHES_11_40
#define SHELLCORE_PATCHES_11_40

static struct shellcore_patch shellcore_patches_1140_retail[] = {
    {0xC59893, "\xE9\xC1\x01\x00\x00", 5}, // jmp 0xC59A59
    {0xC59A59, "\x52\xE9\x53\x06\x00\x00", 6}, // push rdx; jmp 0xC5A0B2
    {0xC5A0B2, "\xE8\xC9\xEF\xFF\xFF\x58\xC3", 7}, // call 0xC59080; pop rax; ret
    {0xC59066, "\xe9\x06\x00\x00\x00", 5}, // jmp 0xC59071
    {0xC59071, "\x31\xc0\x50\xe8\x07\x00\x00\x00\x58\xc3", 10}, // xor eax, eax; push rax; call 0xC59080; pop rax; ret
    {0x763CF9, "\xeb\x04", 2},
    {0x31C791, "\xeb\x04", 2},
    {0x31CB61, "\xeb\x04", 2},
    {0x786911, "\xeb", 1},
    {0x76D685, "\x90\xe9", 2},
    {0x7870A7, "\xeb", 1},
    {0x789665, "\x9e\x01\x00\x00", 4}, // 0x789807
    {0x202F71, "\xe8\xaa\xb4\x66\x00\x31\xc9\xff\xc1\xe9\xd4\x01\x00\x00", 14}, // call 0x86E420; xor ecx; inc ecx; jmp 0x203153
    {0x203153, "\x83\xf8\x02\x0f\x43\xc1\xe9\x02\xf4\xff\xff", 11}, // cmp eax, 2; cmovae eax, ecx; jmp 0x202560
    {0x202A61, "\xe9\x0b\x05\x00\x00", 5}, // jmp 0x202F71

    {0x7AC260, "\xC3", 1}, // callback to sceRifManagerRegisterActivationCallback

    {0x17282F0, "\x31\xc0\xc3", 3}, // VR2 Min Fw Check
    {0xACBB13, "\xeb\x03", 2}, // disable game error message
    {0x3147A0, "\x90\xe9", 2}, // PS4 Disc Installer Patch 1
    {0x31481A, "\x90\xe9", 2}, // PS5 Disc Installer Patch 1
    {0x31491C, "\xeb", 1}, // PS4 PKG Installer Patch 1
    {0x3149F0, "\xeb", 1}, // PS5 PKG Installer Patch 1
    {0x314C11, "\x90\xe9", 2}, // PS4 PKG Installer Patch 2
    {0x314D22, "\xeb", 1}, // PS5 PKG Installer Patch 2
    {0x3151FA, "\x90\xe9", 2}, // PS4 PKG Installer Patch 3
    {0x31528D, "\x90\xe9", 2}, // PS5 PKG Installer Patch 3
    {0x7620B8, "\xeb", 1}, // PS4 PKG Installer Patch 4
    {0x7620B8, "\xeb", 1}, // PS5 PKG Installer Patch 4
    {0x769720, "\x48\x31\xc0\xc3", 4}, // PKG Installer
};

static struct shellcore_patch shellcore_patches_1140_testkit[] = {
};

static struct shellcore_patch shellcore_patches_1140_devkit[] = {
};

#endif // SHELLCORE_PATCHES_11_40
