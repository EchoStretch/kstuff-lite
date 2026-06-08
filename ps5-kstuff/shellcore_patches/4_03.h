#ifndef SHELLCORE_PATCHES_4_03
#define SHELLCORE_PATCHES_4_03

static struct shellcore_patch shellcore_patches_403_retail[] = {
    {0x974fee, "\x52\xeb\x08", 3},
    {0x974ff9, "\xe8\xd2\xfb\xff\xff\x58\xc3", 7}, //call 0x974bd0; pop rax; ret
    {0x974bc1, "\x31\xc0\x50\xeb\xe3", 5}, //xor eax, eax; push rax; jmp 0x974ba9
    {0x974ba9, "\xe8\x22\x00\x00\x00\x58\xc3", 7}, //call 0x974bd0; pop rax; ret
    {0x5307f9, "\xeb\x04", 2}, //jmp 0x5307ff
    {0x26f35c, "\xeb\x04", 2}, //jmp 0x26f362
    {0x26f76c, "\xeb\x04", 2}, //jmp 0x26f772
    {0x54e1f0, "\xeb", 1}, //jmp (destination unchanged)
    {0x536e1d, "\x90\xe9", 2}, //nop; jmp (destination unchanged)
    {0x54db8f, "\xeb", 1}, //jmp (destination unchanged)
    {0x55137a, "\xc8\x00\x00\x00", 4}, //(jmp opcode unchanged) 0x551446
    {0x1a12d1, "\xe8\xea\x88\x47\x00\x31\xc9\xff\xc1\xe9\xf4\x02\x00\x00", 14}, //call 0x619bc0; xor ecx, ecx; inc ecx; jmp 0x1a15d3
    {0x1a15d3, "\x83\xf8\x02\x0f\x43\xc1\xe9\x29\xfa\xff\xff", 11}, //cmp eax, 2; cmovae eax, ecx; jmp 0x1a1007
    {0x1a0fe5, "\xe9\xe7\x02\x00\x00", 5}, //jmp 0x1a12d1

    {0x12B5EB0, "\x31\xC0\xC3", 3}, //VR2 Min Fw Check
    {0x43db4c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x8337a7, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x81CA56, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x267DBB, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x267E52, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x267F6B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x26803F, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x2684A8, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x268679, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x268A45, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x268AE2, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x532897, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x5329AC, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x5348C0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_403_testkit[] = {
    {0x446a5c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x83eb77, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x827E26, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x271DAB, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x271E42, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x271F5B, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x27202F, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x272498, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x272669, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x272A35, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x272AD2, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x53B427, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x53B53C, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x53CE80, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

static struct shellcore_patch shellcore_patches_403_devkit[] = {
    {0x446c3c, "\x66\x0F\x1F\x44\x00\x00", 6}, // force getSceSysDirPath to take isDebuggerOrAppHomeLaunchedApp=1 path, by ArkSama
    {0x83ece7, "\xEB", 1}, // fix trophies not unlocking in certain games
    {0x827F96, "\x90\x90\x90\x90\x90", 5}, //disable game error message

    {0x27231B, "\x90\xE9", 2}, //PS4 Disc Installer Patch 1
    {0x2723B2, "\x90\xE9", 2}, //PS5 Disc Installer Patch 1
    {0x2724CB, "\xEB", 1}, //PS4 PKG Installer Patch 1
    {0x27259F, "\xEB", 1}, //PS5 PKG Installer Patch 1
    {0x272A08, "\x90\xE9", 2}, //PS4 PKG Installer Patch 2
    {0x272BD9, "\xeb", 1}, //PS5 PKG Installer Patch 2
    {0x272FA5, "\x90\xE9", 2}, //PS4 PKG Installer Patch 3
    {0x273042, "\x90\xE9", 2}, //PS5 PKG Installer Patch 3
    {0x53B597, "\xEB", 1}, //PS4 PKG Installer Patch 4
    {0x53B6AC, "\xEB", 1}, //PS5 PKG Installer Patch 4
    {0x53CFF0, "\x48\x31\xC0\xC3", 4}, //PKG Installer
};

#endif // SHELLCORE_PATCHES_4_03

