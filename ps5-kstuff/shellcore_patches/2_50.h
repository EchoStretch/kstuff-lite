#ifndef SHELLCORE_PATCHES_2_50
#define SHELLCORE_PATCHES_2_50

static struct shellcore_patch shellcore_patches_250_retail[] = {
    /* ScePreorder/security wrapper: 3.00 sub_9D1CA0/sub_9D18A0. */
    {0x88757c, "\x31\xc0\x50\xeb\x08", 5}, // 3.00 0x9d18b1 (selector 1): call sub_889390, force a zero return
    {0x887589, "\xe8\x02\x1e\x00\x00\x58\xc3", 7}, // 3.00 0x9d1899 (selector 1): sub_889390 return-value cave
    {0x887584, "\x31\xc0\x50\xeb\xa0", 5}, // 3.00 0x9d1cae (selector 0): call sub_8891B0, force a zero return
    {0x887529, "\xe8\x82\x1c\x00\x00\x58\xc3", 7}, // 3.00 0x9d1cb9 (selector 0): sub_8891B0 return-value cave

    /* Process-starter/AppPromoter checks. */
    {0x4895ae, "\xeb\x04", 2}, // 3.00 0x4dcfb4: bypass mount-result range check
    {0x21abb0, "\xeb\x04", 2}, // 3.00 0x2569b1: bypass subcontainer metadata error
    {0x21ebd7, "\xeb\x04", 2}, // 3.00 0x25af5a: bypass subcontainer metadata error
    {0x4a620e, "\x90\x90", 2}, // 3.00 0x4fafca: ignore EKC version mismatch
    {0x48f53d, "\x90\xe9", 2}, // 3.00 0x4e335d: accept the SKU/app-type branch
    {0x4a5c06, "\xeb", 1}, // 3.00 0x4fbb63: ignore EKC/non-prod mismatch notification
    {0x4a8a83, "\x0f\x02\x00\x00", 4}, // 3.00 0x4ff329: route NUC350 mismatch to the success path

    /* Dispatcher case matched by helper/caller structure (3.00 case 114,
       2.50 case 116; sub_5C4710 -> sub_55FF80). */
    {0x176a41, "\xe8\x3a\x95\x3e\x00\x31\xc9\xff\xc1\xe9\x12\x01\x00\x00", 14}, // 3.00 0x1968c1
    {0x176b61, "\x83\xf8\x02\x0f\x43\xc1\xe9\x22\xfc\xff\xff", 11}, // 3.00 0x1969e1
    {0x17676c, "\xe9\xd0\x02\x00\x00", 5}, // 3.00 0x1965c9: redirect case 116 through the caves

    /* Common shellcore checks. */
    {0x3b271c, "\x66\x0f\x1f\x44\x00\x00", 6}, // 3.00 0x3fc24c: force getSceSysDirPath debugger/app-home path
    {0x7d8584, "\xeb", 1}, // 3.00 0x8b5634: fix trophies not unlocking in certain games
    {0x7bbf26, "\x90\x90\x90\x90\x90", 5}, // 3.00 0x899166: disable game error message

    /* PS4/PS5 disc and PKG installer checks. */
    {0x2171bb, "\x90\xe9", 2}, // 3.00 0x25284b: PS4 Disc Installer Patch 1
    {0x217238, "\x90\xe9", 2}, // 3.00 0x2528c8: PS5 Disc Installer Patch 1
    {0x21733b, "\xeb", 1}, // 3.00 0x2529cb: PS4 PKG Installer Patch 1
    {0x21740f, "\xeb", 1}, // 3.00 0x252a9f: PS5 PKG Installer Patch 1
    {0x21787a, "\x90\xe9", 2}, // 3.00 0x252f35: PS4 PKG Installer Patch 2
    {0x217a4e, "\xeb", 1}, // 3.00 0x253120: PS5 PKG Installer Patch 2
    {0x217e05, "\x90\xe9", 2}, // 3.00 0x2534e5: PS4 PKG Installer Patch 3
    {0x217ea2, "\x90\xe9", 2}, // 3.00 0x253582: PS5 PKG Installer Patch 3
    {0x48b3e7, "\xeb", 1}, // 3.00 0x4def37: PS4 PKG Installer Patch 4
    {0x48b4fc, "\xeb", 1}, // 3.00 0x4df04c: PS5 PKG Installer Patch 4
    {0x48d350, "\x48\x31\xc0\xc3", 4}, // 3.00 0x4e0f10: PKG Installer
};

static struct shellcore_patch shellcore_patches_250_testkit[] = {
};

static struct shellcore_patch shellcore_patches_250_devkit[] = {
};

#endif // SHELLCORE_PATCHES_2_50
