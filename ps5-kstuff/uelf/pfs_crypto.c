#ifndef FREEBSD
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "pfs_crypto.h"
#include "shared_area.h"
#include "utils.h"
#include "fpu.h"

#include "../BearSSL/inc/bearssl.h"
#include <isa-l_crypto/aes_keyexp.h>
#include <isa-l_crypto/aes_xts.h>

enum {
    HMAC_SHA256_BLOCK_SIZE = 64,
    HMAC_SHA256_DIGEST_SIZE = 32,
};

static const uint8_t ypkg_n[256] = {0xc6, 0xcf, 0x71, 0xe7, 0xe5, 0x9a, 0xf0, 0xd1, 0x2a, 0x2c, 0x45, 0x8b, 0xf9, 0x2a, 0xe, 0xc1, 0x43, 0x5, 0x8b, 0xc3, 0x71, 0x17, 0x80, 0x1d, 0xcd, 0x49, 0x7d, 0xde, 0x35, 0x9d, 0x25, 0x9b, 0xa0, 0xd7, 0xa0, 0xf2, 0x7d, 0x6c, 0x8, 0x7e, 0xaa, 0x55, 0x2, 0x68, 0x2b, 0x23, 0xc6, 0x44, 0xb8, 0x44, 0x18, 0xeb, 0x56, 0xcf, 0x16, 0xa2, 0x48, 0x3, 0xc9, 0xe7, 0x4f, 0x87, 0xeb, 0x3d, 0x30, 0xc3, 0x15, 0x88, 0xbf, 0x20, 0xe7, 0x9d, 0xff, 0x77, 0xc, 0xde, 0x1d, 0x24, 0x1e, 0x63, 0xa9, 0x4f, 0x8a, 0xbf, 0x5b, 0xbe, 0x60, 0x19, 0x68, 0x33, 0x3b, 0xfc, 0xed, 0x9f, 0x47, 0x4e, 0x5f, 0xf8, 0xea, 0xcb, 0x3d, 0x0, 0xbd, 0x67, 0x1, 0xf9, 0x2c, 0x6d, 0xc6, 0xac, 0x13, 0x64, 0xe7, 0x67, 0x14, 0xf3, 0xdc, 0x52, 0x69, 0x6a, 0xb9, 0x83, 0x2c, 0x42, 0x30, 0x13, 0x1b, 0xb2, 0xd8, 0xa5, 0x2, 0xd, 0x79, 0xed, 0x96, 0xb1, 0xd, 0xf8, 0xcc, 0xc, 0xdf, 0x81, 0x95, 0x4f, 0x3, 0x58, 0x9, 0x57, 0xe, 0x80, 0x69, 0x2e, 0xfe, 0xff, 0x52, 0x77, 0xea, 0x75, 0x28, 0xa8, 0xfb, 0xc9, 0xbe, 0xbf, 0x9f, 0xbb, 0xb7, 0x79, 0x8e, 0x18, 0x5, 0xe1, 0x80, 0xbd, 0x50, 0x34, 0x94, 0x81, 0xd3, 0x53, 0xc2, 0x69, 0xa2, 0xd2, 0x4c, 0xcf, 0x6c, 0xf4, 0x57, 0x2c, 0x10, 0x4a, 0x3f, 0xfb, 0x22, 0xfd, 0x8b, 0x97, 0xe2, 0xc9, 0x5b, 0xa6, 0x2b, 0xcd, 0xd6, 0x1b, 0x6b, 0xdb, 0x68, 0x7f, 0x4b, 0xc2, 0xa0, 0x50, 0x34, 0xc0, 0x5, 0xe5, 0x8d, 0xef, 0x24, 0x67, 0xff, 0x93, 0x40, 0xcf, 0x2d, 0x62, 0xa2, 0xa0, 0x50, 0xb1, 0xf1, 0x3a, 0xa8, 0x3d, 0xfd, 0x80, 0xd1, 0xf9, 0xb8, 0x5, 0x22, 0xaf, 0xc8, 0x35, 0x45, 0x90, 0x58, 0x8e, 0xe3, 0x3a, 0x7c, 0xbd, 0x3e, 0x27};
static const uint8_t ypkg_d[256] = {0x7f, 0x76, 0xcd, 0xe, 0xe2, 0xd4, 0xde, 0x5, 0x1c, 0xc6, 0xd9, 0xa8, 0xe, 0x8d, 0xfa, 0x7b, 0xca, 0x1e, 0xaa, 0x27, 0x1a, 0x40, 0xf8, 0xf1, 0x22, 0x87, 0x35, 0xdd, 0xdb, 0xfd, 0xee, 0xf8, 0xc2, 0xbc, 0xbd, 0x1, 0xfb, 0x8b, 0xe2, 0x3e, 0x63, 0xb2, 0xb1, 0x22, 0x5c, 0x56, 0x49, 0x6e, 0x11, 0xbe, 0x7, 0x44, 0xb, 0x9a, 0x26, 0x66, 0xd1, 0x49, 0x2c, 0x8f, 0xd3, 0x1b, 0xcf, 0xa4, 0xa1, 0xb8, 0xd1, 0xfb, 0xa4, 0x9e, 0xd2, 0x21, 0x28, 0x83, 0x9, 0x8a, 0xf6, 0xa0, 0xb, 0xa3, 0xd6, 0xf, 0x9b, 0x63, 0x68, 0xcc, 0xbc, 0xc, 0x4e, 0x14, 0x5b, 0x27, 0xa4, 0xa9, 0xf4, 0x2b, 0xb9, 0xb8, 0x7b, 0xc0, 0xe6, 0x51, 0xad, 0x1d, 0x77, 0xd4, 0x6b, 0xb9, 0xce, 0x20, 0xd1, 0x26, 0x66, 0x7e, 0x5e, 0x9e, 0xa2, 0xe9, 0x6b, 0x90, 0xf3, 0x73, 0xb8, 0x52, 0x8f, 0x44, 0x11, 0x3, 0xc, 0x13, 0x97, 0x39, 0x3d, 0x13, 0x22, 0x58, 0xd5, 0x43, 0x82, 0x49, 0xda, 0x6e, 0x7c, 0xa1, 0xc5, 0x8c, 0xa5, 0xb0, 0x9, 0xe0, 0xce, 0x3d, 0xdf, 0xf4, 0x9d, 0x3c, 0x97, 0x15, 0xe2, 0x6a, 0xc7, 0x2b, 0x3c, 0x50, 0x93, 0x23, 0xdb, 0xba, 0x4a, 0x22, 0x66, 0x44, 0xac, 0x78, 0xbb, 0xe, 0x1a, 0x27, 0x43, 0xb5, 0x71, 0x67, 0xaf, 0xf4, 0xab, 0x48, 0x46, 0x93, 0x73, 0xd0, 0x42, 0xab, 0x93, 0x63, 0xe5, 0x6c, 0x9a, 0xde, 0x50, 0x24, 0xc0, 0x23, 0x7d, 0x99, 0x79, 0x3f, 0x22, 0x7, 0xe0, 0xc1, 0x48, 0x56, 0x1b, 0xdf, 0x83, 0x9, 0x12, 0xb4, 0x2d, 0x45, 0x6b, 0xc9, 0xc0, 0x68, 0x85, 0x99, 0x90, 0x79, 0x96, 0x1a, 0xd7, 0xf5, 0x4d, 0x1f, 0x37, 0x83, 0x40, 0x4a, 0xec, 0x39, 0x37, 0xa6, 0x80, 0x92, 0x7d, 0xc5, 0x80, 0xc7, 0xd6, 0x6f, 0xfe, 0x8a, 0x79, 0x89, 0xc6, 0xb1};

static const br_rsa_public_key ypkg = {
    .n = (void*)ypkg_n,
    .nlen = sizeof(ypkg_n),
    .e = (void*)ypkg_d,
    .elen = sizeof(ypkg_d),
};

static int hmac_sha256_seed(struct uelf_sha256_context* inner_ctx, struct uelf_sha256_context* outer_ctx,
                            const uint8_t key[32])
{
    uint8_t pad[HMAC_SHA256_BLOCK_SIZE];
    memset(pad, 0x36, sizeof(pad));
    for(size_t i = 0; i < 32; i++)
        pad[i] ^= key[i];
    uelf_sha256_init(inner_ctx);
    if(uelf_sha256_update(inner_ctx, pad, sizeof(pad)))
        return -1;

    memset(pad, 0x5c, sizeof(pad));
    for(size_t i = 0; i < 32; i++)
        pad[i] ^= key[i];
    uelf_sha256_init(outer_ctx);
    if(uelf_sha256_update(outer_ctx, pad, sizeof(pad)))
        return -1;
    return 0;
}

static int hmac_sha256_finalize(const struct uelf_sha256_context* outer_seed,
                                struct uelf_sha256_context* inner_ctx,
                                uint8_t out[HMAC_SHA256_DIGEST_SIZE])
{
    uint8_t inner_hash[HMAC_SHA256_DIGEST_SIZE];
    if(uelf_sha256_final(inner_ctx, inner_hash))
        return -1;
    *inner_ctx = *outer_seed;
    if(uelf_sha256_update(inner_ctx, inner_hash, sizeof(inner_hash)))
        return -1;
    return uelf_sha256_final(inner_ctx, out);
}

static int hmac_sha256_once(uint8_t out[HMAC_SHA256_DIGEST_SIZE], const uint8_t key[32],
                            const void* part1, size_t part1_len, const void* part2, size_t part2_len)
{
    struct uelf_sha256_context inner_ctx, outer_ctx, ctx;
    if(hmac_sha256_seed(&inner_ctx, &outer_ctx, key))
        return -1;
    ctx = inner_ctx;
    if(part1_len && uelf_sha256_update(&ctx, part1, part1_len))
        return -1;
    if(part2_len && uelf_sha256_update(&ctx, part2, part2_len))
        return -1;
    return hmac_sha256_finalize(&outer_ctx, &ctx, out);
}

static int hmac_sha256_cache_entry_matches(const struct hmac_sha256_cache_entry* entry, int key_id,
                                           const uint8_t* key)
{
    return entry->valid
        && entry->key_id == key_id
        && !memcmp(entry->key, key, PFS_CRYPTO_KEY_SIZE);
}

static struct hmac_sha256_cache_entry* select_hmac_sha256_cache_entry(struct crypto_request_cache* cache,
                                                                      int key_id, const uint8_t* key)
{
    for(size_t i = 0; i < PFS_HMAC_SHA256_CACHE_SLOTS; i++)
    {
        struct hmac_sha256_cache_entry* entry = &cache->hmac[i];
        if(hmac_sha256_cache_entry_matches(entry, key_id, key))
            return entry;
    }
    for(size_t i = 0; i < PFS_HMAC_SHA256_CACHE_SLOTS; i++)
    {
        struct hmac_sha256_cache_entry* entry = &cache->hmac[i];
        if(!entry->valid)
            return entry;
    }
    struct hmac_sha256_cache_entry* entry = &cache->hmac[cache->hmac_next_slot];
    cache->hmac_next_slot++;
    if(cache->hmac_next_slot == PFS_HMAC_SHA256_CACHE_SLOTS)
        cache->hmac_next_slot = 0;
    return entry;
}

static int get_hmac_sha256_cache_entry(struct crypto_request_cache* cache, int key_id, const uint8_t* key,
                                       const struct hmac_sha256_cache_entry** out)
{
    struct hmac_sha256_cache_entry* entry = select_hmac_sha256_cache_entry(cache, key_id, key);
    if(hmac_sha256_cache_entry_matches(entry, key_id, key))
    {
        METRIC_INC(hmac_cache_hits);
        *out = entry;
        return 0;
    }
    METRIC_INC(hmac_cache_misses);

    struct hmac_sha256_cache_entry temp = {.key_id = key_id};
    memcpy(temp.key, key, sizeof(temp.key));
    if(hmac_sha256_seed(&temp.inner_ctx, &temp.outer_ctx, key))
        return -1;
    entry->valid = 0;
    memcpy(entry, &temp, sizeof(temp));
    entry->valid = 1;
    *out = entry;
    return 0;
}

static int pfs_gen_key(uint32_t idx, const uint8_t* seed, const uint8_t* ekpfs, uint8_t* out)
{
    return hmac_sha256_once(out, ekpfs, &idx, sizeof(idx), seed, 16);
}

int pfs_derive_fake_keys(const uint8_t* p_eekpfs, const uint8_t* crypt_seed, uint8_t* ek, uint8_t* sk)
{
    METRIC_INC(pfs_derive_calls);
    if(uelf_fpu_enter())
    {
        METRIC_INC(pfs_derive_failures);
        return 0;
    }
    int ans = 0;
    uint8_t eekpfs[256];
    memcpy(eekpfs, p_eekpfs, 256);
    if(!br_rsa_i62_public(eekpfs, 256, &ypkg))
        goto exit;
    if(eekpfs[0] != 0 || eekpfs[1] != 2)
        goto exit;
    size_t idx = 1;
    while(idx < 256 && eekpfs[idx])
        idx++;
    if(idx != 255 - 32)
        goto exit;
    uint8_t* ekpfs = eekpfs+idx+1;
    if(pfs_gen_key(1, crypt_seed, ekpfs, ek))
        goto exit;
    if(pfs_gen_key(2, crypt_seed, ekpfs, sk))
        goto exit;
    ans = 1;
exit:
    uelf_fpu_exit();
    if(ans)
        METRIC_INC(pfs_derive_successes);
    else
        METRIC_INC(pfs_derive_failures);
    return ans;
}

int pfs_hmac_virtual_fpu_held(struct crypto_request_cache* cache, uint8_t* out, int key_id, const uint8_t* key,
                              uint64_t data, size_t data_size)
{
    struct uelf_sha256_context ctx;
    const struct hmac_sha256_cache_entry* hmac_keys;
    METRIC_INC(hmac_requests);
    METRIC_ADD(hmac_bytes, data_size);
    if(get_hmac_sha256_cache_entry(cache, key_id, key, &hmac_keys))
        return -1;
    ctx = hmac_keys->inner_ctx;
    while(data_size)
    {
        uint64_t chunk_cur;
        uint64_t chunk_end;
        if(!virt2phys(data, &chunk_cur, &chunk_end))
            return -1;
        size_t chk = chunk_end - chunk_cur;
        if(chk > data_size)
            chk = data_size;
        if(uelf_sha256_update(&ctx, DMEM+chunk_cur, chk))
            return -1;
        data += chk;
        data_size -= chk;
    }
    if(hmac_sha256_finalize(&hmac_keys->outer_ctx, &ctx, out))
        return -1;
    return 0;
}

int pfs_hmac_virtual(struct crypto_request_cache* cache, uint8_t* out, int key_id, const uint8_t* key,
                     uint64_t data, size_t data_size)
{
    if(uelf_fpu_enter())
        return -1;
    int ans = pfs_hmac_virtual_fpu_held(cache, out, key_id, key, data, data_size);
    uelf_fpu_exit();
    return ans;
}

static int xts_key_cache_entry_matches(const struct xts_key_cache_entry* entry, int key_id, const uint8_t* key)
{
    return entry->valid
        && entry->key_id == key_id
        && !memcmp(entry->key, key, PFS_CRYPTO_KEY_SIZE);
}

static struct xts_key_cache_entry* select_xts_key_cache_entry(struct crypto_request_cache* cache, int key_id,
                                                              const uint8_t* key)
{
    for(size_t i = 0; i < PFS_XTS_KEY_CACHE_SLOTS; i++)
    {
        struct xts_key_cache_entry* entry = &cache->xts[i];
        if(xts_key_cache_entry_matches(entry, key_id, key))
            return entry;
    }
    for(size_t i = 0; i < PFS_XTS_KEY_CACHE_SLOTS; i++)
    {
        struct xts_key_cache_entry* entry = &cache->xts[i];
        if(!entry->valid)
            return entry;
    }
    struct xts_key_cache_entry* entry = &cache->xts[cache->xts_next_slot];
    cache->xts_next_slot++;
    if(cache->xts_next_slot == PFS_XTS_KEY_CACHE_SLOTS)
        cache->xts_next_slot = 0;
    return entry;
}

static int get_xts_key_cache_entry(struct crypto_request_cache* cache, int key_id, const uint8_t* key,
                                   const struct xts_key_cache_entry** out)
{
    struct xts_key_cache_entry* entry = select_xts_key_cache_entry(cache, key_id, key);
    if(xts_key_cache_entry_matches(entry, key_id, key))
    {
        METRIC_INC(xts_cache_hits);
        *out = entry;
        return 0;
    }
    METRIC_INC(xts_cache_misses);

    struct xts_key_cache_entry temp = {.key_id = key_id};
    memcpy(temp.key, key, sizeof(temp.key));
    // Preserve the old libtomcrypt key split: key[16..31] encrypts data, key[0..15] encrypts tweaks.
    if(isal_aes_keyexp_128(key + 16, temp.data_key_enc, temp.data_key_dec))
        return -1;
    if(isal_aes_keyexp_128(key, temp.tweak_key_enc, temp.tweak_key_dec))
        return -1;
    entry->valid = 0;
    memcpy(entry, &temp, sizeof(temp));
    entry->valid = 1;
    *out = entry;
    return 0;
}

int pfs_xts_virtual_fpu_held(struct crypto_request_cache* cache, uint64_t dst, uint64_t src, int key_id,
                             const uint8_t* key, uint64_t start, uint32_t count, int is_encrypt)
{
    METRIC_TIME_START(start_cycles);
    enum { SECTOR_SIZE = 4096 };
    uint8_t sector[SECTOR_SIZE];
    const struct xts_key_cache_entry* xts_keys;
    METRIC_INC(xts_requests);
    METRIC_ADD(xts_sectors, count);
    if(get_xts_key_cache_entry(cache, key_id, key, &xts_keys))
    {
        METRIC_TIME(xts_cycles_total, xts_cycles_max, start_cycles);
        return -1;
    }
    while(count)
    {
        uint64_t src_phys, src_end, dst_phys, dst_end;
        if(virt2phys(src, &src_phys, &src_end)
        && virt2phys(dst, &dst_phys, &dst_end)
        && src_end - src_phys >= SECTOR_SIZE && dst_end - dst_phys >= SECTOR_SIZE)
        {
            uint64_t src_span = (src_end - src_phys) >> 12;
            uint64_t dst_span = (dst_end - dst_phys) >> 12;
            uint32_t run = count;
            if(run > src_span)
                run = src_span;
            if(run > dst_span)
                run = dst_span;
            METRIC_INC(xts_full_direct_runs);
            METRIC_ADD(xts_full_direct_sectors, run);
            while(run--)
            {
                uint64_t tweak[2] = {start, 0};
                int err = is_encrypt
                    ? isal_aes_xts_enc_128_expanded_key(xts_keys->tweak_key_enc, xts_keys->data_key_enc, (void*)tweak,
                                                        SECTOR_SIZE, DMEM + src_phys, DMEM + dst_phys)
                    : isal_aes_xts_dec_128_expanded_key(xts_keys->tweak_key_enc, xts_keys->data_key_dec, (void*)tweak,
                                                        SECTOR_SIZE, DMEM + src_phys, DMEM + dst_phys);
                if(err)
                {
                    METRIC_TIME(xts_cycles_total, xts_cycles_max, start_cycles);
                    return -1;
                }
                dst_phys += SECTOR_SIZE;
                src_phys += SECTOR_SIZE;
                dst += SECTOR_SIZE;
                src += SECTOR_SIZE;
                start++;
                count--;
            }
            continue;
        }

        uint64_t tweak[2] = {start, 0};
        METRIC_INC(xts_full_fallback_sectors);
        if(copy_from_kernel(sector, src, SECTOR_SIZE))
        {
            METRIC_TIME(xts_cycles_total, xts_cycles_max, start_cycles);
            return -1;
        }
        if(is_encrypt) {
            if(isal_aes_xts_enc_128_expanded_key(xts_keys->tweak_key_enc, xts_keys->data_key_enc, (void*)tweak,
                                                 SECTOR_SIZE, sector, sector))
            {
                METRIC_TIME(xts_cycles_total, xts_cycles_max, start_cycles);
                return -1;
            }
        } else {
            if(isal_aes_xts_dec_128_expanded_key(xts_keys->tweak_key_enc, xts_keys->data_key_dec, (void*)tweak,
                                                 SECTOR_SIZE, sector, sector))
            {
                METRIC_TIME(xts_cycles_total, xts_cycles_max, start_cycles);
                return -1;
            }
        }
        if(copy_to_kernel(dst, sector, SECTOR_SIZE))
        {
            METRIC_TIME(xts_cycles_total, xts_cycles_max, start_cycles);
            return -1;
        }
        dst += SECTOR_SIZE;
        src += SECTOR_SIZE;
        start++;
        count--;
    }
    METRIC_TIME(xts_cycles_total, xts_cycles_max, start_cycles);
    return 0;
}

int pfs_xts_virtual(struct crypto_request_cache* cache, uint64_t dst, uint64_t src, int key_id,
                    const uint8_t* key, uint64_t start, uint32_t count, int is_encrypt)
{
    if(uelf_fpu_enter())
        return -1;
    int ans = pfs_xts_virtual_fpu_held(cache, dst, src, key_id, key, start, count, is_encrypt);
    uelf_fpu_exit();
    return ans;
}
#endif
