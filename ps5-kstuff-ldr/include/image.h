#ifndef IMAGE_H
#define IMAGE_H

#include "types.h"

bool is_pfs_image(const char *name);
bool is_pfsc_image(const char *name);
bool is_ufs_image(const char *name);
bool is_exfat_image(const char *name);

int find_image_in_dir(const char *dir, char *out_path, size_t out_sz,
                      bool *is_ufs_out, bool *is_pfs_out, bool* is_pfsc_out, bool *is_exfat_out);

#endif