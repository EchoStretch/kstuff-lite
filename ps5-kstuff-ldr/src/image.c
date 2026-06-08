#include "image.h"
#include <stdio.h> 
#include <string.h>
#include <dirent.h>
#include <strings.h>

bool is_ufs_image(const char* name) {
    const char* dot = strrchr(name, '.');
    if (!dot) return false;
    return !strcasecmp(dot, ".ffpkg") || !strcasecmp(dot, ".ufs");
}

bool is_pfs_image(const char* name) {
    const char* dot = strrchr(name, '.');
    if (!dot) return false;
    return !strcasecmp(dot, ".pfs");
}

bool is_pfsc_image(const char* name) {
    const char* dot = strrchr(name, '.');
    if (!dot) return false;
    return !strcasecmp(dot, ".ffpfsc");
}

bool is_exfat_image(const char* name) {
    const char* dot = strrchr(name, '.');
    if (!dot) return false;
    return !strcasecmp(dot, ".exfat") || !strcasecmp(dot, ".img");
}

int find_image_in_dir(const char* dir, char* out, size_t out_sz,
                             bool* is_ufs_out, bool* is_pfs_out, bool* is_pfsc_out, bool* is_exfat_out) {
    DIR* d = opendir(dir);
    if (!d) return 0;

    struct dirent* e;
    *is_ufs_out = *is_pfs_out = *is_pfsc_out = *is_exfat_out = false;

    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;

        if (is_pfs_image(e->d_name)) {
            snprintf(out, out_sz, "%s/%s", dir, e->d_name);
            *is_pfs_out = true;
            closedir(d);
            return 1;
        }
        if (is_pfsc_image(e->d_name)) {
            snprintf(out, out_sz, "%s/%s", dir, e->d_name);
            *is_pfsc_out = true;
            closedir(d);
            return 1;
        }
        if (is_ufs_image(e->d_name)) {
            snprintf(out, out_sz, "%s/%s", dir, e->d_name);
            *is_ufs_out = true;
            closedir(d);
            return 1;
        }
        if (is_exfat_image(e->d_name)) {
            snprintf(out, out_sz, "%s/%s", dir, e->d_name);
            *is_exfat_out = true;
            closedir(d);
            return 1;
        }
    }

    closedir(d);
    return 0;
}
