#ifndef EXFAT_MOUNT_C
#define EXFAT_MOUNT_C

#include "types.h"

#include <stdbool.h>
#include <sys/stat.h>

bool mount_exfat_image(const char *file_path, char *out_mount_point);
void unmount_exfat(const char *mount_point);

#endif