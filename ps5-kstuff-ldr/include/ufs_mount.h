#ifndef UFS_MOUNT_C
#define UFS_MOUNT_C

#include <stdbool.h>

bool mount_ufs_image(const char *file_path, char *out_mount_point);
void unmount_ufs(const char *mount_point);

#endif