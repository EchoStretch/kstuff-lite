#ifndef PFS_MOUNT_H
#define PFS_MOUNT_H

#include <stdbool.h>
#include "utils.h"

int sceFsInitMountSaveDataOpt(MountSaveDataOpt *opt);
int sceFsMountSaveData(MountSaveDataOpt *opt, const char *volumePath, const char *mountPath, uint8_t *key);
int sceFsInitUmountSaveDataOpt(UmountSaveDataOpt *opt);
int sceFsUmountSaveData(UmountSaveDataOpt *opt, const char *mountPath, int handle, int ignoreErrors);

bool mount_pfs_image(const char *file_path, char *out_mount_point);
void unmount_pfs(const char *mount_point);

#endif