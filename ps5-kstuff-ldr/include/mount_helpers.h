#ifndef MOUNT_HELPERS_H
#define MOUNT_HELPERS_H

int remount_system_ex(void);
int mount_nullfs(const char *src, const char *dst);
int is_mounted(const char *path);

#endif