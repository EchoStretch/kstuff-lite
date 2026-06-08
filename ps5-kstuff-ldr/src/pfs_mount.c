#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h> 

#include "types.h"
#include "mount_helpers.h"
#include "pfs_mount.h"


bool mount_pfs_image(const char* file_path, char* out_mount_point) {
    const char* filename = strrchr(file_path, '/') ? strrchr(file_path, '/') + 1 : file_path;
    char mount_name[MAX_PATH];
    snprintf(mount_name, sizeof(mount_name), "%s", filename);
    char* dot = strrchr(mount_name, '.'); if (dot) *dot = '\0';

    snprintf(out_mount_point, MAX_PATH, "/data/imgmnt/pfsmnt/%s", mount_name);

    struct stat st;
    if (stat(out_mount_point, &st) == 0) {
        if (is_mounted(out_mount_point)) unmount_pfs(out_mount_point);
        rmdir(out_mount_point);
    }

    if (mkdir(out_mount_point, 0777) && errno != EEXIST) {
        notify("mkdir failed: %s", strerror(errno));
        return false;
    }

    //notify("Mounting PFS: %s → %s", file_path, out_mount_point);

    MountSaveDataOpt opt;
    sceFsInitMountSaveDataOpt(&opt);
    opt.budgetid = "system";

    uint8_t key[0x20] = {0};

    int ret = sceFsMountSaveData(&opt, file_path, out_mount_point, key);
    if (ret < 0) {
        notify("PFS mount failed: 0x%08x", ret);
        rmdir(out_mount_point);
        return false;
    }

    //notify("PFS mounted OK at %s", out_mount_point);
    return true;
}

void unmount_pfs(const char* mount_point) {
    if (!mount_point || !*mount_point) return;
    UmountSaveDataOpt opt;
    sceFsInitUmountSaveDataOpt(&opt);
    //int ret = sceFsUmountSaveData(&opt, mount_point, -1, 1);
    //notify("unmount_pfs ret=0x%08x for %s", ret, mount_point);
    rmdir(mount_point);
}