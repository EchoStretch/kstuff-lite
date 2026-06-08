#include "ufs_mount.h"
#include "types.h"
#include "mount_helpers.h"
#include "utils.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/mount.h>
#include <stdio.h>

bool mount_ufs_image(const char* file_path, char* out_mount_point) {
    struct stat st;
    if (stat(file_path, &st) != 0) {
        notify("stat failed: %s", strerror(errno));
        return false;
    }

    time_t now = time(NULL);
    if (difftime(now, st.st_mtime) < 12.0) {
        notify("Image too new (%.0fs) - skipping", difftime(now, st.st_mtime));
        return false;
    }

    const char* filename = strrchr(file_path, '/') ? strrchr(file_path, '/') + 1 : file_path;
    char mount_name[256];
    strncpy(mount_name, filename, sizeof(mount_name)-1);
    char* dot = strrchr(mount_name, '.'); if (dot) *dot = '\0';

    snprintf(out_mount_point, MAX_PATH, "/data/imgmnt/ufsmnt/%s", mount_name);

    struct statfs sfs;
    if (statfs(out_mount_point, &sfs) == 0 && strcmp(sfs.f_fstypename, "ufs") == 0) {
        notify("UFS already mounted at %s", out_mount_point);
        return true;
    }

    if (mkdir(out_mount_point, 0777) != 0 && errno != EEXIST) {
        notify("mkdir failed: %s", strerror(errno));
        return false;
    }

    int mdctl = open("/dev/mdctl", O_RDWR);
    if (mdctl < 0) {
        notify("/dev/mdctl open failed: %s", strerror(errno));
        return false;
    }

    struct md_ioctl mdio = {0};
    mdio.md_version    = MDIOVERSION;
    mdio.md_type       = MD_VNODE;
    mdio.md_file       = (char*)file_path;
    mdio.md_mediasize  = st.st_size;
    mdio.md_sectorsize = 512;
    mdio.md_options    = MD_AUTOUNIT | MD_READONLY;

    int ret = ioctl(mdctl, (unsigned long)MDIOCATTACH, &mdio);
    if (ret != 0) {
        mdio.md_options = MD_AUTOUNIT;
        ret = ioctl(mdctl, (unsigned long)MDIOCATTACH, &mdio);
        if (ret != 0) {
            notify("MDIOCATTACH failed: %s (errno %d)", strerror(errno), errno);
            close(mdctl);
            return false;
        }
    }

    char devname[32];
    snprintf(devname, sizeof(devname), "/dev/md%u", mdio.md_unit);
    close(mdctl);

    //notify("UFS attached as %s", devname);

    struct iovec iov[] = {
        IOVEC_ENTRY("fstype"), IOVEC_ENTRY("ufs"),
        IOVEC_ENTRY("fspath"), IOVEC_ENTRY(out_mount_point),
        IOVEC_ENTRY("from"),   IOVEC_ENTRY(devname),
    };

    ret = nmount(iov, IOVEC_SIZE(iov), 0);
    if (ret != 0) {
        //notify("nmount rw failed: %s - falling back to rdonly", strerror(errno));
        ret = nmount(iov, IOVEC_SIZE(iov), MNT_RDONLY);
        if (ret != 0) {
            notify("nmount ufs failed: %s", strerror(errno));
            return false;
        }
    }

    //notify("UFS mounted OK → %s", out_mount_point);
    return true;
}

void unmount_ufs(const char* mount_point) {
    if (!mount_point || !*mount_point) return;

    struct statfs sfs;
    if (statfs(mount_point, &sfs) == 0 && strcmp(sfs.f_fstypename, "ufs") == 0) {
        if (unmount(mount_point, MNT_FORCE) != 0) {
            notify("Failed to unmount %s: %s", mount_point, strerror(errno));
        } else {
            notify("UFS unmounted: %s", mount_point);
        }
    }

    for (int i = 0; i < 16; i++) {
        char devname[32];
        snprintf(devname, sizeof(devname), "/dev/md%d", i);
        if (access(devname, F_OK) != 0) continue;

        int mdctl = open("/dev/mdctl", O_RDWR);
        if (mdctl >= 0) {
            struct md_ioctl mdio = {0};
            mdio.md_version = MDIOVERSION;
            mdio.md_unit = i;
            ioctl(mdctl, (unsigned long)MDIOCDETACH, &mdio);
            close(mdctl);
        }
    }

    if (rmdir(mount_point) != 0 && errno != ENOENT) {
        notify("Failed to remove UFS mount dir %s: %s", mount_point, strerror(errno));
    }
}