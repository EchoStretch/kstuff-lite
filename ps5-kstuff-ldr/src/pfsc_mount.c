#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <dirent.h>

#include "types.h"
#include "mount_helpers.h"
#include "pfsc_mount.h"

typedef struct {
    uint16_t source_type;
    uint16_t flags;
    uint32_t reserved0;
    const char *path;
    uint64_t offset;
    uint64_t size;
    const char *bitmap_path;
    uint64_t bitmap_offset;
    uint64_t bitmap_size;
} lvd_layer_t;

typedef struct {
    uint32_t io_version;
    int32_t  device_id;
    uint32_t sector_size;
    uint32_t secondary_unit;
    uint16_t flags;
    uint16_t image_type;
    uint32_t layer_count;
    uint64_t device_size;
    lvd_layer_t *layers_ptr;
} lvd_attach_t;

#define LVD_CTRL_PATH       "/dev/lvdctl"
#define SCE_LVD_IOC_ATTACH  0xC0286D00

static void list_dir_contents(const char *path) {
    DIR *d = opendir(path);
    if (!d) {
        //notify("Cannot list %s: %s", path, strerror(errno));
        return;
    }
    //notify("Contents of %s:", path);
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        //notify("  → %s", e->d_name);
    }
    closedir(d);
}

bool mount_pfsc_image(const char* file_path, char* out_mount_point) {
    const char* filename = strrchr(file_path, '/') ? strrchr(file_path, '/') + 1 : file_path;
    char mount_name[MAX_PATH];
    snprintf(mount_name, sizeof(mount_name), "%s", filename);
    char* dot = strrchr(mount_name, '.'); 
    if (dot) *dot = '\0';

    snprintf(out_mount_point, MAX_PATH, "/data/imgmnt/pfscmnt/%s", mount_name);

    struct stat st;
    if (stat(out_mount_point, &st) == 0) {
        if (is_mounted(out_mount_point)) unmount_pfsc(out_mount_point);
        rmdir(out_mount_point);
    }

    if (mkdir(out_mount_point, 0777) && errno != EEXIST) {
        //notify("mkdir failed: %s", strerror(errno));
        return false;
    }

    //notify("Mounting PFSC container: %s", filename);

    // Try multiple image_type values for PFSC
    const uint16_t image_types[] = {9, 8, 5, 10, 11, 0};
    
    for (int i = 0; i < 6; i++) {
        uint16_t img_type = image_types[i];
        if (img_type == 0) break;

        //notify("Trying image_type = %d", img_type);

        int fd = open(LVD_CTRL_PATH, O_RDWR);
        if (fd < 0) {
            //notify("Failed to open lvdctl");
            break;
        }

        lvd_layer_t layer = {0};
        layer.source_type = 1;
        layer.flags = 1;
        layer.path = file_path;
        if (stat(file_path, &st) == 0)
            layer.size = st.st_size;

        lvd_attach_t req = {0};
        req.io_version = 0;
        req.device_id = -1;
        req.sector_size = 4096;
        req.secondary_unit = 4096;
        req.flags = 0x1C;
        req.image_type = img_type;
        req.layer_count = 1;
        req.device_size = layer.size;
        req.layers_ptr = &layer;

        int ret = ioctl(fd, SCE_LVD_IOC_ATTACH, &req);
        close(fd);

        if (ret != 0 || req.device_id < 0) {
            //notify("LVD attach failed for type %d", img_type);
            continue;
        }

        char devname[32];
        snprintf(devname, sizeof(devname), "/dev/lvd%d", req.device_id);

        char mount_errmsg[256] = {0};
        const char *ekpfs_key = "0000000000000000000000000000000000000000000000000000000000000000";

        struct iovec iov[] = {
            IOVEC_ENTRY("from"),       IOVEC_ENTRY(devname),
            IOVEC_ENTRY("fspath"),     IOVEC_ENTRY(out_mount_point),
            IOVEC_ENTRY("fstype"),     IOVEC_ENTRY("pfs"),
            IOVEC_ENTRY("sigverify"),  IOVEC_ENTRY("0"),
            IOVEC_ENTRY("mkeymode"),   IOVEC_ENTRY("AC"),
            IOVEC_ENTRY("budgetid"),   IOVEC_ENTRY("system"),
            IOVEC_ENTRY("playgo"),     IOVEC_ENTRY("0"),
            IOVEC_ENTRY("disc"),       IOVEC_ENTRY("0"),
            IOVEC_ENTRY("ekpfs"),      IOVEC_ENTRY(ekpfs_key),
            IOVEC_ENTRY("async"),      IOVEC_ENTRY(NULL),
            IOVEC_ENTRY("noatime"),    IOVEC_ENTRY(NULL),
            IOVEC_ENTRY("rdonly"),     IOVEC_ENTRY(NULL),
            IOVEC_ENTRY("errmsg"),     {(void *)mount_errmsg, sizeof(mount_errmsg)},
            IOVEC_ENTRY("force"),      IOVEC_ENTRY(NULL)
        };

        if (nmount(iov, IOVEC_SIZE(iov), MNT_RDONLY) == 0) {
            //notify("PFSC mounted successfully with image_type=%d at %s", img_type, out_mount_point);
            list_dir_contents(out_mount_point);
            return true;
        }

        //notify("nmount failed for type %d", img_type);
    }

    //notify("All PFSC mount attempts failed");
    rmdir(out_mount_point);
    return false;
}

void unmount_pfsc(const char* mount_point) {
    if (!mount_point || !*mount_point) return;
    unmount(mount_point, MNT_FORCE);
    rmdir(mount_point);
}