#include "exfat_mount.h"
#include "mount_helpers.h"
#include "utils.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>

bool mount_exfat_image(const char *file_path, char *out_mount_point) {
    struct stat st;
    if (stat(file_path, &st) != 0) {
        notify("stat failed: %s", strerror(errno));
        return false;
    }

    /*time_t now = time(NULL);
    if (difftime(now, st.st_mtime) < 12.0) {
        notify("Image too new (%.0fs) - skipping", difftime(now, st.st_mtime));
        return false;
    }*/

    const char* filename = strrchr(file_path, '/') ? strrchr(file_path, '/') + 1 : file_path;
    char mount_name[256];
    strncpy(mount_name, filename, sizeof(mount_name)-1);
    char* dot = strrchr(mount_name, '.'); if (dot) *dot = '\0';

    snprintf(out_mount_point, MAX_PATH, "/data/imgmnt/exfatmnt/%s", mount_name);

    struct statfs sfs;
	if (statfs(out_mount_point, &sfs) == 0 && strcmp(sfs.f_fstypename, "exfatfs") == 0) {
        notify("EXFAT already mounted at %s", out_mount_point);
        return true;
    }

    if (mkdir(out_mount_point, 0777) != 0 && errno != EEXIST) {
        notify("mkdir failed: %s", strerror(errno));
        return false;
    }
	
    uint64_t offset = 0;
    int fd = open(file_path,O_RDONLY);
    if(fd>=0){
        uint8_t sector[512]; pread(fd,sector,512,0);
        if(!memcmp(sector+3,"EXFAT   ",8)) offset=0;
        close(fd);
    }

    // MD attach
    int md_fd=open("/dev/mdctl",O_RDWR);
    if(md_fd>=0){
        struct md_ioctl mdio={0};
        mdio.md_version=MDIOVERSION;
        mdio.md_type=MD_VNODE;
        mdio.md_file=(char*)file_path;
        mdio.md_mediasize=st.st_size-offset;
        mdio.md_sectorsize=512;
        mdio.md_options=MD_AUTOUNIT|MD_READONLY;

        if(ioctl(md_fd,(unsigned long)MDIOCATTACH,&mdio)==0){
            close(md_fd);
            char devname[64]; snprintf(devname,sizeof(devname),"/dev/md%u",mdio.md_unit);
            struct iovec iov[]={
                IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
                IOVEC_ENTRY("from"),      IOVEC_ENTRY(devname),
                IOVEC_ENTRY("fspath"),    IOVEC_ENTRY(out_mount_point),
                IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
                IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
                IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
                IOVEC_ENTRY("noatime"),   IOVEC_ENTRY(NULL),
                IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
            };
            if(nmount(iov,IOVEC_SIZE(iov),MNT_RDONLY)==0){
                //notify("exFAT mounted via MD OK → %s",out_mount_point);
                return true;
            }
        } else close(md_fd);
    }

    // LVD fallback
    int lvd_fd=open("/dev/lvdctl",O_RDWR);
    if(lvd_fd>=0){
        lvd_kernel_layer_t layer={0};
        layer.source_type=1; 
		layer.entry_flags=0x1;
        layer.path=file_path; 
		layer.offset=0;
        layer.size=(uint64_t)st.st_size;

        lvd_ioctl_attach_t req={0};
        req.io_version=1;
		req.device_id=-1;
        req.sector_size_0=512u;
		req.sector_size_1=req.sector_size_0;
        req.image_type=7;
		req.layer_count=1;
        req.device_size=(uint64_t)st.st_size;
        req.layers_ptr=&layer;

        if(ioctl(lvd_fd,SCE_LVD_IOC_ATTACH,&req)==0 && req.device_id>=0){
            close(lvd_fd);
            char devname[64]; snprintf(devname,sizeof(devname),"/dev/lvd%d",req.device_id);
            struct iovec iov[]={
                IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
                IOVEC_ENTRY("from"),      IOVEC_ENTRY(devname),
                IOVEC_ENTRY("fspath"),    IOVEC_ENTRY(out_mount_point),
                IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
                IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
                IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
                IOVEC_ENTRY("noatime"),   IOVEC_ENTRY(NULL),
                IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
            };
            if(nmount(iov,IOVEC_SIZE(iov),MNT_RDONLY)==0){
                //notify("exFAT mounted via LVD OK → %s",out_mount_point);
                return true;
            }
        } else close(lvd_fd);
    }

    notify("exFAT mount failed completely");
    return false;
}

void unmount_exfat(const char* mount_point) {
    if (!mount_point || !*mount_point) return;

    struct statfs sfs;
    if (statfs(mount_point, &sfs) == 0 && strcmp(sfs.f_fstypename, "exfatfs") == 0) {
        if (unmount(mount_point, MNT_FORCE) != 0) {
            notify("Failed to unmount exFAT %s: %s", mount_point, strerror(errno));
        } else {
            //notify("exFAT unmounted: %s", mount_point);
        }
    }

    for (int i = 0; i < 16; i++) {
        char devname[32];
        snprintf(devname, sizeof(devname), "/dev/lvd%d", i);
        if (access(devname, F_OK) == 0) {
            int lvdctl = open("/dev/lvdctl", O_RDWR);
            if (lvdctl >= 0) {
                lvd_ioctl_detach_t dreq = {0};
                dreq.device_id = i;
                ioctl(lvdctl, SCE_LVD_IOC_DETACH, &dreq);
                close(lvdctl);
            }
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
        notify("Failed to remove exFAT mount dir %s: %s", mount_point, strerror(errno));
    }
}
