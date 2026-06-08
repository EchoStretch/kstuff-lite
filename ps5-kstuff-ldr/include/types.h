#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/_iovec.h>     // for struct iovec
#include <sys/mount.h>      // for MNT_*, nmount flags
#include <sys/mdioctl.h>

#define IOVEC_ENTRY(x) { (void*)(x), (x) ? strlen(x) + 1 : 0 }
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))
#define MAX_PATH PATH_MAX

#define LVD_SECTOR_SIZE_EXFAT   512u
#define LVD_IMAGE_TYPE_EXFAT    7
#define LVD_OPTION_EXFAT        0x16
#define LVD_OPTION_LEN_EXFAT    0x16

#define SCE_LVD_IOC_ATTACH      0xC0286D00
#define SCE_LVD_IOC_DETACH      0xC0286D01

typedef struct {
    uint8_t reserved;
    const char *budgetid;
} MountSaveDataOpt;

typedef struct {
    uint8_t dummy;
} UmountSaveDataOpt;


// LVD structs (copy from your original code)
typedef struct {
    uint16_t source_type;
    uint8_t  entry_flags;
    uint8_t  reserved0;
    uint32_t reserved1;
    const char *path;
    uint64_t offset;
    uint64_t size;
    const char *bitmap_path;
    uint64_t bitmap_offset;
    uint64_t bitmap_size;
} lvd_kernel_layer_t;

typedef struct {
    uint32_t io_version;
    int32_t  device_id;
    uint32_t sector_size_0;
    uint32_t sector_size_1;
    uint16_t option_len;
    uint16_t image_type;
    uint32_t layer_count;
    uint64_t device_size;
    lvd_kernel_layer_t *layers_ptr;
} lvd_ioctl_attach_t;

typedef struct {
    uint32_t reserved0;
    int32_t  device_id;
    uint8_t  reserved[0x20];
} lvd_ioctl_detach_t;

// notify_request_t
typedef struct notify_request {
    char unused[45];
    char message[3075];
} notify_request_t;

// Image type enum (used in image.h / main.c)
typedef enum {
    IMAGE_TYPE_UNKNOWN = 0,
    IMAGE_TYPE_FOLDER,
    IMAGE_TYPE_PFS,
    IMAGE_TYPE_PFSC,
    IMAGE_TYPE_UFS,
    IMAGE_TYPE_EXFAT
} image_type_t;

#endif