#include "utils.h"
#include "types.h"

#include <stdarg.h>
#include <sys/stat.h>
#include <sys/aio.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

void notify(const char* fmt, ...) {
    notify_request_t req = {};
    va_list args;
    va_start(args, fmt);
    vsnprintf(req.message, sizeof(req.message) - 1, fmt, args);
    va_end(args);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);

    va_list args2;
    va_start(args2, fmt);
    vprintf(fmt, args2);
    printf("\n");
    va_end(args2);
    fflush(stdout);
}

#define BUF_SIZE 0x800000

int copy_file(const char* src, const char* dst) {
    struct stat st;
    if (stat(src, &st) != 0 || !S_ISREG(st.st_mode)) return -1;

    int fd_in = open(src, O_RDONLY);
    if (fd_in < 0) return -1;
    int fd_out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode | 0600);
    if (fd_out < 0) { close(fd_in); return -1; }

    void* buf = malloc(BUF_SIZE);
    if (!buf) { close(fd_in); close(fd_out); return -1; }

    struct aiocb aior = {0};
    struct aiocb aiow = {0};
    aior.aio_fildes = fd_in;
    aior.aio_buf = buf;
    aiow.aio_fildes = fd_out;

    size_t copied = 0;
    const struct aiocb* aiolist[1];

    while (copied < (size_t)st.st_size) {
        size_t chunk = BUF_SIZE;
        if (copied + chunk > (size_t)st.st_size) chunk = st.st_size - copied;

        aior.aio_nbytes = chunk;
        aior.aio_offset = copied;
        if (aio_read(&aior) < 0) break;

        aiolist[0] = &aior;
        if (aio_suspend(aiolist, 1, NULL) < 0) break;

        ssize_t n = aio_return(&aior);
        if (n <= 0) break;

        aiow.aio_buf = buf;
        aiow.aio_nbytes = n;
        aiow.aio_offset = copied;
        if (aio_write(&aiow) < 0) break;

        aiolist[0] = &aiow;
        if (aio_suspend(aiolist, 1, NULL) < 0) break;
        if (aio_return(&aiow) < 0) break;

        copied += n;
    }

    free(buf);
    close(fd_in);
    close(fd_out);

    return copied == (size_t)st.st_size ? 0 : -1;
}

int copy_dir(const char* src, const char* dst) {
    if (mkdir(dst, 0755) && errno != EEXIST) return -1;

    DIR* d = opendir(src);
    if (!d) {
        notify("copy_dir: Cannot open source dir %s: %s", src, strerror(errno));
        return -1;
    }

    struct dirent* e;
    char src_path[MAX_PATH];
    char dst_path[MAX_PATH];

    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;

        snprintf(src_path, sizeof(src_path), "%s/%s", src, e->d_name);
        snprintf(dst_path, sizeof(dst_path), "%s/%s", dst, e->d_name);

        struct stat st;
        if (stat(src_path, &st) != 0) {
            notify("copy_dir: stat failed on %s: %s", src_path, strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            copy_dir(src_path, dst_path);
        } else if (S_ISREG(st.st_mode)) {
            copy_file(src_path, dst_path);
        }
    }

    closedir(d);
    return 0;
}

int remove_dir(const char* path) {
    DIR* d = opendir(path); if (!d) return -1;
    struct dirent* entry;
    while ((entry = readdir(d)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char fullpath[PATH_MAX];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        struct stat st;
        if (stat(fullpath, &st) == -1) continue;
        if (S_ISDIR(st.st_mode)) remove_dir(fullpath);
        else unlink(fullpath);
    }
    closedir(d);
    return rmdir(path);
}

int is_appmeta_file(const char* name) {
    if (!strcasecmp(name, "param.json") || !strcasecmp(name, "param.sfo")) return 1;
    const char* ext = strrchr(name, '.');
    if (!ext) return 0;
    return !strcasecmp(ext, ".png") || !strcasecmp(ext, ".dds") || !strcasecmp(ext, ".at9");
}