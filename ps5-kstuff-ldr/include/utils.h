#ifndef UTILS_H
#define UTILS_H

#include "types.h"

void notify(const char *fmt, ...);
int copy_file(const char *src, const char *dst);
int copy_dir(const char *src, const char *dst);
int remove_dir(const char *path);
int is_appmeta_file(const char *name);

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

#endif