#ifndef KSTUFF_PS4_FOLDER_METADATA_H
#define KSTUFF_PS4_FOLDER_METADATA_H
#include <stddef.h>
#include <stdint.h>

struct ps4_folder_metadata_env
{
    int (*original)(void *, void *, unsigned, void **, size_t *);
    int (*open_file)(const char *, int, ...);
    long (*pread_file)(int, void *, size_t, long);
    int (*close_file)(int);
    void *(*allocate)(size_t);
    void (*release)(void *);
    int *(*error_location)(void);
    char filenames[2][16]; /* Readable environment, separate from execute-only text. */
};

#endif
