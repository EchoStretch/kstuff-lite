/* Read folder metadata with the allocator expected by the existing parsers.
 * The caller supplies all function addresses and readable filename storage.
 */
#include "ps4_folder_metadata.h"

int ps4_folder_metadata_read(void *source, void *context, unsigned entry, void **output,
                             size_t *output_size, const struct ps4_folder_metadata_env *env)
{
    if(!source || *(unsigned *)((char *)source + 8) != 2)
        return env->original(source, context, entry, output, output_size);
    const char *name;
    if(entry == 0x402)
        name = env->filenames[0];
    else if(entry == 0x403)
        name = env->filenames[1];
    else
        return (int)0x80551604;
    const char *root = *(const char **)((char *)source + 0x10);
    if(!root || !output || !output_size)
        return (int)0x80551604;
    char path[1056];
    size_t n = 0;
    while(n < 1024 && root[n])
    {
        path[n] = root[n];
        ++n;
    }
    if(n == 1024)
        return (int)0x80551605;
    if(n && path[n - 1] == '/')
        --n;
    do
    {
        path[n++] = *name;
    } while(*name++);
    int fd = env->open_file(path, 0);
    if(fd < 0)
    {
        unsigned error = (unsigned)*env->error_location();
        if(error == 2)
        {
            *output = NULL;
            *output_size = 0;
            return 0;
        }
        return (int)(0x80020000u | (error & 0xffffu));
    }
    const size_t limit = 1024 * 1024;
    unsigned char *buffer = env->allocate(limit + 1);
    if(!buffer)
    {
        env->close_file(fd);
        return (int)0x80551603;
    }
    size_t length = 0;
    unsigned error = 0;
    while(length <= limit)
    {
        long got = env->pread_file(fd, buffer + length, limit + 1 - length, (long)length);
        if(got < 0)
        {
            unsigned e = (unsigned)*env->error_location();
            if(e == 4)
                continue;
            error = 0x80020000u | (e & 0xffffu);
            break;
        }
        if(!got)
            break;
        if((size_t)got > limit + 1 - length)
        {
            error = 0x80551611;
            break;
        }
        length += (size_t)got;
    }
    env->close_file(fd);
    if(!error && (!length || length > limit))
        error = 0x80551611;
    if(error)
    {
        env->release(buffer);
        return (int)error;
    }
    *output = buffer;
    *output_size = length;
    return 0;
}
