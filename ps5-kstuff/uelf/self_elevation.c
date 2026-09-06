#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysent.h>

#include "self_elevation.h"
#include "traps.h"
#include "utils.h"

#if KSTUFF_SELF_ELEVATION

#define SYSTEM_AUTH_ID UINT64_C(0x4801000000000013)
#define COREDUMP_AUTH_ID UINT64_C(0x4800000000000006)
#define DEBUG_AUTH_ID UINT64_C(0x4800000000010003)
#define MAX_PROCESS_WALK 4096

extern char allproc[];
extern char doreti_iret[];
extern struct sysent sysents[];

struct kernel_layout
{
    uint16_t proc_ucred;
    uint16_t proc_filedesc;
    uint16_t proc_pid;
    uint16_t ucred_uid;
    uint16_t ucred_ruid;
    uint16_t ucred_svuid;
    uint16_t ucred_ngroups;
    uint16_t ucred_rgid;
    uint16_t ucred_svgid;
    uint16_t ucred_auth_id;
    uint16_t ucred_caps;
    uint16_t ucred_attributes;
    uint16_t filedesc_root;
    uint16_t filedesc_jail;
};

static const struct kernel_layout supported_layout = {
    0x40, 0x48, 0xbc, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18,
    0x58, 0x60, 0x80, 0x10, 0x18,
};

enum elevation_frame
{
    ELEVATION_DORETI,
    ELEVATION_TRAP,
    ELEVATION_THREAD,
    ELEVATION_PROCESS,
    ELEVATION_OLD_UCRED,
    ELEVATION_ROOT_UCRED,
    ELEVATION_FILEDESC,
    ELEVATION_PROFILE,
    ELEVATION_ROOT_DIRECTORY,
    ELEVATION_JAIL_DIRECTORY,
    ELEVATION_EUID,
    ELEVATION_FRAME_WORDS,
};

static int is_kernel_pointer(uint64_t pointer)
{
    return pointer && (pointer >> 48) == UINT64_C(0xffff);
}

static int firmware_supported(void)
{
    switch(FWVER)
    {
    case 0x0300:
    case 0x0310:
    case 0x0320:
    case 0x0321:
    case 0x0400:
    case 0x0402:
    case 0x0403:
    case 0x0450:
    case 0x0451:
    case 0x0500:
    case 0x0502:
    case 0x0510:
    case 0x0550:
    case 0x0600:
    case 0x0602:
    case 0x0650:
    case 0x0700:
    case 0x0701:
    case 0x0720:
    case 0x0740:
    case 0x0760:
    case 0x0761:
    case 0x0800:
    case 0x0820:
    case 0x0840:
    case 0x0860:
    case 0x0900:
    case 0x0905:
    case 0x0920:
    case 0x0940:
    case 0x0960:
    case 0x1000:
    case 0x1001:
    case 0x1020:
    case 0x1040:
    case 0x1060:
    case 0x1100:
    case 0x1120:
    case 0x1140:
    case 0x1160:
    case 0x1200:
    case 0x1202:
    case 0x1220:
    case 0x1240:
    case 0x1260:
    case 0x1270:
        return 1;
    default:
        return 0;
    }
}

static const struct kernel_layout* select_layout(void)
{
    return firmware_supported() ? &supported_layout : 0;
}

static int read_process_links(uint64_t process, const struct kernel_layout* layout,
                              uint64_t* ucred, uint64_t* filedesc)
{
    if(!is_kernel_pointer(process)
    || copy_u64_from_kernel(ucred, process + layout->proc_ucred)
    || copy_u64_from_kernel(filedesc, process + layout->proc_filedesc)
    || !is_kernel_pointer(*ucred)
    || !is_kernel_pointer(*filedesc))
        return EFAULT;
    return 0;
}

static int find_process_one(const struct kernel_layout* layout, uint64_t* process_one)
{
    uint64_t process;

    if(copy_u64_from_kernel(&process, (uint64_t)allproc))
        return EFAULT;
    for(unsigned int i = 0; process && i < MAX_PROCESS_WALK; i++)
    {
        uint32_t pid;
        uint64_t next;

        if(!is_kernel_pointer(process)
        || copy_u32_from_kernel(&pid, process + layout->proc_pid))
            return EFAULT;
        if(pid == 1)
        {
            *process_one = process;
            return 0;
        }
        if(copy_u64_from_kernel(&next, process))
            return EFAULT;
        process = next;
    }
    return ESRCH;
}

static uint64_t authority_for_profile(uint64_t profile)
{
    if(profile == KSTUFF_PROFILE_PROCESS_MEMORY)
        return COREDUMP_AUTH_ID;
    if(profile == KSTUFF_PROFILE_DEBUG)
        return DEBUG_AUTH_ID;
    return SYSTEM_AUTH_ID;
}

static int apply_profile(uint64_t ucred, uint64_t root_ucred,
                         const struct kernel_layout* layout, uint64_t profile)
{
    uint32_t identity[6];
    uint8_t caps[16];
    uint8_t attributes[32];
    uint64_t authority = authority_for_profile(profile);
    uint64_t verified_authority;
    uint32_t verified_identity[sizeof(identity) / sizeof(identity[0])];
    uint8_t verified_caps[sizeof(caps)];
    uint8_t verified_attributes[sizeof(attributes)];

    if(copy_from_kernel(identity, root_ucred + layout->ucred_uid,
                        sizeof(identity)))
        return EFAULT;
    memset(caps, 0xff, sizeof(caps));
    if(copy_from_kernel(attributes, ucred + layout->ucred_attributes,
                        sizeof(attributes)))
        return EFAULT;
    attributes[3] |= 0x80;
    if(copy_to_kernel(ucred + layout->ucred_uid, identity, sizeof(identity))
    || copy_u64_to_kernel(ucred + layout->ucred_auth_id, authority)
    || copy_to_kernel(ucred + layout->ucred_caps, caps, sizeof(caps))
    || copy_to_kernel(ucred + layout->ucred_attributes, attributes,
                      sizeof(attributes))
    || copy_from_kernel(verified_identity, ucred + layout->ucred_uid,
                        sizeof(verified_identity))
    || copy_u64_from_kernel(&verified_authority,
                            ucred + layout->ucred_auth_id)
    || copy_from_kernel(verified_caps, ucred + layout->ucred_caps,
                        sizeof(verified_caps))
    || copy_from_kernel(verified_attributes, ucred + layout->ucred_attributes,
                        sizeof(verified_attributes))
    || memcmp(verified_identity, identity, sizeof(identity))
    || verified_authority != authority
    || memcmp(verified_caps, caps, sizeof(caps))
    || memcmp(verified_attributes, attributes, sizeof(attributes)))
        return EFAULT;
    return 0;
}

static int apply_filesystem_root(uint64_t filedesc,
                                 const struct kernel_layout* layout,
                                 uint64_t root_directory,
                                 uint64_t jail_directory)
{
    uint64_t verified_root;
    uint64_t verified_jail;

    if(copy_u64_to_kernel(filedesc + layout->filedesc_root, root_directory)
    || copy_u64_to_kernel(filedesc + layout->filedesc_jail, jail_directory)
    || copy_u64_from_kernel(&verified_root, filedesc + layout->filedesc_root)
    || copy_u64_from_kernel(&verified_jail, filedesc + layout->filedesc_jail)
    || verified_root != root_directory
    || verified_jail != jail_directory)
        return EFAULT;
    return 0;
}

int inspect_current_process(uint64_t thread, uint64_t magic, uint64_t version,
                            uint64_t selector, uint64_t* value)
{
    const struct kernel_layout* layout;
    uint64_t process;
    uint64_t ucred;
    uint64_t filedesc;

    if(magic != KSTUFF_SELF_ELEVATION_MAGIC
    || version != KSTUFF_SELF_ELEVATION_ABI_VERSION
    || selector != KSTUFF_SELF_INSPECTION_AUTH_ID)
        return EINVAL;
    if(!(layout = select_layout()))
        return EPROTONOSUPPORT;
    if(!is_kernel_pointer(thread)
    || copy_u64_from_kernel(&process, thread + td_proc)
    || read_process_links(process, layout, &ucred, &filedesc)
    || copy_u64_from_kernel(value, ucred + layout->ucred_auth_id))
        return EFAULT;
    return 0;
}

int begin_elevate_current_process(uint64_t* regs, uint64_t thread,
                                  uint64_t magic, uint64_t version,
                                  uint64_t profile)
{
    const struct kernel_layout* layout;
    uint64_t frame[ELEVATION_FRAME_WORDS] = {
        [ELEVATION_DORETI] = (uint64_t)doreti_iret,
        [ELEVATION_TRAP] = MKTRAP(TRAP_KEKCALL,
                                  KSTUFF_SELF_ELEVATION_TRAP),
        [ELEVATION_THREAD] = thread,
        [ELEVATION_PROFILE] = profile,
    };
    uint64_t process_one;
    uint64_t root_filedesc;
    uint64_t syscall_target;
    uint32_t euid;
    uint32_t pid;
    int error;

    if(magic != KSTUFF_SELF_ELEVATION_MAGIC
    || version != KSTUFF_SELF_ELEVATION_ABI_VERSION
    || (profile != KSTUFF_PROFILE_DATA_ACCESS
     && profile != KSTUFF_PROFILE_PROCESS_MEMORY
     && profile != KSTUFF_PROFILE_DEBUG))
        return EINVAL;
    if(!(layout = select_layout()))
        return EPROTONOSUPPORT;
    if(!is_kernel_pointer(thread)
    || copy_u64_from_kernel(&frame[ELEVATION_PROCESS], thread + td_proc)
    || read_process_links(frame[ELEVATION_PROCESS], layout,
                          &frame[ELEVATION_OLD_UCRED],
                          &frame[ELEVATION_FILEDESC])
    || copy_u32_from_kernel(&pid, frame[ELEVATION_PROCESS] + layout->proc_pid)
    || !pid)
        return EFAULT;
    if((error = find_process_one(layout, &process_one))
    || (error = read_process_links(process_one, layout,
                                   &frame[ELEVATION_ROOT_UCRED],
                                   &root_filedesc))
    || copy_u64_from_kernel(&frame[ELEVATION_ROOT_DIRECTORY],
                            root_filedesc + layout->filedesc_root)
    || copy_u64_from_kernel(&frame[ELEVATION_JAIL_DIRECTORY],
                            root_filedesc + layout->filedesc_jail)
    || !is_kernel_pointer(frame[ELEVATION_ROOT_DIRECTORY]))
        return error ? error : EFAULT;
    if(!is_kernel_pointer(frame[ELEVATION_JAIL_DIRECTORY]))
        frame[ELEVATION_JAIL_DIRECTORY] = frame[ELEVATION_ROOT_DIRECTORY];
    /* Calling seteuid with the existing effective UID makes the kernel clone
     * the credential and release the old reference through its native path. */
    if(copy_u32_from_kernel(&euid,
                            frame[ELEVATION_OLD_UCRED] + layout->ucred_uid))
        return EFAULT;
    frame[ELEVATION_EUID] = euid;
    if(copy_u64_from_kernel(&syscall_target,
                            (uint64_t)&sysents[SYS_seteuid].sy_call)
    || !is_kernel_pointer(syscall_target)
    || push_stack_checked(regs, frame, sizeof(frame)))
        return EFAULT;

    regs[RAX] = (uint64_t)&sysents[SYS_seteuid];
    regs[RDI] = thread;
    regs[RSI] = regs[RSP] + ELEVATION_EUID * sizeof(uint64_t);
    regs[RIP] = syscall_target;
    handle_syscall(regs, 0);
    return 0;
}

void finish_elevate_current_process(uint64_t* regs)
{
    const struct kernel_layout* layout = select_layout();
    uint64_t frame[ELEVATION_FRAME_WORDS];
    uint64_t new_ucred;
    int error = (uint32_t)regs[RAX];

    if(pop_stack_checked(regs, frame, sizeof(frame)))
        return;
    regs[RIP] = frame[ELEVATION_FRAME_WORDS - 1];
    if(!layout)
        error = EPROTONOSUPPORT;
    else if(!error
         && (copy_u64_from_kernel(&new_ucred,
                                 frame[ELEVATION_PROCESS - 1]
                                 + layout->proc_ucred)
         || !is_kernel_pointer(new_ucred)
         || new_ucred == frame[ELEVATION_OLD_UCRED - 1]
         || apply_profile(new_ucred,
                          frame[ELEVATION_ROOT_UCRED - 1], layout,
                          frame[ELEVATION_PROFILE - 1])
         || apply_filesystem_root(frame[ELEVATION_FILEDESC - 1], layout,
                                  frame[ELEVATION_ROOT_DIRECTORY - 1],
                                  frame[ELEVATION_JAIL_DIRECTORY - 1])))
        error = EFAULT;

    if(!error
    && copy_u64_to_kernel(frame[ELEVATION_THREAD - 1] + td_retval, 0))
        error = EFAULT;
    regs[RAX] = error;
}

#endif
