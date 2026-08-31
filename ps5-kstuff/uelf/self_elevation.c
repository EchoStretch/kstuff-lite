#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "self_elevation.h"
#include "utils.h"

#if KSTUFF_SELF_ELEVATION

#define SYSTEM_AUTH_ID UINT64_C(0x4801000000000013)
#define COREDUMP_AUTH_ID UINT64_C(0x4800000000000006)
#define DEBUG_AUTH_ID UINT64_C(0x4800000000010003)
#define MAX_PROCESS_WALK 4096

extern char allproc[];

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
    uint16_t ucred_prison;
    uint16_t ucred_auth_id;
    uint16_t ucred_caps;
    uint16_t ucred_attributes;
    uint16_t filedesc_root;
    uint16_t filedesc_jail;
};

static const struct kernel_layout supported_layout = {
    0x40, 0x48, 0xbc, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18,
    0x30, 0x58, 0x60, 0x80, 0x10, 0x18,
};

struct process_state
{
    uint32_t uid;
    uint32_t ruid;
    uint32_t svuid;
    uint32_t ngroups;
    uint32_t rgid;
    uint32_t svgid;
    uint64_t prison;
    uint64_t auth_id;
    uint8_t caps[16];
    uint8_t attributes[32];
    uint64_t root_directory;
    uint64_t jail_directory;
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

static int read_state(uint64_t ucred, uint64_t filedesc,
                      const struct kernel_layout* layout, struct process_state* state)
{
    if(copy_u32_from_kernel(&state->uid, ucred + layout->ucred_uid)
    || copy_u32_from_kernel(&state->ruid, ucred + layout->ucred_ruid)
    || copy_u32_from_kernel(&state->svuid, ucred + layout->ucred_svuid)
    || copy_u32_from_kernel(&state->ngroups, ucred + layout->ucred_ngroups)
    || copy_u32_from_kernel(&state->rgid, ucred + layout->ucred_rgid)
    || copy_u32_from_kernel(&state->svgid, ucred + layout->ucred_svgid)
    || copy_u64_from_kernel(&state->prison, ucred + layout->ucred_prison)
    || copy_u64_from_kernel(&state->auth_id, ucred + layout->ucred_auth_id)
    || copy_from_kernel(state->caps, ucred + layout->ucred_caps, sizeof(state->caps))
    || copy_from_kernel(state->attributes, ucred + layout->ucred_attributes,
                        sizeof(state->attributes))
    || copy_u64_from_kernel(&state->root_directory, filedesc + layout->filedesc_root)
    || copy_u64_from_kernel(&state->jail_directory, filedesc + layout->filedesc_jail))
        return EFAULT;
    return 0;
}

static int write_state(uint64_t ucred, uint64_t filedesc,
                       const struct kernel_layout* layout,
                       const struct process_state* state)
{
    if(copy_u32_to_kernel(ucred + layout->ucred_uid, state->uid)
    || copy_u32_to_kernel(ucred + layout->ucred_ruid, state->ruid)
    || copy_u32_to_kernel(ucred + layout->ucred_svuid, state->svuid)
    || copy_u32_to_kernel(ucred + layout->ucred_ngroups, state->ngroups)
    || copy_u32_to_kernel(ucred + layout->ucred_rgid, state->rgid)
    || copy_u32_to_kernel(ucred + layout->ucred_svgid, state->svgid)
    || copy_u64_to_kernel(ucred + layout->ucred_prison, state->prison)
    || copy_u64_to_kernel(ucred + layout->ucred_auth_id, state->auth_id)
    || copy_to_kernel(ucred + layout->ucred_caps, state->caps, sizeof(state->caps))
    || copy_to_kernel(ucred + layout->ucred_attributes, state->attributes,
                      sizeof(state->attributes))
    || copy_u64_to_kernel(filedesc + layout->filedesc_root, state->root_directory)
    || copy_u64_to_kernel(filedesc + layout->filedesc_jail, state->jail_directory))
        return EFAULT;
    return 0;
}

static int states_equal(const struct process_state* left,
                        const struct process_state* right)
{
    return left->uid == right->uid
        && left->ruid == right->ruid
        && left->svuid == right->svuid
        && left->ngroups == right->ngroups
        && left->rgid == right->rgid
        && left->svgid == right->svgid
        && left->prison == right->prison
        && left->auth_id == right->auth_id
        && !memcmp(left->caps, right->caps, sizeof(left->caps))
        && !memcmp(left->attributes, right->attributes, sizeof(left->attributes))
        && left->root_directory == right->root_directory
        && left->jail_directory == right->jail_directory;
}

static int restore_state(uint64_t ucred, uint64_t filedesc,
                         const struct kernel_layout* layout,
                         const struct process_state* original)
{
    struct process_state restored;
    if(write_state(ucred, filedesc, layout, original)
    || read_state(ucred, filedesc, layout, &restored)
    || !states_equal(&restored, original))
        return EIO;
    return 0;
}

int inspect_current_process(uint64_t thread, uint64_t magic, uint64_t version,
                            uint64_t selector, uint64_t* value)
{
    const struct kernel_layout* layout;
    struct process_state state;
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
    || read_state(ucred, filedesc, layout, &state))
        return EFAULT;

    *value = state.auth_id;
    return 0;
}

int elevate_current_process(uint64_t thread, uint64_t magic, uint64_t version,
                            uint64_t profile)
{
    const struct kernel_layout* layout;
    struct process_state original;
    struct process_state root;
    struct process_state target;
    struct process_state verified;
    uint64_t current_process;
    uint64_t current_ucred;
    uint64_t current_filedesc;
    uint64_t process_one;
    uint64_t root_ucred;
    uint64_t root_filedesc;
    uint32_t current_pid;
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
    || copy_u64_from_kernel(&current_process, thread + td_proc)
    || read_process_links(current_process, layout, &current_ucred, &current_filedesc)
    || copy_u32_from_kernel(&current_pid, current_process + layout->proc_pid)
    || !current_pid)
        return EFAULT;
    if((error = find_process_one(layout, &process_one))
    || (error = read_process_links(process_one, layout, &root_ucred, &root_filedesc))
    || (error = read_state(current_ucred, current_filedesc, layout, &original))
    || (error = read_state(root_ucred, root_filedesc, layout, &root)))
        return error;
    if(!is_kernel_pointer(root.prison) || !is_kernel_pointer(root.root_directory))
        return EFAULT;

    target = original;
    target.uid = 0;
    target.ruid = 0;
    target.svuid = 0;
    target.ngroups = 0;
    target.rgid = 0;
    target.svgid = 0;
    target.prison = root.prison;
    if(profile == KSTUFF_PROFILE_PROCESS_MEMORY)
        target.auth_id = COREDUMP_AUTH_ID;
    else if(profile == KSTUFF_PROFILE_DEBUG)
        target.auth_id = DEBUG_AUTH_ID;
    else
        target.auth_id = SYSTEM_AUTH_ID;
    memset(target.caps, 0xff, sizeof(target.caps));
    target.attributes[3] |= 0x80;
    target.root_directory = root.root_directory;
    target.jail_directory = is_kernel_pointer(root.jail_directory)
                          ? root.jail_directory : root.root_directory;

    if(write_state(current_ucred, current_filedesc, layout, &target)
    || read_state(current_ucred, current_filedesc, layout, &verified)
    || !states_equal(&verified, &target))
    {
        error = restore_state(current_ucred, current_filedesc, layout, &original);
        return error ? error : EFAULT;
    }
    return 0;
}

#endif
