// Kernel ABI shims for Android NDK versions that lag behind the device kernel.

#ifndef COMPAT_H
#define COMPAT_H

#include <linux/bpf.h>

enum {
#if defined(BPF_F_NO_PREALLOC)
    COMPAT_MAP_NO_PREALLOC = BPF_F_NO_PREALLOC,
#else
    COMPAT_MAP_NO_PREALLOC = 1U,
#endif

#if defined(BPF_PSEUDO_MAP_FD)
    COMPAT_PSEUDO_MAP_FD = BPF_PSEUDO_MAP_FD,
#else
    COMPAT_PSEUDO_MAP_FD = 1,
#endif

#if defined(BPF_OBJ_NAME_LEN)
    COMPAT_OBJECT_NAME_LEN = BPF_OBJ_NAME_LEN,
#else
    COMPAT_OBJECT_NAME_LEN = 16,
#endif

#if defined(BPF_FUNC_get_socket_uid)
    COMPAT_GET_SOCKET_UID = BPF_FUNC_get_socket_uid,
#else
    COMPAT_GET_SOCKET_UID = 47,
#endif

#if defined(BPF_FUNC_skb_load_bytes)
    COMPAT_SKB_LOAD_BYTES = BPF_FUNC_skb_load_bytes,
#else
    COMPAT_SKB_LOAD_BYTES = 26,
#endif
};

#endif
