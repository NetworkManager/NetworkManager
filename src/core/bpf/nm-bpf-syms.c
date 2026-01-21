/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-bpf-syms.h"

#include <dlfcn.h>

#define LIBBPF_SONAME "libbpf.so.1"

NM_BPF_DLSYM(libbpf_strerror);
NM_BPF_DLSYM(bpf_link__destroy);
NM_BPF_DLSYM(bpf_program__attach_tcx);
NM_BPF_DLSYM(bpf_object__attach_skeleton);
NM_BPF_DLSYM(bpf_object__destroy_skeleton);
NM_BPF_DLSYM(bpf_object__detach_skeleton);
NM_BPF_DLSYM(bpf_object__load_skeleton);
NM_BPF_DLSYM(bpf_object__open_skeleton);

gboolean
nm_bpf_syms_load(void)
{
    static int result = -1;
    void      *handle;

    if (result >= 0)
        return result;

    result = FALSE;

    handle = dlopen(LIBBPF_SONAME, RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE);
    if (!handle) {
        nm_log_warn(LOGD_CORE, "bpf: could not dlopen " LIBBPF_SONAME);
        goto out;
    }

#define TRY_BIND_SYMBOL(symbol)                                                                 \
    G_STMT_START                                                                                \
    {                                                                                           \
        void *_sym = dlsym(handle, #symbol);                                                    \
                                                                                                \
        if (!_sym) {                                                                            \
            nm_log_warn(LOGD_CORE, "bpf: could not find symbol %s in " LIBBPF_SONAME, #symbol); \
            goto out;                                                                           \
        }                                                                                       \
        sym_##symbol = _sym;                                                                    \
    }                                                                                           \
    G_STMT_END

    TRY_BIND_SYMBOL(libbpf_strerror);
    TRY_BIND_SYMBOL(bpf_link__destroy);
    TRY_BIND_SYMBOL(bpf_object__attach_skeleton);
    TRY_BIND_SYMBOL(bpf_object__destroy_skeleton);
    TRY_BIND_SYMBOL(bpf_object__detach_skeleton);
    TRY_BIND_SYMBOL(bpf_object__load_skeleton);
    TRY_BIND_SYMBOL(bpf_object__open_skeleton);
    TRY_BIND_SYMBOL(bpf_program__attach_tcx);

    nm_log_dbg(LOGD_CORE, "bpf: dynamic symbols loaded from " LIBBPF_SONAME);
    result = TRUE;

out:
    return result;
}
