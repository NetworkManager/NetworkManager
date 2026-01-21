/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_BPF_SYMS_H__
#define __NM_BPF_SYMS_H__

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define NM_BPF_DLSYM(symbol) typeof(symbol) *sym_##symbol

extern NM_BPF_DLSYM(libbpf_strerror);
extern NM_BPF_DLSYM(bpf_link__destroy);
extern NM_BPF_DLSYM(bpf_program__attach_tcx);
extern NM_BPF_DLSYM(bpf_object__attach_skeleton);
extern NM_BPF_DLSYM(bpf_object__destroy_skeleton);
extern NM_BPF_DLSYM(bpf_object__detach_skeleton);
extern NM_BPF_DLSYM(bpf_object__load_skeleton);
extern NM_BPF_DLSYM(bpf_object__open_skeleton);

gboolean nm_bpf_syms_load(void);

#endif /* __NM_BPF_SYMS_H__ */