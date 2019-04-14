/*
 * A noop implementation of eBPF filter for IPv4 Address Conflict Detection
 *
 * These are a collection of dummy functions that have no effect, but allows
 * n-acd to compile without eBPF support.
 *
 * See n-acd-bpf.c for documentation.
 */

#include <c-stdaux.h>
#include <stddef.h>
#include "n-acd-private.h"

int n_acd_bpf_map_create(int *mapfdp, size_t max_entries) {
        *mapfdp = -1;
        return 0;
}

int n_acd_bpf_map_add(int mapfd, struct in_addr *addrp) {
        return 0;
}

int n_acd_bpf_map_remove(int mapfd, struct in_addr *addrp) {
        return 0;
}

int n_acd_bpf_compile(int *progfdp, int mapfd, struct ether_addr *macp) {
        *progfdp = -1;
        return 0;
}
