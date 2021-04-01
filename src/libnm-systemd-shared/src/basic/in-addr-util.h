/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

#include "hash-funcs.h"
#include "macro.h"
#include "util.h"

union in_addr_union {
        struct in_addr in;
        struct in6_addr in6;
        uint8_t bytes[CONST_MAX(sizeof(struct in_addr), sizeof(struct in6_addr))];
};

struct in_addr_data {
        int family;
        union in_addr_union address;
};

bool in4_addr_is_null(const struct in_addr *a);
static inline bool in4_addr_is_set(const struct in_addr *a) {
        return !in4_addr_is_null(a);
}
bool in6_addr_is_null(const struct in6_addr *a);
static inline bool in6_addr_is_set(const struct in6_addr *a) {
        return !in6_addr_is_null(a);
}
int in_addr_is_null(int family, const union in_addr_union *u);
static inline bool in_addr_is_set(int family, const union in_addr_union *u) {
        return in_addr_is_null(family, u) == 0;
}
static inline int in_addr_data_is_null(const struct in_addr_data *a) {
        assert(a);
        return in_addr_is_null(a->family, &a->address);
}
static inline bool in_addr_data_is_set(const struct in_addr_data *a) {
        return in_addr_data_is_null(a);
}

int in_addr_is_multicast(int family, const union in_addr_union *u);

bool in4_addr_is_link_local(const struct in_addr *a);
bool in6_addr_is_link_local(const struct in6_addr *a);
int in_addr_is_link_local(int family, const union in_addr_union *u);
bool in6_addr_is_link_local_all_nodes(const struct in6_addr *a);

bool in4_addr_is_localhost(const struct in_addr *a);
int in_addr_is_localhost(int family, const union in_addr_union *u);

bool in4_addr_is_local_multicast(const struct in_addr *a);
bool in4_addr_is_non_local(const struct in_addr *a);

bool in4_addr_equal(const struct in_addr *a, const struct in_addr *b);
bool in6_addr_equal(const struct in6_addr *a, const struct in6_addr *b);
int in_addr_equal(int family, const union in_addr_union *a, const union in_addr_union *b);
int in_addr_prefix_intersect(int family, const union in_addr_union *a, unsigned aprefixlen, const union in_addr_union *b, unsigned bprefixlen);
int in_addr_prefix_next(int family, union in_addr_union *u, unsigned prefixlen);
int in_addr_prefix_nth(int family, union in_addr_union *u, unsigned prefixlen, uint64_t nth);
int in_addr_random_prefix(int family, union in_addr_union *u, unsigned prefixlen_fixed_part, unsigned prefixlen);
int in_addr_prefix_range(
                int family,
                const union in_addr_union *in,
                unsigned prefixlen,
                union in_addr_union *ret_start,
                union in_addr_union *ret_end);
int in_addr_to_string(int family, const union in_addr_union *u, char **ret);
int in_addr_prefix_to_string(int family, const union in_addr_union *u, unsigned prefixlen, char **ret);
int in_addr_port_ifindex_name_to_string(int family, const union in_addr_union *u, uint16_t port, int ifindex, const char *server_name, char **ret);
static inline int in_addr_ifindex_to_string(int family, const union in_addr_union *u, int ifindex, char **ret) {
        return in_addr_port_ifindex_name_to_string(family, u, 0, ifindex, NULL, ret);
}
static inline int in_addr_port_to_string(int family, const union in_addr_union *u, uint16_t port, char **ret) {
        return in_addr_port_ifindex_name_to_string(family, u, port, 0, NULL, ret);
}
int in_addr_from_string(int family, const char *s, union in_addr_union *ret);
int in_addr_from_string_auto(const char *s, int *ret_family, union in_addr_union *ret);

unsigned char in4_addr_netmask_to_prefixlen(const struct in_addr *addr);
struct in_addr* in4_addr_prefixlen_to_netmask(struct in_addr *addr, unsigned char prefixlen);
int in4_addr_default_prefixlen(const struct in_addr *addr, unsigned char *prefixlen);
int in4_addr_default_subnet_mask(const struct in_addr *addr, struct in_addr *mask);
int in_addr_mask(int family, union in_addr_union *addr, unsigned char prefixlen);
int in_addr_prefix_covers(int family, const union in_addr_union *prefix, unsigned char prefixlen, const union in_addr_union *address);
int in_addr_parse_prefixlen(int family, const char *p, unsigned char *ret);
int in_addr_prefix_from_string(const char *p, int family, union in_addr_union *ret_prefix, unsigned char *ret_prefixlen);

typedef enum InAddrPrefixLenMode {
        PREFIXLEN_FULL,   /* Default to prefixlen of address size, 32 for IPv4 or 128 for IPv6, if not specified. */
        PREFIXLEN_REFUSE, /* Fail with -ENOANO if prefixlen is not specified. */
        PREFIXLEN_LEGACY, /* Default to legacy default prefixlen calculation from address if not specified. */
} InAddrPrefixLenMode;

int in_addr_prefix_from_string_auto_internal(const char *p, InAddrPrefixLenMode mode, int *ret_family, union in_addr_union *ret_prefix, unsigned char *ret_prefixlen);
static inline int in_addr_prefix_from_string_auto(const char *p, int *ret_family, union in_addr_union *ret_prefix, unsigned char *ret_prefixlen) {
        return in_addr_prefix_from_string_auto_internal(p, PREFIXLEN_FULL, ret_family, ret_prefix, ret_prefixlen);
}

static inline size_t FAMILY_ADDRESS_SIZE(int family) {
        assert(IN_SET(family, AF_INET, AF_INET6));
        return family == AF_INET6 ? 16 : 4;
}

/* Workaround for clang, explicitly specify the maximum-size element here.
 * See also oss-fuzz#11344. */
#define IN_ADDR_NULL ((union in_addr_union) { .in6 = {} })

void in6_addr_hash_func(const struct in6_addr *addr, struct siphash *state);
int in6_addr_compare_func(const struct in6_addr *a, const struct in6_addr *b);

extern const struct hash_ops in_addr_data_hash_ops;
extern const struct hash_ops in6_addr_hash_ops;
