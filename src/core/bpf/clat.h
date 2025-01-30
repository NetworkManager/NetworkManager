/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NAT64_H__
#define __NAT64_H__

#include <linux/in6.h>

struct clat_v6_config_key {
    struct in6_addr local_v6;
    struct in6_addr pref64;
    __u32           ifindex;
};

struct clat_v6_config_value {
    struct in_addr local_v4;
};

struct clat_v4_config_key {
    struct in_addr local_v4;
    __u32          ifindex;
};

struct clat_v4_config_value {
    struct in6_addr local_v6;
    struct in6_addr pref64;
};

#endif
