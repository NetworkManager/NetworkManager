/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NAT64_H__
#define __NAT64_H__

#include <linux/in6.h>

struct clat_config {
    struct in6_addr local_v6;
    struct in6_addr pref64;
    struct in_addr  local_v4;
    unsigned        pref64_len;
};

#endif
