/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-net-aux.h"

#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>

/*****************************************************************************/

G_STATIC_ASSERT((int) FR_ACT_UNSPEC == RTN_UNSPEC);
G_STATIC_ASSERT((int) FR_ACT_TO_TBL == RTN_UNICAST);
G_STATIC_ASSERT((int) FR_ACT_GOTO == RTN_LOCAL);
G_STATIC_ASSERT((int) FR_ACT_NOP == RTN_BROADCAST);
G_STATIC_ASSERT((int) FR_ACT_RES3 == RTN_ANYCAST);
G_STATIC_ASSERT((int) FR_ACT_RES4 == RTN_MULTICAST);
G_STATIC_ASSERT((int) FR_ACT_BLACKHOLE == RTN_BLACKHOLE);
G_STATIC_ASSERT((int) FR_ACT_UNREACHABLE == RTN_UNREACHABLE);
G_STATIC_ASSERT((int) FR_ACT_PROHIBIT == RTN_PROHIBIT);

/* see iproute2's rtnl_rtntype_a2n() */
NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    nm_net_aux_rtnl_rtntype_a2n,
    int,
    { nm_assert(name); },
    {
        NM_AUTO_PROTECT_ERRNO(errsv);
        return _nm_utils_ascii_str_to_int64(name, 0, 0, 255, -1);
    },
    {"anycast", RTN_ANYCAST},
    {"blackhole", RTN_BLACKHOLE},
    {"brd", RTN_BROADCAST},
    {"broadcast", RTN_BROADCAST},
    {"local", RTN_LOCAL},
    {"multicast", RTN_MULTICAST},
    {"nat", RTN_NAT},
    {"prohibit", RTN_PROHIBIT},
    {"throw", RTN_THROW},
    {"unicast", RTN_UNICAST},
    {"unreachable", RTN_UNREACHABLE},
    {"xresolve", RTN_XRESOLVE}, );

const char *
nm_net_aux_rtnl_rtntype_n2a(guint8 v)
{
    /* see iproute2's rtnl_rtntype_n2a(). */

    switch (v) {
    case RTN_UNSPEC:
        return "none";
    case RTN_UNICAST:
        return "unicast";
    case RTN_LOCAL:
        return "local";
    case RTN_BROADCAST:
        return "broadcast";
    case RTN_ANYCAST:
        return "anycast";
    case RTN_MULTICAST:
        return "multicast";
    case RTN_BLACKHOLE:
        return "blackhole";
    case RTN_UNREACHABLE:
        return "unreachable";
    case RTN_PROHIBIT:
        return "prohibit";
    case RTN_THROW:
        return "throw";
    case RTN_NAT:
        return "nat";
    case RTN_XRESOLVE:
        return "xresolve";
    }

    /* unlike the iproute2 code, this returns %NULL for unknown values.
     * You may represent this value as "%d" integer, but do it yourself. */
    return NULL;
}
