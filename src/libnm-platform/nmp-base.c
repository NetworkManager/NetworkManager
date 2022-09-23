/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 - 2018 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nmp-base.h"

#include <linux/rtnetlink.h>
#include <linux/if.h>
#include "nm-compat-headers/linux/if_addr.h"

/*****************************************************************************/

NM_UTILS_FLAGS2STR_DEFINE(nm_platform_link_flags2str,
                          unsigned,
                          NM_UTILS_FLAGS2STR(IFF_LOOPBACK, "loopback"),
                          NM_UTILS_FLAGS2STR(IFF_BROADCAST, "broadcast"),
                          NM_UTILS_FLAGS2STR(IFF_POINTOPOINT, "pointopoint"),
                          NM_UTILS_FLAGS2STR(IFF_MULTICAST, "multicast"),
                          NM_UTILS_FLAGS2STR(IFF_NOARP, "noarp"),
                          NM_UTILS_FLAGS2STR(IFF_ALLMULTI, "allmulti"),
                          NM_UTILS_FLAGS2STR(IFF_PROMISC, "promisc"),
                          NM_UTILS_FLAGS2STR(IFF_MASTER, "master"),
                          NM_UTILS_FLAGS2STR(IFF_SLAVE, "slave"),
                          NM_UTILS_FLAGS2STR(IFF_DEBUG, "debug"),
                          NM_UTILS_FLAGS2STR(IFF_DYNAMIC, "dynamic"),
                          NM_UTILS_FLAGS2STR(IFF_AUTOMEDIA, "automedia"),
                          NM_UTILS_FLAGS2STR(IFF_PORTSEL, "portsel"),
                          NM_UTILS_FLAGS2STR(IFF_NOTRAILERS, "notrailers"),
                          NM_UTILS_FLAGS2STR(IFF_UP, "up"),
                          NM_UTILS_FLAGS2STR(IFF_RUNNING, "running"),
                          NM_UTILS_FLAGS2STR(IFF_LOWER_UP, "lowerup"),
                          NM_UTILS_FLAGS2STR(IFF_DORMANT, "dormant"),
                          NM_UTILS_FLAGS2STR(IFF_ECHO, "echo"), );

NM_UTILS_ENUM2STR_DEFINE(nm_platform_link_inet6_addrgenmode2str,
                         guint8,
                         NM_UTILS_ENUM2STR(NM_IN6_ADDR_GEN_MODE_NONE, "none"),
                         NM_UTILS_ENUM2STR(NM_IN6_ADDR_GEN_MODE_EUI64, "eui64"),
                         NM_UTILS_ENUM2STR(NM_IN6_ADDR_GEN_MODE_STABLE_PRIVACY, "stable-privacy"),
                         NM_UTILS_ENUM2STR(NM_IN6_ADDR_GEN_MODE_RANDOM, "random"), );

NM_UTILS_FLAGS2STR_DEFINE(nm_platform_addr_flags2str,
                          unsigned,
                          NM_UTILS_FLAGS2STR(IFA_F_SECONDARY, "secondary"),
                          NM_UTILS_FLAGS2STR(IFA_F_NODAD, "nodad"),
                          NM_UTILS_FLAGS2STR(IFA_F_OPTIMISTIC, "optimistic"),
                          NM_UTILS_FLAGS2STR(IFA_F_DADFAILED, "dadfailed"),
                          NM_UTILS_FLAGS2STR(IFA_F_HOMEADDRESS, "homeaddress"),
                          NM_UTILS_FLAGS2STR(IFA_F_DEPRECATED, "deprecated"),
                          NM_UTILS_FLAGS2STR(IFA_F_TENTATIVE, "tentative"),
                          NM_UTILS_FLAGS2STR(IFA_F_PERMANENT, "permanent"),
                          NM_UTILS_FLAGS2STR(IFA_F_MANAGETEMPADDR, "mngtmpaddr"),
                          NM_UTILS_FLAGS2STR(IFA_F_NOPREFIXROUTE, "noprefixroute"),
                          NM_UTILS_FLAGS2STR(IFA_F_MCAUTOJOIN, "mcautojoin"),
                          NM_UTILS_FLAGS2STR(IFA_F_STABLE_PRIVACY, "stable-privacy"), );

G_STATIC_ASSERT(IFA_F_SECONDARY == IFA_F_TEMPORARY);

NM_UTILS_ENUM2STR_DEFINE(nm_platform_route_scope2str,
                         int,
                         NM_UTILS_ENUM2STR(RT_SCOPE_NOWHERE, "nowhere"),
                         NM_UTILS_ENUM2STR(RT_SCOPE_HOST, "host"),
                         NM_UTILS_ENUM2STR(RT_SCOPE_LINK, "link"),
                         NM_UTILS_ENUM2STR(RT_SCOPE_SITE, "site"),
                         NM_UTILS_ENUM2STR(RT_SCOPE_UNIVERSE, "global"), );
