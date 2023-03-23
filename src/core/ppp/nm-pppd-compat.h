/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) Eivind Næss, eivnaes@yahoo.com
 */

#ifndef __NM_PPPD_COMPAT_H__
#define __NM_PPPD_COMPAT_H__

/* Define INET6 to compile with IPv6 support against older pppd headers,
   pppd >= 2.5.0 use PPP_WITH_IPV6CP and is defined in pppdconf.h */
#define INET6 1

/* PPP < 2.5.0 defines and exports VERSION which overlaps with current package VERSION define.
   this silly macro magic is to work around that. */
#undef VERSION
#include <pppd/pppd.h>

#ifndef PPPD_VERSION
#define PPPD_VERSION VERSION
#endif

#include <pppd/fsm.h>
#include <pppd/eui64.h>
#include <pppd/ipcp.h>
#include <pppd/ipv6cp.h>
#include <pppd/upap.h>

#ifdef HAVE_PPPD_CHAP_H
#include <pppd/chap.h>
#endif

#ifdef HAVE_PPPD_CHAP_NEW_H
#include <pppd/chap-new.h>
#endif

#ifdef HAVE_PPPD_CHAP_MS_H
#include <pppd/chap_ms.h>
#endif

#ifndef PPP_PROTO_CHAP
#define PPP_PROTO_CHAP 0xc223
#endif

#ifndef PPP_PROTO_EAP
#define PPP_PROTO_EAP 0xc227
#endif

#if WITH_PPP_VERSION < PPP_VERSION(2, 5, 0)

static inline bool
debug_on(void)
{
    return debug;
}

static inline const char *
ppp_ipparam(void)
{
    return ipparam;
}

static inline int
ppp_ifunit(void)
{
    return ifunit;
}

static inline const char *
ppp_ifname(void)
{
    return ifname;
}

static inline int
ppp_get_mtu(int idx)
{
    return netif_get_mtu(idx);
}

static inline void
ppp_set_ifname(const char *new_name)
{
    g_strlcpy(ifname, new_name, IF_NAMESIZE);
}

typedef enum ppp_notify {
    NF_PID_CHANGE,
    NF_PHASE_CHANGE,
    NF_EXIT,
    NF_SIGNALED,
    NF_IP_UP,
    NF_IP_DOWN,
    NF_IPV6_UP,
    NF_IPV6_DOWN,
    NF_AUTH_UP,
    NF_LINK_DOWN,
    NF_FORK,
    NF_MAX_NOTIFY
} ppp_notify_t;

typedef void(ppp_notify_fn)(void *ctx, int arg);

static inline void
ppp_add_notify(ppp_notify_t type, ppp_notify_fn *func, void *ctx)
{
    struct notifier **list[NF_MAX_NOTIFY] = {
        [NF_PID_CHANGE]   = &pidchange,
        [NF_PHASE_CHANGE] = &phasechange,
        [NF_EXIT]         = &exitnotify,
        [NF_SIGNALED]     = &sigreceived,
        [NF_IP_UP]        = &ip_up_notifier,
        [NF_IP_DOWN]      = &ip_down_notifier,
        [NF_IPV6_UP]      = &ipv6_up_notifier,
        [NF_IPV6_DOWN]    = &ipv6_down_notifier,
        [NF_AUTH_UP]      = &auth_up_notifier,
        [NF_LINK_DOWN]    = &link_down_notifier,
        [NF_FORK]         = &fork_notifier,
    };

    struct notifier **notify = list[type];
    if (notify) {
        add_notifier(notify, func, ctx);
    }
}

#endif /* #if WITH_PPP_VERSION < PPP_VERSION(2,5,0) */
#endif /* #ifdef __NM_PPPD_COMPAT_H__ */
