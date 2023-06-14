/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2023 Eivind Næss, eivnaes@yahoo.com
 */

/*****************************************************************************/

/* PPP headers define some symbols as we do. We need to be careful to handle
 * the conflict, and include stuff in a certain order. */

#include <config.h>
#define ___CONFIG_H__

/*****************************************************************************/

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
_Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wstrict-prototypes\"")
#define _NM_PRAGMA_WARNING_REENABLE _Pragma("GCC diagnostic pop")
#elif defined(__clang__)
_Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wunknown-warning-option\"")
    _Pragma("clang diagnostic ignored \"-Wstrict-prototypes\"")
#define _NM_PRAGMA_WARNING_REENABLE _Pragma("clang diagnostic pop")
#else
#define _NM_PRAGMA_WARNING_REENABLE
#endif

/*****************************************************************************/

#define INET6 1

#include <pppd/pppd.h>

#ifdef DATE
/* Before ppp 2.5, pppd/patchlevel.h defined "DATE". Use that for detection. */
#define PPP_VERSION_2_5_OR_NEWER 0
#else
#define PPP_VERSION_2_5_OR_NEWER 1
#endif

#include <pppd/eui64.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>
#include <pppd/ipv6cp.h>
#include <pppd/upap.h>

#if PPP_VERSION_2_5_OR_NEWER
#include <pppd/chap.h>
#else
#include <pppd/chap-new.h>
#include <pppd/chap_ms.h>
#endif

    char pppd_version[] = (
#if PPP_VERSION_2_5_OR_NEWER
        PPPD_VERSION
#else
            VERSION
#endif
    );

#undef VERSION

_NM_PRAGMA_WARNING_REENABLE;

/*****************************************************************************/

#include "libnm-glib-aux/nm-default-glib.h"

#include "nm-pppd-compat.h"

#include <net/if.h>
#include <dlfcn.h>

#include "nm-ppp-status.h"

/*****************************************************************************/

G_STATIC_ASSERT(PPP_VERSION_2_5_OR_NEWER == NM_PPP_VERSION_2_5_OR_NEWER);

/*****************************************************************************/

G_STATIC_ASSERT((gint64) NM_PPP_STATUS_DEAD == PHASE_DEAD);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_INITIALIZE == PHASE_INITIALIZE);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_SERIALCONN == PHASE_SERIALCONN);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_DORMANT == PHASE_DORMANT);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_ESTABLISH == PHASE_ESTABLISH);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_AUTHENTICATE == PHASE_AUTHENTICATE);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_CALLBACK == PHASE_CALLBACK);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_NETWORK == PHASE_NETWORK);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_RUNNING == PHASE_RUNNING);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_TERMINATE == PHASE_TERMINATE);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_DISCONNECT == PHASE_DISCONNECT);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_HOLDOFF == PHASE_HOLDOFF);
G_STATIC_ASSERT((gint64) NM_PPP_STATUS_MASTER == PHASE_MASTER);

G_STATIC_ASSERT(NM_PPPD_COMPAT_MAXNAMELEN == MAXNAMELEN);
G_STATIC_ASSERT(NM_PPPD_COMPAT_MAXSECRETLEN == MAXSECRETLEN);

/*****************************************************************************/

int
nm_pppd_compat_get_ifunit(void)
{
    int i;

#if PPP_VERSION_2_5_OR_NEWER
    i = ppp_ifunit();
#else
    i = ifunit;
#endif

    return i;
}

const char *
nm_pppd_compat_get_ifname(void)
{
    const char *s;

#if PPP_VERSION_2_5_OR_NEWER
    s = ppp_ifname();
#else
    s = ifname;
#endif

    nm_assert(s);
    nm_assert(strlen(s) < IFNAMSIZ);
    return s;
}

void
nm_pppd_compat_set_ifname(const char *arg_ifname)
{
    nm_assert(arg_ifname);
    nm_assert(strlen(arg_ifname) < IFNAMSIZ);

#if PPP_VERSION_2_5_OR_NEWER
    ppp_set_ifname(arg_ifname);
#else
    g_strlcpy(ifname, arg_ifname, IFNAMSIZ);
#endif
}

const char *
nm_pppd_compat_get_ipparam(void)
{
    const char *s;

#if PPP_VERSION_2_5_OR_NEWER
    s = ppp_ipparam();
#else
    s = ipparam;
#endif

    return s;
}

void
nm_pppd_compat_get_ipcp_options(NMPppdCompatIPCPOptions *out_got, NMPppdCompatIPCPOptions *out_his)
{
    const ipcp_options *const got = &ipcp_gotoptions[0];
    const ipcp_options *const his = &ipcp_hisoptions[0];

    nm_assert(out_got);
    nm_assert(out_his);

    *out_got = (NMPppdCompatIPCPOptions){
        .ouraddr  = got->ouraddr,
        .hisaddr  = got->hisaddr,
        .dnsaddr  = {got->dnsaddr[0], got->dnsaddr[1]},
        .winsaddr = {got->winsaddr[0], got->winsaddr[1]},
    };

    *out_his = (NMPppdCompatIPCPOptions){
        .ouraddr  = his->ouraddr,
        .hisaddr  = his->hisaddr,
        .dnsaddr  = {his->dnsaddr[0], his->dnsaddr[1]},
        .winsaddr = {his->winsaddr[0], his->winsaddr[1]},
    };
}

void
nm_pppd_compat_get_ipv6cp_options(NMPppdCompatIPV6CPOptions *out_got,
                                  NMPppdCompatIPV6CPOptions *out_his)
{
    const ipv6cp_options *const his = &ipv6cp_hisoptions[0];
    const ipv6cp_options *const got = &ipv6cp_gotoptions[0];

    G_STATIC_ASSERT(sizeof(guint64) == sizeof(eui64_t));

    nm_assert(out_got);
    nm_assert(out_his);

    *out_got = (NMPppdCompatIPV6CPOptions){};
    memcpy(&out_got->ourid, &got->ourid, sizeof(guint64));
    memcpy(&out_got->hisid, &got->hisid, sizeof(guint64));

    *out_his = (NMPppdCompatIPV6CPOptions){};
    memcpy(&out_his->ourid, &his->ourid, sizeof(guint64));
    memcpy(&out_his->hisid, &his->hisid, sizeof(guint64));
}

void
nm_pppd_compat_set_chap_passwd_hook(int (*hook)(char *user, char *password))
{
    chap_passwd_hook = hook;
}

void
nm_pppd_compat_set_chap_check_hook(int (*hook)(void))
{
    chap_check_hook = hook;
}

void
nm_pppd_compat_set_pap_passwd_hook(int (*hook)(char *user, char *passwd))
{
    pap_passwd_hook = hook;
}

void
nm_pppd_compat_set_pap_check_hook(int (*hook)(void))
{
    pap_check_hook = hook;
}

gboolean
nm_pppd_compat_add_notify(NMPppdCompatNotifyT type, void (*func)(void *ctx, int arg), void *ctx)
{
    nm_assert(NM_IN_SET(type,
                        NM_PPPD_COMPAT_NF_PID_CHANGE,
                        NM_PPPD_COMPAT_NF_PHASE_CHANGE,
                        NM_PPPD_COMPAT_NF_EXIT,
                        NM_PPPD_COMPAT_NF_SIGNALED,
                        NM_PPPD_COMPAT_NF_IP_UP,
                        NM_PPPD_COMPAT_NF_IP_DOWN,
                        NM_PPPD_COMPAT_NF_IPV6_UP,
                        NM_PPPD_COMPAT_NF_IPV6_DOWN,
                        NM_PPPD_COMPAT_NF_AUTH_UP,
                        NM_PPPD_COMPAT_NF_LINK_DOWN,
                        NM_PPPD_COMPAT_NF_FORK));
    nm_assert(func);

#if PPP_VERSION_2_5_OR_NEWER
    {
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_PID_CHANGE == NF_PID_CHANGE);
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_PHASE_CHANGE == NF_PHASE_CHANGE);
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_EXIT == NF_EXIT);
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_SIGNALED == NF_SIGNALED);
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_IP_UP == NF_IP_UP);
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_IP_DOWN == NF_IP_DOWN);
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_IPV6_UP == NF_IPV6_UP);
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_IPV6_DOWN == NF_IPV6_DOWN);
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_AUTH_UP == NF_AUTH_UP);
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_LINK_DOWN == NF_LINK_DOWN);
        G_STATIC_ASSERT((gint64) NM_PPPD_COMPAT_NF_FORK == NF_FORK);

        ppp_add_notify((gint64) type, func, ctx);
        return TRUE;
    }
#else
    {
        static struct notifier **list[] = {
            [NM_PPPD_COMPAT_NF_PID_CHANGE]   = &pidchange,
            [NM_PPPD_COMPAT_NF_PHASE_CHANGE] = &phasechange,
            [NM_PPPD_COMPAT_NF_EXIT]         = &exitnotify,
            [NM_PPPD_COMPAT_NF_SIGNALED]     = &sigreceived,
            [NM_PPPD_COMPAT_NF_IP_UP]        = &ip_up_notifier,
            [NM_PPPD_COMPAT_NF_IP_DOWN]      = &ip_down_notifier,
            [NM_PPPD_COMPAT_NF_IPV6_UP]      = NULL /* ipv6_up_notifier */,
            [NM_PPPD_COMPAT_NF_IPV6_DOWN]    = NULL /* ipv6_down_notifier */,
            [NM_PPPD_COMPAT_NF_AUTH_UP]      = &auth_up_notifier,
            [NM_PPPD_COMPAT_NF_LINK_DOWN]    = &link_down_notifier,
            [NM_PPPD_COMPAT_NF_FORK]         = &fork_notifier,
        };
        struct notifier **notifier;

        nm_assert(_NM_INT_NOT_NEGATIVE(type) && type < G_N_ELEMENTS(list));

        if (NM_IN_SET(type, NM_PPPD_COMPAT_NF_IPV6_UP, NM_PPPD_COMPAT_NF_IPV6_DOWN)) {
            static gsize load_once = 0;

            /* pppd might be build without IPv6 support. Load the symbols dynamically. */
            if (g_once_init_enter(&load_once)) {
                void *handle;

                handle = dlopen(NULL, RTLD_NOW | RTLD_GLOBAL);
                if (handle) {
                    list[NM_PPPD_COMPAT_NF_IPV6_UP]   = dlsym(handle, "ipv6_up_notifier");
                    list[NM_PPPD_COMPAT_NF_IPV6_DOWN] = dlsym(handle, "ipv6_down_notifier");
                    dlclose(handle);
                }
                g_once_init_leave(&load_once, 1);
            }

            notifier = list[type];
        } else {
            notifier = list[type];
            nm_assert(notifier);
        }

        if (notifier)
            add_notifier(notifier, func, ctx);

        return !!notifier;
    }
#endif
}
