/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) Eivind Næss, eivnaes@yahoo.com
 */

#ifndef __NM_PPPD_COMPAT_H__
#define __NM_PPPD_COMPAT_H__

#define INET6      1

// PPP < 2.5.0 defines and exports VERSION which overlaps with current package VERSION define.
//   this silly macro magic is to work around that.

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
#define PPP_PROTO_CHAP              0xc223
#endif 

#ifndef PPP_PROTO_EAP
#define PPP_PROTO_EAP               0xc227
#endif

#if WITH_PPP_VERSION < PPP_VERSION(2,5,0)

static inline bool debug_on(void)
{
    return debug;
}

static inline const char *ppp_ipparam(void)
{
    return ipparam;
}

static inline int ppp_ifunit(void)
{
    return ifunit;
}

static inline const char *ppp_ifname(void)
{
    return ifname;
}

static inline int ppp_get_mtu(int idx)
{
    return netif_get_mtu(idx);
}

static inline void ppp_set_ifname(const char *new_name)
{
    g_strlcpy(ifname, new_name, IF_NAMESIZE);
}


#endif // #if WITH_PPP_VERSION < PPP_VERSION(2,5,0)
#endif // #ifdef __NM_PPPD_COMPAT_H__
