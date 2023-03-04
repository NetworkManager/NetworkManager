/* nm-pppd-compat.h - Compatibility header for pppd plugin
 *
 * Copyright (C) Eivind Næss, eivnaes@yahoo.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
/* SPDX-License-Identifier: GPL-2.0-or-later */

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
