/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-rdisc.h - Perform IPv6 router discovery
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright 2015 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_RDISC_PRIVATE_H__
#define __NETWORKMANAGER_RDISC_PRIVATE_H__

#include "nm-rdisc.h"

/* Functions only used by rdisc implementations */

void nm_rdisc_ra_received (NMRDisc *rdisc, guint32 now, NMRDiscConfigMap changed);

gboolean nm_rdisc_add_gateway    (NMRDisc *rdisc, const NMRDiscGateway *new);
gboolean nm_rdisc_add_address    (NMRDisc *rdisc, const NMRDiscAddress *new);
gboolean nm_rdisc_add_route      (NMRDisc *rdisc, const NMRDiscRoute *new);
gboolean nm_rdisc_add_dns_server (NMRDisc *rdisc, const NMRDiscDNSServer *new);
gboolean nm_rdisc_add_dns_domain (NMRDisc *rdisc, const NMRDiscDNSDomain *new);

/*********************************************************************************************/

#define _NMLOG_DOMAIN                     LOGD_IP6
#define _NMLOG(level, ...)                _LOG(level, _NMLOG_DOMAIN,  rdisc, __VA_ARGS__)

#define _LOG(level, domain, self, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            char __prefix[64]; \
            const char *__p_prefix = _NMLOG_PREFIX_NAME; \
            const NMRDisc *const __self = (self); \
            \
            if (__self) { \
                g_snprintf (__prefix, sizeof (__prefix), "%s[%p,%s%s%s]", \
                            _NMLOG_PREFIX_NAME, __self, \
                            NM_PRINT_FMT_QUOTE_STRING (__self->ifname)); \
                __p_prefix = __prefix; \
            } \
            _nm_log (__level, __domain, 0, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     __p_prefix _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*********************************************************************************************/

#endif /* __NETWORKMANAGER_RDISC_PRIVATE_H__ */
