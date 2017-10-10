/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-ndisc.h - Perform IPv6 neighbor discovery
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

#ifndef __NETWORKMANAGER_NDISC_PRIVATE_H__
#define __NETWORKMANAGER_NDISC_PRIVATE_H__

#include "nm-ndisc.h"

/* Functions only used by ndisc implementations */

struct _NMNDiscDataInternal {
	NMNDiscData public;
	GArray *gateways;
	GArray *addresses;
	GArray *routes;
	GArray *dns_servers;
	GArray *dns_domains;
};

typedef struct _NMNDiscDataInternal NMNDiscDataInternal;

void nm_ndisc_ra_received (NMNDisc *ndisc, gint32 now, NMNDiscConfigMap changed);
void nm_ndisc_rs_received (NMNDisc *ndisc);

gboolean nm_ndisc_add_gateway              (NMNDisc *ndisc, const NMNDiscGateway *new);
gboolean nm_ndisc_complete_and_add_address (NMNDisc *ndisc, NMNDiscAddress *new);
gboolean nm_ndisc_add_route                (NMNDisc *ndisc, const NMNDiscRoute *new);
gboolean nm_ndisc_add_dns_server           (NMNDisc *ndisc, const NMNDiscDNSServer *new);
gboolean nm_ndisc_add_dns_domain           (NMNDisc *ndisc, const NMNDiscDNSDomain *new);

/*****************************************************************************/

#define _NMLOG_DOMAIN                     LOGD_IP6
#define _NMLOG(level, ...)                _LOG(level, _NMLOG_DOMAIN,  ndisc, __VA_ARGS__)

#define _LOG(level, domain, self, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            NMNDisc *const __self = (self); \
            char __prefix[64]; \
            const char *__ifname = __self ? nm_ndisc_get_ifname (__self) : NULL; \
            \
            _nm_log (__level, __domain, 0, __ifname, NULL, \
                     "%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     (__self \
                        ?  nm_sprintf_buf (__prefix, "%s[%p,%s%s%s]", \
                                           _NMLOG_PREFIX_NAME, __self, \
                                           NM_PRINT_FMT_QUOTE_STRING (__ifname)) \
                        : _NMLOG_PREFIX_NAME) \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

#endif /* __NETWORKMANAGER_NDISC_PRIVATE_H__ */
