// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_CLIENT_LOGGING_H__
#define __NETWORKMANAGER_DHCP_CLIENT_LOGGING_H__

#include "nm-dhcp-client.h"

static inline NMLogDomain
_nm_dhcp_client_get_domain (NMDhcpClient *self)
{
	if (self) {
		switch (nm_dhcp_client_get_addr_family (self)) {
		case AF_INET:
			return LOGD_DHCP4;
		case AF_INET6:
			return LOGD_DHCP6;
		default:
			nm_assert_not_reached ();
			break;
		}
	}
	return LOGD_DHCP;
}

#define _NMLOG_PREFIX_NAME    "dhcp"
#define _NMLOG_DOMAIN         LOGD_DHCP
#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel _level = (level); \
        \
        /* we check first for LOGD_DHCP instead of the correct domain.
         * In the worst case, we guess wrong and enter the block.
         *
         * Same for the _NMLOG_ENABLED() macro. Probably it would be more
         * expensive to determine the correct value then what we could
         * safe. */ \
        if (nm_logging_enabled (_level, _NMLOG_DOMAIN)) { \
            NMDhcpClient *_self = (NMDhcpClient *) (self); \
            const char *__ifname = _self ? nm_dhcp_client_get_iface (_self) : NULL; \
            const NMLogDomain _domain = _nm_dhcp_client_get_domain (_self); \
            \
            nm_log (_level, _domain, __ifname, NULL, \
                    "%s%s%s%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                    _NMLOG_PREFIX_NAME, \
                    (_domain == LOGD_DHCP4 ? "4" : (_domain == LOGD_DHCP6 ? "6" : "")), \
                    NM_PRINT_FMT_QUOTED (__ifname, " (", __ifname, ")", "") \
                    _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

#define _NMLOG2(level, domain, ifname, ...) \
    G_STMT_START { \
        const NMLogLevel _level = (level); \
        const NMLogDomain _domain = (domain); \
        \
        /* we check first for LOGD_DHCP instead of the correct domain.
         * In the worst case, we guess wrong and enter the block.
         *
         * Same for the _NMLOG_ENABLED() macro. Probably it would be more
         * expensive to determine the correct value then what we could
         * safe. */ \
        if (nm_logging_enabled (_level, _domain)) { \
            const char *__ifname = (ifname); \
            \
            nm_log (_level, _domain, __ifname, NULL, \
                    "%s%s%s%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                    _NMLOG_PREFIX_NAME, \
                    (_domain == LOGD_DHCP4 ? "4" : (_domain == LOGD_DHCP6 ? "6" : "")), \
                    NM_PRINT_FMT_QUOTED (__ifname, " (", __ifname, ")", "") \
                    _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

#endif /* __NETWORKMANAGER_DHCP_CLIENT_LOGGING_H__ */
