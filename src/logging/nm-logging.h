/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2006 - 2012 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef NM_LOGGING_H
#define NM_LOGGING_H

#ifdef __NM_TEST_UTILS_H__
#error nm-test-utils.h must be included as last header
#endif

#include <glib.h>
#include <glib-object.h>

/* Log domains */
enum {
	LOGD_NONE       = 0LL,
	LOGD_PLATFORM   = (1LL << 1), /* Platform services */
	LOGD_RFKILL     = (1LL << 2),
	LOGD_ETHER      = (1LL << 3),
	LOGD_WIFI       = (1LL << 4),
	LOGD_BT         = (1LL << 5),
	LOGD_MB         = (1LL << 6), /* mobile broadband */
	LOGD_DHCP4      = (1LL << 7),
	LOGD_DHCP6      = (1LL << 8),
	LOGD_PPP        = (1LL << 9),
	LOGD_WIFI_SCAN  = (1LL << 10),
	LOGD_IP4        = (1LL << 11),
	LOGD_IP6        = (1LL << 12),
	LOGD_AUTOIP4    = (1LL << 13),
	LOGD_DNS        = (1LL << 14),
	LOGD_VPN        = (1LL << 15),
	LOGD_SHARING    = (1LL << 16), /* Connection sharing/dnsmasq */
	LOGD_SUPPLICANT = (1LL << 17), /* WiFi and 802.1x */
	LOGD_AGENTS     = (1LL << 18), /* Secret agents */
	LOGD_SETTINGS   = (1LL << 19), /* Settings */
	LOGD_SUSPEND    = (1LL << 20), /* Suspend/Resume */
	LOGD_CORE       = (1LL << 21), /* Core daemon and policy stuff */
	LOGD_DEVICE     = (1LL << 22), /* Device state and activation */
	LOGD_OLPC       = (1LL << 23),
	LOGD_WIMAX      = (1LL << 24),
	LOGD_INFINIBAND = (1LL << 25),
	LOGD_FIREWALL   = (1LL << 26),
	LOGD_ADSL       = (1LL << 27),
	LOGD_BOND       = (1LL << 28),
	LOGD_VLAN       = (1LL << 29),
	LOGD_BRIDGE     = (1LL << 30),
	LOGD_DBUS_PROPS = (1LL << 31),
	LOGD_TEAM       = (1LL << 32),
	LOGD_CONCHECK   = (1LL << 33),
	LOGD_DCB        = (1LL << 34), /* Data Center Bridging */
	LOGD_DISPATCH   = (1LL << 35),
};

#define LOGD_DHCP (LOGD_DHCP4 | LOGD_DHCP6)
#define LOGD_IP   (LOGD_IP4 | LOGD_IP6)
#define LOGD_HW LOGD_PLATFORM

/* Log levels */
enum {
	LOGL_DEBUG,
	LOGL_INFO,
	LOGL_WARN,
	LOGL_ERR,

	LOGL_MAX
};

typedef enum {
	NM_LOGGING_ERROR_UNKNOWN_LEVEL = 0,  /*< nick=UnknownLevel >*/
	NM_LOGGING_ERROR_UNKNOWN_DOMAIN = 1, /*< nick=UnknownDomain >*/
} NMLoggingError;

#define NM_LOGGING_ERROR (nm_logging_error_quark ())
GQuark nm_logging_error_quark    (void);


#define nm_log_err(domain, ...) \
	_nm_log (G_STRLOC, G_STRFUNC, domain, LOGL_ERR, ## __VA_ARGS__ )

#define nm_log_warn(domain, ...) \
	_nm_log (G_STRLOC, G_STRFUNC, domain, LOGL_WARN, ## __VA_ARGS__ )

#define nm_log_info(domain, ...) \
	_nm_log (G_STRLOC, G_STRFUNC, domain, LOGL_INFO, ## __VA_ARGS__ )

#define nm_log_dbg(domain, ...) \
	_nm_log (G_STRLOC, G_STRFUNC, domain, LOGL_DEBUG, ## __VA_ARGS__ )

#define nm_log(domain, level, ...) \
	_nm_log (G_STRLOC, G_STRFUNC, domain, level, ## __VA_ARGS__ )

void _nm_log (const char *loc,
              const char *func,
              guint64 domain,
              guint32 level,
              const char *fmt,
              ...) __attribute__((__format__ (__printf__, 5, 6)));

char *nm_logging_level_to_string (void);
char *nm_logging_domains_to_string (void);
gboolean nm_logging_enabled (guint32 level, guint64 domain);

const char *nm_logging_all_levels_to_string (void);
const char *nm_logging_all_domains_to_string (void);

/* Undefine the nm-utils.h logging stuff to ensure errors */
#undef nm_get_timestamp
#undef nm_info
#undef nm_info_str
#undef nm_debug
#undef nm_debug_str
#undef nm_warning
#undef nm_warning_str
#undef nm_error
#undef nm_error_str

gboolean nm_logging_setup (const char  *level,
                           const char  *domains,
                           char       **bad_domains,
                           GError     **error);
void     nm_logging_syslog_openlog   (gboolean debug);
void     nm_logging_syslog_closelog  (void);

#endif /* NM_LOGGING_H */
