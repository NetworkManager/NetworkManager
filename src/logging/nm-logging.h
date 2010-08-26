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
 * Copyright (C) 2006 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef NM_LOGGING_H
#define NM_LOGGING_H

#include <glib.h>
#include <glib-object.h>

/* Log domains */
enum {
	LOGD_NONE       = 0x00000000,
	LOGD_HW         = 0x00000001, /* Hardware detection and info */
	LOGD_RFKILL     = 0x00000002,
	LOGD_ETHER      = 0x00000004,
	LOGD_WIFI       = 0x00000008,
	LOGD_BT         = 0x00000010,
	LOGD_MB         = 0x00000020, /* mobile broadband */
	LOGD_DHCP4      = 0x00000040,
	LOGD_DHCP6      = 0x00000080,
	LOGD_PPP        = 0x00000100,
	LOGD_WIFI_SCAN  = 0x00000200,
	LOGD_IP4        = 0x00000400,
	LOGD_IP6        = 0x00000800,
	LOGD_AUTOIP4    = 0x00001000,
	LOGD_DNS        = 0x00002000,
	LOGD_VPN        = 0x00004000,
	LOGD_SHARING    = 0x00008000, /* Connection sharing/dnsmasq */
	LOGD_SUPPLICANT = 0x00010000, /* WiFi and 802.1x */
	LOGD_USER_SET   = 0x00020000, /* User settings */
	LOGD_SYS_SET    = 0x00040000, /* System settings */
	LOGD_SUSPEND    = 0x00080000, /* Suspend/Resume */
	LOGD_CORE       = 0x00100000, /* Core daemon and policy stuff */
	LOGD_DEVICE     = 0x00200000, /* Device state and activation */
	LOGD_OLPC_MESH  = 0x00400000,
};

#define LOGD_DHCP (LOGD_DHCP4 | LOGD_DHCP6)

/* Log levels */
enum {
	LOGL_ERR   = 0x00000001,
	LOGL_WARN  = 0x00000002,
	LOGL_INFO  = 0x00000004,
	LOGL_DEBUG = 0x00000008
};

#define NM_LOGGING_ERROR (nm_logging_error_quark ())
#define NM_TYPE_LOGGING_ERROR (nm_logging_error_get_type ())
GQuark nm_logging_error_quark    (void);
GType  nm_logging_error_get_type (void);


#define nm_log_err(domain, fmt, args...) \
	{ _nm_log (G_STRLOC, G_STRFUNC, domain, LOGL_ERR, fmt, ##args); }

#define nm_log_warn(domain, fmt, args...) \
	{ _nm_log (G_STRLOC, G_STRFUNC, domain, LOGL_WARN, fmt, ##args); }

#define nm_log_info(domain, fmt, args...) \
	{ _nm_log (G_STRLOC, G_STRFUNC, domain, LOGL_INFO, fmt, ##args); }

#define nm_log_dbg(domain, fmt, args...) \
	{ _nm_log (G_STRLOC, G_STRFUNC, domain, LOGL_DEBUG, fmt, ##args); }

#define nm_log(domain, level, fmt, args...) \
	{ _nm_log (G_STRLOC, G_STRFUNC, domain, level, fmt, ##args); }

void _nm_log (const char *loc, const char *func,
              guint32 domain, guint32 level,
              const char *fmt, ...);

const char *nm_logging_level_to_string (void);
char *nm_logging_domains_to_string (void);
gboolean nm_logging_level_enabled (guint32 level);

/* Undefine the nm-utils.h logging stuff to ensure errors */
#undef nm_print_backtrace
#undef nm_get_timestamp
#undef nm_info
#undef nm_info_str
#undef nm_debug
#undef nm_debug_str
#undef nm_warning
#undef nm_warning_str
#undef nm_error
#undef nm_error_str

gboolean nm_logging_setup     (const char *level, const char *domains, GError **error);
void     nm_logging_start     (gboolean become_daemon);
void     nm_logging_backtrace (void);
void     nm_logging_shutdown  (void);

#endif /* NM_LOGGING_H */
