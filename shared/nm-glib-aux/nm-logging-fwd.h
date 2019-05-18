/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2006 - 2018 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NM_LOGGING_DEFINES_H__
#define __NM_LOGGING_DEFINES_H__

/* Log domains */

typedef enum  { /*< skip >*/
	LOGD_NONE       = 0LL,
	LOGD_PLATFORM   = (1LL << 0), /* Platform services */
	LOGD_RFKILL     = (1LL << 1),
	LOGD_ETHER      = (1LL << 2),
	LOGD_WIFI       = (1LL << 3),
	LOGD_BT         = (1LL << 4),
	LOGD_MB         = (1LL << 5), /* mobile broadband */
	LOGD_DHCP4      = (1LL << 6),
	LOGD_DHCP6      = (1LL << 7),
	LOGD_PPP        = (1LL << 8),
	LOGD_WIFI_SCAN  = (1LL << 9),
	LOGD_IP4        = (1LL << 10),
	LOGD_IP6        = (1LL << 11),
	LOGD_AUTOIP4    = (1LL << 12),
	LOGD_DNS        = (1LL << 13),
	LOGD_VPN        = (1LL << 14),
	LOGD_SHARING    = (1LL << 15), /* Connection sharing/dnsmasq */
	LOGD_SUPPLICANT = (1LL << 16), /* Wi-Fi and 802.1x */
	LOGD_AGENTS     = (1LL << 17), /* Secret agents */
	LOGD_SETTINGS   = (1LL << 18), /* Settings */
	LOGD_SUSPEND    = (1LL << 19), /* Suspend/Resume */
	LOGD_CORE       = (1LL << 20), /* Core daemon and policy stuff */
	LOGD_DEVICE     = (1LL << 21), /* Device state and activation */
	LOGD_OLPC       = (1LL << 22),
	LOGD_INFINIBAND = (1LL << 23),
	LOGD_FIREWALL   = (1LL << 24),
	LOGD_ADSL       = (1LL << 25),
	LOGD_BOND       = (1LL << 26),
	LOGD_VLAN       = (1LL << 27),
	LOGD_BRIDGE     = (1LL << 28),
	LOGD_DBUS_PROPS = (1LL << 29),
	LOGD_TEAM       = (1LL << 30),
	LOGD_CONCHECK   = (1LL << 31),
	LOGD_DCB        = (1LL << 32), /* Data Center Bridging */
	LOGD_DISPATCH   = (1LL << 33),
	LOGD_AUDIT      = (1LL << 34),
	LOGD_SYSTEMD    = (1LL << 35),
	LOGD_VPN_PLUGIN = (1LL << 36),
	LOGD_PROXY      = (1LL << 37),

	__LOGD_MAX,
	LOGD_ALL       = (((__LOGD_MAX - 1LL) << 1) - 1LL),
	LOGD_DEFAULT   = LOGD_ALL & ~(
	                              LOGD_DBUS_PROPS |
	                              LOGD_WIFI_SCAN |
	                              LOGD_VPN_PLUGIN |
	                              0),

	/* aliases: */
	LOGD_DHCP       = LOGD_DHCP4 | LOGD_DHCP6,
	LOGD_IP         = LOGD_IP4 | LOGD_IP6,
} NMLogDomain;

/* Log levels */
typedef enum  { /*< skip >*/
	LOGL_TRACE,
	LOGL_DEBUG,
	LOGL_INFO,
	LOGL_WARN,
	LOGL_ERR,

	_LOGL_N_REAL, /* the number of actual logging levels */

	_LOGL_OFF = _LOGL_N_REAL, /* special logging level that is always disabled. */
	_LOGL_KEEP,               /* special logging level to indicate that the logging level should not be changed. */

	_LOGL_N, /* the number of logging levels including "OFF" */
} NMLogLevel;

gboolean _nm_log_enabled_impl (gboolean mt_require_locking,
                               NMLogLevel level,
                               NMLogDomain domain);

void _nm_log_impl (const char *file,
                   guint line,
                   const char *func,
                   gboolean mt_require_locking,
                   NMLogLevel level,
                   NMLogDomain domain,
                   int error,
                   const char *ifname,
                   const char *con_uuid,
                   const char *fmt,
                   ...) _nm_printf (10, 11);

static inline NMLogLevel
nm_log_level_from_syslog (int syslog_level)
{
	switch (syslog_level) {
	case 0 /* LOG_EMERG */   : return LOGL_ERR;
	case 1 /* LOG_ALERT */   : return LOGL_ERR;
	case 2 /* LOG_CRIT */    : return LOGL_ERR;
	case 3 /* LOG_ERR */     : return LOGL_ERR;
	case 4 /* LOG_WARNING */ : return LOGL_WARN;
	case 5 /* LOG_NOTICE */  : return LOGL_INFO;
	case 6 /* LOG_INFO */    : return LOGL_DEBUG;
	case 7 /* LOG_DEBUG */   : return LOGL_TRACE;
	default:
		return syslog_level >= 0 ? LOGL_TRACE : LOGL_ERR;
	}
}

/*****************************************************************************/

struct timespec;

/* this function must be implemented to handle the notification when
 * the first monotonic-timestamp is fetched. */
extern void _nm_utils_monotonic_timestamp_initialized (const struct timespec *tp,
                                                       gint64 offset_sec,
                                                       gboolean is_boottime);

#endif /* __NM_LOGGING_DEFINES_H__ */
