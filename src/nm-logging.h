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

#ifndef __NETWORKMANAGER_LOGGING_H__
#define __NETWORKMANAGER_LOGGING_H__

#ifdef __NM_TEST_UTILS_H__
#error nm-test-utils.h must be included as last header
#endif

#include "nm-logging.h"

#include "nm-default.h"
#include "nm-macros-internal.h"

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
	LOGD_SUPPLICANT = (1LL << 16), /* WiFi and 802.1x */
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

	__LOGD_MAX,
	LOGD_ALL       = ((__LOGD_MAX - 1LL) << 1) - 1LL,
	LOGD_DEFAULT   = LOGD_ALL & ~(
	                              LOGD_DBUS_PROPS |
	                              LOGD_WIFI_SCAN |
	                              0),

	/* aliases: */
	LOGD_DHCP       = LOGD_DHCP4 | LOGD_DHCP6,
	LOGD_IP         = LOGD_IP4 | LOGD_IP6,
	LOGD_HW         = LOGD_PLATFORM,
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

	_LOGL_N, /* the number of logging levels including "OFF" */
} NMLogLevel;

#define nm_log_err(domain, ...)     nm_log (LOGL_ERR,   (domain), __VA_ARGS__)
#define nm_log_warn(domain, ...)    nm_log (LOGL_WARN,  (domain), __VA_ARGS__)
#define nm_log_info(domain, ...)    nm_log (LOGL_INFO,  (domain), __VA_ARGS__)
#define nm_log_dbg(domain, ...)     nm_log (LOGL_DEBUG, (domain), __VA_ARGS__)
#define nm_log_trace(domain, ...)   nm_log (LOGL_TRACE, (domain), __VA_ARGS__)

/* A wrapper for the _nm_log_impl() function that adds call site information.
 * Contrary to nm_log(), it unconditionally calls the function without
 * checking whether logging for the given level and domain is enabled. */
#define _nm_log(level, domain, error, ...) \
    G_STMT_START { \
        _nm_log_impl (__FILE__, __LINE__, G_STRFUNC, (level), (domain), (error), ""__VA_ARGS__); \
    } G_STMT_END

/* nm_log() only evaluates it's argument list after checking
 * whether logging for the given level/domain is enabled.  */
#define nm_log(level, domain, ...) \
    G_STMT_START { \
        if (nm_logging_enabled ((level), (domain))) { \
            _nm_log (level, domain, 0, __VA_ARGS__); \
        } \
    } G_STMT_END


#define _nm_log_ptr(level, domain, self, ...) \
   nm_log ((level), (domain), "[%p] " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), self _NM_UTILS_MACRO_REST(__VA_ARGS__))

/* log a message for an object (with providing a generic @self pointer) */
#define nm_log_ptr(level, domain, self, ...) \
    G_STMT_START { \
        NM_PRAGMA_WARNING_DISABLE("-Wtautological-compare") \
        if ((level) <= LOGL_DEBUG) { \
            _nm_log_ptr ((level), (domain), (self), __VA_ARGS__); \
        } else { \
            nm_log ((level), (domain), __VA_ARGS__); \
        } \
        NM_PRAGMA_WARNING_REENABLE \
    } G_STMT_END


#define _nm_log_obj(level, domain, self, ...) \
    _nm_log_ptr ((level), (domain), (self), __VA_ARGS__)

/* log a message for an object (with providing a @self pointer to a GObject).
 * Contrary to nm_log_ptr(), @self must be a GObject type (or %NULL).
 * As of now, nm_log_obj() is identical to nm_log_ptr(), but we might change that */
#define nm_log_obj(level, domain, self, ...) \
    nm_log_ptr ((level), (domain), (self), __VA_ARGS__)


void _nm_log_impl (const char *file,
                   guint line,
                   const char *func,
                   NMLogLevel level,
                   NMLogDomain domain,
                   int error,
                   const char *fmt,
                   ...) __attribute__((__format__ (__printf__, 7, 8)));

const char *nm_logging_level_to_string (void);
const char *nm_logging_domains_to_string (void);
gboolean nm_logging_enabled (NMLogLevel level, NMLogDomain domain);

const char *nm_logging_all_levels_to_string (void);
const char *nm_logging_all_domains_to_string (void);

gboolean nm_logging_setup (const char  *level,
                           const char  *domains,
                           char       **bad_domains,
                           GError     **error);
void     nm_logging_syslog_openlog (const char *logging_backend);

/*****************************************************************************/

/* This is the default definition of _NMLOG_ENABLED(). Special implementations
 * might want to undef this and redefine it. */
#define _NMLOG_ENABLED(level) ( nm_logging_enabled ((level), (_NMLOG_DOMAIN)) )

#define _LOGt(...)          _NMLOG (LOGL_TRACE, __VA_ARGS__)
#define _LOGD(...)          _NMLOG (LOGL_DEBUG, __VA_ARGS__)
#define _LOGI(...)          _NMLOG (LOGL_INFO , __VA_ARGS__)
#define _LOGW(...)          _NMLOG (LOGL_WARN , __VA_ARGS__)
#define _LOGE(...)          _NMLOG (LOGL_ERR  , __VA_ARGS__)

#define _LOGt_ENABLED(...)  _NMLOG_ENABLED (LOGL_TRACE, ##__VA_ARGS__)
#define _LOGD_ENABLED(...)  _NMLOG_ENABLED (LOGL_DEBUG, ##__VA_ARGS__)
#define _LOGI_ENABLED(...)  _NMLOG_ENABLED (LOGL_INFO , ##__VA_ARGS__)
#define _LOGW_ENABLED(...)  _NMLOG_ENABLED (LOGL_WARN , ##__VA_ARGS__)
#define _LOGE_ENABLED(...)  _NMLOG_ENABLED (LOGL_ERR  , ##__VA_ARGS__)

/* _LOGt() and _LOGT() both log with level TRACE, but the latter is disabled by default,
 * unless building with --with-more-logging. */
#ifdef NM_MORE_LOGGING
#define _LOGT_ENABLED(...)  _NMLOG_ENABLED (LOGL_TRACE, ##__VA_ARGS__)
#define _LOGT(...)          _NMLOG (LOGL_TRACE, __VA_ARGS__)
#else
/* still call the logging macros to get compile time checks, but they will be optimized out. */
#define _LOGT_ENABLED(...)  ( FALSE && (_NMLOG_ENABLED (LOGL_TRACE, ##__VA_ARGS__)) )
#define _LOGT(...)          G_STMT_START { if (FALSE) { _NMLOG (LOGL_TRACE, __VA_ARGS__); } } G_STMT_END
#endif

/*****************************************************************************/

/* Some implementation define a second set of logging macros, for a separate
 * use. As with the _LOGD() macro familiy above, the exact implementation
 * depends on the file that uses them.
 * Still, it encourages a common pattern to have the common set of macros
 * like _LOG2D(), _LOG2I(), etc. and have _LOG2T() which by default
 * is disabled at compile time. */

#define _NMLOG2_ENABLED(level) ( nm_logging_enabled ((level), (_NMLOG2_DOMAIN)) )

#define _LOG2t(...)          _NMLOG2 (LOGL_TRACE, __VA_ARGS__)
#define _LOG2D(...)          _NMLOG2 (LOGL_DEBUG, __VA_ARGS__)
#define _LOG2I(...)          _NMLOG2 (LOGL_INFO , __VA_ARGS__)
#define _LOG2W(...)          _NMLOG2 (LOGL_WARN , __VA_ARGS__)
#define _LOG2E(...)          _NMLOG2 (LOGL_ERR  , __VA_ARGS__)

#define _LOG2t_ENABLED(...)  _NMLOG2_ENABLED (LOGL_TRACE, ##__VA_ARGS__)
#define _LOG2D_ENABLED(...)  _NMLOG2_ENABLED (LOGL_DEBUG, ##__VA_ARGS__)
#define _LOG2I_ENABLED(...)  _NMLOG2_ENABLED (LOGL_INFO , ##__VA_ARGS__)
#define _LOG2W_ENABLED(...)  _NMLOG2_ENABLED (LOGL_WARN , ##__VA_ARGS__)
#define _LOG2E_ENABLED(...)  _NMLOG2_ENABLED (LOGL_ERR  , ##__VA_ARGS__)

#ifdef NM_MORE_LOGGING
#define _LOG2T_ENABLED(...)  _NMLOG2_ENABLED (LOGL_TRACE, ##__VA_ARGS__)
#define _LOG2T(...)          _NMLOG2 (LOGL_TRACE, __VA_ARGS__)
#else
/* still call the logging macros to get compile time checks, but they will be optimized out. */
#define _LOG2T_ENABLED(...)  ( FALSE && (_NMLOG2_ENABLED (LOGL_TRACE, ##__VA_ARGS__)) )
#define _LOG2T(...)          G_STMT_START { if (FALSE) { _NMLOG2 (LOGL_TRACE, __VA_ARGS__); } } G_STMT_END
#endif

/*****************************************************************************/

#endif /* __NETWORKMANAGER_LOGGING_H__ */
