// SPDX-License-Identifier: LGPL-2.1+
/*
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

static inline int
nm_log_level_to_syslog (NMLogLevel nm_level)
{
	switch (nm_level) {
	case LOGL_ERR:    return 3; /* LOG_ERR */
	case LOGL_WARN:   return 4; /* LOG_WARN */
	case LOGL_INFO:   return 5; /* LOG_NOTICE */
	case LOGL_DEBUG:  return 6; /* LOG_INFO */
	case LOGL_TRACE:  return 7; /* LOG_DEBUG */
	default:          return 0; /* LOG_EMERG */
	}
}

/*****************************************************************************/

struct timespec;

/* this function must be implemented to handle the notification when
 * the first monotonic-timestamp is fetched. */
extern void _nm_utils_monotonic_timestamp_initialized (const struct timespec *tp,
                                                       gint64 offset_sec,
                                                       gboolean is_boottime);

/*****************************************************************************/

/* This is the default definition of _NMLOG_ENABLED(). Special implementations
 * might want to undef this and redefine it. */
#define _NMLOG_ENABLED(level) ( nm_logging_enabled ((level), (_NMLOG_DOMAIN)) )

#define _LOGT(...)          _NMLOG (LOGL_TRACE, __VA_ARGS__)
#define _LOGD(...)          _NMLOG (LOGL_DEBUG, __VA_ARGS__)
#define _LOGI(...)          _NMLOG (LOGL_INFO , __VA_ARGS__)
#define _LOGW(...)          _NMLOG (LOGL_WARN , __VA_ARGS__)
#define _LOGE(...)          _NMLOG (LOGL_ERR  , __VA_ARGS__)

#define _LOGT_ENABLED(...)  _NMLOG_ENABLED (LOGL_TRACE, ##__VA_ARGS__)
#define _LOGD_ENABLED(...)  _NMLOG_ENABLED (LOGL_DEBUG, ##__VA_ARGS__)
#define _LOGI_ENABLED(...)  _NMLOG_ENABLED (LOGL_INFO , ##__VA_ARGS__)
#define _LOGW_ENABLED(...)  _NMLOG_ENABLED (LOGL_WARN , ##__VA_ARGS__)
#define _LOGE_ENABLED(...)  _NMLOG_ENABLED (LOGL_ERR  , ##__VA_ARGS__)

#define _LOGT_err(errsv, ...) _NMLOG_err (errsv, LOGL_TRACE, __VA_ARGS__)
#define _LOGD_err(errsv, ...) _NMLOG_err (errsv, LOGL_DEBUG, __VA_ARGS__)
#define _LOGI_err(errsv, ...) _NMLOG_err (errsv, LOGL_INFO , __VA_ARGS__)
#define _LOGW_err(errsv, ...) _NMLOG_err (errsv, LOGL_WARN , __VA_ARGS__)
#define _LOGE_err(errsv, ...) _NMLOG_err (errsv, LOGL_ERR  , __VA_ARGS__)

/* _LOGT() and _LOGt() both log with level TRACE, but the latter is disabled by default,
 * unless building with --with-more-logging. */
#if NM_MORE_LOGGING
#define _LOGt_ENABLED(...)    _NMLOG_ENABLED (LOGL_TRACE, ##__VA_ARGS__)
#define _LOGt(...)            _NMLOG (LOGL_TRACE, __VA_ARGS__)
#define _LOGt_err(errsv, ...) _NMLOG_err (errsv, LOGL_TRACE, __VA_ARGS__)
#else
/* still call the logging macros to get compile time checks, but they will be optimized out. */
#define _LOGt_ENABLED(...)    ( FALSE && (_NMLOG_ENABLED (LOGL_TRACE, ##__VA_ARGS__)) )
#define _LOGt(...)            G_STMT_START { if (FALSE) { _NMLOG (LOGL_TRACE, __VA_ARGS__); } } G_STMT_END
#define _LOGt_err(errsv, ...) G_STMT_START { if (FALSE) { _NMLOG_err (errsv, LOGL_TRACE, __VA_ARGS__); } } G_STMT_END
#endif

/*****************************************************************************/

/* Some implementation define a second set of logging macros, for a separate
 * use. As with the _LOGD() macro family above, the exact implementation
 * depends on the file that uses them.
 * Still, it encourages a common pattern to have the common set of macros
 * like _LOG2D(), _LOG2I(), etc. and have _LOG2t() which by default
 * is disabled at compile time. */

#define _NMLOG2_ENABLED(level) ( nm_logging_enabled ((level), (_NMLOG2_DOMAIN)) )

#define _LOG2T(...)          _NMLOG2 (LOGL_TRACE, __VA_ARGS__)
#define _LOG2D(...)          _NMLOG2 (LOGL_DEBUG, __VA_ARGS__)
#define _LOG2I(...)          _NMLOG2 (LOGL_INFO , __VA_ARGS__)
#define _LOG2W(...)          _NMLOG2 (LOGL_WARN , __VA_ARGS__)
#define _LOG2E(...)          _NMLOG2 (LOGL_ERR  , __VA_ARGS__)

#define _LOG2T_ENABLED(...)  _NMLOG2_ENABLED (LOGL_TRACE, ##__VA_ARGS__)
#define _LOG2D_ENABLED(...)  _NMLOG2_ENABLED (LOGL_DEBUG, ##__VA_ARGS__)
#define _LOG2I_ENABLED(...)  _NMLOG2_ENABLED (LOGL_INFO , ##__VA_ARGS__)
#define _LOG2W_ENABLED(...)  _NMLOG2_ENABLED (LOGL_WARN , ##__VA_ARGS__)
#define _LOG2E_ENABLED(...)  _NMLOG2_ENABLED (LOGL_ERR  , ##__VA_ARGS__)

#define _LOG2T_err(errsv, ...) _NMLOG2_err (errsv, LOGL_TRACE, __VA_ARGS__)
#define _LOG2D_err(errsv, ...) _NMLOG2_err (errsv, LOGL_DEBUG, __VA_ARGS__)
#define _LOG2I_err(errsv, ...) _NMLOG2_err (errsv, LOGL_INFO , __VA_ARGS__)
#define _LOG2W_err(errsv, ...) _NMLOG2_err (errsv, LOGL_WARN , __VA_ARGS__)
#define _LOG2E_err(errsv, ...) _NMLOG2_err (errsv, LOGL_ERR  , __VA_ARGS__)

#if NM_MORE_LOGGING
#define _LOG2t_ENABLED(...)    _NMLOG2_ENABLED (LOGL_TRACE, ##__VA_ARGS__)
#define _LOG2t(...)            _NMLOG2 (LOGL_TRACE, __VA_ARGS__)
#define _LOG2t_err(errsv, ...) _NMLOG2_err (errsv, LOGL_TRACE, __VA_ARGS__)
#else
/* still call the logging macros to get compile time checks, but they will be optimized out. */
#define _LOG2t_ENABLED(...)    ( FALSE && (_NMLOG2_ENABLED (LOGL_TRACE, ##__VA_ARGS__)) )
#define _LOG2t(...)            G_STMT_START { if (FALSE) { _NMLOG2 (LOGL_TRACE, __VA_ARGS__); } } G_STMT_END
#define _LOG2t_err(errsv, ...) G_STMT_START { if (FALSE) { _NMLOG2_err (errsv, LOGL_TRACE, __VA_ARGS__); } } G_STMT_END
#endif

#define _NMLOG3_ENABLED(level) ( nm_logging_enabled ((level), (_NMLOG3_DOMAIN)) )

#define _LOG3T(...)          _NMLOG3 (LOGL_TRACE, __VA_ARGS__)
#define _LOG3D(...)          _NMLOG3 (LOGL_DEBUG, __VA_ARGS__)
#define _LOG3I(...)          _NMLOG3 (LOGL_INFO , __VA_ARGS__)
#define _LOG3W(...)          _NMLOG3 (LOGL_WARN , __VA_ARGS__)
#define _LOG3E(...)          _NMLOG3 (LOGL_ERR  , __VA_ARGS__)

#define _LOG3T_ENABLED(...)  _NMLOG3_ENABLED (LOGL_TRACE, ##__VA_ARGS__)
#define _LOG3D_ENABLED(...)  _NMLOG3_ENABLED (LOGL_DEBUG, ##__VA_ARGS__)
#define _LOG3I_ENABLED(...)  _NMLOG3_ENABLED (LOGL_INFO , ##__VA_ARGS__)
#define _LOG3W_ENABLED(...)  _NMLOG3_ENABLED (LOGL_WARN , ##__VA_ARGS__)
#define _LOG3E_ENABLED(...)  _NMLOG3_ENABLED (LOGL_ERR  , ##__VA_ARGS__)

#define _LOG3T_err(errsv, ...) _NMLOG3_err (errsv, LOGL_TRACE, __VA_ARGS__)
#define _LOG3D_err(errsv, ...) _NMLOG3_err (errsv, LOGL_DEBUG, __VA_ARGS__)
#define _LOG3I_err(errsv, ...) _NMLOG3_err (errsv, LOGL_INFO , __VA_ARGS__)
#define _LOG3W_err(errsv, ...) _NMLOG3_err (errsv, LOGL_WARN , __VA_ARGS__)
#define _LOG3E_err(errsv, ...) _NMLOG3_err (errsv, LOGL_ERR  , __VA_ARGS__)

#if NM_MORE_LOGGING
#define _LOG3t_ENABLED(...)    _NMLOG3_ENABLED (LOGL_TRACE, ##__VA_ARGS__)
#define _LOG3t(...)            _NMLOG3 (LOGL_TRACE, __VA_ARGS__)
#define _LOG3t_err(errsv, ...) _NMLOG3_err (errsv, LOGL_TRACE, __VA_ARGS__)
#else
/* still call the logging macros to get compile time checks, but they will be optimized out. */
#define _LOG3t_ENABLED(...)    ( FALSE && (_NMLOG3_ENABLED (LOGL_TRACE, ##__VA_ARGS__)) )
#define _LOG3t(...)            G_STMT_START { if (FALSE) { _NMLOG3 (LOGL_TRACE, __VA_ARGS__); } } G_STMT_END
#define _LOG3t_err(errsv, ...) G_STMT_START { if (FALSE) { _NMLOG3_err (errsv, LOGL_TRACE, __VA_ARGS__); } } G_STMT_END
#endif

/*****************************************************************************/

#endif /* __NM_LOGGING_DEFINES_H__ */
