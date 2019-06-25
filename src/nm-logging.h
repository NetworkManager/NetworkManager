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

#include "nm-glib-aux/nm-logging-fwd.h"

#define NM_LOG_CONFIG_BACKEND_DEBUG   "debug"
#define NM_LOG_CONFIG_BACKEND_SYSLOG  "syslog"
#define NM_LOG_CONFIG_BACKEND_JOURNAL "journal"

static inline NMLogDomain
LOGD_IP_from_af (int addr_family)
{
	switch (addr_family) {
	case AF_INET:  return LOGD_IP4;
	case AF_INET6: return LOGD_IP6;
	}
	g_return_val_if_reached (LOGD_NONE);
}

#define nm_log_err(domain, ...)     nm_log (LOGL_ERR,   (domain),  NULL, NULL, __VA_ARGS__)
#define nm_log_warn(domain, ...)    nm_log (LOGL_WARN,  (domain),  NULL, NULL, __VA_ARGS__)
#define nm_log_info(domain, ...)    nm_log (LOGL_INFO,  (domain),  NULL, NULL, __VA_ARGS__)
#define nm_log_dbg(domain, ...)     nm_log (LOGL_DEBUG, (domain),  NULL, NULL, __VA_ARGS__)
#define nm_log_trace(domain, ...)   nm_log (LOGL_TRACE, (domain),  NULL, NULL, __VA_ARGS__)

//#define _NM_LOG_FUNC G_STRFUNC
#define _NM_LOG_FUNC NULL

/* A wrapper for the _nm_log_impl() function that adds call site information.
 * Contrary to nm_log(), it unconditionally calls the function without
 * checking whether logging for the given level and domain is enabled. */
#define _nm_log_mt(mt_require_locking, level, domain, error, ifname, con_uuid, ...) \
    G_STMT_START { \
        _nm_log_impl (__FILE__, \
                      __LINE__, \
                      _NM_LOG_FUNC, \
                      (mt_require_locking), \
                      (level), \
                      (domain), \
                      (error), \
                      (ifname), \
                      (con_uuid), \
                      ""__VA_ARGS__); \
    } G_STMT_END

#define _nm_log(level, domain, error, ifname, con_uuid, ...) \
	_nm_log_mt (!(NM_THREAD_SAFE_ON_MAIN_THREAD), level, domain, error, ifname, con_uuid, __VA_ARGS__)

/* nm_log() only evaluates its argument list after checking
 * whether logging for the given level/domain is enabled.  */
#define nm_log(level, domain, ifname, con_uuid, ...) \
    G_STMT_START { \
        if (nm_logging_enabled ((level), (domain))) { \
            _nm_log (level, domain, 0, ifname, con_uuid, __VA_ARGS__); \
        } \
    } G_STMT_END

#define _nm_log_ptr(level, domain, ifname, con_uuid, self, prefix, ...) \
   nm_log ((level), \
           (domain), \
           (ifname), \
           (con_uuid), \
           "%s[%p] " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
           (prefix) ?: "", \
           self _NM_UTILS_MACRO_REST(__VA_ARGS__))

static inline gboolean
_nm_log_ptr_is_debug (NMLogLevel level)
{
	return level <= LOGL_DEBUG;
}

/* log a message for an object (with providing a generic @self pointer) */
#define nm_log_ptr(level, domain, ifname, con_uuid, self, prefix, ...) \
    G_STMT_START { \
        if (_nm_log_ptr_is_debug (level)) { \
            _nm_log_ptr ((level), \
                         (domain), \
                         (ifname), \
                         (con_uuid), \
                         (self), \
                         (prefix), \
                         __VA_ARGS__); \
        } else { \
            const char *__prefix = (prefix); \
            \
            nm_log ((level), \
                    (domain), \
                    (ifname), \
                    (con_uuid), \
                    "%s%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                    __prefix ?: "", \
                    __prefix ? " " : "" _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
        } \
    } G_STMT_END

#define _nm_log_obj(level, domain, ifname, con_uuid, self, prefix, ...) \
    _nm_log_ptr ((level), \
                 (domain), \
                 (ifname), \
                 (con_uuid), \
                 (self), \
                 prefix, \
                 __VA_ARGS__)

/* log a message for an object (with providing a @self pointer to a GObject).
 * Contrary to nm_log_ptr(), @self must be a GObject type (or %NULL).
 * As of now, nm_log_obj() is identical to nm_log_ptr(), but we might change that */
#define nm_log_obj(level, domain, ifname, con_uuid, self, prefix, ...) \
    nm_log_ptr ((level), \
                (domain), \
                (ifname), \
                (con_uuid), \
                (self), \
                prefix, \
                __VA_ARGS__)

const char *nm_logging_level_to_string (void);
const char *nm_logging_domains_to_string (void);

/*****************************************************************************/

extern NMLogDomain _nm_logging_enabled_state[_LOGL_N_REAL];

static inline gboolean
_nm_logging_enabled_lockfree (NMLogLevel level, NMLogDomain domain)
{
	nm_assert (((guint) level) < G_N_ELEMENTS (_nm_logging_enabled_state));
	return    (((guint) level) < G_N_ELEMENTS (_nm_logging_enabled_state))
	       && !!(_nm_logging_enabled_state[level] & domain);
}

gboolean _nm_logging_enabled_locking (NMLogLevel level, NMLogDomain domain);

static inline gboolean
nm_logging_enabled_mt (gboolean mt_require_locking, NMLogLevel level, NMLogDomain domain)
{
	if (mt_require_locking)
		return _nm_logging_enabled_locking (level, domain);

	NM_ASSERT_ON_MAIN_THREAD ();
	return _nm_logging_enabled_lockfree (level, domain);
}

#define nm_logging_enabled(level, domain) \
	nm_logging_enabled_mt (!(NM_THREAD_SAFE_ON_MAIN_THREAD), level, domain)

/*****************************************************************************/

NMLogLevel nm_logging_get_level (NMLogDomain domain);

const char *nm_logging_all_levels_to_string (void);
const char *nm_logging_all_domains_to_string (void);

gboolean nm_logging_setup (const char  *level,
                           const char  *domains,
                           char       **bad_domains,
                           GError     **error);

void nm_logging_init_pre (const char *syslog_identifier,
                          char *prefix_take);

void     nm_logging_init (const char *logging_backend, gboolean debug);

gboolean nm_logging_syslog_enabled (void);

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

#define __NMLOG_DEFAULT(level, domain, prefix, ...) \
	G_STMT_START { \
		nm_log ((level), (domain), NULL, NULL, \
		        "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
		        (prefix) \
		        _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
	} G_STMT_END

#define __NMLOG_DEFAULT_WITH_ADDR(level, domain, prefix, ...) \
	G_STMT_START { \
		nm_log ((level), (domain), NULL, NULL, \
		        "%s["NM_HASH_OBFUSCATE_PTR_FMT"]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
		        (prefix), \
		        NM_HASH_OBFUSCATE_PTR (self) \
		        _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
	} G_STMT_END

/*****************************************************************************/

extern void _nm_logging_clear_platform_logging_cache (void);

#endif /* __NETWORKMANAGER_LOGGING_H__ */
