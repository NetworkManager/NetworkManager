/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
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

#define nm_log_err(domain, ...)   nm_log(LOGL_ERR, (domain), NULL, NULL, __VA_ARGS__)
#define nm_log_warn(domain, ...)  nm_log(LOGL_WARN, (domain), NULL, NULL, __VA_ARGS__)
#define nm_log_info(domain, ...)  nm_log(LOGL_INFO, (domain), NULL, NULL, __VA_ARGS__)
#define nm_log_dbg(domain, ...)   nm_log(LOGL_DEBUG, (domain), NULL, NULL, __VA_ARGS__)
#define nm_log_trace(domain, ...) nm_log(LOGL_TRACE, (domain), NULL, NULL, __VA_ARGS__)

//#define _NM_LOG_FUNC G_STRFUNC
#define _NM_LOG_FUNC NULL

/* A wrapper for the _nm_log_impl() function that adds call site information.
 * Contrary to nm_log(), it unconditionally calls the function without
 * checking whether logging for the given level and domain is enabled. */
#define _nm_log_mt(mt_require_locking, level, domain, error, ifname, con_uuid, ...) \
    G_STMT_START                                                                    \
    {                                                                               \
        _nm_log_impl(__FILE__,                                                      \
                     __LINE__,                                                      \
                     _NM_LOG_FUNC,                                                  \
                     (mt_require_locking),                                          \
                     (level),                                                       \
                     (domain),                                                      \
                     (error),                                                       \
                     (ifname),                                                      \
                     (con_uuid),                                                    \
                     ""__VA_ARGS__);                                                \
    }                                                                               \
    G_STMT_END

#define _nm_log(level, domain, error, ifname, con_uuid, ...) \
    _nm_log_mt(!(NM_THREAD_SAFE_ON_MAIN_THREAD),             \
               level,                                        \
               domain,                                       \
               error,                                        \
               ifname,                                       \
               con_uuid,                                     \
               __VA_ARGS__)

/* nm_log() only evaluates its argument list after checking
 * whether logging for the given level/domain is enabled.  */
#define nm_log(level, domain, ifname, con_uuid, ...)                  \
    G_STMT_START                                                      \
    {                                                                 \
        if (nm_logging_enabled((level), (domain))) {                  \
            _nm_log(level, domain, 0, ifname, con_uuid, __VA_ARGS__); \
        }                                                             \
    }                                                                 \
    G_STMT_END

#define _nm_log_ptr(level, domain, ifname, con_uuid, self, prefix, ...)             \
    nm_log((level),                                                                 \
           (domain),                                                                \
           (ifname),                                                                \
           (con_uuid),                                                              \
           "%s[" NM_HASH_OBFUSCATE_PTR_FMT "] " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
           (prefix) ?: "",                                                          \
           NM_HASH_OBFUSCATE_PTR(self) _NM_UTILS_MACRO_REST(__VA_ARGS__))

static inline gboolean
_nm_log_ptr_is_debug(NMLogLevel level)
{
    return level <= LOGL_DEBUG;
}

/* log a message for an object (with providing a generic @self pointer) */
#define nm_log_ptr(level, domain, ifname, con_uuid, self, prefix, ...)                           \
    G_STMT_START                                                                                 \
    {                                                                                            \
        if (_nm_log_ptr_is_debug(level)) {                                                       \
            _nm_log_ptr((level), (domain), (ifname), (con_uuid), (self), (prefix), __VA_ARGS__); \
        } else {                                                                                 \
            const char *__prefix = (prefix);                                                     \
                                                                                                 \
            nm_log((level),                                                                      \
                   (domain),                                                                     \
                   (ifname),                                                                     \
                   (con_uuid),                                                                   \
                   "%s%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                                    \
                   __prefix ?: "",                                                               \
                   __prefix ? " " : "" _NM_UTILS_MACRO_REST(__VA_ARGS__));                       \
        }                                                                                        \
    }                                                                                            \
    G_STMT_END

#define _nm_log_obj(level, domain, ifname, con_uuid, self, prefix, ...) \
    _nm_log_ptr((level), (domain), (ifname), (con_uuid), (self), prefix, __VA_ARGS__)

/* log a message for an object (with providing a @self pointer to a GObject).
 * Contrary to nm_log_ptr(), @self must be a GObject type (or %NULL).
 * As of now, nm_log_obj() is identical to nm_log_ptr(), but we might change that */
#define nm_log_obj(level, domain, ifname, con_uuid, self, prefix, ...) \
    nm_log_ptr((level), (domain), (ifname), (con_uuid), (self), prefix, __VA_ARGS__)

const char *nm_logging_level_to_string(void);
const char *nm_logging_domains_to_string(void);

/*****************************************************************************/

extern NMLogDomain _nm_logging_enabled_state[_LOGL_N_REAL];

static inline gboolean
_nm_logging_enabled_lockfree(NMLogLevel level, NMLogDomain domain)
{
    nm_assert(((guint) level) < G_N_ELEMENTS(_nm_logging_enabled_state));
    return (((guint) level) < G_N_ELEMENTS(_nm_logging_enabled_state))
           && !!(_nm_logging_enabled_state[level] & domain);
}

gboolean _nm_logging_enabled_locking(NMLogLevel level, NMLogDomain domain);

static inline gboolean
nm_logging_enabled_mt(gboolean mt_require_locking, NMLogLevel level, NMLogDomain domain)
{
    if (mt_require_locking)
        return _nm_logging_enabled_locking(level, domain);

    NM_ASSERT_ON_MAIN_THREAD();
    return _nm_logging_enabled_lockfree(level, domain);
}

#define nm_logging_enabled(level, domain) \
    nm_logging_enabled_mt(!(NM_THREAD_SAFE_ON_MAIN_THREAD), level, domain)

/*****************************************************************************/

NMLogLevel nm_logging_get_level(NMLogDomain domain);

const char *nm_logging_all_levels_to_string(void);
const char *nm_logging_all_domains_to_string(void);

gboolean
nm_logging_setup(const char *level, const char *domains, char **bad_domains, GError **error);

void nm_logging_init_pre(const char *syslog_identifier, char *prefix_take);

void nm_logging_init(const char *logging_backend, gboolean debug);

gboolean nm_logging_syslog_enabled(void);

/*****************************************************************************/

#define __NMLOG_DEFAULT(level, domain, prefix, ...)         \
    G_STMT_START                                            \
    {                                                       \
        nm_log((level),                                     \
               (domain),                                    \
               NULL,                                        \
               NULL,                                        \
               "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),   \
               (prefix) _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    }                                                       \
    G_STMT_END

#define __NMLOG_DEFAULT_WITH_ADDR(level, domain, prefix, ...)                            \
    G_STMT_START                                                                         \
    {                                                                                    \
        nm_log((level),                                                                  \
               (domain),                                                                 \
               NULL,                                                                     \
               NULL,                                                                     \
               "%s[" NM_HASH_OBFUSCATE_PTR_FMT "]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
               (prefix),                                                                 \
               NM_HASH_OBFUSCATE_PTR(self) _NM_UTILS_MACRO_REST(__VA_ARGS__));           \
    }                                                                                    \
    G_STMT_END

/*****************************************************************************/

extern void _nm_logging_clear_platform_logging_cache(void);

#endif /* __NETWORKMANAGER_LOGGING_H__ */
