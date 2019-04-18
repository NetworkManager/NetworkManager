/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2014 - 2018 Red Hat, Inc.
 */

#ifndef __NM_SD_ADAPT_SHARED_H__
#define __NM_SD_ADAPT_SHARED_H__

#include "nm-default.h"

#include <syslog.h>

#include "nm-glib-aux/nm-logging-fwd.h"

/*****************************************************************************/

/* strerror() is not thread-safe. Patch systemd-sources via a define. */
#define strerror(errsv) nm_strerror_native (errsv)

/*****************************************************************************/

static inline NMLogLevel
_slog_level_to_nm (int slevel)
{
	switch (LOG_PRI (slevel)) {
	case LOG_DEBUG:   return LOGL_DEBUG;
	case LOG_WARNING: return LOGL_WARN;
	case LOG_CRIT:
	case LOG_ERR:     return LOGL_ERR;
	case LOG_INFO:
	case LOG_NOTICE:
	default:          return LOGL_INFO;
	}
}

static inline int
_nm_log_get_max_level_realm (void)
{
	/* inline function, to avoid coverity warning about constant expression. */
	return LOG_DEBUG;
}
#define log_get_max_level_realm(realm) _nm_log_get_max_level_realm ()

#define log_internal_realm(level, error, file, line, func, format, ...) \
({ \
	const int _nm_e = (error); \
	const NMLogLevel _nm_l = _slog_level_to_nm ((level)); \
	\
	if (_nm_log_enabled_impl (!(NM_THREAD_SAFE_ON_MAIN_THREAD), _nm_l, LOGD_SYSTEMD)) { \
		const char *_nm_location = strrchr ((""file), '/'); \
		\
		_nm_log_impl (_nm_location ? _nm_location + 1 : (""file), (line), (func), !(NM_THREAD_SAFE_ON_MAIN_THREAD), _nm_l, LOGD_SYSTEMD, _nm_e, NULL, NULL, ("%s"format), "libsystemd: ", ## __VA_ARGS__); \
	} \
	(_nm_e > 0 ? -_nm_e : _nm_e); \
})

#define log_assert_failed(text, file, line, func) \
G_STMT_START { \
	log_internal (LOG_CRIT, 0, file, line, func, "Assertion '%s' failed at %s:%u, function %s(). Aborting.", text, file, line, func); \
	g_assert_not_reached (); \
} G_STMT_END

#define log_assert_failed_unreachable(text, file, line, func) \
G_STMT_START { \
	log_internal (LOG_CRIT, 0, file, line, func, "Code should not be reached '%s' at %s:%u, function %s(). Aborting.", text, file, line, func); \
	g_assert_not_reached (); \
} G_STMT_END

#define log_assert_failed_return(text, file, line, func) \
({ \
	log_internal (LOG_DEBUG, 0, file, line, func, "Assertion '%s' failed at %s:%u, function %s(). Ignoring.", text, file, line, func); \
	g_return_if_fail_warning (G_LOG_DOMAIN, G_STRFUNC, text); \
	(void) 0; \
})

/*****************************************************************************/

#define VALGRIND 0

#define ENABLE_DEBUG_HASHMAP 0

/*****************************************************************************
 * The remainder of the header is only enabled when building the systemd code
 * itself.
 *****************************************************************************/

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_SYSTEMD

#include <sys/syscall.h>
#include <sys/ioctl.h>

static inline pid_t
raw_getpid (void) {
#if defined(__alpha__)
	return (pid_t) syscall (__NR_getxpid);
#else
	return (pid_t) syscall (__NR_getpid);
#endif
}

static inline pid_t _nm_gettid(void) {
        return (pid_t) syscall(SYS_gettid);
}
#define gettid() _nm_gettid ()

/* we build with C11 and thus <uchar.h> provides char32_t,char16_t. */
#define HAVE_CHAR32_T 1
#define HAVE_CHAR16_T 1

#if defined(HAVE_DECL_REALLOCARRAY) && HAVE_DECL_REALLOCARRAY == 1
#define HAVE_REALLOCARRAY 1
#else
#define HAVE_REALLOCARRAY 0
#endif

#if defined(HAVE_DECL_EXPLICIT_BZERO) && HAVE_DECL_EXPLICIT_BZERO == 1
#define HAVE_EXPLICIT_BZERO 1
#else
#define HAVE_EXPLICIT_BZERO 0
#endif

#endif /* (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_SYSTEMD */

/*****************************************************************************/

#endif /* __NM_SD_ADAPT_SHARED_H__ */
