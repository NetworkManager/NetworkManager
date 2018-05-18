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
 * Copyright (C) 2014 - 2015 Red Hat, Inc.
 */

#ifndef NM_SD_ADAPT_H
#define NM_SD_ADAPT_H

#include "nm-default.h"

#include <stdbool.h>
#include <syslog.h>
#include <sys/resource.h>
#include <time.h>

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

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

#define ENABLE_DEBUG_HASHMAP 0

#ifndef HAVE_SYS_AUXV_H
#define HAVE_SYS_AUXV_H 0
#endif

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
	if (nm_logging_enabled (_nm_l, LOGD_SYSTEMD)) { \
		const char *_nm_location = strrchr ((""file), '/'); \
		\
		_nm_log_impl (_nm_location ? _nm_location + 1 : (""file), (line), (func), _nm_l, LOGD_DHCP, _nm_e, NULL, NULL, ("%s"format), "libsystemd: ", ## __VA_ARGS__); \
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

/*****************************************************************************
 * The remainder of the header is only enabled when building the systemd code
 * itself.
 *****************************************************************************/

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_SYSTEMD

#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <elf.h>
#ifdef HAVE_SYS_AUXV_H
#include <sys/auxv.h>
#endif
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#include <net/if_arp.h>

/* Missing in Linux 3.2.0, in Ubuntu 12.04 */
#ifndef BPF_XOR
#define BPF_XOR 0xa0
#endif

#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88cc
#endif

#ifndef HAVE_SECURE_GETENV
#  ifdef HAVE___SECURE_GETENV
#    define secure_getenv __secure_getenv
#  else
#    error neither secure_getenv nor __secure_getenv is available
#  endif
#endif

#define VALGRIND 0

static inline pid_t
raw_getpid (void) {
#if defined(__alpha__)
	return (pid_t) syscall (__NR_getxpid);
#else
	return (pid_t) syscall (__NR_getpid);
#endif
}

/*****************************************************************************/

/* work around missing uchar.h */
typedef guint16 char16_t;
typedef guint32 char32_t;

/*****************************************************************************/

static inline int
sd_notify (int unset_environment, const char *state)
{
	return 0;
}

/* Can't include both net/if.h and linux/if.h; so have to define this here */
#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

/*
 * Some toolchains (E.G. uClibc 0.9.33 and earlier) don't export
 * CLOCK_BOOTTIME even though the kernel supports it, so provide a
 * local definition
 */
#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

#include "sd-id128.h"
#include "sparse-endian.h"
#include "async.h"
#include "util.h"

static inline pid_t gettid(void) {
        return (pid_t) syscall(SYS_gettid);
}

#endif /* (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_SYSTEMD */

#endif /* NM_SD_ADAPT_H */

