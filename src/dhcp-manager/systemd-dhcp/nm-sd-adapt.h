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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef NM_SD_ADAPT_H
#define NM_SD_ADAPT_H

#include <config.h>

#include <glib.h>

#include <netinet/in.h>
#include <stdbool.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <elf.h>
#ifdef HAVE_SYS_AUXV_H
#include <sys/auxv.h>
#endif
#include <unistd.h>
#include <sys/syscall.h>

#include "nm-logging.h"

/* Missing in Linux 3.2.0, in Ubuntu 12.04 */
#ifndef BPF_XOR
#define BPF_XOR 0xa0
#endif

static inline guint32
_slog_level_to_nm (int slevel)
{
    switch (slevel) {
    case LOG_DEBUG:   return LOGL_DEBUG;
	case LOG_WARNING: return LOGL_WARN;
	case LOG_ERR:     return LOGL_ERR;
	case LOG_INFO:
	case LOG_NOTICE:
	default:          return LOGL_INFO;
	}
}

#define log_meta(level, file, line, func, format, ...) \
G_STMT_START { \
	guint32 _l = _slog_level_to_nm ((level)); \
	if (nm_logging_enabled (_l, LOGD_DHCP)) { \
		const char *_location = strrchr (file "", '/'); \
		\
		_nm_log_impl (_location ? _location + 1 : file, line, func, _l, LOGD_DHCP, 0, format, ## __VA_ARGS__); \
	} \
} G_STMT_END

#define log_debug(...)       log_full(LOG_DEBUG, __VA_ARGS__)
#define log_error(...)       log_full(LOG_ERR, __VA_ARGS__)
#define log_full(level, ...) log_meta((level), __FILE__, __LINE__, __func__, __VA_ARGS__);

#define log_dhcp_client(client, fmt, ...) \
	log_meta(LOG_DEBUG, __FILE__, __LINE__, __func__, "DHCP CLIENT (0x%x): " fmt, client->xid, ##__VA_ARGS__)

#define log_assert_failed(e, file, line, func) \
G_STMT_START { \
	nm_log_err (LOGD_DHCP, #file ":" #line "(" #func "): assertion failed: " # e); \
	g_assert (FALSE); \
} G_STMT_END

#define log_assert_failed_unreachable(t, file, line, func) \
G_STMT_START { \
	nm_log_err (LOGD_DHCP, #file ":" #line "(" #func "): assert unreachable: " # t); \
	g_assert_not_reached (); \
} G_STMT_END

#define log_assert_failed_return(e, file, line, func) \
	nm_log_err (LOGD_DHCP, #file ":" #line "(" #func "): assert return: " # e); \

#define log_oom nm_log_err(LOGD_CORE, "%s:%s/%s: OOM", __FILE__, __LINE__, __func__)

/* Can't include both net/if.h and linux/if.h; so have to define this here */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

#define noreturn G_GNUC_NORETURN

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

#endif /* NM_SD_ADAPT_H */

