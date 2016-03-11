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

#include "nm-default.h"

#include <dlfcn.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <strings.h>
#include <string.h>

#if defined (NO_SYSTEMD_JOURNAL) && defined (SYSTEMD_JOURNAL)
#undef SYSTEMD_JOURNAL
#define SYSTEMD_JOURNAL 0
#endif

#if SYSTEMD_JOURNAL
#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-journal.h>
#endif

#include "nm-errors.h"
#include "nm-core-utils.h"

typedef enum {
	LOG_FORMAT_FLAG_NONE                                = 0,
	LOG_FORMAT_FLAG_TIMESTAMP_DEBUG                     = (1LL << 0),
	LOG_FORMAT_FLAG_TIMESTAMP_INFO                      = (1LL << 1),
	LOG_FORMAT_FLAG_TIMESTAMP_ERROR                     = (1LL << 2),
	LOG_FORMAT_FLAG_LOCATION_DEBUG                      = (1LL << 3),
	LOG_FORMAT_FLAG_LOCATION_INFO                       = (1LL << 4),
	LOG_FORMAT_FLAG_LOCATION_ERROR                      = (1LL << 5),
	LOG_FORMAT_FLAG_ALIGN_LOCATION                      = (1LL << 6),

	_LOG_FORMAT_FLAG_TIMESTAMP                          = LOG_FORMAT_FLAG_TIMESTAMP_DEBUG |
	                                                      LOG_FORMAT_FLAG_TIMESTAMP_INFO |
	                                                      LOG_FORMAT_FLAG_TIMESTAMP_ERROR,
	_LOG_FORMAT_FLAG_LOCATION                           = LOG_FORMAT_FLAG_LOCATION_DEBUG |
	                                                      LOG_FORMAT_FLAG_LOCATION_INFO |
	                                                      LOG_FORMAT_FLAG_LOCATION_ERROR,

	_LOG_FORMAT_FLAG_LEVEL_DEBUG                        = LOG_FORMAT_FLAG_TIMESTAMP_DEBUG |
	                                                      LOG_FORMAT_FLAG_LOCATION_DEBUG,
	_LOG_FORMAT_FLAG_LEVEL_INFO                         = LOG_FORMAT_FLAG_TIMESTAMP_INFO |
	                                                      LOG_FORMAT_FLAG_LOCATION_INFO,
	_LOG_FORMAT_FLAG_LEVEL_ERROR                        = LOG_FORMAT_FLAG_TIMESTAMP_ERROR |
	                                                      LOG_FORMAT_FLAG_LOCATION_ERROR,

	_LOG_FORMAT_FLAG_SYSLOG                             = _LOG_FORMAT_FLAG_TIMESTAMP |
	                                                      LOG_FORMAT_FLAG_LOCATION_DEBUG |
	                                                      LOG_FORMAT_FLAG_LOCATION_ERROR |
	                                                      LOG_FORMAT_FLAG_ALIGN_LOCATION,

	_LOG_FORMAT_FLAG_DEFAULT                            = _LOG_FORMAT_FLAG_TIMESTAMP,
} LogFormatFlags;

void (*_nm_logging_clear_platform_logging_cache) (void);

static void
nm_log_handler (const gchar *log_domain,
                GLogLevelFlags level,
                const gchar *message,
                gpointer ignored);

typedef struct {
	NMLogDomain num;
	const char *name;
} LogDesc;

typedef struct {
	const char *name;
	const char *level_str;
	int syslog_level;
	GLogLevelFlags g_log_level;
	LogFormatFlags log_format_level;
} LogLevelDesc;

static struct {
	NMLogLevel log_level;
	NMLogDomain logging[_LOGL_N_REAL];
	gboolean logging_set_up;
	LogFormatFlags log_format_flags;
	enum {
		LOG_BACKEND_GLIB,
		LOG_BACKEND_SYSLOG,
		LOG_BACKEND_JOURNAL,
	} log_backend;
	char *logging_domains_to_string;
	const LogLevelDesc level_desc[_LOGL_N];

#define _DOMAIN_DESC_LEN 37
	/* Would be nice to use C99 flexible array member here,
	 * but that feature doesn't seem well supported. */
	const LogDesc domain_desc[_DOMAIN_DESC_LEN];
} global = {
	.log_level = LOGL_INFO,
	.log_backend = LOG_BACKEND_GLIB,
	.log_format_flags = _LOG_FORMAT_FLAG_DEFAULT,
	.level_desc = {
		[LOGL_TRACE] = { "TRACE", "<trace>", LOG_DEBUG,   G_LOG_LEVEL_DEBUG,   _LOG_FORMAT_FLAG_LEVEL_DEBUG },
		[LOGL_DEBUG] = { "DEBUG", "<debug>", LOG_INFO,    G_LOG_LEVEL_DEBUG,   _LOG_FORMAT_FLAG_LEVEL_DEBUG },
		[LOGL_INFO]  = { "INFO",  "<info>",  LOG_INFO,    G_LOG_LEVEL_INFO,    _LOG_FORMAT_FLAG_LEVEL_INFO },
		[LOGL_WARN]  = { "WARN",  "<warn>",  LOG_WARNING, G_LOG_LEVEL_MESSAGE, _LOG_FORMAT_FLAG_LEVEL_INFO },
		[LOGL_ERR]   = { "ERR",   "<error>", LOG_ERR,     G_LOG_LEVEL_MESSAGE, _LOG_FORMAT_FLAG_LEVEL_ERROR },
		[_LOGL_OFF]  = { "OFF",   NULL,      0,           0,                   0 },
		[_LOGL_KEEP] = { "KEEP",  NULL,      0,           0,                   0 },
	},
	.domain_desc = {
		{ LOGD_PLATFORM,  "PLATFORM" },
		{ LOGD_RFKILL,    "RFKILL" },
		{ LOGD_ETHER,     "ETHER" },
		{ LOGD_WIFI,      "WIFI" },
		{ LOGD_BT,        "BT" },
		{ LOGD_MB,        "MB" },
		{ LOGD_DHCP4,     "DHCP4" },
		{ LOGD_DHCP6,     "DHCP6" },
		{ LOGD_PPP,       "PPP" },
		{ LOGD_WIFI_SCAN, "WIFI_SCAN" },
		{ LOGD_IP4,       "IP4" },
		{ LOGD_IP6,       "IP6" },
		{ LOGD_AUTOIP4,   "AUTOIP4" },
		{ LOGD_DNS,       "DNS" },
		{ LOGD_VPN,       "VPN" },
		{ LOGD_SHARING,   "SHARING" },
		{ LOGD_SUPPLICANT,"SUPPLICANT" },
		{ LOGD_AGENTS,    "AGENTS" },
		{ LOGD_SETTINGS,  "SETTINGS" },
		{ LOGD_SUSPEND,   "SUSPEND" },
		{ LOGD_CORE,      "CORE" },
		{ LOGD_DEVICE,    "DEVICE" },
		{ LOGD_OLPC,      "OLPC" },
		{ LOGD_INFINIBAND,"INFINIBAND" },
		{ LOGD_FIREWALL,  "FIREWALL" },
		{ LOGD_ADSL,      "ADSL" },
		{ LOGD_BOND,      "BOND" },
		{ LOGD_VLAN,      "VLAN" },
		{ LOGD_BRIDGE,    "BRIDGE" },
		{ LOGD_DBUS_PROPS,"DBUS_PROPS" },
		{ LOGD_TEAM,      "TEAM" },
		{ LOGD_CONCHECK,  "CONCHECK" },
		{ LOGD_DCB,       "DCB" },
		{ LOGD_DISPATCH,  "DISPATCH" },
		{ LOGD_AUDIT,     "AUDIT" },
		{ LOGD_SYSTEMD,   "SYSTEMD" },
		{ 0, NULL }
		/* keep _DOMAIN_DESC_LEN in sync */
	},
};

/* We have more then 32 logging domains. Assert that it compiles to a 64 bit sized enum */
G_STATIC_ASSERT (sizeof (NMLogDomain) >= sizeof (guint64));

/* Combined domains */
#define LOGD_ALL_STRING     "ALL"
#define LOGD_DEFAULT_STRING "DEFAULT"
#define LOGD_DHCP_STRING    "DHCP"
#define LOGD_IP_STRING      "IP"

/************************************************************************/

static char *_domains_to_string (gboolean include_level_override);

/************************************************************************/

static void
_ensure_initialized (void)
{
	if (G_UNLIKELY (!global.logging_set_up)) {
		int errsv = errno;

		nm_logging_setup ("INFO", LOGD_DEFAULT_STRING, NULL, NULL);

		/* must ensure that errno is not modified. */
		errno = errsv;
	}
}

static gboolean
match_log_level (const char  *level,
                 NMLogLevel  *out_level,
                 GError     **error)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS (global.level_desc); i++) {
		if (!g_ascii_strcasecmp (global.level_desc[i].name, level)) {
			*out_level = i;
			return TRUE;
		}
	}

	g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_LOG_LEVEL,
	             _("Unknown log level '%s'"), level);
	return FALSE;
}

gboolean
nm_logging_setup (const char  *level,
                  const char  *domains,
                  char       **bad_domains,
                  GError     **error)
{
	GString *unrecognized = NULL;
	NMLogDomain new_logging[G_N_ELEMENTS (global.logging)];
	NMLogLevel new_log_level = global.log_level;
	char **tmp, **iter;
	int i;
	gboolean had_platform_debug;
	gs_free char *domains_free = NULL;

	g_return_val_if_fail (!bad_domains || !*bad_domains, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* domains */
	if (!domains || !*domains) {
		domains = global.logging_set_up
		          ? (domains_free = _domains_to_string (FALSE))
		          : LOGD_DEFAULT_STRING;
	}

	global.logging_set_up = TRUE;

	for (i = 0; i < G_N_ELEMENTS (new_logging); i++)
		new_logging[i] = 0;

	/* levels */
	if (level && *level) {
		if (!match_log_level (level, &new_log_level, error))
			return FALSE;
		if (new_log_level == _LOGL_KEEP) {
			new_log_level = global.log_level;
			for (i = 0; i < G_N_ELEMENTS (new_logging); i++)
				new_logging[i] = global.logging[i];
		}
	}

	tmp = g_strsplit_set (domains, ", ", 0);
	for (iter = tmp; iter && *iter; iter++) {
		const LogDesc *diter;
		NMLogLevel domain_log_level;
		NMLogDomain bits;
		char *p;

		if (!strlen (*iter))
			continue;

		p = strchr (*iter, ':');
		if (p) {
			*p = '\0';
			if (!match_log_level (p + 1, &domain_log_level, error)) {
				g_strfreev (tmp);
				return FALSE;
			}
		} else
			domain_log_level = new_log_level;

		bits = 0;

		/* Check for combined domains */
		if (!g_ascii_strcasecmp (*iter, LOGD_ALL_STRING))
			bits = LOGD_ALL;
		else if (!g_ascii_strcasecmp (*iter, LOGD_DEFAULT_STRING))
			bits = LOGD_DEFAULT;
		else if (!g_ascii_strcasecmp (*iter, LOGD_DHCP_STRING))
			bits = LOGD_DHCP;
		else if (!g_ascii_strcasecmp (*iter, LOGD_IP_STRING))
			bits = LOGD_IP;

		/* Check for compatibility domains */
		else if (!g_ascii_strcasecmp (*iter, "HW"))
			bits = LOGD_PLATFORM;
		else if (!g_ascii_strcasecmp (*iter, "WIMAX"))
			continue;

		else {
			for (diter = &global.domain_desc[0]; diter->name; diter++) {
				if (!g_ascii_strcasecmp (diter->name, *iter)) {
					bits = diter->num;
					break;
				}
			}

			if (!bits) {
				if (!bad_domains) {
					g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_LOG_DOMAIN,
					             _("Unknown log domain '%s'"), *iter);
					return FALSE;
				}

				if (unrecognized)
					g_string_append (unrecognized, ", ");
				else
					unrecognized = g_string_new (NULL);
				g_string_append (unrecognized, *iter);
				continue;
			}
		}

		if (domain_log_level == _LOGL_KEEP) {
			for (i = 0; i < G_N_ELEMENTS (new_logging); i++)
				new_logging[i] = (new_logging[i] & ~bits) | (global.logging[i] & bits);
		} else {
			for (i = 0; i < G_N_ELEMENTS (new_logging); i++) {
				if (i < domain_log_level)
					new_logging[i] &= ~bits;
				else
					new_logging[i] |= bits;
			}
		}
	}
	g_strfreev (tmp);

	g_clear_pointer (&global.logging_domains_to_string, g_free);

	had_platform_debug = nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM);

	global.log_level = new_log_level;
	for (i = 0; i < G_N_ELEMENTS (new_logging); i++)
		global.logging[i] = new_logging[i];

	if (   had_platform_debug
	    && _nm_logging_clear_platform_logging_cache
	    && !nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM)) {
		/* when debug logging is enabled, platform will cache all access to
		 * sysctl. When the user disables debug-logging, we want to clear that
		 * cache right away. */
		_nm_logging_clear_platform_logging_cache ();
	}

	if (unrecognized)
		*bad_domains = g_string_free (unrecognized, FALSE);

	return TRUE;
}

const char *
nm_logging_level_to_string (void)
{
	return global.level_desc[global.log_level].name;
}

const char *
nm_logging_all_levels_to_string (void)
{
	static GString *str;

	if (G_UNLIKELY (!str)) {
		int i;

		str = g_string_new (NULL);
		for (i = 0; i < G_N_ELEMENTS (global.level_desc); i++) {
			if (str->len)
				g_string_append_c (str, ',');
			g_string_append (str, global.level_desc[i].name);
		}
	}

	return str->str;
}

const char *
nm_logging_domains_to_string (void)
{
	_ensure_initialized ();

	if (G_UNLIKELY (!global.logging_domains_to_string))
		global.logging_domains_to_string = _domains_to_string (TRUE);

	return global.logging_domains_to_string;
}

static char *
_domains_to_string (gboolean include_level_override)
{
	const LogDesc *diter;
	GString *str;
	int i;

	/* We don't just return g_strdup (global.log_domains) because we want to expand
	 * "DEFAULT" and "ALL".
	 */

	str = g_string_sized_new (75);
	for (diter = &global.domain_desc[0]; diter->name; diter++) {
		/* If it's set for any lower level, it will also be set for LOGL_ERR */
		if (!(diter->num & global.logging[LOGL_ERR]))
			continue;

		if (str->len)
			g_string_append_c (str, ',');
		g_string_append (str, diter->name);

		if (!include_level_override)
			continue;

		/* Check if it's logging at a lower level than the default. */
		for (i = 0; i < global.log_level; i++) {
			if (diter->num & global.logging[i]) {
				g_string_append_printf (str, ":%s", global.level_desc[i].name);
				break;
			}
		}
		/* Check if it's logging at a higher level than the default. */
		if (!(diter->num & global.logging[global.log_level])) {
			for (i = global.log_level + 1; i < G_N_ELEMENTS (global.logging); i++) {
				if (diter->num & global.logging[i]) {
					g_string_append_printf (str, ":%s", global.level_desc[i].name);
					break;
				}
			}
		}
	}
	return g_string_free (str, FALSE);
}

const char *
nm_logging_all_domains_to_string (void)
{
	static GString *str;

	if (G_UNLIKELY (!str)) {
		const LogDesc *diter;

		str = g_string_new (LOGD_DEFAULT_STRING);
		for (diter = &global.domain_desc[0]; diter->name; diter++) {
			g_string_append_c (str, ',');
			g_string_append (str, diter->name);
			if (diter->num == LOGD_DHCP6)
				g_string_append (str, "," LOGD_DHCP_STRING);
			else if (diter->num == LOGD_IP6)
				g_string_append (str, "," LOGD_IP_STRING);
		}
		g_string_append (str, "," LOGD_ALL_STRING);
	}

	return str->str;
}

gboolean
nm_logging_enabled (NMLogLevel level, NMLogDomain domain)
{
	if ((guint) level >= G_N_ELEMENTS (global.logging))
		g_return_val_if_reached (FALSE);

	/* This function is guaranteed not to modify errno. */
	_ensure_initialized ();

	return !!(global.logging[level] & domain);
}

#if SYSTEMD_JOURNAL
__attribute__((__format__ (__printf__, 4, 5)))
static void
_iovec_set_format (struct iovec *iov, gboolean *iov_free, int i, const char *format, ...)
{
	va_list ap;
	char *str;

	va_start (ap, format);
	str = g_strdup_vprintf (format, ap);
	va_end (ap);

	iov[i].iov_base = str;
	iov[i].iov_len = strlen (str);
	iov_free[i] = TRUE;
}

static void
_iovec_set_string (struct iovec *iov, gboolean *iov_free, int i, const char *str, gsize len)
{
	iov[i].iov_base = (char *) str;
	iov[i].iov_len = len;
	iov_free[i] = FALSE;
}
#define _iovec_set_literal_string(iov, iov_free, i, str) _iovec_set_string ((iov), (iov_free), (i), (""str""), NM_STRLEN (str))
#endif

void
_nm_log_impl (const char *file,
              guint line,
              const char *func,
              NMLogLevel level,
              NMLogDomain domain,
              int error,
              const char *fmt,
              ...)
{
	va_list args;
	char *msg;
	char *fullmsg;
	char s_buf_timestamp[64];
	char s_buf_location[1024];
	GTimeVal tv;

	if ((guint) level >= G_N_ELEMENTS (global.logging))
		g_return_if_reached ();

	_ensure_initialized ();

	if (!(global.logging[level] & domain))
		return;

	/* Make sure that %m maps to the specified error */
	if (error != 0) {
		if (error < 0)
			error = -error;
		errno = error;
	}

	va_start (args, fmt);
	msg = g_strdup_vprintf (fmt, args);
	va_end (args);

	if (NM_FLAGS_ANY (global.log_format_flags, global.level_desc[level].log_format_level & _LOG_FORMAT_FLAG_TIMESTAMP)) {
		g_get_current_time (&tv);
		nm_sprintf_buf (s_buf_timestamp, " [%ld.%04ld]", tv.tv_sec, (tv.tv_usec + 50) / 100);
	} else
		s_buf_timestamp[0] = '\0';

	s_buf_location[0] = '\0';
	if (NM_FLAGS_ANY (global.log_format_flags, global.level_desc[level].log_format_level & _LOG_FORMAT_FLAG_LOCATION)) {
#define MAX_LEN_FILE 37
#define MAX_LEN_FUNC 26
		gsize l = sizeof (s_buf_location);
		char *p = s_buf_location, *p_buf;
		gsize len;
		char s_buf[MAX (MAX_LEN_FILE, MAX_LEN_FUNC) + 30];

		if (file) {
			if (NM_FLAGS_HAS (global.log_format_flags, LOG_FORMAT_FLAG_ALIGN_LOCATION)) {
				/* left-align the "[file:line]" string, but truncate from left to MAX_LEN_FILE chars. */
				len = strlen (file);
				nm_sprintf_buf (s_buf, "[%s:%u]",
				                len > MAX_LEN_FILE ? &file[len - MAX_LEN_FILE] : file,
				                line);
				len = strlen (s_buf);
				if (len > MAX_LEN_FILE) {
					p_buf = &s_buf[len - MAX_LEN_FILE];
					p_buf[0] = '[';
				} else
					p_buf = s_buf;
				nm_utils_strbuf_append (&p, &l, " %-"G_STRINGIFY (MAX_LEN_FILE)"s", p_buf);
			} else
				nm_utils_strbuf_append (&p, &l, " [%s:%u]", file, line);
		}
		if (func) {
			if (NM_FLAGS_HAS (global.log_format_flags, LOG_FORMAT_FLAG_ALIGN_LOCATION)) {
				/* left-align the "func():" string, but truncate from left to MAX_LEN_FUNC chars. */
				len = strlen (func);
				nm_sprintf_buf (s_buf, "%s():",
				                len > MAX_LEN_FUNC ? &func[len - MAX_LEN_FUNC] : func);
				len = strlen (s_buf);
				nm_utils_strbuf_append (&p, &l, " %-"G_STRINGIFY (MAX_LEN_FUNC)"s",
				                        len > MAX_LEN_FUNC ? &s_buf[len - MAX_LEN_FUNC] : s_buf);
			} else
				nm_utils_strbuf_append (&p, &l, " %s():", func);
		}
	}

	switch (global.log_backend) {
#if SYSTEMD_JOURNAL
	case LOG_BACKEND_JOURNAL:
		{
			gint64 now, boottime;
#define _NUM_MAX_FIELDS_SYSLOG_FACILITY 10
#define _NUM_FIELDS (10 + _NUM_MAX_FIELDS_SYSLOG_FACILITY)
			int i_field = 0;
			struct iovec iov[_NUM_FIELDS];
			gboolean iov_free[_NUM_FIELDS];

			now = nm_utils_get_monotonic_timestamp_ns ();
			boottime = nm_utils_monotonic_timestamp_as_boottime (now, 1);

			_iovec_set_format (iov, iov_free, i_field++, "PRIORITY=%d", global.level_desc[level].syslog_level);
			_iovec_set_format (iov, iov_free, i_field++, "MESSAGE="
			                   "%-7s%s%s %s",
			                   global.level_desc[level].level_str,
			                   s_buf_timestamp,
			                   s_buf_location,
			                   msg);
			_iovec_set_literal_string (iov, iov_free, i_field++, "SYSLOG_IDENTIFIER=" G_LOG_DOMAIN);
			_iovec_set_format (iov, iov_free, i_field++, "SYSLOG_PID=%ld", (long) getpid ());
			{
				const LogDesc *diter;
				int i_domain = _NUM_MAX_FIELDS_SYSLOG_FACILITY;
				const char *s_domain_1 = NULL;
				GString *s_domain_all = NULL;
				NMLogDomain dom_all = domain;
				NMLogDomain dom = dom_all & global.logging[level];

				for (diter = &global.domain_desc[0]; diter->name; diter++) {
					if (!NM_FLAGS_HAS (dom_all, diter->num))
						continue;

					/* construct a list of all domains (not only the enabled ones).
					 * Note that in by far most cases, there is only one domain present.
					 * Hence, save the construction of the GString. */
					dom_all &= ~diter->num;
					if (!s_domain_1)
						s_domain_1 = diter->name;
					else {
						if (!s_domain_all)
							s_domain_all = g_string_new (s_domain_1);
						g_string_append_c (s_domain_all, ',');
						g_string_append (s_domain_all, diter->name);
					}

					if (NM_FLAGS_HAS (dom, diter->num)) {
						if (i_domain > 0) {
							/* SYSLOG_FACILITY is specified multiple times for each domain that is actually enabled. */
							_iovec_set_format (iov, iov_free, i_field++, "SYSLOG_FACILITY=%s", diter->name);
							i_domain--;
						}
						dom &= ~diter->num;
					}
					if (!dom && !dom_all)
						break;
				}
				if (s_domain_all) {
					_iovec_set_format (iov, iov_free, i_field++, "NM_LOG_DOMAINS=%s", s_domain_all->str);
					g_string_free (s_domain_all, TRUE);
				} else
					_iovec_set_format (iov, iov_free, i_field++, "NM_LOG_DOMAINS=%s", s_domain_1);
			}
			_iovec_set_format (iov, iov_free, i_field++, "NM_LOG_LEVEL=%s", global.level_desc[level].name);
			_iovec_set_format (iov, iov_free, i_field++, "CODE_FUNC=%s", func ?: "");
			_iovec_set_format (iov, iov_free, i_field++, "CODE_FILE=%s", file ?: "");
			_iovec_set_format (iov, iov_free, i_field++, "CODE_LINE=%u", line);
			_iovec_set_format (iov, iov_free, i_field++, "TIMESTAMP_MONOTONIC=%lld.%06lld", (long long) (now / NM_UTILS_NS_PER_SECOND), (long long) ((now % NM_UTILS_NS_PER_SECOND) / 1000));
			_iovec_set_format (iov, iov_free, i_field++, "TIMESTAMP_BOOTTIME=%lld.%06lld", (long long) (boottime / NM_UTILS_NS_PER_SECOND), (long long) ((boottime % NM_UTILS_NS_PER_SECOND) / 1000));
			if (error != 0)
				_iovec_set_format (iov, iov_free, i_field++, "ERRNO=%d", error);

			nm_assert (i_field <= G_N_ELEMENTS (iov));

			sd_journal_sendv (iov, i_field);

			for (; i_field > 0; ) {
				i_field--;
				if (iov_free[i_field])
					g_free (iov[i_field].iov_base);
			}
		}
		break;
#endif
	default:
		fullmsg = g_strdup_printf ("%-7s%s%s %s",
		                           global.level_desc[level].level_str,
		                           s_buf_timestamp,
		                           s_buf_location,
		                           msg);

		if (global.log_backend == LOG_BACKEND_SYSLOG)
			syslog (global.level_desc[level].syslog_level, "%s", fullmsg);
		else
			g_log (G_LOG_DOMAIN, global.level_desc[level].g_log_level, "%s", fullmsg);
		g_free (fullmsg);
		break;
	}

	g_free (msg);
}

/************************************************************************/

static void
nm_log_handler (const gchar *log_domain,
                GLogLevelFlags level,
                const gchar *message,
                gpointer ignored)
{
	int syslog_priority;

	switch (level & G_LOG_LEVEL_MASK) {
	case G_LOG_LEVEL_ERROR:
		syslog_priority = LOG_CRIT;
		break;
	case G_LOG_LEVEL_CRITICAL:
		syslog_priority = LOG_ERR;
		break;
	case G_LOG_LEVEL_WARNING:
		syslog_priority = LOG_WARNING;
		break;
	case G_LOG_LEVEL_MESSAGE:
		syslog_priority = LOG_NOTICE;
		break;
	case G_LOG_LEVEL_DEBUG:
		syslog_priority = LOG_DEBUG;
		break;
	case G_LOG_LEVEL_INFO:
	default:
		syslog_priority = LOG_INFO;
		break;
	}

	switch (global.log_backend) {
#if SYSTEMD_JOURNAL
	case LOG_BACKEND_JOURNAL:
		{
			gint64 now, boottime;

			now = nm_utils_get_monotonic_timestamp_ns ();
			boottime = nm_utils_monotonic_timestamp_as_boottime (now, 1);

			sd_journal_send ("PRIORITY=%d", syslog_priority,
			                 "MESSAGE=%s", message ?: "",
			                 "SYSLOG_IDENTIFIER=%s", G_LOG_DOMAIN,
			                 "SYSLOG_PID=%ld", (long) getpid (),
			                 "SYSLOG_FACILITY=GLIB",
			                 "GLIB_DOMAIN=%s", log_domain ?: "",
			                 "GLIB_LEVEL=%d", (int) (level & G_LOG_LEVEL_MASK),
			                 "TIMESTAMP_MONOTONIC=%lld.%06lld", (long long) (now / NM_UTILS_NS_PER_SECOND), (long long) ((now % NM_UTILS_NS_PER_SECOND) / 1000),
			                 "TIMESTAMP_BOOTTIME=%lld.%06lld", (long long) (boottime / NM_UTILS_NS_PER_SECOND), (long long) ((boottime % NM_UTILS_NS_PER_SECOND) / 1000),
			                 NULL);
		}
		break;
#endif
	default:
		syslog (syslog_priority, "%s", message ?: "");
		break;
	}
}

void
nm_logging_syslog_openlog (const char *logging_backend)
{
	LogFormatFlags log_format_flags;

	if (global.log_backend != LOG_BACKEND_GLIB)
		g_return_if_reached ();

	if (!logging_backend)
		logging_backend = ""NM_CONFIG_LOGGING_BACKEND_DEFAULT;

	log_format_flags = _LOG_FORMAT_FLAG_DEFAULT;

	if (strcmp (logging_backend, "debug") == 0) {
		global.log_backend = LOG_BACKEND_SYSLOG;
		openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR | LOG_PID, LOG_USER);
#if SYSTEMD_JOURNAL
	} else if (strcmp (logging_backend, "syslog") != 0) {
		global.log_backend = LOG_BACKEND_JOURNAL;

		/* ensure we read a monotonic timestamp. Reading the timestamp the first
		 * time causes a logging message. We don't want to do that during _nm_log_impl. */
		nm_utils_get_monotonic_timestamp_ns ();
#endif
	} else {
		global.log_backend = LOG_BACKEND_SYSLOG;
		openlog (G_LOG_DOMAIN, LOG_PID, LOG_DAEMON);
	}

	global.log_format_flags = log_format_flags;

	g_log_set_handler (G_LOG_DOMAIN,
	                   G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
	                   nm_log_handler,
	                   NULL);
}

