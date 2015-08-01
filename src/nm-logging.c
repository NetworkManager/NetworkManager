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

#include "config.h"

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

#include <glib/gi18n.h>

#if SYSTEMD_JOURNAL
#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-journal.h>
#endif

#include "nm-glib.h"
#include "nm-logging.h"
#include "nm-errors.h"
#include "gsystem-local-alloc.h"
#include "NetworkManagerUtils.h"

static void
nm_log_handler (const gchar *log_domain,
                GLogLevelFlags level,
                const gchar *message,
                gpointer ignored);

static NMLogLevel log_level = LOGL_INFO;
static char *log_domains;
static NMLogDomain logging[_LOGL_N_REAL];
static gboolean logging_set_up;
enum {
	LOG_BACKEND_GLIB,
	LOG_BACKEND_SYSLOG,
	LOG_BACKEND_JOURNAL,
	LOG_BACKEND_JOURNAL_SYSLOG_STYLE,
} log_backend = LOG_BACKEND_GLIB;
static char *logging_domains_to_string;

typedef struct {
	NMLogDomain num;
	const char *name;
} LogDesc;

typedef struct {
	const char *name;
	const char *level_str;
	int syslog_level;
	GLogLevelFlags g_log_level;
	gboolean full_details;
} LogLevelDesc;

static const LogLevelDesc level_desc[_LOGL_N] = {
	[LOGL_TRACE] = { "TRACE", "<trace>", LOG_DEBUG,   G_LOG_LEVEL_DEBUG,   TRUE  },
	[LOGL_DEBUG] = { "DEBUG", "<debug>", LOG_INFO,    G_LOG_LEVEL_DEBUG,   TRUE  },
	[LOGL_INFO]  = { "INFO",  "<info>",  LOG_INFO,    G_LOG_LEVEL_MESSAGE, FALSE },
	[LOGL_WARN]  = { "WARN",  "<warn>",  LOG_WARNING, G_LOG_LEVEL_WARNING, FALSE },
	[LOGL_ERR]   = { "ERR",   "<error>", LOG_ERR,     G_LOG_LEVEL_WARNING, TRUE  },
	[_LOGL_OFF]  = { "OFF",   NULL,      0,           0,                   FALSE },
};

static const LogDesc domain_descs[] = {
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
	{ 0, NULL }
};

/* We have more then 32 logging domains. Assert that it compiles to a 64 bit sized enum */
G_STATIC_ASSERT (sizeof (NMLogDomain) >= sizeof (guint64));

/* Combined domains */
#define LOGD_ALL_STRING     "ALL"
#define LOGD_DEFAULT_STRING "DEFAULT"
#define LOGD_DHCP_STRING    "DHCP"
#define LOGD_IP_STRING      "IP"

/************************************************************************/

static void
_ensure_initialized (void)
{
	if (G_UNLIKELY (!logging_set_up))
		nm_logging_setup ("INFO", "DEFAULT", NULL, NULL);
}

static gboolean
match_log_level (const char  *level,
                 NMLogLevel  *out_level,
                 GError     **error)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS (level_desc); i++) {
		if (!g_ascii_strcasecmp (level_desc[i].name, level)) {
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
	NMLogDomain new_logging[G_N_ELEMENTS (logging)];
	NMLogLevel new_log_level = log_level;
	char **tmp, **iter;
	int i;

	g_return_val_if_fail (!bad_domains || !*bad_domains, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	logging_set_up = TRUE;

	for (i = 0; i < G_N_ELEMENTS (new_logging); i++)
		new_logging[i] = 0;

	/* levels */
	if (level && *level) {
		if (!match_log_level (level, &new_log_level, error))
			return FALSE;
	}

	/* domains */
	if (!domains || !*domains)
		domains = log_domains ? log_domains : "DEFAULT";

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
			for (diter = &domain_descs[0]; diter->name; diter++) {
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

		for (i = 0; i < G_N_ELEMENTS (new_logging); i++) {
			if (i < domain_log_level)
				new_logging[i] &= ~bits;
			else
				new_logging[i] |= bits;
		}
	}
	g_strfreev (tmp);

	if (log_domains != (char *)domains) {
		g_free (log_domains);
		log_domains = g_strdup (domains);
	}

	g_clear_pointer (&logging_domains_to_string, g_free);

	log_level = new_log_level;
	for (i = 0; i < G_N_ELEMENTS (new_logging); i++)
		logging[i] = new_logging[i];

	if (unrecognized)
		*bad_domains = g_string_free (unrecognized, FALSE);

	return TRUE;
}

const char *
nm_logging_level_to_string (void)
{
	return level_desc[log_level].name;
}

const char *
nm_logging_all_levels_to_string (void)
{
	static GString *str;

	if (G_UNLIKELY (!str)) {
		int i;

		str = g_string_new (NULL);
		for (i = 0; i < G_N_ELEMENTS (level_desc); i++) {
			if (str->len)
				g_string_append_c (str, ',');
			g_string_append (str, level_desc[i].name);
		}
	}

	return str->str;
}

const char *
nm_logging_domains_to_string (void)
{
	_ensure_initialized ();

	if (G_UNLIKELY (!logging_domains_to_string)) {
		const LogDesc *diter;
		GString *str;
		int i;

		/* We don't just return g_strdup (log_domains) because we want to expand
		 * "DEFAULT" and "ALL".
		 */

		str = g_string_sized_new (75);
		for (diter = &domain_descs[0]; diter->name; diter++) {
			/* If it's set for any lower level, it will also be set for LOGL_ERR */
			if (!(diter->num & logging[LOGL_ERR]))
				continue;

			if (str->len)
				g_string_append_c (str, ',');
			g_string_append (str, diter->name);

			/* Check if it's logging at a lower level than the default. */
			for (i = 0; i < log_level; i++) {
				if (diter->num & logging[i]) {
					g_string_append_printf (str, ":%s", level_desc[i].name);
					break;
				}
			}
			/* Check if it's logging at a higher level than the default. */
			if (!(diter->num & logging[log_level])) {
				for (i = log_level + 1; i < G_N_ELEMENTS (logging); i++) {
					if (diter->num & logging[i]) {
						g_string_append_printf (str, ":%s", level_desc[i].name);
						break;
					}
				}
			}
		}
		logging_domains_to_string = g_string_free (str, FALSE);
	}
	return logging_domains_to_string;
}

const char *
nm_logging_all_domains_to_string (void)
{
	static GString *str;

	if (G_UNLIKELY (!str)) {
		const LogDesc *diter;

		str = g_string_new (LOGD_DEFAULT_STRING);
		for (diter = &domain_descs[0]; diter->name; diter++) {
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
	if ((guint) level >= G_N_ELEMENTS (logging))
		g_return_val_if_reached (FALSE);

	_ensure_initialized ();

	return !!(logging[level] & domain);
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
#define _iovec_set_literal_string(iov, iov_free, i, str) _iovec_set_string ((iov), (iov_free), (i), (""str""), STRLEN (str))
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
	char *fullmsg = NULL;
	GTimeVal tv;

	if ((guint) level >= G_N_ELEMENTS (logging))
		g_return_if_reached ();

	_ensure_initialized ();

	if (!(logging[level] & domain))
		return;

	/* Make sure that %m maps to the specified error */
	if (error != 0)
		errno = error;

	va_start (args, fmt);
	msg = g_strdup_vprintf (fmt, args);
	va_end (args);

	switch (log_backend) {
#if SYSTEMD_JOURNAL
	case LOG_BACKEND_JOURNAL:
	case LOG_BACKEND_JOURNAL_SYSLOG_STYLE:
		{
			gint64 now, boottime;
#define _NUM_MAX_FIELDS_SYSLOG_FACILITY 10
#define _NUM_FIELDS (10 + _NUM_MAX_FIELDS_SYSLOG_FACILITY)
			int i_field = 0;
			struct iovec iov[_NUM_FIELDS];
			gboolean iov_free[_NUM_FIELDS];

			now = nm_utils_get_monotonic_timestamp_ns ();
			boottime = nm_utils_monotonic_timestamp_as_boottime (now, 1);

			_iovec_set_format (iov, iov_free, i_field++, "PRIORITY=%d", level_desc[level].syslog_level);
			if (   log_backend == LOG_BACKEND_JOURNAL_SYSLOG_STYLE
			    && level_desc[level].full_details) {
				g_get_current_time (&tv);
				_iovec_set_format (iov, iov_free, i_field++, "MESSAGE=%-7s [%ld.%06ld] [%s:%u] %s(): %s", level_desc[level].level_str, tv.tv_sec, tv.tv_usec, file, line, func, msg);
			} else
				_iovec_set_format (iov, iov_free, i_field++, "MESSAGE=%-7s %s", level_desc[level].level_str, msg);
			_iovec_set_literal_string (iov, iov_free, i_field++, "SYSLOG_IDENTIFIER=" G_LOG_DOMAIN);
			_iovec_set_format (iov, iov_free, i_field++, "SYSLOG_PID=%ld", (long) getpid ());
			{
				const LogDesc *diter;
				int i_domain = _NUM_MAX_FIELDS_SYSLOG_FACILITY;
				const char *s_domain_1 = NULL;
				GString *s_domain_all = NULL;
				NMLogDomain dom_all = domain;
				NMLogDomain dom = dom_all & logging[level];

				for (diter = &domain_descs[0]; diter->name; diter++) {
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
			_iovec_set_format (iov, iov_free, i_field++, "NM_LOG_LEVEL=%s", level_desc[level].name);
			_iovec_set_format (iov, iov_free, i_field++, "CODE_FUNC=%s", func);
			_iovec_set_format (iov, iov_free, i_field++, "CODE_FILE=%s", file);
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
		if (level_desc[level].full_details) {
			g_get_current_time (&tv);
			fullmsg = g_strdup_printf ("%-7s [%ld.%06ld] [%s:%u] %s(): %s", level_desc[level].level_str, tv.tv_sec, tv.tv_usec, file, line, func, msg);
		} else
			fullmsg = g_strdup_printf ("%-7s %s", level_desc[level].level_str, msg);

		if (log_backend == LOG_BACKEND_SYSLOG)
			syslog (level_desc[level].syslog_level, "%s", fullmsg);
		else
			g_log (G_LOG_DOMAIN, level_desc[level].g_log_level, "%s", fullmsg);
		break;
	}

	g_free (msg);
	g_free (fullmsg);
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

	switch (log_backend) {
#if SYSTEMD_JOURNAL
	case LOG_BACKEND_JOURNAL:
	case LOG_BACKEND_JOURNAL_SYSLOG_STYLE:
		{
			gint64 now, boottime;

			now = nm_utils_get_monotonic_timestamp_ns ();
			boottime = nm_utils_monotonic_timestamp_as_boottime (now, 1);

			sd_journal_send ("PRIORITY=%d", syslog_priority,
			                 "MESSAGE=%s", str_if_set (message, ""),
			                 "SYSLOG_IDENTIFIER=%s", G_LOG_DOMAIN,
			                 "SYSLOG_PID=%ld", (long) getpid (),
			                 "SYSLOG_FACILITY=GLIB",
			                 "GLIB_DOMAIN=%s", str_if_set (log_domain, ""),
			                 "GLIB_LEVEL=%d", (int) (level & G_LOG_LEVEL_MASK),
			                 "TIMESTAMP_MONOTONIC=%lld.%06lld", (long long) (now / NM_UTILS_NS_PER_SECOND), (long long) ((now % NM_UTILS_NS_PER_SECOND) / 1000),
			                 "TIMESTAMP_BOOTTIME=%lld.%06lld", (long long) (boottime / NM_UTILS_NS_PER_SECOND), (long long) ((boottime % NM_UTILS_NS_PER_SECOND) / 1000),
			                 NULL);
		}
		break;
#endif
	default:
		syslog (syslog_priority, "%s", str_if_set (message, ""));
		break;
	}
}

void
nm_logging_syslog_openlog (const char *logging_backend)
{
	if (log_backend != LOG_BACKEND_GLIB)
		g_return_if_reached ();

	if (!logging_backend)
		logging_backend = ""NM_CONFIG_LOGGING_BACKEND_DEFAULT;

	if (strcmp (logging_backend, "debug") == 0) {
		log_backend = LOG_BACKEND_SYSLOG;
		openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR | LOG_PID, LOG_USER);
#if SYSTEMD_JOURNAL
	} else if (strcmp (logging_backend, "syslog") != 0) {
		if (strcmp (logging_backend, "journal-syslog-style") != 0)
			log_backend = LOG_BACKEND_JOURNAL;
		else
			log_backend = LOG_BACKEND_JOURNAL_SYSLOG_STYLE;

		/* ensure we read a monotonic timestamp. Reading the timestamp the first
		 * time causes a logging message. We don't want to do that during _nm_log_impl. */
		nm_utils_get_monotonic_timestamp_ns ();
#endif
	} else {
		log_backend = LOG_BACKEND_SYSLOG;
		openlog (G_LOG_DOMAIN, LOG_PID, LOG_DAEMON);
	}

	g_log_set_handler (G_LOG_DOMAIN,
	                   G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
	                   nm_log_handler,
	                   NULL);
}

