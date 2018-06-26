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

#if SYSTEMD_JOURNAL
#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-journal.h>
#endif

#include "nm-errors.h"
#include "nm-core-utils.h"

/* often we have some static string where we need to know the maximum length.
 * _MAX_LEN() returns @max but adds a debugging assertion that @str is indeed
 * shorter then @mac. */
#define _MAX_LEN(max, str) \
	({ \
		const char *const _str = (str); \
		\
		nm_assert (_str && strlen (str) < (max)); \
		(max); \
	})

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

	/* nm-logging uses syslog internally. Note that the three most-verbose syslog levels
	 * are LOG_DEBUG, LOG_INFO and LOG_NOTICE. Journal already highlights LOG_NOTICE
	 * as special.
	 *
	 * On the other hand, we have three levels LOGL_TRACE, LOGL_DEBUG and LOGL_INFO,
	 * which are regular messages not to be highlighted. For that reason, we must map
	 * LOGL_TRACE and LOGL_DEBUG both to syslog level LOG_DEBUG. */
	int syslog_level;

	GLogLevelFlags g_log_level;
} LogLevelDesc;

NMLogDomain _nm_logging_enabled_state[_LOGL_N_REAL] = {
	/* nm_logging_setup ("INFO", LOGD_DEFAULT_STRING, NULL, NULL);
	 *
	 * Note: LOGD_VPN_PLUGIN is special and must be disabled for
	 * DEBUG and TRACE levels. */
	[LOGL_INFO] = LOGD_DEFAULT,
	[LOGL_WARN] = LOGD_DEFAULT,
	[LOGL_ERR]  = LOGD_DEFAULT,
};

static struct Global {
	NMLogLevel log_level;
	bool uses_syslog:1;
	bool syslog_identifier_initialized:1;
	bool debug_stderr:1;
	const char *prefix;
	const char *syslog_identifier;
	enum {
		/* before we setup syslog (during start), the backend defaults to GLIB, meaning:
		 * we use g_log() for all logging. At that point, the application is not yet supposed
		 * to do any logging and doing so indicates a bug.
		 *
		 * Afterwards, the backend is either SYSLOG or JOURNAL. From that point, also
		 * g_log() is redirected to this backend via a logging handler. */
		LOG_BACKEND_GLIB,
		LOG_BACKEND_SYSLOG,
		LOG_BACKEND_JOURNAL,
	} log_backend;
	char *logging_domains_to_string;
	const LogLevelDesc level_desc[_LOGL_N];

#define _DOMAIN_DESC_LEN 39
	/* Would be nice to use C99 flexible array member here,
	 * but that feature doesn't seem well supported. */
	const LogDesc domain_desc[_DOMAIN_DESC_LEN];
} global = {
	/* nm_logging_setup ("INFO", LOGD_DEFAULT_STRING, NULL, NULL); */
	.log_level = LOGL_INFO,
	.log_backend = LOG_BACKEND_GLIB,
	.syslog_identifier = "SYSLOG_IDENTIFIER="G_LOG_DOMAIN,
	.prefix = "",
	.level_desc = {
		[LOGL_TRACE] = { "TRACE", "<trace>", LOG_DEBUG,   G_LOG_LEVEL_DEBUG,   },
		[LOGL_DEBUG] = { "DEBUG", "<debug>", LOG_DEBUG,   G_LOG_LEVEL_DEBUG,   },
		[LOGL_INFO]  = { "INFO",  "<info>",  LOG_INFO,    G_LOG_LEVEL_INFO,    },
		[LOGL_WARN]  = { "WARN",  "<warn>",  LOG_WARNING, G_LOG_LEVEL_MESSAGE, },
		[LOGL_ERR]   = { "ERR",   "<error>", LOG_ERR,     G_LOG_LEVEL_MESSAGE, },
		[_LOGL_OFF]  = { "OFF",   NULL,      0,           0,                   },
		[_LOGL_KEEP] = { "KEEP",  NULL,      0,           0,                   },
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
		{ LOGD_VPN_PLUGIN,"VPN_PLUGIN" },
		{ LOGD_PROXY,     "PROXY" },
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

/*****************************************************************************/

static char *_domains_to_string (gboolean include_level_override);

/*****************************************************************************/

static gboolean
_syslog_identifier_valid_domain (const char *domain)
{
	char c;

	if (!domain || !domain[0])
		return FALSE;

	/* we pass the syslog identifier as format string. No funny stuff. */

	for (; (c = domain[0]); domain++) {
		if (   (c >= 'a' && c <= 'z')
		    || (c >= 'A' && c <= 'Z')
		    || (c >= '0' && c <= '9')
		    || NM_IN_SET (c, '-', '_'))
			continue;
		return FALSE;
	}
	return TRUE;
}

static gboolean
_syslog_identifier_assert (const struct Global *gl)
{
	g_assert (gl);
	g_assert (gl->syslog_identifier);
	g_assert (g_str_has_prefix (gl->syslog_identifier, "SYSLOG_IDENTIFIER="));
	g_assert (_syslog_identifier_valid_domain (&gl->syslog_identifier[NM_STRLEN ("SYSLOG_IDENTIFIER=")]));
	return TRUE;
}

static const char *
syslog_identifier_domain (const struct Global *gl)
{
	nm_assert (_syslog_identifier_assert (gl));
	return &gl->syslog_identifier[NM_STRLEN ("SYSLOG_IDENTIFIER=")];
}

#if SYSTEMD_JOURNAL
static const char *
syslog_identifier_full (const struct Global *gl)
{
	nm_assert (_syslog_identifier_assert (gl));
	return &gl->syslog_identifier[0];
}
#endif

void
nm_logging_set_syslog_identifier (const char *domain)
{
	if (global.log_backend != LOG_BACKEND_GLIB)
		g_return_if_reached ();

	if (!_syslog_identifier_valid_domain (domain))
		g_return_if_reached ();

	if (global.syslog_identifier_initialized)
		g_return_if_reached ();

	global.syslog_identifier_initialized = TRUE;
	global.syslog_identifier = g_strdup_printf ("SYSLOG_IDENTIFIER=%s", domain);
	nm_assert (_syslog_identifier_assert (&global));
}

/*****************************************************************************/

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
	NMLogDomain new_logging[G_N_ELEMENTS (_nm_logging_enabled_state)];
	NMLogLevel new_log_level = global.log_level;
	char **tmp, **iter;
	int i;
	gboolean had_platform_debug;
	gs_free char *domains_free = NULL;

	g_return_val_if_fail (!bad_domains || !*bad_domains, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* domains */
	if (!domains || !*domains)
		domains = (domains_free = _domains_to_string (FALSE));

	for (i = 0; i < G_N_ELEMENTS (new_logging); i++)
		new_logging[i] = 0;

	/* levels */
	if (level && *level) {
		if (!match_log_level (level, &new_log_level, error))
			return FALSE;
		if (new_log_level == _LOGL_KEEP) {
			new_log_level = global.log_level;
			for (i = 0; i < G_N_ELEMENTS (new_logging); i++)
				new_logging[i] = _nm_logging_enabled_state[i];
		}
	}

	tmp = g_strsplit_set (domains, ", ", 0);
	for (iter = tmp; iter && *iter; iter++) {
		const LogDesc *diter;
		NMLogLevel domain_log_level;
		NMLogDomain bits;
		char *p;

		/* LOGD_VPN_PLUGIN is protected, that is, when setting ALL or DEFAULT,
		 * it does not enable the verbose levels DEBUG and TRACE, because that
		 * may expose sensitive data. */
		NMLogDomain protect = LOGD_NONE;

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

		if (domains_free) {
			/* The caller didn't provide any domains to set (`nmcli general logging level DEBUG`).
			 * We reset all domains that were previously set, but we still want to protect
			 * VPN_PLUGIN domain. */
			protect = LOGD_VPN_PLUGIN;
		}

		/* Check for combined domains */
		if (!g_ascii_strcasecmp (*iter, LOGD_ALL_STRING)) {
			bits = LOGD_ALL;
			protect = LOGD_VPN_PLUGIN;
		} else if (!g_ascii_strcasecmp (*iter, LOGD_DEFAULT_STRING)) {
			bits = LOGD_DEFAULT;
			protect = LOGD_VPN_PLUGIN;
		} else if (!g_ascii_strcasecmp (*iter, LOGD_DHCP_STRING))
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
				new_logging[i] = (new_logging[i] & ~bits) | (_nm_logging_enabled_state[i] & bits);
		} else {
			for (i = 0; i < G_N_ELEMENTS (new_logging); i++) {
				if (i < domain_log_level)
					new_logging[i] &= ~bits;
				else {
					new_logging[i] |= bits;
					if (   (protect & bits)
					    && i < LOGL_INFO)
						new_logging[i] &= ~protect;
				}
			}
		}
	}
	g_strfreev (tmp);

	g_clear_pointer (&global.logging_domains_to_string, g_free);

	had_platform_debug = nm_logging_enabled (LOGL_DEBUG, LOGD_PLATFORM);

	global.log_level = new_log_level;
	for (i = 0; i < G_N_ELEMENTS (new_logging); i++)
		_nm_logging_enabled_state[i] = new_logging[i];

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
		if (!(diter->num & _nm_logging_enabled_state[LOGL_ERR]))
			continue;

		if (str->len)
			g_string_append_c (str, ',');
		g_string_append (str, diter->name);

		if (!include_level_override)
			continue;

		/* Check if it's logging at a lower level than the default. */
		for (i = 0; i < global.log_level; i++) {
			if (diter->num & _nm_logging_enabled_state[i]) {
				g_string_append_printf (str, ":%s", global.level_desc[i].name);
				break;
			}
		}
		/* Check if it's logging at a higher level than the default. */
		if (!(diter->num & _nm_logging_enabled_state[global.log_level])) {
			for (i = global.log_level + 1; i < G_N_ELEMENTS (_nm_logging_enabled_state); i++) {
				if (diter->num & _nm_logging_enabled_state[i]) {
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

/**
 * nm_logging_get_level:
 * @domain: find the lowest enabled logging level for the
 *   given domain. If this is a set of multiple
 *   domains, the most verbose level will be returned.
 *
 * Returns: the lowest (most verbose) logging level for the
 *   give @domain, or %_LOGL_OFF if it is disabled.
 **/
NMLogLevel
nm_logging_get_level (NMLogDomain domain)
{
	NMLogLevel sl = _LOGL_OFF;

	G_STATIC_ASSERT (LOGL_TRACE == 0);
	while (   sl > LOGL_TRACE
	       && nm_logging_enabled (sl - 1, domain))
		sl--;
	return sl;
}

#if SYSTEMD_JOURNAL
static void
_iovec_set (struct iovec *iov, const void *str, gsize len)
{
	iov->iov_base = (void *) str;
	iov->iov_len = len;
}

static void
_iovec_set_string (struct iovec *iov, const char *str)
{
	_iovec_set (iov, str, strlen (str));
}

_nm_printf (3, 4)
static void
_iovec_set_format (struct iovec *iov, gpointer *iov_free, const char *format, ...)
{
	va_list ap;
	char *str;

	va_start (ap, format);
	str = g_strdup_vprintf (format, ap);
	va_end (ap);

	_iovec_set_string (iov, str);
	*iov_free = str;
}

#define _iovec_set_format_a(iov, reserve_extra, format, ...) \
	G_STMT_START { \
		const gsize _size = (reserve_extra) + (NM_STRLEN (format) + 3); \
		char *const _buf = g_alloca (_size); \
		int _len; \
		\
		_len = g_snprintf (_buf, _size, ""format"", ##__VA_ARGS__);\
		\
		nm_assert (_len >= 0); \
		nm_assert (_len <= _size); \
		nm_assert (_len == strlen (_buf)); \
		\
		_iovec_set ((iov), _buf, _len); \
	} G_STMT_END
#endif

void
_nm_log_impl (const char *file,
              guint line,
              const char *func,
              NMLogLevel level,
              NMLogDomain domain,
              int error,
              const char *ifname,
              const char *conn_uuid,
              const char *fmt,
              ...)
{
	va_list args;
	char *msg;
	GTimeVal tv;
	int errno_saved;

	if ((guint) level >= G_N_ELEMENTS (_nm_logging_enabled_state))
		g_return_if_reached ();

	if (!(_nm_logging_enabled_state[level] & domain))
		return;

	errno_saved = errno;

	/* Make sure that %m maps to the specified error */
	if (error != 0) {
		if (error < 0)
			error = -error;
		errno = error;
	}

	va_start (args, fmt);
	msg = g_strdup_vprintf (fmt, args);
	va_end (args);

#define MESSAGE_FMT "%s%-7s [%ld.%04ld] %s"
#define MESSAGE_ARG(global, tv, msg) \
    (global).prefix, \
    (global).level_desc[level].level_str, \
    (tv).tv_sec, \
    ((tv).tv_usec / 100), \
    (msg)

	g_get_current_time (&tv);

	if (global.debug_stderr)
		g_printerr (MESSAGE_FMT"\n", MESSAGE_ARG (global, tv, msg));

	switch (global.log_backend) {
#if SYSTEMD_JOURNAL
	case LOG_BACKEND_JOURNAL:
		{
			gint64 now, boottime;
#define _NUM_MAX_FIELDS_SYSLOG_FACILITY 10
			struct iovec iov_data[12 + _NUM_MAX_FIELDS_SYSLOG_FACILITY];
			struct iovec *iov = iov_data;
			gpointer iov_free_data[5];
			gpointer *iov_free = iov_free_data;
			nm_auto_free_gstring GString *s_domain_all = NULL;

			now = nm_utils_get_monotonic_timestamp_ns ();
			boottime = nm_utils_monotonic_timestamp_as_boottime (now, 1);

			_iovec_set_format_a (iov++, 30, "PRIORITY=%d", global.level_desc[level].syslog_level);
			_iovec_set_format (iov++, iov_free++, "MESSAGE="MESSAGE_FMT, MESSAGE_ARG (global, tv, msg));
			_iovec_set_string (iov++, syslog_identifier_full (&global));
			_iovec_set_format_a (iov++, 30, "SYSLOG_PID=%ld", (long) getpid ());
			{
				const LogDesc *diter;
				int i_domain = _NUM_MAX_FIELDS_SYSLOG_FACILITY;
				const char *s_domain_1 = NULL;
				NMLogDomain dom_all = domain;
				NMLogDomain dom = dom_all & _nm_logging_enabled_state[level];

				for (diter = &global.domain_desc[0]; diter->name; diter++) {
					if (!NM_FLAGS_ANY (dom_all, diter->num))
						continue;

					/* construct a list of all domains (not only the enabled ones).
					 * Note that in by far most cases, there is only one domain present.
					 * Hence, save the construction of the GString. */
					dom_all &= ~diter->num;
					if (!s_domain_1)
						s_domain_1 = diter->name;
					else {
						if (!s_domain_all) {
							s_domain_all = g_string_new ("NM_LOG_DOMAINS=");
							g_string_append (s_domain_all, s_domain_1);
						}
						g_string_append_c (s_domain_all, ',');
						g_string_append (s_domain_all, diter->name);
					}

					if (NM_FLAGS_ANY (dom, diter->num)) {
						if (i_domain > 0) {
							/* SYSLOG_FACILITY is specified multiple times for each domain that is actually enabled. */
							_iovec_set_format_a (iov++, _MAX_LEN (30, diter->name), "SYSLOG_FACILITY=%s", diter->name);
							i_domain--;
						}
						dom &= ~diter->num;
					}
					if (!dom && !dom_all)
						break;
				}
				if (s_domain_all)
					_iovec_set (iov++, s_domain_all->str, s_domain_all->len);
				else
					_iovec_set_format_a (iov++, _MAX_LEN (30, s_domain_1), "NM_LOG_DOMAINS=%s", s_domain_1);
			}
			_iovec_set_format_a (iov++, _MAX_LEN (15, global.level_desc[level].name), "NM_LOG_LEVEL=%s", global.level_desc[level].name);
			if (func)
				_iovec_set_format (iov++, iov_free++, "CODE_FUNC=%s", func);
			_iovec_set_format (iov++, iov_free++, "CODE_FILE=%s", file ?: "");
			_iovec_set_format_a (iov++, 20, "CODE_LINE=%u", line);
			_iovec_set_format_a (iov++, 60, "TIMESTAMP_MONOTONIC=%lld.%06lld", (long long) (now / NM_UTILS_NS_PER_SECOND), (long long) ((now % NM_UTILS_NS_PER_SECOND) / 1000));
			_iovec_set_format_a (iov++, 60, "TIMESTAMP_BOOTTIME=%lld.%06lld", (long long) (boottime / NM_UTILS_NS_PER_SECOND), (long long) ((boottime % NM_UTILS_NS_PER_SECOND) / 1000));
			if (error != 0)
				_iovec_set_format_a (iov++, 30, "ERRNO=%d", error);
			if (ifname)
				_iovec_set_format (iov++, iov_free++, "NM_DEVICE=%s", ifname);
			if (conn_uuid)
				_iovec_set_format (iov++, iov_free++, "NM_CONNECTION=%s", conn_uuid);

			nm_assert (iov <= &iov_data[G_N_ELEMENTS (iov_data)]);
			nm_assert (iov_free <= &iov_free_data[G_N_ELEMENTS (iov_free_data)]);

			sd_journal_sendv (iov_data, iov - iov_data);

			for (; --iov_free >= iov_free_data; )
				g_free (*iov_free);
		}
		break;
#endif
	case LOG_BACKEND_SYSLOG:
		syslog (global.level_desc[level].syslog_level,
		        MESSAGE_FMT, MESSAGE_ARG (global, tv, msg));
		break;
	default:
		g_log (syslog_identifier_domain (&global), global.level_desc[level].g_log_level,
		       MESSAGE_FMT, MESSAGE_ARG (global, tv, msg));
		break;
	}

	g_free (msg);

	errno = errno_saved;
}

/*****************************************************************************/

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

	if (global.debug_stderr)
		g_printerr ("%s%s\n", global.prefix, message ?: "");

	switch (global.log_backend) {
#if SYSTEMD_JOURNAL
	case LOG_BACKEND_JOURNAL:
		{
			gint64 now, boottime;

			now = nm_utils_get_monotonic_timestamp_ns ();
			boottime = nm_utils_monotonic_timestamp_as_boottime (now, 1);

			sd_journal_send ("PRIORITY=%d", syslog_priority,
			                 "MESSAGE=%s%s", global.prefix, message ?: "",
			                 syslog_identifier_full (&global),
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
		syslog (syslog_priority, "%s%s", global.prefix, message ?: "");
		break;
	}
}

gboolean
nm_logging_syslog_enabled (void)
{
	return global.uses_syslog;
}

void
nm_logging_set_prefix (const char *format, ...)
{
	char *prefix;
	va_list ap;

	/* prefix can only be set once, to a non-empty string. Also, after
	 * nm_logging_syslog_openlog() the prefix cannot be set either. */
	if (global.log_backend != LOG_BACKEND_GLIB)
		g_return_if_reached ();
	if (global.prefix[0])
		g_return_if_reached ();

	va_start (ap, format);
	prefix = g_strdup_vprintf (format, ap);
	va_end (ap);

	if (!prefix || !prefix[0])
		g_return_if_reached ();

	/* we pass the allocated string on and never free it. */
	global.prefix = prefix;
}

void
nm_logging_syslog_openlog (const char *logging_backend, gboolean debug)
{
	gboolean fetch_monotonic_timestamp = FALSE;
	gboolean obsolete_debug_backend = FALSE;

	nm_assert (NM_IN_STRSET (""NM_CONFIG_DEFAULT_LOGGING_BACKEND,
	                         NM_LOG_CONFIG_BACKEND_JOURNAL,
	                         NM_LOG_CONFIG_BACKEND_SYSLOG));

	if (global.log_backend != LOG_BACKEND_GLIB)
		g_return_if_reached ();

	if (!logging_backend)
		logging_backend = ""NM_CONFIG_DEFAULT_LOGGING_BACKEND;

	if (nm_streq (logging_backend, NM_LOG_CONFIG_BACKEND_DEBUG)) {
		/* "debug" was wrongly documented as a valid logging backend. It makes no sense however,
		 * because printing to stderr only makes sense when not demonizing. Whether to daemonize
		 * is only controlled via command line arguments (--no-daemon, --debug) and not via the
		 * logging backend from configuration.
		 *
		 * Fall back to the default. */
		logging_backend = ""NM_CONFIG_DEFAULT_LOGGING_BACKEND;
		obsolete_debug_backend = TRUE;
	}

#if SYSTEMD_JOURNAL
	if (!nm_streq (logging_backend, NM_LOG_CONFIG_BACKEND_SYSLOG)) {
		global.log_backend = LOG_BACKEND_JOURNAL;
		global.uses_syslog = TRUE;
		global.debug_stderr = debug;
		fetch_monotonic_timestamp = TRUE;
	} else
#endif
	{
		global.log_backend = LOG_BACKEND_SYSLOG;
		global.uses_syslog = TRUE;
		global.debug_stderr = debug;
		openlog (syslog_identifier_domain (&global), LOG_PID, LOG_DAEMON);
	}

	g_log_set_handler (syslog_identifier_domain (&global),
	                   G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
	                   nm_log_handler,
	                   NULL);

	if (fetch_monotonic_timestamp) {
		/* ensure we read a monotonic timestamp. Reading the timestamp the first
		 * time causes a logging message. We don't want to do that during _nm_log_impl. */
		nm_utils_get_monotonic_timestamp_ns ();
	}

	if (obsolete_debug_backend)
		nm_log_dbg (LOGD_CORE, "config: ignore deprecated logging backend 'debug', fallback to '%s'", logging_backend);

	if (nm_streq (logging_backend, NM_LOG_CONFIG_BACKEND_SYSLOG)) {
		/* good */
	} else if (nm_streq (logging_backend, NM_LOG_CONFIG_BACKEND_JOURNAL)) {
#if !SYSTEMD_JOURNAL
		nm_log_warn (LOGD_CORE, "config: logging backend 'journal' is not available, fallback to 'syslog'");
#endif
	} else {
		nm_log_warn (LOGD_CORE, "config: invalid logging backend '%s', fallback to '%s'",
		             logging_backend,
#if SYSTEMD_JOURNAL
		             NM_LOG_CONFIG_BACKEND_JOURNAL
#else
		             NM_LOG_CONFIG_BACKEND_SYSLOG
#endif
		             );
	}
}
