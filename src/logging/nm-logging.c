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

#include "nm-logging.h"

static void
nm_log_handler (const gchar *log_domain,
                GLogLevelFlags level,
                const gchar *message,
                gpointer ignored);

#define LOGD_ALL \
	(LOGD_PLATFORM | LOGD_RFKILL | LOGD_ETHER | LOGD_WIFI | LOGD_BT | LOGD_MB | \
	 LOGD_DHCP4 | LOGD_DHCP6 | LOGD_PPP | LOGD_WIFI_SCAN | LOGD_IP4 | \
	 LOGD_IP6 | LOGD_AUTOIP4 | LOGD_DNS | LOGD_VPN | LOGD_SHARING | \
	 LOGD_SUPPLICANT | LOGD_AGENTS | LOGD_SETTINGS | LOGD_SUSPEND | \
	 LOGD_CORE | LOGD_DEVICE | LOGD_OLPC_MESH | LOGD_WIMAX | \
	 LOGD_INFINIBAND | LOGD_FIREWALL | LOGD_ADSL | LOGD_BOND | \
	 LOGD_VLAN | LOGD_BRIDGE | LOGD_DBUS_PROPS | LOGD_TEAM | LOGD_CONCHECK | \
	 LOGD_DCB)

#define LOGD_DEFAULT (LOGD_ALL & ~(LOGD_WIFI_SCAN | LOGD_DBUS_PROPS))

static guint32 log_level = LOGL_INFO;
static char *log_domains;
static guint64 logging[LOGL_MAX];
static gboolean syslog_opened;

typedef struct {
	guint64 num;
	const char *name;
} LogDesc;

static const char *level_names[LOGL_MAX] = {
	/* Must be in sync with nm-logging.h */
	"DEBUG",
	"INFO",
	"WARN",
	"ERR",
};

static const LogDesc domain_descs[] = {
	{ LOGD_NONE,      "NONE" },
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
	{ LOGD_OLPC_MESH, "OLPC" },
	{ LOGD_WIMAX,     "WIMAX" },
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
	{ 0, NULL }
};

/* Combined domains */
#define LOGD_ALL_STRING     "ALL"
#define LOGD_DEFAULT_STRING "DEFAULT"
#define LOGD_DHCP_STRING    "DHCP"
#define LOGD_IP_STRING      "IP"

/************************************************************************/

GQuark
nm_logging_error_quark (void)
{
    static GQuark ret = 0;

    if (ret == 0)
        ret = g_quark_from_static_string ("nm_logging_error");
    return ret;
}

/************************************************************************/

static gboolean
match_log_level (const char  *level,
                 guint32     *out_level,
                 GError     **error)
{
	int i;

	for (i = 0; i < LOGL_MAX; i++) {
		if (!strcasecmp (level_names[i], level)) {
			*out_level = i;
			return TRUE;
		}
	}

	g_set_error (error, NM_LOGGING_ERROR, NM_LOGGING_ERROR_UNKNOWN_LEVEL,
	             _("Unknown log level '%s'"), level);
	return FALSE;
}

gboolean
nm_logging_setup (const char *level, const char *domains, GError **error)
{
	guint64 new_logging[LOGL_MAX];
	guint32 new_log_level = log_level;
	int i;

	if (!domains)
		domains = log_domains ? log_domains : "DEFAULT";

	for (i = 0; i < LOGL_MAX; i++)
		new_logging[i] = 0;

	/* levels */
	if (level && strlen (level)) {
		if (!match_log_level (level, &new_log_level, error))
			return FALSE;
	}

	/* domains */
	if (domains && strlen (domains)) {
		char **tmp, **iter;

		tmp = g_strsplit_set (domains, ", ", 0);
		for (iter = tmp; iter && *iter; iter++) {
			const LogDesc *diter;
			guint32 domain_log_level;
			guint64 bits;
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
			if (!strcasecmp (*iter, LOGD_ALL_STRING))
				bits = LOGD_ALL;
			else if (!strcasecmp (*iter, LOGD_DEFAULT_STRING))
				bits = LOGD_DEFAULT;
			else if (!strcasecmp (*iter, LOGD_DHCP_STRING))
				bits = LOGD_DHCP;
			else if (!strcasecmp (*iter, LOGD_IP_STRING))
				bits = LOGD_IP;

			/* Check for compatibility domains */
			else if (!strcasecmp (*iter, "HW"))
				bits = LOGD_PLATFORM;

			else {
				for (diter = &domain_descs[0]; diter->name; diter++) {
					if (!strcasecmp (diter->name, *iter)) {
						bits = diter->num;
						break;
					}
				}
			}

			if (!bits) {
				g_set_error (error, NM_LOGGING_ERROR, NM_LOGGING_ERROR_UNKNOWN_DOMAIN,
				             _("Unknown log domain '%s'"), *iter);
				return FALSE;
			}

			for (i = 0; i < domain_log_level; i++)
				new_logging[i] &= ~bits;
			for (i = domain_log_level; i < LOGL_MAX; i++)
				new_logging[i] |= bits;
		}
		g_strfreev (tmp);

		if (log_domains != (char *)domains) {
			g_free (log_domains);
			log_domains = g_strdup (domains);
		}

		for (i = 0; i < LOGL_MAX; i++)
			logging[i] = new_logging[i];
	}

	log_level = new_log_level;

	return TRUE;
}

const char *
nm_logging_level_to_string (void)
{
	return level_names[log_level];
}

const char *
nm_logging_all_levels_to_string (void)
{
	static GString *str;

	if (G_UNLIKELY (!str)) {
		int i;

		str = g_string_new (NULL);
		for (i = 0; i < LOGL_MAX; i++) {
			if (str->len)
				g_string_append_c (str, ',');
			g_string_append (str, level_names[i]);
		}
	}

	return str->str;
}

char *
nm_logging_domains_to_string (void)
{
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
				g_string_append_printf (str, ":%s", level_names[i]);
				break;
			}
		}
		/* Check if it's logging at a higher level than the default. */
		if (!(diter->num & logging[log_level])) {
			for (i = log_level + 1; i < LOGL_MAX; i++) {
				if (diter->num & logging[i]) {
					g_string_append_printf (str, ":%s", level_names[i]);
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
nm_logging_enabled (guint32 level, guint64 domain)
{
	g_return_val_if_fail (level < LOGL_MAX, FALSE);

	return !!(logging[level] & domain);
}

void
_nm_log (const char *loc,
         const char *func,
         guint64 domain,
         guint32 level,
         const char *fmt,
         ...)
{
	va_list args;
	char *msg;
	char *fullmsg = NULL;
	GTimeVal tv;
	int syslog_level = LOG_INFO;

	g_return_if_fail (level < LOGL_MAX);

	if (!(logging[level] & domain))
		return;

	va_start (args, fmt);
	msg = g_strdup_vprintf (fmt, args);
	va_end (args);

	switch (level) {
	case LOGL_DEBUG:
		g_get_current_time (&tv);
		syslog_level = LOG_INFO;
		fullmsg = g_strdup_printf ("<debug> [%ld.%ld] [%s] %s(): %s", tv.tv_sec, tv.tv_usec, loc, func, msg);
		break;
	case LOGL_INFO:
		syslog_level = LOG_INFO;
		fullmsg = g_strconcat ("<info> ", msg, NULL);
		break;
	case LOGL_WARN:
		syslog_level = LOG_WARNING;
		fullmsg = g_strconcat ("<warn> ", msg, NULL);
		break;
	case LOGL_ERR:
		syslog_level = LOG_ERR;
		g_get_current_time (&tv);
		fullmsg = g_strdup_printf ("<error> [%ld.%ld] [%s] %s(): %s", tv.tv_sec, tv.tv_usec, loc, func, msg);
		break;
	default:
		g_assert_not_reached ();
	}

	if (syslog_opened)
		syslog (syslog_level, "%s", fullmsg);
	else {
		FILE *log_target;
		if (level == LOGL_WARN || level == LOGL_ERR)
			log_target = stderr;
		else
			log_target = stdout;
		fprintf (log_target, "%s\n", fullmsg);
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

	switch (level) {
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

	syslog (syslog_priority, "%s", message);
}

void
nm_logging_syslog_openlog (gboolean debug)
{
	static gsize log_handler_initialized = 0;

	if (debug)
		openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR | LOG_PID, LOG_USER);
	else
		openlog (G_LOG_DOMAIN, LOG_PID, LOG_DAEMON);
	syslog_opened = TRUE;

	if (g_once_init_enter (&log_handler_initialized)) {
		g_log_set_handler (G_LOG_DOMAIN,
		                   G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
		                   nm_log_handler,
		                   NULL);
		g_once_init_leave (&log_handler_initialized, 1);
	}
}

void
nm_logging_syslog_closelog (void)
{
	if (syslog_opened)
		closelog ();
}
