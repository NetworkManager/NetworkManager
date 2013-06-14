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
	 LOGD_VLAN | LOGD_BRIDGE)

#define LOGD_DEFAULT (LOGD_ALL & ~LOGD_WIFI_SCAN)

static guint32 log_level = LOGL_INFO | LOGL_WARN | LOGL_ERR;
static guint32 log_domains = LOGD_DEFAULT;
static gboolean syslog_opened;

typedef struct {
	guint32 num;
	const char *name;
} LogDesc;

static const LogDesc level_descs[] = {
	{ LOGL_ERR, "ERR" },
	{ LOGL_WARN | LOGL_ERR, "WARN" },
	{ LOGL_INFO | LOGL_WARN | LOGL_ERR, "INFO" },
	{ LOGL_DEBUG | LOGL_INFO | LOGL_WARN | LOGL_ERR, "DEBUG" },
	{ 0, NULL }
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

gboolean
nm_logging_setup (const char *level, const char *domains, GError **error)
{
	char **tmp, **iter;
	guint32 new_domains = 0;

	/* levels */
	if (level && strlen (level)) {
		gboolean found = FALSE;
		const LogDesc *diter;

		for (diter = &level_descs[0]; diter->name; diter++) {
			if (!strcasecmp (diter->name, level)) {
				log_level = diter->num;
				found = TRUE;
				break;
			}
		}

		if (!found) {
			g_set_error (error, NM_LOGGING_ERROR, NM_LOGGING_ERROR_UNKNOWN_LEVEL,
			             _("Unknown log level '%s'"), level);
			return FALSE;
		}
	}

	/* domains */
	if (domains && strlen (domains)) {
		tmp = g_strsplit_set (domains, ", ", 0);
		for (iter = tmp; iter && *iter; iter++) {
			const LogDesc *diter;
			gboolean found = FALSE;

			if (!strlen (*iter))
				continue;

			for (diter = &domain_descs[0]; diter->name; diter++) {
				if (!strcasecmp (diter->name, *iter)) {
					new_domains |= diter->num;
					found = TRUE;
					break;
				}
			}

			/* Check for combined domains */
			if (!strcasecmp (*iter, LOGD_ALL_STRING)) {
				new_domains = LOGD_ALL;
				found = TRUE;
			} else if (!strcasecmp (*iter, LOGD_DEFAULT_STRING)) {
				new_domains = LOGD_DEFAULT;
				found = TRUE;
			} else if (!strcasecmp (*iter, LOGD_DHCP_STRING)) {
				new_domains |= LOGD_DHCP;
				found = TRUE;
			} else if (!strcasecmp (*iter, LOGD_IP_STRING)) {
				new_domains |= LOGD_IP;
				found = TRUE;
			}

			/* Check for compatibility domains */
			if (!strcasecmp (*iter, "HW")) {
				new_domains |= LOGD_PLATFORM;
				found = TRUE;
			}

			if (!found) {
				g_set_error (error, NM_LOGGING_ERROR, NM_LOGGING_ERROR_UNKNOWN_DOMAIN,
				             _("Unknown log domain '%s'"), *iter);
				return FALSE;
			}
		}
		g_strfreev (tmp);
		log_domains = new_domains;
	}

	return TRUE;
}

const char *
nm_logging_level_to_string (void)
{
	const LogDesc *diter;

	for (diter = &level_descs[0]; diter->name; diter++) {
		if (diter->num == log_level)
			return diter->name;
	}
	g_warn_if_reached ();
	return "";
}

const char *
nm_logging_all_levels_to_string (void)
{
	static GString *str;

	if (G_UNLIKELY (!str)) {
		const LogDesc *diter;

		str = g_string_new (NULL);
		for (diter = &level_descs[0]; diter->name; diter++) {
			if (str->len)
				g_string_append_c (str, ',');
			g_string_append (str, diter->name);
		}
	}

	return str->str;
}

char *
nm_logging_domains_to_string (void)
{
	const LogDesc *diter;
	GString *str;

	str = g_string_sized_new (75);
	for (diter = &domain_descs[0]; diter->name; diter++) {
		if (diter->num & log_domains) {
			if (str->len)
				g_string_append_c (str, ',');
			g_string_append (str, diter->name);
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

		str = g_string_new ("DEFAULT");
		for (diter = &domain_descs[0]; diter->name; diter++) {
			g_string_append_c (str, ',');
			g_string_append (str, diter->name);
			if (diter->num == LOGD_DHCP6)
				g_string_append (str, ",DHCP");
			else if (diter->num == LOGD_IP6)
				g_string_append (str, ",IP");
		}
		g_string_append (str, ",ALL");
	}

	return str->str;
}

gboolean
nm_logging_level_enabled (guint32 level)
{
	return !!(log_level & level);
}

gboolean
nm_logging_domain_enabled (guint32 domain)
{
	return !!(log_domains & domain);
}

void
_nm_log (const char *loc,
         const char *func,
         guint32 domain,
         guint32 level,
         const char *fmt,
         ...)
{
	va_list args;
	char *msg;
	char *fullmsg = NULL;
	GTimeVal tv;
	int syslog_level = LOG_INFO;

	if (!(log_level & level) || !(log_domains & domain))
		return;

	va_start (args, fmt);
	msg = g_strdup_vprintf (fmt, args);
	va_end (args);

	if ((log_level & LOGL_DEBUG) && (level == LOGL_DEBUG)) {
		g_get_current_time (&tv);
		syslog_level = LOG_INFO;
		fullmsg = g_strdup_printf ("<debug> [%ld.%ld] [%s] %s(): %s", tv.tv_sec, tv.tv_usec, loc, func, msg);
	} else if ((log_level & LOGL_INFO) && (level == LOGL_INFO)) {
		syslog_level = LOG_INFO;
		fullmsg = g_strconcat ("<info> ", msg, NULL);
	} else if ((log_level & LOGL_WARN) && (level == LOGL_WARN)) {
		syslog_level = LOG_WARNING;
		fullmsg = g_strconcat ("<warn> ", msg, NULL);
	} else if ((log_level & LOGL_ERR) && (level == LOGL_ERR)) {
		syslog_level = LOG_ERR;
		g_get_current_time (&tv);
		fullmsg = g_strdup_printf ("<error> [%ld.%ld] [%s] %s(): %s", tv.tv_sec, tv.tv_usec, loc, func, msg);
	} else
		g_assert_not_reached ();

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
