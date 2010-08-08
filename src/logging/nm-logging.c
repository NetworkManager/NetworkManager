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
 * Copyright (C) 2006 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <syslog.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <execinfo.h>
#include <strings.h>
#include <string.h>

#include <glib/gi18n.h>

#include "nm-logging.h"

static guint32 log_level = LOGL_INFO | LOGL_WARN | LOGL_ERR;
static guint32 log_domains = \
	LOGD_HW | LOGD_RFKILL | LOGD_ETHER | LOGD_WIFI | LOGD_BT | LOGD_MB | \
	LOGD_DHCP4 | LOGD_DHCP6 | LOGD_PPP | LOGD_IP4 | LOGD_IP6 | LOGD_AUTOIP4 | \
	LOGD_DNS | LOGD_VPN | LOGD_SHARING | LOGD_SUPPLICANT | LOGD_USER_SET | \
	LOGD_SYS_SET | LOGD_SUSPEND | LOGD_CORE | LOGD_DEVICE | LOGD_OLPC_MESH;

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
	{ LOGD_HW,        "HW" },
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
	{ LOGD_USER_SET,  "USER_SET" },
	{ LOGD_SYS_SET,   "SYS_SET" },
	{ LOGD_SUSPEND,   "SUSPEND" },
	{ LOGD_CORE,      "CORE" },
	{ LOGD_DEVICE,    "DEVICE" },
	{ LOGD_OLPC_MESH, "OLPC" },
	{ 0, NULL }
};

/************************************************************************/

enum {
    NM_LOGGING_ERROR_UNKNOWN_LEVEL = 0,
    NM_LOGGING_ERROR_UNKNOWN_DOMAIN = 1,
};

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GQuark
nm_logging_error_quark (void)
{
    static GQuark ret = 0;

    if (ret == 0)
        ret = g_quark_from_static_string ("nm_logging_error");
    return ret;
}

GType
nm_logging_error_get_type (void)
{
    static GType etype = 0;

    if (etype == 0) {
        static const GEnumValue values[] = {
            ENUM_ENTRY (NM_LOGGING_ERROR_UNKNOWN_LEVEL,  "UnknownLevel"),
            ENUM_ENTRY (NM_LOGGING_ERROR_UNKNOWN_DOMAIN, "UnknownDomain"),
            { 0, 0, 0 }
        };
        etype = g_enum_register_static ("NMLoggingError", values);
    }
    return etype;
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

gboolean
nm_logging_level_enabled (guint32 level)
{
	return !!(log_level & level);
}

void _nm_log (const char *loc,
              const char *func,
              guint32 domain,
              guint32 level,
              const char *fmt,
              ...)
{
	va_list args;
	char *msg;
	GTimeVal tv;

	if (!(log_level & level) || !(log_domains & domain))
		return;

	va_start (args, fmt);
	msg = g_strdup_vprintf (fmt, args);
	va_end (args);

	if ((log_level & LOGL_DEBUG) && (level == LOGL_DEBUG)) {
		g_get_current_time (&tv);
		syslog (LOG_INFO, "<debug> [%ld.%ld] [%s] %s(): %s\n", tv.tv_sec, tv.tv_usec, loc, func, msg);
	} else if ((log_level & LOGL_INFO) && (level == LOGL_INFO))
		syslog (LOG_INFO, "<info> %s\n", msg);
	else if ((log_level & LOGL_WARN) && (level == LOGL_WARN))
		syslog (LOG_WARNING, "<warn> %s\n", msg);
	else if ((log_level & LOGL_ERR) && (level == LOGL_ERR)) {
		g_get_current_time (&tv);
		syslog (LOG_ERR, "<error> [%ld.%ld] [%s] %s(): %s\n", tv.tv_sec, tv.tv_usec, loc, func, msg);
	}
	g_free (msg);
}

/************************************************************************/

static void
fallback_get_backtrace (void)
{
	void *frames[64];
	Dl_info info;
	size_t size;
	guint32 i;
	const char *name;

	size = backtrace (frames, G_N_ELEMENTS (frames));

	syslog (LOG_CRIT, "******************* START **********************************");
	for (i = 0; i < size; i++) {
		dladdr (frames[i], &info);
		name = (info.dli_fname && *info.dli_fname) ? info.dli_fname : "(vdso)";
		if (info.dli_saddr) {
			syslog (LOG_CRIT, "Frame %d: %s (%s+0x%lx) [%p]",
			        i, name,
			        info.dli_sname,
			        (gulong)(frames[i] - info.dli_saddr),
			        frames[i]);
		} else {
			syslog (LOG_CRIT, "Frame %d: %s (%p+0x%lx) [%p]",
			        i, name,
			        info.dli_fbase,
			        (gulong)(frames[i] - info.dli_saddr),
			        frames[i]);
		}
	}
	syslog (LOG_CRIT, "******************* END **********************************");
}


static gboolean
crashlogger_get_backtrace (void)
{
	gboolean success = FALSE;
	int pid;	

	pid = fork();
	if (pid > 0)
	{
		/* Wait for the child to finish */
		int estatus;
		if (waitpid (pid, &estatus, 0) != -1)
		{
			/* Only succeed if the crashlogger succeeded */
			if (WIFEXITED (estatus) && (WEXITSTATUS (estatus) == 0))
				success = TRUE;
		}
	}
	else if (pid == 0)
	{
		/* Child process */
		execl (LIBEXECDIR"/nm-crash-logger",
				LIBEXECDIR"/nm-crash-logger", NULL);
	}

	return success;
}


void
nm_logging_backtrace (void)
{
	struct stat s;
	gboolean fallback = TRUE;
	
	/* Try to use gdb via nm-crash-logger if it exists, since
	 * we get much better information out of it.  Otherwise
	 * fall back to execinfo.
	 */
	if (stat (LIBEXECDIR"/nm-crash-logger", &s) == 0)
		fallback = crashlogger_get_backtrace () ? FALSE : TRUE;

	if (fallback)
		fallback_get_backtrace ();
}


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
nm_logging_start (gboolean become_daemon)
{
	if (become_daemon)
		openlog (G_LOG_DOMAIN, LOG_PID, LOG_DAEMON);
	else
		openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR | LOG_PID, LOG_USER);

	g_log_set_handler (G_LOG_DOMAIN, 
	                   G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
	                   nm_log_handler,
	                   NULL);
}

void
nm_logging_shutdown (void)
{
	closelog ();
}
