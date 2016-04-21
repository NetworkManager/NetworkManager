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
 * Copyright (C) 2010 - 2012 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "nm-core-internal.h"

#include "nm-dns-plugin.h"
#include "NetworkManagerUtils.h"

typedef struct {
	GPid pid;
	guint watch_id;
	char *progname;
	char *pidfile;
} NMDnsPluginPrivate;

#define NM_DNS_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DNS_PLUGIN, NMDnsPluginPrivate))

G_DEFINE_TYPE_EXTENDED (NMDnsPlugin, nm_dns_plugin, G_TYPE_OBJECT, G_TYPE_FLAG_ABSTRACT, {})

enum {
	FAILED,
	CHILD_QUIT,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

/******************************************************************************/

#define _NMLOG_PREFIX_NAME                "dns-plugin"
#define _NMLOG_DOMAIN                     LOGD_DNS
#define _NMLOG(level, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        \
        if (nm_logging_enabled (__level, _NMLOG_DOMAIN)) { \
            char __prefix[20]; \
            const NMDnsPlugin *const __self = (self); \
            \
            _nm_log (__level, _NMLOG_DOMAIN, 0, \
                     "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME, \
                     (!__self \
                        ? "" \
                        : nm_sprintf_buf (__prefix, "[%p]", __self)) \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/******************************************************************************/

gboolean
nm_dns_plugin_update (NMDnsPlugin *self,
                      const GSList *vpn_configs,
                      const GSList *dev_configs,
                      const GSList *other_configs,
                      const NMGlobalDnsConfig *global_config,
                      const char *hostname)
{
	g_return_val_if_fail (NM_DNS_PLUGIN_GET_CLASS (self)->update != NULL, FALSE);

	return NM_DNS_PLUGIN_GET_CLASS (self)->update (self,
	                                               vpn_configs,
	                                               dev_configs,
	                                               other_configs,
	                                               global_config,
	                                               hostname);
}

static gboolean
is_caching (NMDnsPlugin *self)
{
	return FALSE;
}

gboolean
nm_dns_plugin_is_caching (NMDnsPlugin *self)
{
	return NM_DNS_PLUGIN_GET_CLASS (self)->is_caching (self);
}

const char *
nm_dns_plugin_get_name (NMDnsPlugin *self)
{
	g_assert (NM_DNS_PLUGIN_GET_CLASS (self)->get_name);
	return NM_DNS_PLUGIN_GET_CLASS (self)->get_name (self);
}

/********************************************/

static void
_clear_pidfile (NMDnsPlugin *self)
{
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	if (priv->pidfile) {
		unlink (priv->pidfile);
		g_clear_pointer (&priv->pidfile, g_free);
	}
}

static void
kill_existing (const char *progname, const char *pidfile, const char *kill_match)
{
	glong pid;
	gs_free char *contents = NULL;
	gs_free char *cmdline_contents = NULL;
	guint64 start_time;
	char proc_path[256];
	gs_free_error GError *error = NULL;

	if (!pidfile)
		return;

	if (!kill_match)
		g_return_if_reached ();

	if (!g_file_get_contents (pidfile, &contents, NULL, &error)) {
		if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			return;
		goto out;
	}

	pid = _nm_utils_ascii_str_to_int64 (contents, 10, 2, INT_MAX, -1);
	if (pid == -1)
		goto out;

	start_time = nm_utils_get_start_time_for_pid (pid, NULL, NULL);
	if (start_time == 0)
		goto out;

	nm_sprintf_buf (proc_path, "/proc/%ld/cmdline", pid);
	if (!g_file_get_contents (proc_path, &cmdline_contents, NULL, NULL))
		goto out;

	if (!strstr (cmdline_contents, kill_match))
		goto out;

	nm_utils_kill_process_sync (pid, start_time, SIGKILL, _NMLOG_DOMAIN,
	                            progname ?: "<dns-process>",
	                            0, 0, 1000);

out:
	unlink (pidfile);
}

static void
watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMDnsPlugin *self = NM_DNS_PLUGIN (user_data);
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	priv->pid = 0;
	priv->watch_id = 0;
	g_clear_pointer (&priv->progname, g_free);
	_clear_pidfile (self);

	g_signal_emit (self, signals[CHILD_QUIT], 0, status);
}

GPid
nm_dns_plugin_child_spawn (NMDnsPlugin *self,
                           const char **argv,
                           const char *pidfile,
                           const char *kill_match)
{
	NMDnsPluginPrivate *priv;
	GError *error = NULL;
	GPid pid;
	gs_free char *cmdline = NULL;
	gs_free char *progname = NULL;

	g_return_val_if_fail (argv && argv[0], 0);
	g_return_val_if_fail (NM_IS_DNS_PLUGIN (self), 0);

	priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	g_return_val_if_fail (!priv->pid, 0);
	nm_assert (!priv->progname);
	nm_assert (!priv->watch_id);
	nm_assert (!priv->pidfile);

	progname = g_path_get_basename (argv[0]);
	kill_existing (progname, pidfile, kill_match);

	_LOGI ("starting %s...", progname);
	_LOGD ("command line: %s",
	       (cmdline = g_strjoinv (" ", (char **) argv)));

	if (!g_spawn_async (NULL, (char **) argv, NULL,
	                   G_SPAWN_DO_NOT_REAP_CHILD,
	                   nm_utils_setpgid, NULL,
	                   &pid,
	                   &error)) {
		_LOGW ("failed to spawn %s: %s",
		       progname, error->message);
		g_clear_error (&error);
		return 0;
	}

	_LOGD ("%s started with pid %d", progname, pid);
	priv->watch_id = g_child_watch_add (pid, (GChildWatchFunc) watch_cb, self);
	priv->pid = pid;
	priv->progname = nm_unauto (&progname);
	priv->pidfile = g_strdup (pidfile);

	return pid;
}

gboolean
nm_dns_plugin_child_kill (NMDnsPlugin *self)
{
	NMDnsPluginPrivate *priv = NM_DNS_PLUGIN_GET_PRIVATE (self);

	nm_clear_g_source (&priv->watch_id);
	if (priv->pid) {
		nm_utils_kill_child_sync (priv->pid, SIGTERM, _NMLOG_DOMAIN,
		                          priv->progname ?: "<dns-process>", NULL, 1000, 0);
		priv->pid = 0;
		g_clear_pointer (&priv->progname, g_free);
	}
	_clear_pidfile (self);

	return TRUE;
}

/********************************************/

static void
nm_dns_plugin_init (NMDnsPlugin *self)
{
}

static void
dispose (GObject *object)
{
	NMDnsPlugin *self = NM_DNS_PLUGIN (object);

	nm_dns_plugin_child_kill (self);

	G_OBJECT_CLASS (nm_dns_plugin_parent_class)->dispose (object);
}

static void
nm_dns_plugin_class_init (NMDnsPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);

	g_type_class_add_private (plugin_class, sizeof (NMDnsPluginPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	plugin_class->is_caching = is_caching;

	/* signals */
	signals[FAILED] =
	    g_signal_new (NM_DNS_PLUGIN_FAILED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMDnsPluginClass, failed),
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	signals[CHILD_QUIT] =
	    g_signal_new (NM_DNS_PLUGIN_CHILD_QUIT,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMDnsPluginClass, child_quit),
	                  NULL, NULL,
	                  g_cclosure_marshal_VOID__INT,
	                  G_TYPE_NONE, 1, G_TYPE_INT);
}

